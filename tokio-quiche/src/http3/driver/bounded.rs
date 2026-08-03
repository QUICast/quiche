// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::fmt;
use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Semaphore;

use super::client::ClientH3Command;
use super::client::ClientH3Event;
use super::client::ClientHooks;
use super::server::ServerH3Command;
use super::server::ServerH3Event;
use super::server::ServerHooks;
use super::webtransport;
use super::webtransport::WebTransportCommand;
use super::H3ConnectionError;
use super::H3Controller;
use super::H3Driver;
use super::H3Event;
use super::H3EventQueueStats;
use super::InboundFrameStream;
use super::IncomingH3Headers;
use super::NewClientRequest;
use super::OutboundFrame;
use super::OutboundFrameSender;
use super::WebTransportController;
use super::WebTransportDatagramError;
use super::WebTransportOpenStreamOutcome;
use super::WebTransportRetentionStats;
use super::WebTransportSessionCloseError;
use super::WebTransportSessionEvent;
use super::WebTransportSessionTerminalOutcome;
use super::WebTransportStreamControlOutcome;
use super::WebTransportStreamReadOutcome;
use super::WebTransportStreamReadyOutcome;
use super::WebTransportStreamSendTerminalOutcome;
use super::WebTransportStreamWriteLease;
use super::WebTransportStreamWriteLeaseOperation;
use super::WebTransportStreamWriteLeaseOutcome;
use crate::http3::settings::Http3Settings;
use crate::http3::H3AuditStats;
use crate::quic::HandshakeInfo;
use crate::quic::Incoming;
use crate::quic::IncomingPacketSource;
use crate::quic::IoWorkerMemoryProfile;
use crate::quic::QuicheConnection;
use crate::settings::QuicSettings;

const QPACK_FIELD_OVERHEAD: usize = 32;

/// Immutable operating mode selected when constructing an H3 driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H3ConnectionMode {
    /// Existing unrestricted HTTP/3 APIs and behavior.
    GeneralH3,
    /// One bounded draft-16 WebTransport session using only selected I/O.
    BoundedSelectedWebTransport,
}

/// Endpoint role captured by a bounded driver's applied profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedWebTransportEndpoint {
    /// Client-side H3 driver.
    Client,
    /// Server-side H3 driver.
    Server,
}

/// WebTransport-over-HTTP/3 revision implemented by the bounded profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedWebTransportRevision {
    /// `draft-ietf-webtrans-http3-16`.
    Draft16,
}

/// Datagram capability applied by the bounded profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedWebTransportDatagrams {
    /// Negotiation remains available for draft-16, but selected Datagram APIs
    /// and transport Datagram queues retain no storage.
    Disabled,
}

/// Limits applied to one CONNECT request or response field section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedConnectHeaderLimits {
    /// Maximum header field count.
    pub max_fields: usize,
    /// Maximum bytes in one field name.
    pub max_name_bytes: usize,
    /// Maximum bytes in one field value.
    pub max_value_bytes: usize,
    /// Maximum aggregate name plus value bytes.
    pub max_aggregate_bytes: usize,
}

impl Default for BoundedConnectHeaderLimits {
    fn default() -> Self {
        Self {
            max_fields: 64,
            max_name_bytes: 1024,
            max_value_bytes: 8192,
            max_aggregate_bytes: 32 * 1024,
        }
    }
}

impl BoundedConnectHeaderLimits {
    fn field_section_size(self) -> Result<usize, BoundedProfileError> {
        self.max_fields
            .checked_mul(QPACK_FIELD_OVERHEAD)
            .and_then(|overhead| overhead.checked_add(self.max_aggregate_bytes))
            .ok_or(BoundedProfileError::ArithmeticOverflow(
                "CONNECT field-section size",
            ))
    }

    pub(crate) fn validate<T: quiche::h3::NameValue>(
        self, headers: &[T],
    ) -> Result<usize, BoundedConnectHeaderError> {
        if headers.len() > self.max_fields {
            return Err(BoundedConnectHeaderError::FieldCount {
                max: self.max_fields,
                actual: headers.len(),
            });
        }

        let mut aggregate = 0usize;
        for (index, header) in headers.iter().enumerate() {
            let name = header.name();
            let value = header.value();
            if name.len() > self.max_name_bytes {
                return Err(BoundedConnectHeaderError::NameTooLarge {
                    index,
                    max: self.max_name_bytes,
                    actual: name.len(),
                });
            }
            if value.len() > self.max_value_bytes {
                return Err(BoundedConnectHeaderError::ValueTooLarge {
                    index,
                    max: self.max_value_bytes,
                    actual: value.len(),
                });
            }
            aggregate = aggregate
                .checked_add(name.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(BoundedConnectHeaderError::AggregateOverflow)?;
            if aggregate > self.max_aggregate_bytes {
                return Err(BoundedConnectHeaderError::AggregateTooLarge {
                    max: self.max_aggregate_bytes,
                    actual: aggregate,
                });
            }
        }
        Ok(aggregate)
    }
}

/// Failure while checking a bounded CONNECT field section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundedConnectHeaderError {
    /// Too many fields were supplied.
    FieldCount {
        /// Configured maximum.
        max: usize,
        /// Supplied count.
        actual: usize,
    },
    /// One field name exceeded its bound.
    NameTooLarge {
        /// Zero-based field index.
        index: usize,
        /// Configured maximum.
        max: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// One field value exceeded its bound.
    ValueTooLarge {
        /// Zero-based field index.
        index: usize,
        /// Configured maximum.
        max: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// Aggregate name plus value bytes exceeded their bound.
    AggregateTooLarge {
        /// Configured maximum.
        max: usize,
        /// Supplied aggregate byte length.
        actual: usize,
    },
    /// Aggregate length arithmetic overflowed.
    AggregateOverflow,
    /// The fields do not form a draft-16 WebTransport CONNECT request.
    NotWebTransportConnect,
    /// A server response omitted a valid `:status` field.
    NotHttpResponse,
}

impl fmt::Display for BoundedConnectHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid bounded WebTransport CONNECT headers: {self:?}")
    }
}

impl std::error::Error for BoundedConnectHeaderError {}

/// Right-sized, checked CONNECT fields accepted by the bounded controller.
#[derive(Debug, Eq, PartialEq)]
pub struct BoundedConnectHeaders {
    headers: Box<[quiche::h3::Header]>,
    aggregate_bytes: usize,
}

impl BoundedConnectHeaders {
    /// Copies checked fields into transport-ready owned storage.
    ///
    /// Validation completes before any transport-owned field is allocated.
    pub fn copy_from<T: quiche::h3::NameValue>(
        headers: &[T], limits: BoundedConnectHeaderLimits,
    ) -> Result<Self, BoundedConnectHeaderError> {
        let aggregate_bytes = limits.validate(headers)?;
        let headers = headers
            .iter()
            .map(|header| quiche::h3::Header::new(header.name(), header.value()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            headers,
            aggregate_bytes,
        })
    }

    /// Returns the checked fields.
    pub fn as_slice(&self) -> &[quiche::h3::Header] {
        &self.headers
    }

    /// Returns aggregate name plus value bytes.
    pub fn aggregate_bytes(&self) -> usize {
        self.aggregate_bytes
    }

    pub(crate) fn into_vec(self) -> Vec<quiche::h3::Header> {
        self.headers.into_vec()
    }
}

/// QUIC transport settings that must match a bounded H3 driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedWebTransportQuicSettings {
    /// Connection receive credit advertised initially.
    pub initial_max_data: u64,
    /// Initial receive credit for locally initiated bidirectional streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial receive credit for remotely initiated bidirectional streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial receive credit for unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// Initial peer-initiated bidirectional stream count.
    pub initial_max_streams_bidi: u64,
    /// Initial peer-initiated unidirectional stream count.
    pub initial_max_streams_uni: u64,
    /// Maximum adaptive connection receive window.
    pub max_connection_window: u64,
    /// Maximum adaptive per-stream receive window.
    pub max_stream_window: u64,
    /// Active connection-ID limit, also bounding retained path recovery state.
    pub active_connection_id_limit: u64,
    /// Maximum incoming UDP allocation supplied by the managed router.
    pub max_recv_udp_payload_size: usize,
    /// Configured maximum outgoing UDP payload size.
    pub max_send_udp_payload_size: usize,
    /// Whether core path lifecycle events are retained.
    ///
    /// This must be `false` for the bounded profile because its controller
    /// does not expose path events.
    pub retain_path_events: bool,
    /// Local storage cap for source Connection IDs.
    pub max_source_connection_ids: usize,
    /// Maximum received PATH_CHALLENGE values retained per path.
    pub max_path_challenge_recv_queue_len: usize,
}

impl Default for BoundedWebTransportQuicSettings {
    fn default() -> Self {
        let settings = QuicSettings::default();
        Self {
            initial_max_data: 1024 * 1024,
            initial_max_stream_data_bidi_local: 256 * 1024,
            initial_max_stream_data_bidi_remote: 256 * 1024,
            initial_max_stream_data_uni: 256 * 1024,
            initial_max_streams_bidi: 64,
            initial_max_streams_uni: 64,
            max_connection_window: 1024 * 1024,
            max_stream_window: 512 * 1024,
            active_connection_id_limit: settings.active_connection_id_limit,
            max_recv_udp_payload_size: settings.max_recv_udp_payload_size,
            max_send_udp_payload_size: settings.max_send_udp_payload_size,
            retain_path_events: false,
            max_source_connection_ids: settings.active_connection_id_limit
                as usize,
            max_path_challenge_recv_queue_len: 3,
        }
    }
}

impl BoundedWebTransportQuicSettings {
    /// Applies the immutable transport profile to endpoint QUIC settings.
    pub fn apply_to(self, settings: &mut QuicSettings) {
        settings.enable_dgram = true;
        settings.enable_reset_stream_at = true;
        settings.initial_max_data = self.initial_max_data;
        settings.initial_max_stream_data_bidi_local =
            self.initial_max_stream_data_bidi_local;
        settings.initial_max_stream_data_bidi_remote =
            self.initial_max_stream_data_bidi_remote;
        settings.initial_max_stream_data_uni = self.initial_max_stream_data_uni;
        settings.initial_max_streams_bidi = self.initial_max_streams_bidi;
        settings.initial_max_streams_uni = self.initial_max_streams_uni;
        settings.max_connection_window = self.max_connection_window;
        settings.max_stream_window = self.max_stream_window;
        settings.active_connection_id_limit = self.active_connection_id_limit;
        settings.max_recv_udp_payload_size = self.max_recv_udp_payload_size;
        settings.max_send_udp_payload_size = self.max_send_udp_payload_size;
        settings.retain_path_events = self.retain_path_events;
        settings.max_source_connection_ids = self.max_source_connection_ids;
        settings.max_path_challenge_recv_queue_len =
            self.max_path_challenge_recv_queue_len;
        settings.track_unknown_transport_parameters = None;
        settings.qlog_dir = None;
        settings.keylog_file = None;
        settings.capture_quiche_logs = false;
        settings.enable_expensive_packet_count_metrics = false;
    }
}

/// Managed IO worker settings required by the bounded profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedWebTransportIoSettings {
    /// Maximum packets retained in one connection's incoming lane.
    pub incoming_packet_queue_capacity: usize,
    /// Full-size egress allocations allowed per runtime worker.
    pub send_buffer_pool_capacity_per_worker: usize,
    /// Endpoint-wide listener Connection-ID command capacity.
    pub connection_map_command_capacity: usize,
}

impl Default for BoundedWebTransportIoSettings {
    fn default() -> Self {
        Self {
            incoming_packet_queue_capacity: 64,
            send_buffer_pool_capacity_per_worker: 4,
            connection_map_command_capacity: 4096,
        }
    }
}

impl BoundedWebTransportIoSettings {
    /// Applies the managed hard-bounded worker policy to endpoint settings.
    pub fn apply_to(self, settings: &mut QuicSettings) {
        settings.pool_send_buffer = true;
        settings.hard_bound_send_buffer_pool = true;
        settings.send_buffer_pool_capacity_per_worker =
            self.send_buffer_pool_capacity_per_worker;
        settings.incoming_packet_queue_capacity =
            self.incoming_packet_queue_capacity;
        settings.connection_map_command_capacity =
            Some(self.connection_map_command_capacity);
    }

    fn expected_profile(self) -> IoWorkerMemoryProfile {
        IoWorkerMemoryProfile {
            incoming_packet_source: IncomingPacketSource::ManagedSocket,
            incoming_packet_queue_capacity: self
                .incoming_packet_queue_capacity
                .max(1),
            max_incoming_packet_allocation_bytes:
                datagram_socket::MAX_DATAGRAM_SIZE,
            pool_send_buffer: true,
            send_buffer_pool_capacity_per_worker: self
                .send_buffer_pool_capacity_per_worker,
            hard_bound_send_buffer_pool: true,
            send_buffer_allocation_bytes: crate::quic::SEND_BUFFER_SIZE,
            connection_map_command_capacity: Some(
                self.connection_map_command_capacity,
            ),
            qlog_enabled: false,
            keylog_enabled: false,
        }
    }
}

/// Limits for the selected WebTransport runtime and its bounded lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedSelectedWebTransportLimits {
    /// Capacity of the private endpoint H3 command lane.
    pub h3_command_capacity: usize,
    /// Capacity of the private endpoint H3 event lane.
    pub h3_event_capacity: usize,
    /// Capacity of the selected WebTransport command lane.
    pub selected_command_capacity: usize,
    /// Aggregate and per-session pending associated-stream cap.
    pub max_pending_streams: usize,
    /// Aggregate and per-session active associated-stream cap.
    pub max_active_streams: usize,
    /// Aggregate selected stream-readable/writable waiter cap.
    pub max_stream_waiters: usize,
    /// Aggregate session-terminal waiter cap.
    pub max_session_terminal_waiters: usize,
    /// Per-session terminal waiter cap.
    pub max_session_terminal_waiters_per_session: usize,
    /// Aggregate and per-session terminal waiter/fact cap.
    pub max_send_terminal_waiters: usize,
    /// Retained bounded-client CONNECT owners. The one-session profile
    /// requires exactly one slot.
    pub max_client_connect_owners: usize,
    /// Selected runtime work cap per driver callback.
    pub max_session_work_per_callback: usize,
    /// Maximum payload exposed by one selected write attempt.
    pub max_stream_write_bytes: usize,
    /// Maximum caller-owned bytes lent by one selected write lease.
    pub max_stream_write_lease_retained_bytes: usize,
    /// Maximum compiler-known inline size of one admitted lease owner.
    pub max_stream_write_lease_owner_bytes: usize,
    /// Maximum allocation returned by one selected read.
    pub max_stream_read_bytes: usize,
    /// Maximum selected reads whose result ownership has not returned.
    pub max_concurrent_stream_reads: usize,
    /// Hard copied stream-send backing cap retained by core quiche.
    pub max_stream_send_retained_bytes: usize,
    /// Hard retained stream-send chunk cap in core quiche.
    pub max_stream_send_retained_chunks: usize,
    /// Hard recovery packet-record cap per retained path.
    pub max_tracked_sent_packets_per_path: usize,
    /// Hard retransmission-tracked frame cap per packet.
    pub max_tracked_frames_per_packet: usize,
}

impl Default for BoundedSelectedWebTransportLimits {
    fn default() -> Self {
        Self {
            h3_command_capacity: 8,
            h3_event_capacity: 64,
            selected_command_capacity: 256,
            max_pending_streams: 64,
            max_active_streams: 64,
            max_stream_waiters: 128,
            max_session_terminal_waiters: 64,
            max_session_terminal_waiters_per_session: 64,
            max_send_terminal_waiters: 64,
            max_client_connect_owners: 1,
            max_session_work_per_callback: 64,
            max_stream_write_bytes: 64 * 1024,
            max_stream_write_lease_retained_bytes: 64 * 1024,
            max_stream_write_lease_owner_bytes: 4096,
            max_stream_read_bytes: 64 * 1024,
            max_concurrent_stream_reads: 64,
            max_stream_send_retained_bytes: 8 * 1024 * 1024,
            max_stream_send_retained_chunks: 2048,
            max_tracked_sent_packets_per_path: 4096,
            max_tracked_frames_per_packet: 8,
        }
    }
}

/// Construction settings for one bounded selected-WebTransport H3 driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedSelectedWebTransportSettings {
    /// CONNECT request and response field bounds.
    pub connect_headers: BoundedConnectHeaderLimits,
    /// Selected-I/O and lane bounds.
    pub selected: BoundedSelectedWebTransportLimits,
    /// QUIC transport values verified at establishment.
    pub quic: BoundedWebTransportQuicSettings,
    /// Managed IO worker values verified at establishment.
    pub io: BoundedWebTransportIoSettings,
    /// Aggregate ceiling for all checked dynamic components.
    pub dynamic_retained_memory_ceiling: usize,
    /// Explicit allowance for allocator rounding and collection node overhead.
    pub implementation_margin_bytes: usize,
}

impl Default for BoundedSelectedWebTransportSettings {
    fn default() -> Self {
        Self {
            connect_headers: BoundedConnectHeaderLimits::default(),
            selected: BoundedSelectedWebTransportLimits::default(),
            quic: BoundedWebTransportQuicSettings::default(),
            io: BoundedWebTransportIoSettings::default(),
            dynamic_retained_memory_ceiling: 1024 * 1024 * 1024,
            implementation_margin_bytes: 4 * 1024 * 1024,
        }
    }
}

impl BoundedSelectedWebTransportSettings {
    /// Applies every QUIC and managed-worker setting checked at establishment.
    pub fn apply_to_quic_settings(self, settings: &mut QuicSettings) {
        self.quic.apply_to(settings);
        self.io.apply_to(settings);
        settings.dgram_recv_max_queue_len = 0;
        settings.dgram_send_max_queue_len = 0;
        settings.dgram_recv_max_queue_bytes = 0;
        settings.dgram_recv_max_queue_allocation_bytes = 0;
        settings.dgram_send_max_queue_bytes = 0;
        settings.dgram_send_max_queue_allocation_bytes = 0;
        settings.stream_send_max_retained_bytes =
            self.selected.max_stream_send_retained_bytes;
        settings.stream_send_max_retained_chunks =
            self.selected.max_stream_send_retained_chunks;
        settings.max_tracked_sent_packets_per_path =
            self.selected.max_tracked_sent_packets_per_path;
        settings.max_tracked_frames_per_packet =
            self.selected.max_tracked_frames_per_packet;
    }

    /// Returns checked user-space envelope components before construction.
    ///
    /// For an endpoint admitting only this profile, the conservative process
    /// bound is:
    ///
    /// `sum(dynamic_retained_memory_ceiling per admitted connection) +
    /// worker_count * shared_egress_bytes_per_worker + connection_count *
    /// per_connection_transient_egress_bytes + embedding fixed margin`.
    ///
    /// Kernel socket memory is deliberately separate:
    ///
    /// `socket_count * configured(send_socket_buffer + recv_socket_buffer)`.
    ///
    /// Allocator metadata, TLS/backend fixed state, and collection-node
    /// rounding belong in the embedding fixed margin. Kernel queues and a
    /// caller-owned write-lease payload are not charged to the Rust dynamic
    /// ceiling.
    pub fn checked_memory_envelope(
        self, endpoint: BoundedWebTransportEndpoint,
    ) -> Result<BoundedMemoryEnvelope, BoundedProfileError> {
        let prepared = self.prepare(endpoint)?;
        Ok(BoundedMemoryEnvelope {
            dynamic_components: prepared.applied.dynamic_components,
            dynamic_retained_memory_ceiling: prepared
                .applied
                .dynamic_retained_memory_ceiling,
            fixed_pools: prepared.applied.fixed_pools,
        })
    }

    pub(crate) fn prepare(
        self, endpoint: BoundedWebTransportEndpoint,
    ) -> Result<PreparedBoundedProfile, BoundedProfileError> {
        self.validate()?;
        let field_section_size = self.connect_headers.field_section_size()?;
        let endpoint_command_size = match endpoint {
            BoundedWebTransportEndpoint::Client =>
                mem::size_of::<ClientH3Command>(),
            BoundedWebTransportEndpoint::Server =>
                mem::size_of::<ServerH3Command>(),
        };
        let endpoint_event_size = match endpoint {
            BoundedWebTransportEndpoint::Client =>
                mem::size_of::<ClientH3Event>(),
            BoundedWebTransportEndpoint::Server =>
                mem::size_of::<ServerH3Event>(),
        };
        let components = self.memory_components(
            endpoint,
            field_section_size,
            endpoint_command_size,
            endpoint_event_size,
        )?;
        if components.total > self.dynamic_retained_memory_ceiling {
            return Err(BoundedProfileError::DynamicEnvelopeTooSmall {
                required: components.total,
                configured: self.dynamic_retained_memory_ceiling,
            });
        }

        let worker = self.io.expected_profile();
        let fixed_pools = BoundedFixedPoolCeilings {
            shared_egress_bytes_per_worker: worker
                .send_buffer_pool_capacity_per_worker
                .checked_mul(worker.send_buffer_allocation_bytes)
                .ok_or(BoundedProfileError::ArithmeticOverflow(
                    "shared egress pool ceiling",
                ))?,
            per_connection_transient_egress_bytes:
                crate::quic::TRANSIENT_SEND_BUFFER_SIZE,
            raw_stream_scratch_bytes: 0,
            router_receive_scratch_bytes:
                crate::buf_factory::BufFactory::MAX_BUF_SIZE,
            connection_map_command_lane_bytes: self
                .io
                .connection_map_command_capacity
                .checked_mul(
                    crate::quic::connection_map_command_slot_upper_bound(),
                )
                .and_then(|lane| {
                    lane.checked_add(
                        crate::quic::connection_map_command_batch_upper_bound(),
                    )
                })
                .ok_or(BoundedProfileError::ArithmeticOverflow(
                    "Connection-ID map command lane",
                ))?,
        };
        let applied = AppliedBoundedWebTransportProfile {
            mode: H3ConnectionMode::BoundedSelectedWebTransport,
            endpoint,
            revision: BoundedWebTransportRevision::Draft16,
            webtransport_enabled: true,
            max_sessions: 1,
            quic: self.quic,
            connect_headers: self.connect_headers,
            selected: self.selected,
            h3_command_capacity: self.selected.h3_command_capacity,
            h3_event_capacity: self.selected.h3_event_capacity,
            datagrams: BoundedWebTransportDatagrams::Disabled,
            datagram_send_items: 0,
            datagram_send_bytes: 0,
            datagram_recv_items: 0,
            datagram_recv_bytes: 0,
            retention_limits_frozen: true,
            io_worker: worker,
            fixed_pools,
            dynamic_components: components,
            dynamic_retained_memory_ceiling: self.dynamic_retained_memory_ceiling,
        };

        Ok(PreparedBoundedProfile {
            http3: self.http3_settings(field_section_size)?,
            applied,
            status: Arc::new(OnceLock::new()),
            client_connect_ownership: matches!(
                endpoint,
                BoundedWebTransportEndpoint::Client
            )
            .then(|| {
                Arc::new(BoundedClientConnectOwnership::new(
                    self.selected.max_client_connect_owners,
                ))
            }),
        })
    }

    fn http3_settings(
        self, field_section_size: usize,
    ) -> Result<Http3Settings, BoundedProfileError> {
        let max_header_list_size =
            u64::try_from(field_section_size).map_err(|_| {
                BoundedProfileError::ArithmeticOverflow(
                    "HTTP/3 field-section setting",
                )
            })?;

        Ok(Http3Settings {
            command_capacity: self.selected.h3_command_capacity,
            event_capacity: self.selected.h3_event_capacity,
            max_requests_per_connection: Some(1),
            max_header_list_size: Some(max_header_list_size),
            max_header_field_count: Some(self.connect_headers.max_fields),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            enable_extended_connect: true,
            enable_webtransport: true,
            webtransport_max_pending_streams: self.selected.max_pending_streams,
            webtransport_max_pending_streams_per_session: self
                .selected
                .max_pending_streams,
            webtransport_max_active_streams: self.selected.max_active_streams,
            webtransport_max_active_streams_per_session: self
                .selected
                .max_active_streams,
            webtransport_max_stream_waiters: self.selected.max_stream_waiters,
            webtransport_max_session_terminal_waiters: self
                .selected
                .max_session_terminal_waiters,
            webtransport_max_session_terminal_waiters_per_session: self
                .selected
                .max_session_terminal_waiters_per_session,
            webtransport_max_send_terminal_waiters: self
                .selected
                .max_send_terminal_waiters,
            webtransport_max_send_terminal_waiters_per_session: self
                .selected
                .max_send_terminal_waiters,
            webtransport_max_datagram_waiters: 0,
            webtransport_max_session_work_per_callback: self
                .selected
                .max_session_work_per_callback,
            webtransport_command_capacity: self
                .selected
                .selected_command_capacity,
            webtransport_max_stream_write_bytes: self
                .selected
                .max_stream_write_bytes,
            webtransport_max_stream_write_lease_retained_bytes: self
                .selected
                .max_stream_write_lease_retained_bytes,
            webtransport_max_stream_write_lease_owner_bytes: self
                .selected
                .max_stream_write_lease_owner_bytes,
            webtransport_max_stream_read_bytes: self
                .selected
                .max_stream_read_bytes,
            webtransport_max_datagram_send_allocation_bytes: 0,
            webtransport_max_datagram_prefixed_allocation_bytes: 0,
            webtransport_max_pending_datagrams: 0,
            webtransport_max_pending_datagrams_per_session: 0,
            webtransport_max_pending_datagram_bytes: 0,
            webtransport_max_pending_datagram_bytes_per_session: 0,
            webtransport_max_pending_datagram_allocation_bytes: 0,
            webtransport_max_pending_datagram_allocation_bytes_per_session: 0,
            multicast_datagram_channel_id: None,
            experimental_raw_quic_stream_ids: Vec::new(),
            ..Default::default()
        })
    }

    fn validate(self) -> Result<(), BoundedProfileError> {
        for (name, value) in [
            ("CONNECT max fields", self.connect_headers.max_fields),
            (
                "CONNECT max name bytes",
                self.connect_headers.max_name_bytes,
            ),
            (
                "CONNECT max value bytes",
                self.connect_headers.max_value_bytes,
            ),
            (
                "CONNECT aggregate bytes",
                self.connect_headers.max_aggregate_bytes,
            ),
            ("H3 command capacity", self.selected.h3_command_capacity),
            ("H3 event capacity", self.selected.h3_event_capacity),
            (
                "selected command capacity",
                self.selected.selected_command_capacity,
            ),
            ("pending streams", self.selected.max_pending_streams),
            ("active streams", self.selected.max_active_streams),
            ("stream waiters", self.selected.max_stream_waiters),
            (
                "session terminal waiters",
                self.selected.max_session_terminal_waiters,
            ),
            (
                "per-session terminal waiters",
                self.selected.max_session_terminal_waiters_per_session,
            ),
            (
                "send terminal waiters",
                self.selected.max_send_terminal_waiters,
            ),
            (
                "bounded client CONNECT owners",
                self.selected.max_client_connect_owners,
            ),
            ("callback work", self.selected.max_session_work_per_callback),
            ("stream write bytes", self.selected.max_stream_write_bytes),
            (
                "write lease retained bytes",
                self.selected.max_stream_write_lease_retained_bytes,
            ),
            (
                "write lease owner bytes",
                self.selected.max_stream_write_lease_owner_bytes,
            ),
            ("stream read bytes", self.selected.max_stream_read_bytes),
            (
                "concurrent stream reads",
                self.selected.max_concurrent_stream_reads,
            ),
            (
                "stream send retained bytes",
                self.selected.max_stream_send_retained_bytes,
            ),
            (
                "stream send retained chunks",
                self.selected.max_stream_send_retained_chunks,
            ),
            (
                "tracked sent packets",
                self.selected.max_tracked_sent_packets_per_path,
            ),
            (
                "tracked frames per packet",
                self.selected.max_tracked_frames_per_packet,
            ),
            (
                "incoming packet capacity",
                self.io.incoming_packet_queue_capacity,
            ),
            (
                "Connection-ID map command capacity",
                self.io.connection_map_command_capacity,
            ),
            (
                "dynamic retained memory ceiling",
                self.dynamic_retained_memory_ceiling,
            ),
        ] {
            if value == 0 {
                return Err(BoundedProfileError::ZeroLimit(name));
            }
        }
        for (name, value) in [
            ("initial_max_data", self.quic.initial_max_data),
            (
                "initial_max_stream_data_bidi_local",
                self.quic.initial_max_stream_data_bidi_local,
            ),
            (
                "initial_max_stream_data_bidi_remote",
                self.quic.initial_max_stream_data_bidi_remote,
            ),
            (
                "initial_max_stream_data_uni",
                self.quic.initial_max_stream_data_uni,
            ),
            (
                "initial_max_streams_bidi",
                self.quic.initial_max_streams_bidi,
            ),
            ("initial_max_streams_uni", self.quic.initial_max_streams_uni),
            (
                "active_connection_id_limit",
                self.quic.active_connection_id_limit,
            ),
            ("max_connection_window", self.quic.max_connection_window),
            ("max_stream_window", self.quic.max_stream_window),
        ] {
            if value > octets::MAX_VAR_INT {
                return Err(BoundedProfileError::InvalidWireValue(name));
            }
        }
        let max_recv_udp_payload_size =
            u64::try_from(self.quic.max_recv_udp_payload_size).map_err(|_| {
                BoundedProfileError::InvalidWireValue("max_recv_udp_payload_size")
            })?;
        if max_recv_udp_payload_size > octets::MAX_VAR_INT {
            return Err(BoundedProfileError::InvalidWireValue(
                "max_recv_udp_payload_size",
            ));
        }
        if self.quic.max_recv_udp_payload_size < 1200 ||
            self.quic.max_send_udp_payload_size < 1200
        {
            return Err(BoundedProfileError::InvalidSetting(
                "UDP payload limits must be at least 1200",
            ));
        }
        if self.io.send_buffer_pool_capacity_per_worker >
            crate::quic::SEND_BUF_POOL_HARD_CAP
        {
            return Err(BoundedProfileError::WorkerPoolTooLarge {
                max: crate::quic::SEND_BUF_POOL_HARD_CAP,
                actual: self.io.send_buffer_pool_capacity_per_worker,
            });
        }
        if self.quic.active_connection_id_limit < 2 {
            return Err(BoundedProfileError::InvalidSetting(
                "active_connection_id_limit must be at least two",
            ));
        }
        if self.quic.max_source_connection_ids < 2 {
            return Err(BoundedProfileError::InvalidSetting(
                "max_source_connection_ids must be at least two",
            ));
        }
        if u64::try_from(self.quic.max_source_connection_ids).map_err(|_| {
            BoundedProfileError::ArithmeticOverflow("source Connection-ID limit")
        })? > self.quic.active_connection_id_limit
        {
            return Err(BoundedProfileError::InvalidSetting(
                "source Connection-ID cap exceeds active_connection_id_limit",
            ));
        }
        if self.quic.max_connection_window < self.quic.initial_max_data {
            return Err(BoundedProfileError::InvalidSetting(
                "max_connection_window is below initial_max_data",
            ));
        }
        let max_initial_stream_window = self
            .quic
            .initial_max_stream_data_bidi_local
            .max(self.quic.initial_max_stream_data_bidi_remote)
            .max(self.quic.initial_max_stream_data_uni);
        if self.quic.max_stream_window < max_initial_stream_window {
            return Err(BoundedProfileError::InvalidSetting(
                "max_stream_window is below an initial stream window",
            ));
        }
        if self.selected.max_session_terminal_waiters_per_session >
            self.selected.max_session_terminal_waiters
        {
            return Err(BoundedProfileError::InvalidSetting(
                "per-session terminal waiter cap exceeds connection cap",
            ));
        }
        if self.selected.max_client_connect_owners != 1 {
            return Err(BoundedProfileError::InvalidSetting(
                "the one-session profile requires one client CONNECT owner",
            ));
        }
        if self.quic.retain_path_events {
            return Err(BoundedProfileError::InvalidSetting(
                "bounded mode cannot retain path events",
            ));
        }
        Ok(())
    }

    fn memory_components(
        self, endpoint: BoundedWebTransportEndpoint, field_section_size: usize,
        endpoint_command_size: usize, endpoint_event_size: usize,
    ) -> Result<BoundedDynamicMemoryComponents, BoundedProfileError> {
        let checked_mul = |a: usize, b: usize, name| {
            a.checked_mul(b)
                .ok_or(BoundedProfileError::ArithmeticOverflow(name))
        };
        let stream_receive_backing =
            usize::try_from(self.quic.max_connection_window).map_err(|_| {
                BoundedProfileError::ArithmeticOverflow(
                    "connection receive window",
                )
            })?;
        let remote_bidi = usize::try_from(self.quic.initial_max_streams_bidi)
            .map_err(|_| {
                BoundedProfileError::ArithmeticOverflow(
                    "peer bidirectional stream count",
                )
            })?;
        let remote_uni = usize::try_from(self.quic.initial_max_streams_uni)
            .map_err(|_| {
                BoundedProfileError::ArithmeticOverflow(
                    "peer unidirectional stream count",
                )
            })?;
        // Local H3 control/QPACK streams, one CONNECT, and shutdown overlap.
        const H3_FIXED_STREAM_ALLOWANCE: usize = 8;
        let live_streams = remote_bidi
            .checked_add(remote_uni)
            .and_then(|value| value.checked_add(self.selected.max_active_streams))
            .and_then(|value| value.checked_add(H3_FIXED_STREAM_ALLOWANCE))
            .ok_or(BoundedProfileError::ArithmeticOverflow(
                "live stream count",
            ))?;
        // Every retained byte can arrive in a separate STREAM frame. Empty FIN
        // fragments add at most one entry per live stream.
        let receive_fragments =
            stream_receive_backing.checked_add(live_streams).ok_or(
                BoundedProfileError::ArithmeticOverflow("receive fragment count"),
            )?;
        let stream_receive_fragment_metadata = checked_mul(
            receive_fragments,
            quiche::stream_receive_fragment_metadata_size(),
            "stream receive fragment metadata",
        )?;
        let core_stream_metadata = checked_mul(
            live_streams,
            quiche::live_stream_metadata_size::<crate::buf_factory::BufFactory>(),
            "core live stream metadata",
        )?;
        let h3_stream_metadata = checked_mul(
            live_streams,
            quiche::h3::stream_retained_metadata_upper_bound(),
            "H3 live stream metadata",
        )?;
        let h3_driver_stream_metadata = checked_mul(
            live_streams,
            super::streams::retained_stream_metadata_upper_bound(),
            "Tokio H3 live stream metadata",
        )?;
        let h3_stream_handoff_backing = checked_mul(
            live_streams,
            crate::buf_factory::BufFactory::MAX_BUF_SIZE,
            "Tokio H3 stream handoff backing",
        )?;
        let h3_body_scratch = crate::buf_factory::BufFactory::MAX_BUF_SIZE
            .checked_mul(2)
            .ok_or(BoundedProfileError::ArithmeticOverflow("H3 body scratch"))?;
        let incoming_packet_lane = checked_mul(
            self.io.incoming_packet_queue_capacity,
            datagram_socket::MAX_DATAGRAM_SIZE + mem::size_of::<Incoming>(),
            "incoming packet lane",
        )?;
        // Encoded QPACK, decoded fields, the bounded application handoff, and
        // an admitted response can overlap. Outer field arrays are charged
        // separately because RFC field-section accounting uses only 32 bytes
        // of per-field overhead while Rust's owned Header is larger.
        let connect_header_storage = field_section_size
            .checked_mul(4)
            .and_then(|value| {
                self.connect_headers
                    .max_fields
                    .checked_mul(mem::size_of::<quiche::h3::Header>())
                    .and_then(|metadata| metadata.checked_mul(4))
                    .and_then(|metadata| value.checked_add(metadata))
            })
            .ok_or(BoundedProfileError::ArithmeticOverflow(
                "CONNECT header storage",
            ))?;
        let bounded_client_connect_owner_metadata =
            if matches!(endpoint, BoundedWebTransportEndpoint::Client) {
                checked_mul(
                    self.selected.max_client_connect_owners,
                    bounded_client_connect_owner_metadata_upper_bound(),
                    "bounded client CONNECT owner metadata",
                )?
            } else {
                0
            };
        let selected_command_lane = checked_mul(
            self.selected.selected_command_capacity,
            mem::size_of::<WebTransportCommand>(),
            "selected command lane",
        )?;
        let h3_command_lane = checked_mul(
            self.selected.h3_command_capacity,
            endpoint_command_size,
            "H3 command lane",
        )?;
        let h3_command_payloads = checked_mul(
            self.selected.h3_command_capacity,
            webtransport::MAX_CLOSE_MESSAGE_LEN,
            "H3 command payloads",
        )?;
        let h3_event_lane = checked_mul(
            self.selected.h3_event_capacity,
            endpoint_event_size,
            "H3 event lane",
        )?;
        let selected_state_metadata = webtransport::runtime_metadata_upper_bound(
            self.selected.max_pending_streams,
            self.selected.max_active_streams,
            self.selected.max_stream_waiters,
            self.selected.max_send_terminal_waiters,
            self.selected.max_session_terminal_waiters,
        )
        .and_then(|value| value.checked_mul(2))
        .ok_or(BoundedProfileError::ArithmeticOverflow(
            "selected runtime metadata",
        ))?;
        let selected_read_results = checked_mul(
            self.selected.max_concurrent_stream_reads,
            self.selected.max_stream_read_bytes,
            "selected read results",
        )?;
        let selected_write_lease_owners = checked_mul(
            self.selected.selected_command_capacity,
            self.selected.max_stream_write_lease_owner_bytes,
            "selected write-lease owners",
        )?;
        let path_count = usize::try_from(self.quic.active_connection_id_limit)
            .map_err(|_| {
                BoundedProfileError::ArithmeticOverflow("recovery path count")
            })?;
        let recovery_records = checked_mul(
            self.selected.max_tracked_sent_packets_per_path,
            path_count,
            "recovery record count",
        )?;
        let recovery_metadata = checked_mul(
            recovery_records,
            quiche::tracked_sent_packet_metadata_size(),
            "recovery metadata",
        )?;
        let recovery_packet_equivalents_per_path = self
            .selected
            .max_tracked_sent_packets_per_path
            .checked_mul(7)
            .and_then(|value| value.checked_add(6))
            .ok_or(BoundedProfileError::ArithmeticOverflow(
                "recovery frame queue packet equivalents",
            ))?;
        let recovery_frame_slots = recovery_packet_equivalents_per_path
            .checked_mul(self.selected.max_tracked_frames_per_packet)
            .and_then(|value| value.checked_mul(path_count))
            .ok_or(BoundedProfileError::ArithmeticOverflow(
                "recovery frame slots",
            ))?;
        // Queue capacities can geometrically approach twice their largest
        // occupancy. Empty queues are shrunk by core recovery.
        let recovery_frame_metadata = recovery_frame_slots
            .checked_mul(quiche::tracked_frame_metadata_size())
            .and_then(|value| value.checked_mul(2))
            .ok_or(BoundedProfileError::ArithmeticOverflow(
                "recovery frame metadata",
            ))?;
        // Across all frames copied out of one packet, owned frame backing is
        // bounded by that packet's configured UDP payload size.
        let recovery_frame_owned_backing = recovery_packet_equivalents_per_path
            .checked_mul(self.quic.max_send_udp_payload_size)
            .and_then(|value| value.checked_mul(path_count))
            .ok_or(BoundedProfileError::ArithmeticOverflow(
                "recovery frame owned backing",
            ))?;
        let path_metadata = checked_mul(
            path_count,
            quiche::path_metadata_size(),
            "path metadata",
        )?;
        let path_challenge_storage = checked_mul(
            path_count,
            self.quic.max_path_challenge_recv_queue_len,
            "PATH_CHALLENGE item count",
        )?
        .checked_mul(mem::size_of::<[u8; 8]>())
        .ok_or(BoundedProfileError::ArithmeticOverflow(
            "PATH_CHALLENGE storage",
        ))?;
        let connection_id_metadata =
            quiche::connection_id_retention_metadata_upper_bound(
                path_count,
                self.quic.max_source_connection_ids,
            )
            .and_then(|core| {
                self.quic
                    .max_source_connection_ids
                    .checked_mul(crate::quic::connection_map_entry_upper_bound())
                    .and_then(|router| core.checked_add(router))
            })
            .ok_or(BoundedProfileError::ArithmeticOverflow(
                "Connection-ID metadata",
            ))?;
        let stream_chunk_metadata = checked_mul(
            self.selected.max_stream_send_retained_chunks,
            quiche::stream_send_chunk_metadata_size::<
                crate::buf_factory::BufFactory,
            >(),
            "stream send chunk metadata",
        )?;

        let values = [
            self.selected.max_stream_send_retained_bytes,
            stream_chunk_metadata,
            stream_receive_backing,
            stream_receive_fragment_metadata,
            core_stream_metadata,
            h3_stream_metadata,
            h3_driver_stream_metadata,
            h3_stream_handoff_backing,
            h3_body_scratch,
            incoming_packet_lane,
            connect_header_storage,
            bounded_client_connect_owner_metadata,
            selected_command_lane,
            h3_command_lane,
            h3_command_payloads,
            h3_event_lane,
            selected_state_metadata,
            selected_read_results,
            selected_write_lease_owners,
            recovery_metadata,
            recovery_frame_metadata,
            recovery_frame_owned_backing,
            path_metadata,
            path_challenge_storage,
            connection_id_metadata,
            self.implementation_margin_bytes,
        ];
        let total = values.into_iter().try_fold(0usize, |total, value| {
            total.checked_add(value).ok_or(
                BoundedProfileError::ArithmeticOverflow(
                    "dynamic memory envelope",
                ),
            )
        })?;

        Ok(BoundedDynamicMemoryComponents {
            stream_send_backing: self.selected.max_stream_send_retained_bytes,
            stream_send_chunk_metadata: stream_chunk_metadata,
            stream_receive_backing,
            stream_receive_fragment_metadata,
            core_stream_metadata,
            h3_stream_metadata,
            h3_driver_stream_metadata,
            h3_stream_handoff_backing,
            h3_body_scratch,
            incoming_packet_lane,
            connect_header_storage,
            bounded_client_connect_owner_metadata,
            selected_command_lane,
            h3_command_lane,
            h3_command_payloads,
            h3_event_lane,
            selected_state_metadata,
            selected_read_results,
            selected_write_lease_owners,
            recovery_metadata,
            recovery_frame_metadata,
            recovery_frame_owned_backing,
            path_metadata,
            path_challenge_storage,
            connection_id_metadata,
            datagram_storage: 0,
            implementation_margin: self.implementation_margin_bytes,
            total,
        })
    }
}

/// Checked dynamic user-space envelope components for one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedDynamicMemoryComponents {
    /// Copied stream payload backing retained through ACK/reset/stop.
    pub stream_send_backing: usize,
    /// In-structure metadata for retained stream-send chunks.
    pub stream_send_chunk_metadata: usize,
    /// Maximum receive-flow-control backing.
    pub stream_receive_backing: usize,
    /// Worst-case fragmented receive-buffer metadata and Arc headers.
    pub stream_receive_fragment_metadata: usize,
    /// Live core QUIC stream maps and readiness indexes.
    pub core_stream_metadata: usize,
    /// Live HTTP/3 parser stream state and bounded parser buffers.
    pub h3_stream_metadata: usize,
    /// Tokio H3 stream contexts, bounded channel slots, and readiness state.
    pub h3_driver_stream_metadata: usize,
    /// Payload backing held in bounded per-stream H3 handoff lanes.
    pub h3_stream_handoff_backing: usize,
    /// One driver read scratch allocation and one bounded body handoff.
    pub h3_body_scratch: usize,
    /// Managed incoming packet payload and lane metadata.
    pub incoming_packet_lane: usize,
    /// Peak encoded, decoded, and right-sized CONNECT field storage.
    pub connect_header_storage: usize,
    /// Private bounded-client CONNECT channel and audit ownership.
    pub bounded_client_connect_owner_metadata: usize,
    /// Selected WebTransport command-lane metadata.
    pub selected_command_lane: usize,
    /// Private endpoint H3 command-lane metadata.
    pub h3_command_lane: usize,
    /// Maximum queued close-message backing in the private H3 lane.
    pub h3_command_payloads: usize,
    /// Private endpoint H3 event-lane metadata.
    pub h3_event_lane: usize,
    /// Selected session, stream, waiter, and terminal metadata.
    pub selected_state_metadata: usize,
    /// Exact-capacity selected read results awaiting caller ownership.
    pub selected_read_results: usize,
    /// Maximum transport-owned inline storage for admitted lease owners.
    pub selected_write_lease_owners: usize,
    /// Per-path sent-packet recovery metadata.
    pub recovery_metadata: usize,
    /// Sent, ACKed, lost, and PTO recovery frame collection metadata.
    pub recovery_frame_metadata: usize,
    /// Maximum frame-owned backing retained across recovery collections.
    pub recovery_frame_owned_backing: usize,
    /// In-structure state for every retained network path.
    pub path_metadata: usize,
    /// Received PATH_CHALLENGE payload storage across retained paths.
    pub path_challenge_storage: usize,
    /// Core and listener-map Connection-ID state for this connection.
    pub connection_id_metadata: usize,
    /// Datagram storage, zero for this profile.
    pub datagram_storage: usize,
    /// Caller-configured allocator and collection-node allowance.
    pub implementation_margin: usize,
    /// Checked sum of every component above.
    pub total: usize,
}

/// Fixed reusable-pool ceilings charged separately from dynamic retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedFixedPoolCeilings {
    /// Full-size shared egress storage per Tokio runtime worker.
    pub shared_egress_bytes_per_worker: usize,
    /// Per-connection one-MTU fallback while the shared pool is leased out.
    pub per_connection_transient_egress_bytes: usize,
    /// Raw-stream scratch, disabled in this profile.
    pub raw_stream_scratch_bytes: usize,
    /// One endpoint-shared managed-socket receive scratch allocation.
    pub router_receive_scratch_bytes: usize,
    /// Endpoint-shared bounded Connection-ID command lane and drain batch.
    pub connection_map_command_lane_bytes: usize,
}

/// Checked preconstruction memory envelope for one bounded connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedMemoryEnvelope {
    /// Independently checked dynamic component maxima.
    pub dynamic_components: BoundedDynamicMemoryComponents,
    /// Hard aggregate dynamic ceiling configured for one connection.
    pub dynamic_retained_memory_ceiling: usize,
    /// Shared-worker and per-connection fixed scratch ceilings.
    pub fixed_pools: BoundedFixedPoolCeilings,
}

impl BoundedMemoryEnvelope {
    /// Computes fixed egress storage for worker and connection counts.
    pub fn fixed_egress_bytes(
        self, worker_count: usize, connection_count: usize,
    ) -> Result<usize, BoundedProfileError> {
        worker_count
            .checked_mul(self.fixed_pools.shared_egress_bytes_per_worker)
            .and_then(|shared| {
                connection_count
                    .checked_mul(
                        self.fixed_pools.per_connection_transient_egress_bytes,
                    )
                    .and_then(|per_connection| shared.checked_add(per_connection))
            })
            .and_then(|total| {
                total.checked_add(self.fixed_pools.router_receive_scratch_bytes)
            })
            .and_then(|total| {
                total.checked_add(
                    self.fixed_pools.connection_map_command_lane_bytes,
                )
            })
            .ok_or(BoundedProfileError::ArithmeticOverflow(
                "fixed egress envelope",
            ))
    }
}

/// Immutable settings snapshot verified against a live bounded driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppliedBoundedWebTransportProfile {
    /// Construction-time H3 mode.
    pub mode: H3ConnectionMode,
    /// Driver endpoint role.
    pub endpoint: BoundedWebTransportEndpoint,
    /// Applied WebTransport revision.
    pub revision: BoundedWebTransportRevision,
    /// Whether native WebTransport classification is enabled.
    pub webtransport_enabled: bool,
    /// Pending plus active session limit.
    pub max_sessions: usize,
    /// Applied and verified QUIC settings.
    pub quic: BoundedWebTransportQuicSettings,
    /// Applied CONNECT field bounds.
    pub connect_headers: BoundedConnectHeaderLimits,
    /// Applied selected runtime limits.
    pub selected: BoundedSelectedWebTransportLimits,
    /// Applied private H3 command capacity.
    pub h3_command_capacity: usize,
    /// Applied private H3 event capacity.
    pub h3_event_capacity: usize,
    /// Applied selected Datagram profile.
    pub datagrams: BoundedWebTransportDatagrams,
    /// Core Datagram send item cap.
    pub datagram_send_items: usize,
    /// Core Datagram send byte cap.
    pub datagram_send_bytes: usize,
    /// Core Datagram receive item cap.
    pub datagram_recv_items: usize,
    /// Core Datagram receive byte cap.
    pub datagram_recv_bytes: usize,
    /// Whether live core retained-storage limit mutation is disabled.
    pub retention_limits_frozen: bool,
    /// Applied managed IO worker settings.
    pub io_worker: IoWorkerMemoryProfile,
    /// Fixed reusable-pool ceilings.
    pub fixed_pools: BoundedFixedPoolCeilings,
    /// Checked dynamic envelope components.
    pub dynamic_components: BoundedDynamicMemoryComponents,
    /// Configured dynamic retained-memory ceiling.
    pub dynamic_retained_memory_ceiling: usize,
}

/// Checked construction or live-profile mismatch error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundedProfileError {
    /// A required finite limit was zero.
    ZeroLimit(&'static str),
    /// Limits were internally inconsistent.
    InvalidSetting(&'static str),
    /// A transport setting cannot be represented by a QUIC varint.
    InvalidWireValue(&'static str),
    /// Checked envelope arithmetic overflowed.
    ArithmeticOverflow(&'static str),
    /// The configured worker pool exceeds the implementation hard ceiling.
    WorkerPoolTooLarge {
        /// Implementation maximum.
        max: usize,
        /// Configured value.
        actual: usize,
    },
    /// Independent maxima do not fit the configured aggregate ceiling.
    DynamicEnvelopeTooSmall {
        /// Checked required bytes.
        required: usize,
        /// Configured bytes.
        configured: usize,
    },
    /// The connection was not created through a managed IO worker.
    MissingIoWorkerProfile,
    /// A live immutable setting differed from the configured profile.
    AppliedSettingMismatch {
        /// Name of the mismatched setting.
        setting: &'static str,
    },
    /// A general H3 capability reached a bounded driver through an internal
    /// sender that is intentionally absent from its public controller.
    ForbiddenOperation(&'static str),
}

impl fmt::Display for BoundedProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bounded WebTransport profile error: {self:?}")
    }
}

impl std::error::Error for BoundedProfileError {}

pub(crate) type AppliedProfileStatus =
    Arc<OnceLock<Result<AppliedBoundedWebTransportProfile, BoundedProfileError>>>;

struct BoundedClientConnectOwner {
    session_id: u64,
    _send: OutboundFrameSender,
    _recv: InboundFrameStream,
    _audit: Arc<H3AuditStats>,
}

#[derive(Default)]
struct BoundedClientConnectOwnershipState {
    owner: Option<BoundedClientConnectOwner>,
    terminal_session_id: Option<u64>,
    closed: bool,
    installed_total: u64,
    terminal_release_total: u64,
    teardown_release_total: u64,
    late_install_total: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundedClientConnectOwnerInstall {
    Installed,
    NotRetained,
    AlreadyTerminal,
    Closed,
    Occupied,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BoundedClientConnectOwnershipStats {
    current: usize,
    max: usize,
    installed_total: u64,
    terminal_release_total: u64,
    teardown_release_total: u64,
    late_install_total: u64,
}

pub(crate) struct BoundedClientConnectOwnership {
    max: usize,
    state: Mutex<BoundedClientConnectOwnershipState>,
}

impl BoundedClientConnectOwnership {
    fn new(max: usize) -> Self {
        Self {
            max,
            state: Mutex::new(BoundedClientConnectOwnershipState::default()),
        }
    }

    fn install(
        &self, incoming: IncomingH3Headers, retain: bool,
    ) -> (
        BoundedClientConnectOwnerInstall,
        Vec<quiche::h3::Header>,
        bool,
    ) {
        let IncomingH3Headers {
            stream_id,
            headers,
            send,
            recv,
            read_fin,
            h3_audit_stats,
        } = incoming;
        let owner = BoundedClientConnectOwner {
            session_id: stream_id,
            _send: send,
            _recv: recv,
            _audit: h3_audit_stats,
        };
        if !retain {
            return (
                BoundedClientConnectOwnerInstall::NotRetained,
                headers,
                read_fin,
            );
        }
        let result = {
            let mut state = self.lock_state();
            if state.closed {
                state.late_install_total =
                    state.late_install_total.saturating_add(1);
                BoundedClientConnectOwnerInstall::Closed
            } else if state.terminal_session_id == Some(stream_id) {
                state.late_install_total =
                    state.late_install_total.saturating_add(1);
                BoundedClientConnectOwnerInstall::AlreadyTerminal
            } else if state.owner.is_some() || self.max == 0 {
                BoundedClientConnectOwnerInstall::Occupied
            } else {
                state.owner = Some(owner);
                state.installed_total = state.installed_total.saturating_add(1);
                BoundedClientConnectOwnerInstall::Installed
            }
        };
        (result, headers, read_fin)
    }

    pub(crate) fn observe_event(&self, event: &WebTransportSessionEvent) {
        let session_id = match event {
            WebTransportSessionEvent::Rejected { session_id, .. } |
            WebTransportSessionEvent::Terminated { session_id, .. } =>
                *session_id,
            _ => return,
        };
        let released = {
            let mut state = self.lock_state();
            state.terminal_session_id.get_or_insert(session_id);
            if state
                .owner
                .as_ref()
                .is_some_and(|owner| owner.session_id == session_id)
            {
                state.terminal_release_total =
                    state.terminal_release_total.saturating_add(1);
                state.owner.take()
            } else {
                None
            }
        };
        drop(released);
    }

    pub(crate) fn clear(&self) {
        let released = {
            let mut state = self.lock_state();
            state.closed = true;
            let released = state.owner.take();
            if released.is_some() {
                state.teardown_release_total =
                    state.teardown_release_total.saturating_add(1);
            }
            released
        };
        drop(released);
    }

    fn stats(&self) -> BoundedClientConnectOwnershipStats {
        let state = self.lock_state();
        BoundedClientConnectOwnershipStats {
            current: usize::from(state.owner.is_some()),
            max: self.max,
            installed_total: state.installed_total,
            terminal_release_total: state.terminal_release_total,
            teardown_release_total: state.teardown_release_total,
            late_install_total: state.late_install_total,
        }
    }

    fn lock_state(
        &self,
    ) -> std::sync::MutexGuard<'_, BoundedClientConnectOwnershipState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

const fn bounded_client_connect_owner_metadata_upper_bound() -> usize {
    mem::size_of::<BoundedClientConnectOwnership>() +
        mem::size_of::<BoundedClientConnectOwnershipState>() +
        mem::size_of::<BoundedClientConnectOwner>() +
        4 * mem::size_of::<usize>()
}

pub(crate) struct PreparedBoundedProfile {
    pub(crate) http3: Http3Settings,
    pub(crate) applied: AppliedBoundedWebTransportProfile,
    pub(crate) status: AppliedProfileStatus,
    pub(crate) client_connect_ownership:
        Option<Arc<BoundedClientConnectOwnership>>,
}

/// Selected draft-16 stream I/O without Bytes or Datagram escape paths.
///
/// Generic Bytes writes and Datagrams are deliberately absent:
///
/// ```compile_fail
/// # use bytes::Bytes;
/// # use tokio_quiche::http3::driver::BoundedSelectedWebTransportController;
/// fn forbidden(controller: &BoundedSelectedWebTransportController) {
///     let _ = controller.write_stream(0, 4, Bytes::new(), false);
///     let _ = controller.send_datagram(0, Bytes::new());
/// }
/// ```
#[derive(Clone)]
pub struct BoundedSelectedWebTransportController {
    inner: WebTransportController,
    read_permits: Arc<Semaphore>,
    client_connect_ownership: Option<Arc<BoundedClientConnectOwnership>>,
}

impl BoundedSelectedWebTransportController {
    fn new(
        inner: WebTransportController, max_concurrent_reads: usize,
        client_connect_ownership: Option<Arc<BoundedClientConnectOwnership>>,
    ) -> Self {
        Self {
            inner,
            read_permits: Arc::new(Semaphore::new(max_concurrent_reads)),
            client_connect_ownership,
        }
    }

    /// Waits without stream allocation for the exact session to terminate.
    pub async fn wait_session_terminal(
        &self, session_id: u64,
    ) -> WebTransportSessionTerminalOutcome {
        self.inner.wait_session_terminal(session_id).await
    }

    /// Opens one bidirectional stream for the exact active Session ID.
    pub async fn open_bidirectional_stream(
        &self, session_id: u64,
    ) -> WebTransportOpenStreamOutcome {
        self.inner.open_bidirectional_stream(session_id).await
    }

    /// Opens one unidirectional stream for the exact active Session ID.
    pub async fn open_unidirectional_stream(
        &self, session_id: u64,
    ) -> WebTransportOpenStreamOutcome {
        self.inner.open_unidirectional_stream(session_id).await
    }

    /// Performs one bounded selected-stream write using caller-owned storage.
    pub async fn write_stream_lease<L>(
        &self, session_id: u64, stream_id: u64, lease: L, fin: bool,
    ) -> WebTransportStreamWriteLeaseOutcome<L>
    where
        L: WebTransportStreamWriteLease,
    {
        self.inner
            .write_stream_lease(session_id, stream_id, lease, fin)
            .await
    }

    /// Attempts immediate admission of one caller-owned selected-stream write.
    pub fn try_write_stream_lease<L>(
        &self, session_id: u64, stream_id: u64, lease: L, fin: bool,
    ) -> Result<
        WebTransportStreamWriteLeaseOperation<L>,
        WebTransportStreamWriteLeaseOutcome<L>,
    >
    where
        L: WebTransportStreamWriteLease,
    {
        self.inner
            .try_write_stream_lease(session_id, stream_id, lease, fin)
    }

    /// Reads one bounded payload fragment from an exact associated stream.
    pub async fn read_stream(
        &self, session_id: u64, stream_id: u64, max_bytes: usize,
    ) -> WebTransportStreamReadOutcome {
        let Ok(_permit) = Arc::clone(&self.read_permits).try_acquire_owned()
        else {
            return WebTransportStreamReadOutcome::Rejected(
                super::WebTransportSelectionError::ResourceLimit,
            );
        };
        self.inner
            .read_stream(session_id, stream_id, max_bytes)
            .await
    }

    /// Waits without polling for selected-stream receive readiness.
    pub async fn wait_stream_readable(
        &self, session_id: u64, stream_id: u64,
    ) -> WebTransportStreamReadyOutcome {
        self.inner.wait_stream_readable(session_id, stream_id).await
    }

    /// Waits without polling for selected-stream send readiness.
    pub async fn wait_stream_writable(
        &self, session_id: u64, stream_id: u64,
    ) -> WebTransportStreamReadyOutcome {
        self.inner.wait_stream_writable(session_id, stream_id).await
    }

    /// Waits for the latched terminal state of a selected send direction.
    pub async fn wait_stream_send_terminal(
        &self, session_id: u64, stream_id: u64,
    ) -> WebTransportStreamSendTerminalOutcome {
        self.inner
            .wait_stream_send_terminal(session_id, stream_id)
            .await
    }

    /// Retires only selected-API observation of one send direction.
    pub async fn retire_stream_send_terminal(
        &self, session_id: u64, stream_id: u64,
    ) -> WebTransportStreamSendTerminalOutcome {
        self.inner
            .retire_stream_send_terminal(session_id, stream_id)
            .await
    }

    /// Sends RESET_STREAM_AT using draft-16 error-code transformation.
    pub async fn reset_stream(
        &self, session_id: u64, stream_id: u64, error_code: u32,
    ) -> WebTransportStreamControlOutcome {
        self.inner
            .reset_stream(session_id, stream_id, error_code)
            .await
    }

    /// Sends STOP_SENDING using draft-16 error-code transformation.
    pub async fn stop_stream(
        &self, session_id: u64, stream_id: u64, error_code: u32,
    ) -> WebTransportStreamControlOutcome {
        self.inner
            .stop_stream(session_id, stream_id, error_code)
            .await
    }

    /// Returns diagnostic selected-I/O and core transport accounting.
    pub async fn retention_stats(
        &self,
    ) -> Result<WebTransportRetentionStats, WebTransportDatagramError> {
        let mut stats = self.inner.retention_stats().await?;
        if let Some(ownership) = &self.client_connect_ownership {
            let owner = ownership.stats();
            stats.bounded_client_connect_owners = owner.current;
            stats.max_bounded_client_connect_owners = owner.max;
            stats.bounded_client_connect_owner_installed_total =
                owner.installed_total;
            stats.bounded_client_connect_owner_terminal_release_total =
                owner.terminal_release_total;
            stats.bounded_client_connect_owner_teardown_release_total =
                owner.teardown_release_total;
            stats.bounded_client_connect_owner_late_install_total =
                owner.late_install_total;
            stats.metadata_index_entries =
                stats.metadata_index_entries.saturating_add(owner.current);
        }
        Ok(stats)
    }
}

/// Restricted client controller for one bounded draft-16 session.
///
/// Generic QUIC/H3 command and request senders are deliberately absent:
///
/// ```compile_fail
/// # use tokio_quiche::http3::driver::BoundedClientWebTransportController;
/// fn forbidden(controller: &BoundedClientWebTransportController) {
///     let _ = controller.cmd_sender();
///     let _ = controller.h3_cmd_sender();
///     let _ = controller.request_sender();
/// }
/// ```
pub struct BoundedClientWebTransportController {
    inner: H3Controller<ClientHooks>,
    selected: BoundedSelectedWebTransportController,
    connect_headers: BoundedConnectHeaderLimits,
    status: AppliedProfileStatus,
    connect_requested: AtomicBool,
    connect_ownership: Arc<BoundedClientConnectOwnership>,
}

/// Nonblocking bounded CONNECT admission failure with ownership preserved.
#[derive(Debug)]
pub enum BoundedConnectAdmissionError {
    /// The fields were bounded but do not form a draft-16 CONNECT.
    Invalid {
        /// Validation failure.
        error: BoundedConnectHeaderError,
        /// Original checked fields.
        headers: BoundedConnectHeaders,
    },
    /// The private H3 command lane is currently full.
    QueueFull {
        /// Original checked fields.
        headers: BoundedConnectHeaders,
    },
    /// The paired driver has terminated.
    DriverGone {
        /// Original checked fields.
        headers: BoundedConnectHeaders,
    },
    /// This connection has already consumed its single CONNECT attempt.
    SessionAlreadyRequested {
        /// Original checked fields.
        headers: BoundedConnectHeaders,
    },
}

impl fmt::Display for BoundedConnectAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bounded WebTransport CONNECT admission failed: {self:?}")
    }
}

impl std::error::Error for BoundedConnectAdmissionError {}

/// Client-visible events from the restricted bounded profile.
#[derive(Debug)]
pub enum BoundedClientWebTransportEvent {
    /// The CONNECT request was assigned its physical stream and Session ID.
    ConnectOpened {
        /// Caller-provided request identifier.
        request_id: u64,
        /// Physical CONNECT stream and WebTransport Session ID.
        session_id: u64,
    },
    /// The peer's bounded CONNECT response fields arrived.
    ConnectResponse {
        /// Exact WebTransport Session ID.
        session_id: u64,
        /// Right-sized checked response fields.
        headers: BoundedConnectHeaders,
        /// Whether the CONNECT receive direction also ended.
        fin: bool,
    },
    /// The CONNECT could not be issued or negotiated.
    ConnectRejected {
        /// Caller-provided request identifier.
        request_id: u64,
    },
    /// Native session lifecycle transition.
    Session(WebTransportSessionEvent),
    /// H3 or QUIC terminated the connection.
    ConnectionError(quiche::h3::Error),
    /// The H3 driver stopped, optionally with its terminal reason.
    ConnectionShutdown(Option<H3ConnectionError>),
    /// A generic path produced an event forbidden by bounded mode.
    ProfileViolation,
}

impl BoundedClientWebTransportController {
    /// Returns this controller's immutable construction mode.
    pub const fn mode(&self) -> H3ConnectionMode {
        H3ConnectionMode::BoundedSelectedWebTransport
    }

    /// Returns the restricted selected-stream controller.
    pub fn selected(&self) -> BoundedSelectedWebTransportController {
        self.selected.clone()
    }

    /// Returns the immutable live-applied profile after establishment.
    pub fn applied_profile(
        &self,
    ) -> Result<Option<AppliedBoundedWebTransportProfile>, BoundedProfileError>
    {
        applied_profile(&self.status)
    }

    /// Returns the CONNECT field bounds applied to this controller.
    pub fn connect_header_limits(&self) -> BoundedConnectHeaderLimits {
        self.connect_headers
    }

    /// Attempts to admit the single bounded draft-16 CONNECT request.
    ///
    /// The command lane is reserved before fields are converted into the
    /// driver's request representation. Every rejection returns field
    /// ownership unchanged.
    pub fn try_connect(
        &self, request_id: u64, headers: BoundedConnectHeaders,
    ) -> Result<(), BoundedConnectAdmissionError> {
        if let Err(error) = self.connect_headers.validate(headers.as_slice()) {
            return Err(BoundedConnectAdmissionError::Invalid { error, headers });
        }
        if !webtransport::is_connect(headers.as_slice()) {
            return Err(BoundedConnectAdmissionError::Invalid {
                error: BoundedConnectHeaderError::NotWebTransportConnect,
                headers,
            });
        }
        let permit = match self.inner.cmd_sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) =>
                return Err(BoundedConnectAdmissionError::QueueFull { headers }),
            Err(mpsc::error::TrySendError::Closed(())) =>
                return Err(BoundedConnectAdmissionError::DriverGone { headers }),
        };
        if self
            .connect_requested
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(BoundedConnectAdmissionError::SessionAlreadyRequested {
                headers,
            });
        }
        let (body_writer, body_reader) = oneshot::channel();
        drop(body_reader);
        permit.send(ClientH3Command::ClientRequest(NewClientRequest {
            request_id,
            headers: headers.into_vec(),
            body_writer: Some(body_writer),
        }));
        Ok(())
    }

    /// Receives the next bounded client event.
    pub async fn recv_event(&mut self) -> Option<BoundedClientWebTransportEvent> {
        loop {
            let Some(event) = self.inner.event_receiver_mut().recv().await else {
                self.connect_ownership.clear();
                return None;
            };
            match event {
                ClientH3Event::NewOutboundRequest {
                    stream_id,
                    request_id,
                } =>
                    return Some(BoundedClientWebTransportEvent::ConnectOpened {
                        request_id,
                        session_id: stream_id,
                    }),
                ClientH3Event::WebTransportRequestRejected { request_id } =>
                    return Some(
                        BoundedClientWebTransportEvent::ConnectRejected {
                            request_id,
                        },
                    ),
                ClientH3Event::Core(H3Event::IncomingHeaders(incoming)) => {
                    let session_id = incoming.stream_id;
                    let Ok(headers) = BoundedConnectHeaders::copy_from(
                        &incoming.headers,
                        self.connect_headers,
                    ) else {
                        self.connect_ownership.clear();
                        return Some(
                            BoundedClientWebTransportEvent::ProfileViolation,
                        );
                    };
                    let Some(status) = super::response_status(headers.as_slice())
                    else {
                        self.connect_ownership.clear();
                        return Some(
                            BoundedClientWebTransportEvent::ProfileViolation,
                        );
                    };
                    let retain = (200..300).contains(&status);
                    let (install, _raw_headers, read_fin) =
                        self.connect_ownership.install(incoming, retain);
                    if install == BoundedClientConnectOwnerInstall::Occupied {
                        self.connect_ownership.clear();
                        return Some(
                            BoundedClientWebTransportEvent::ProfileViolation,
                        );
                    }
                    return Some(
                        BoundedClientWebTransportEvent::ConnectResponse {
                            session_id,
                            headers,
                            fin: read_fin,
                        },
                    );
                },
                ClientH3Event::Core(H3Event::WebTransportSession(event)) =>
                    return Some(BoundedClientWebTransportEvent::Session(event)),
                ClientH3Event::Core(H3Event::ConnectionError(error)) => {
                    self.connect_ownership.clear();
                    return Some(
                        BoundedClientWebTransportEvent::ConnectionError(error),
                    );
                },
                ClientH3Event::Core(H3Event::ConnectionShutdown(reason)) => {
                    self.connect_ownership.clear();
                    return Some(
                        BoundedClientWebTransportEvent::ConnectionShutdown(
                            reason,
                        ),
                    );
                },
                ClientH3Event::Core(
                    H3Event::NewFlow { .. } |
                    H3Event::RawStreamData { .. } |
                    H3Event::WebTransportStreamData { .. },
                ) => {
                    self.connect_ownership.clear();
                    return Some(
                        BoundedClientWebTransportEvent::ProfileViolation,
                    );
                },
                ClientH3Event::Core(_) => {},
            }
        }
    }

    /// Returns monotonic accounting for the private bounded event lane.
    pub fn event_queue_stats(&self) -> H3EventQueueStats {
        self.inner.event_queue_stats()
    }

    /// Closes the active session with a bounded draft-16 close capsule.
    pub fn close_session(
        &self, session_id: u64, error_code: u32, message: String,
    ) -> Result<(), WebTransportSessionCloseError> {
        self.inner
            .close_webtransport_session(session_id, error_code, message)
    }
}

impl Drop for BoundedClientWebTransportController {
    fn drop(&mut self) {
        self.connect_ownership.clear();
    }
}

/// Restricted server controller for one bounded draft-16 session.
///
/// The legacy outbound-frame and generic command capabilities are never
/// returned by this controller.
pub struct BoundedServerWebTransportController {
    inner: H3Controller<ServerHooks>,
    selected: BoundedSelectedWebTransportController,
    connect_headers: BoundedConnectHeaderLimits,
    status: AppliedProfileStatus,
}

/// Restricted one-shot response capability for a bounded server CONNECT.
pub struct BoundedServerConnectResponder {
    send: OutboundFrameSender,
    connect_headers: BoundedConnectHeaderLimits,
    sent: bool,
}

impl fmt::Debug for BoundedServerConnectResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedServerConnectResponder").finish()
    }
}

/// Bounded response admission failure with header ownership preserved.
#[derive(Debug)]
pub enum BoundedConnectResponseError {
    /// The checked fields do not form an HTTP response.
    Invalid {
        /// Validation failure.
        error: BoundedConnectHeaderError,
        /// Original checked fields.
        headers: BoundedConnectHeaders,
    },
    /// The stream's bounded frame lane is full.
    QueueFull {
        /// Original checked fields.
        headers: BoundedConnectHeaders,
    },
    /// The request stream has already closed.
    StreamClosed {
        /// Original checked fields.
        headers: BoundedConnectHeaders,
    },
    /// A final response was already admitted through this capability.
    AlreadySent {
        /// Original checked fields.
        headers: BoundedConnectHeaders,
    },
}

impl fmt::Display for BoundedConnectResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bounded CONNECT response failed: {self:?}")
    }
}

impl std::error::Error for BoundedConnectResponseError {}

impl BoundedServerConnectResponder {
    /// Attempts to admit exactly one bounded CONNECT response field section.
    pub fn try_send_response(
        &mut self, headers: BoundedConnectHeaders,
    ) -> Result<(), BoundedConnectResponseError> {
        if self.sent {
            return Err(BoundedConnectResponseError::AlreadySent { headers });
        }
        if let Err(error) = self.connect_headers.validate(headers.as_slice()) {
            return Err(BoundedConnectResponseError::Invalid { error, headers });
        }
        if super::response_status(headers.as_slice())
            .is_none_or(|status| status < 200)
        {
            return Err(BoundedConnectResponseError::Invalid {
                error: BoundedConnectHeaderError::NotHttpResponse,
                headers,
            });
        }
        let Some(sender) = self.send.get_ref() else {
            return Err(BoundedConnectResponseError::StreamClosed { headers });
        };
        match sender.try_reserve() {
            Ok(permit) => {
                permit.send(OutboundFrame::Headers(headers.into_vec(), None));
                self.sent = true;
                Ok(())
            },
            Err(mpsc::error::TrySendError::Full(())) =>
                Err(BoundedConnectResponseError::QueueFull { headers }),
            Err(mpsc::error::TrySendError::Closed(())) =>
                Err(BoundedConnectResponseError::StreamClosed { headers }),
        }
    }
}

/// Server-visible events from the restricted bounded profile.
#[derive(Debug)]
pub enum BoundedServerWebTransportEvent {
    /// One bounded draft-16 CONNECT request awaits a response.
    ConnectRequested {
        /// Physical CONNECT stream and WebTransport Session ID.
        session_id: u64,
        /// Right-sized checked request fields.
        headers: BoundedConnectHeaders,
        /// Restricted response capability for this CONNECT stream.
        responder: BoundedServerConnectResponder,
        /// Whether the request arrived during QUIC early data.
        early_data: bool,
    },
    /// Native session lifecycle transition.
    Session(WebTransportSessionEvent),
    /// H3 or QUIC terminated the connection.
    ConnectionError(quiche::h3::Error),
    /// The H3 driver stopped, optionally with its terminal reason.
    ConnectionShutdown(Option<H3ConnectionError>),
    /// A generic path produced an event forbidden by bounded mode.
    ProfileViolation,
}

impl BoundedServerWebTransportController {
    /// Returns this controller's immutable construction mode.
    pub const fn mode(&self) -> H3ConnectionMode {
        H3ConnectionMode::BoundedSelectedWebTransport
    }

    /// Returns the restricted selected-stream controller.
    pub fn selected(&self) -> BoundedSelectedWebTransportController {
        self.selected.clone()
    }

    /// Returns the immutable live-applied profile after establishment.
    pub fn applied_profile(
        &self,
    ) -> Result<Option<AppliedBoundedWebTransportProfile>, BoundedProfileError>
    {
        applied_profile(&self.status)
    }

    /// Returns the CONNECT field bounds applied to this controller.
    pub fn connect_header_limits(&self) -> BoundedConnectHeaderLimits {
        self.connect_headers
    }

    /// Receives the next bounded server event.
    pub async fn recv_event(&mut self) -> Option<BoundedServerWebTransportEvent> {
        loop {
            let event = self.inner.event_receiver_mut().recv().await?;
            match event {
                ServerH3Event::Headers {
                    incoming_headers,
                    is_in_early_data,
                    ..
                } => {
                    let headers = BoundedConnectHeaders::copy_from(
                        &incoming_headers.headers,
                        self.connect_headers,
                    )
                    .expect("bounded request headers were checked in-driver");
                    return Some(
                        BoundedServerWebTransportEvent::ConnectRequested {
                            session_id: incoming_headers.stream_id,
                            headers,
                            responder: BoundedServerConnectResponder {
                                send: incoming_headers.send,
                                connect_headers: self.connect_headers,
                                sent: false,
                            },
                            early_data: *is_in_early_data,
                        },
                    );
                },
                ServerH3Event::Core(H3Event::WebTransportSession(event)) =>
                    return Some(BoundedServerWebTransportEvent::Session(event)),
                ServerH3Event::Core(H3Event::ConnectionError(error)) =>
                    return Some(BoundedServerWebTransportEvent::ConnectionError(
                        error,
                    )),
                ServerH3Event::Core(H3Event::ConnectionShutdown(reason)) =>
                    return Some(
                        BoundedServerWebTransportEvent::ConnectionShutdown(
                            reason,
                        ),
                    ),
                ServerH3Event::Core(
                    H3Event::IncomingHeaders(_) |
                    H3Event::NewFlow { .. } |
                    H3Event::RawStreamData { .. } |
                    H3Event::WebTransportStreamData { .. },
                ) =>
                    return Some(BoundedServerWebTransportEvent::ProfileViolation),
                ServerH3Event::Core(_) => {},
            }
        }
    }

    /// Returns monotonic accounting for the private bounded event lane.
    pub fn event_queue_stats(&self) -> H3EventQueueStats {
        self.inner.event_queue_stats()
    }

    /// Closes the active session with a bounded draft-16 close capsule.
    pub fn close_session(
        &self, session_id: u64, error_code: u32, message: String,
    ) -> Result<(), WebTransportSessionCloseError> {
        self.inner
            .close_webtransport_session(session_id, error_code, message)
    }
}

impl H3Driver<ClientHooks> {
    /// Constructs the opt-in bounded draft-16 client profile.
    pub fn new_bounded_selected_webtransport(
        settings: BoundedSelectedWebTransportSettings,
    ) -> Result<(Self, BoundedClientWebTransportController), BoundedProfileError>
    {
        let prepared = settings.prepare(BoundedWebTransportEndpoint::Client)?;
        let status = Arc::clone(&prepared.status);
        let connect_ownership = Arc::clone(
            prepared
                .client_connect_ownership
                .as_ref()
                .expect("a bounded client profile owns its CONNECT handles"),
        );
        let http3 = prepared.http3.clone();
        let (driver, inner) = Self::new_inner(http3, Some(prepared));
        let selected = inner
            .webtransport_controller()
            .expect("a prepared bounded profile enables selected WebTransport");
        Ok((driver, BoundedClientWebTransportController {
            inner,
            selected: BoundedSelectedWebTransportController::new(
                selected,
                settings.selected.max_concurrent_stream_reads,
                Some(Arc::clone(&connect_ownership)),
            ),
            connect_headers: settings.connect_headers,
            status,
            connect_requested: AtomicBool::new(false),
            connect_ownership,
        }))
    }
}

impl H3Driver<ServerHooks> {
    /// Constructs the opt-in bounded draft-16 server profile.
    pub fn new_bounded_selected_webtransport(
        settings: BoundedSelectedWebTransportSettings,
    ) -> Result<(Self, BoundedServerWebTransportController), BoundedProfileError>
    {
        let prepared = settings.prepare(BoundedWebTransportEndpoint::Server)?;
        let status = Arc::clone(&prepared.status);
        let http3 = prepared.http3.clone();
        let (driver, inner) = Self::new_inner(http3, Some(prepared));
        let selected = inner
            .webtransport_controller()
            .expect("a prepared bounded profile enables selected WebTransport");
        Ok((driver, BoundedServerWebTransportController {
            inner,
            selected: BoundedSelectedWebTransportController::new(
                selected,
                settings.selected.max_concurrent_stream_reads,
                None,
            ),
            connect_headers: settings.connect_headers,
            status,
        }))
    }
}

fn applied_profile(
    status: &AppliedProfileStatus,
) -> Result<Option<AppliedBoundedWebTransportProfile>, BoundedProfileError> {
    match status.get() {
        Some(Ok(profile)) => Ok(Some(*profile)),
        Some(Err(error)) => Err(error.clone()),
        None => Ok(None),
    }
}

impl PreparedBoundedProfile {
    pub(crate) fn verify_live(
        &self, qconn: &mut QuicheConnection, handshake_info: &HandshakeInfo,
    ) -> Result<AppliedBoundedWebTransportProfile, BoundedProfileError> {
        let expected_server =
            matches!(self.applied.endpoint, BoundedWebTransportEndpoint::Server);
        check_setting(qconn.is_server() == expected_server, "endpoint role")?;

        let local = qconn.local_transport_params();
        let expected = self.applied.quic;
        check_setting(
            local.initial_max_data == expected.initial_max_data,
            "initial_max_data",
        )?;
        check_setting(
            local.initial_max_stream_data_bidi_local ==
                expected.initial_max_stream_data_bidi_local,
            "initial_max_stream_data_bidi_local",
        )?;
        check_setting(
            local.initial_max_stream_data_bidi_remote ==
                expected.initial_max_stream_data_bidi_remote,
            "initial_max_stream_data_bidi_remote",
        )?;
        check_setting(
            local.initial_max_stream_data_uni ==
                expected.initial_max_stream_data_uni,
            "initial_max_stream_data_uni",
        )?;
        check_setting(
            local.initial_max_streams_bidi == expected.initial_max_streams_bidi,
            "initial_max_streams_bidi",
        )?;
        check_setting(
            local.initial_max_streams_uni == expected.initial_max_streams_uni,
            "initial_max_streams_uni",
        )?;
        check_setting(
            local.active_conn_id_limit == expected.active_connection_id_limit,
            "active_connection_id_limit",
        )?;
        check_setting(
            local.max_udp_payload_size ==
                u64::try_from(expected.max_recv_udp_payload_size).map_err(
                    |_| BoundedProfileError::AppliedSettingMismatch {
                        setting: "max_recv_udp_payload_size",
                    },
                )?,
            "max_recv_udp_payload_size",
        )?;
        check_setting(
            qconn.configured_max_send_udp_payload_size() ==
                expected.max_send_udp_payload_size.max(1200),
            "max_send_udp_payload_size",
        )?;
        check_setting(
            qconn.max_connection_window() == expected.max_connection_window,
            "max_connection_window",
        )?;
        check_setting(
            qconn.max_stream_window() == expected.max_stream_window,
            "max_stream_window",
        )?;
        check_setting(local.reset_stream_at, "reset_stream_at")?;
        check_setting(
            local.max_datagram_frame_size.is_some(),
            "Datagram negotiation",
        )?;

        let selected = self.applied.selected;
        check_setting(
            qconn.stream_send_retention_limits() ==
                quiche::StreamSendRetentionLimits {
                    max_bytes: selected.max_stream_send_retained_bytes,
                    max_chunks: selected.max_stream_send_retained_chunks,
                },
            "stream-send retention limits",
        )?;
        let disabled_datagrams = quiche::DatagramQueueLimits {
            max_items: 0,
            max_bytes: 0,
            max_allocation_bytes: 0,
        };
        check_setting(
            qconn.dgram_recv_queue_limits() == disabled_datagrams,
            "Datagram receive retention limits",
        )?;
        check_setting(
            qconn.dgram_send_queue_limits() == disabled_datagrams,
            "Datagram send retention limits",
        )?;
        check_setting(
            qconn.max_tracked_sent_packets_per_path() ==
                selected.max_tracked_sent_packets_per_path,
            "sent-packet recovery limit",
        )?;
        check_setting(
            qconn.max_tracked_frames_per_packet() ==
                selected.max_tracked_frames_per_packet,
            "sent-packet frame limit",
        )?;
        check_setting(
            qconn.path_event_retention_enabled() == expected.retain_path_events,
            "path-event retention",
        )?;
        check_setting(
            qconn.max_source_connection_ids() ==
                expected.max_source_connection_ids,
            "source Connection-ID storage cap",
        )?;
        check_setting(
            qconn.path_challenge_recv_max_queue_len() ==
                expected.max_path_challenge_recv_queue_len,
            "PATH_CHALLENGE receive queue",
        )?;
        check_setting(
            qconn.tracked_unknown_transport_parameter_limit().is_none(),
            "unknown transport-parameter retention",
        )?;

        let io_worker = handshake_info
            .io_worker_memory_profile()
            .ok_or(BoundedProfileError::MissingIoWorkerProfile)?;
        check_setting(
            io_worker == self.applied.io_worker,
            "managed IO worker profile",
        )?;
        qconn.freeze_retention_limits();
        check_setting(
            qconn.retention_limits_frozen() ==
                self.applied.retention_limits_frozen,
            "retained-storage limit freeze",
        )?;
        Ok(self.applied)
    }

    pub(crate) fn record_live(
        &self,
        result: Result<AppliedBoundedWebTransportProfile, BoundedProfileError>,
    ) {
        let _ = self.status.set(result);
    }
}

fn check_setting(
    valid: bool, setting: &'static str,
) -> Result<(), BoundedProfileError> {
    if valid {
        Ok(())
    } else {
        Err(BoundedProfileError::AppliedSettingMismatch { setting })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Instant;

    use super::*;
    use crate::http3::driver::WebTransportSessionCloseReason;
    use crate::http3::driver::WebTransportStreamDirection;
    use crate::ApplicationOverQuic as _;
    use assert_matches::assert_matches;

    fn connect_headers() -> Vec<quiche::h3::Header> {
        vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"webtransport-h3"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"example.test"),
            quiche::h3::Header::new(b":path", b"/moq"),
        ]
    }

    fn bounded_core_config(
        settings: BoundedSelectedWebTransportSettings,
    ) -> quiche::Config {
        let mut config = super::super::test_utils::default_quiche_config();
        let quic = settings.quic;
        config.enable_dgram(true, 0, 0);
        config.enable_reset_stream_at(true);
        config.set_dgram_queue_retention_limits(
            quiche::DatagramQueueLimits {
                max_items: 0,
                max_bytes: 0,
                max_allocation_bytes: 0,
            },
            quiche::DatagramQueueLimits {
                max_items: 0,
                max_bytes: 0,
                max_allocation_bytes: 0,
            },
        );
        config.set_stream_send_retention_limits(
            quiche::StreamSendRetentionLimits {
                max_bytes: settings.selected.max_stream_send_retained_bytes,
                max_chunks: settings.selected.max_stream_send_retained_chunks,
            },
        );
        config.set_max_tracked_sent_packets_per_path(
            settings.selected.max_tracked_sent_packets_per_path,
        );
        config.set_max_tracked_frames_per_packet(
            settings.selected.max_tracked_frames_per_packet,
        );
        config.set_retain_path_events(settings.quic.retain_path_events);
        config.set_max_source_connection_ids(
            settings.quic.max_source_connection_ids,
        );
        config.set_path_challenge_recv_max_queue_len(
            settings.quic.max_path_challenge_recv_queue_len,
        );
        config.set_initial_max_data(quic.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(
            quic.initial_max_stream_data_bidi_local,
        );
        config.set_initial_max_stream_data_bidi_remote(
            quic.initial_max_stream_data_bidi_remote,
        );
        config.set_initial_max_stream_data_uni(quic.initial_max_stream_data_uni);
        config.set_initial_max_streams_bidi(quic.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(quic.initial_max_streams_uni);
        config.set_max_connection_window(quic.max_connection_window);
        config.set_max_stream_window(quic.max_stream_window);
        config.set_active_connection_id_limit(quic.active_connection_id_limit);
        config.set_max_recv_udp_payload_size(quic.max_recv_udp_payload_size);
        config.set_max_send_udp_payload_size(quic.max_send_udp_payload_size);
        config
    }

    fn drive_server(
        driver: &mut H3Driver<ServerHooks>,
        pipe: &mut quiche::test_utils::Pipe<crate::buf_factory::BufFactory>,
    ) {
        driver.process_reads(&mut pipe.server).unwrap();
        driver.process_writes(&mut pipe.server).unwrap();
    }

    fn drive_client(
        driver: &mut H3Driver<ClientHooks>,
        pipe: &mut quiche::test_utils::Pipe<crate::buf_factory::BufFactory>,
    ) {
        driver.process_reads(&mut pipe.client).unwrap();
        driver.process_writes(&mut pipe.client).unwrap();
    }

    struct BoundedClientHarness {
        pipe: quiche::test_utils::Pipe<crate::buf_factory::BufFactory>,
        peer: quiche::h3::Connection,
        driver: H3Driver<ClientHooks>,
        controller: BoundedClientWebTransportController,
        session_id: u64,
    }

    impl BoundedClientHarness {
        async fn pending() -> Self {
            let settings = BoundedSelectedWebTransportSettings::default();
            let mut config = bounded_core_config(settings);
            let mut pipe = quiche::test_utils::Pipe::<
                crate::buf_factory::BufFactory,
            >::with_config_and_buf(&mut config)
            .unwrap();
            pipe.handshake().unwrap();

            let peer_settings = settings
                .prepare(BoundedWebTransportEndpoint::Server)
                .unwrap()
                .http3;
            let mut peer = quiche::h3::Connection::with_transport(
                &mut pipe.server,
                &quiche::h3::Config::from(&peer_settings),
            )
            .unwrap();
            let (mut driver, controller) =
                H3Driver::<ClientHooks>::new_bounded_selected_webtransport(
                    settings,
                )
                .unwrap();
            let handshake = HandshakeInfo::new(Instant::now(), None)
                .with_io_worker_memory_profile(settings.io.expected_profile());
            driver
                .on_conn_established(&mut pipe.client, &handshake)
                .unwrap();

            pipe.advance().unwrap();
            drive_client(&mut driver, &mut pipe);
            pipe.advance().unwrap();
            while peer.poll(&mut pipe.server).is_ok() {}

            let headers = BoundedConnectHeaders::copy_from(
                &connect_headers(),
                settings.connect_headers,
            )
            .unwrap();
            controller.try_connect(7, headers).unwrap();
            driver.wait_for_data(&mut pipe.client).await.unwrap();
            drive_client(&mut driver, &mut pipe);
            pipe.advance().unwrap();
            let session_id = assert_matches!(
                peer.poll(&mut pipe.server),
                Ok((stream_id, quiche::h3::Event::Headers { .. })) => stream_id
            );

            Self {
                pipe,
                peer,
                driver,
                controller,
                session_id,
            }
        }

        async fn consume_request_events(&mut self) {
            assert_matches!(
                self.controller.recv_event().await,
                Some(BoundedClientWebTransportEvent::Session(
                    WebTransportSessionEvent::Pending { session_id }
                )) if session_id == self.session_id
            );
            assert_matches!(
                self.controller.recv_event().await,
                Some(BoundedClientWebTransportEvent::ConnectOpened {
                    request_id: 7,
                    session_id,
                }) if session_id == self.session_id
            );
        }

        fn send_response(&mut self, status: u16, fin: bool) {
            let status = status.to_string();
            self.peer
                .send_response(
                    &mut self.pipe.server,
                    self.session_id,
                    &[quiche::h3::Header::new(b":status", status.as_bytes())],
                    fin,
                )
                .unwrap();
            self.pipe.advance().unwrap();
            self.drive();
        }

        async fn consume_success_response(&mut self, fin: bool) {
            assert_matches!(
                self.controller.recv_event().await,
                Some(BoundedClientWebTransportEvent::Session(
                    WebTransportSessionEvent::Accepted { session_id }
                )) if session_id == self.session_id
            );
            assert_matches!(
                self.controller.recv_event().await,
                Some(BoundedClientWebTransportEvent::ConnectResponse {
                    session_id,
                    fin: actual_fin,
                    ..
                }) if session_id == self.session_id && actual_fin == fin
            );
        }

        async fn active() -> Self {
            let mut harness = Self::pending().await;
            harness.consume_request_events().await;
            harness.send_response(200, false);
            harness.consume_success_response(false).await;
            harness
        }

        fn drive(&mut self) {
            drive_client(&mut self.driver, &mut self.pipe);
        }

        async fn open_stream(
            &mut self, direction: WebTransportStreamDirection,
        ) -> u64 {
            let selected = self.controller.selected();
            let session_id = self.session_id;
            let open = tokio::spawn(async move {
                match direction {
                    WebTransportStreamDirection::Bidi =>
                        selected.open_bidirectional_stream(session_id).await,
                    WebTransportStreamDirection::Uni =>
                        selected.open_unidirectional_stream(session_id).await,
                }
            });
            tokio::task::yield_now().await;
            self.drive();
            assert_matches!(
                open.await.unwrap(),
                WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
            )
        }

        async fn retention_stats(&mut self) -> WebTransportRetentionStats {
            let selected = self.controller.selected();
            let stats =
                tokio::spawn(async move { selected.retention_stats().await });
            tokio::task::yield_now().await;
            self.drive();
            stats.await.unwrap().unwrap()
        }

        async fn write_stream(
            &mut self, stream_id: u64, payload: &'static [u8], fin: bool,
        ) {
            let write = self
                .controller
                .selected()
                .try_write_stream_lease(
                    self.session_id,
                    stream_id,
                    TestLease {
                        bytes: Arc::from(payload),
                    },
                    fin,
                )
                .unwrap();
            self.drive();
            assert_matches!(
                write.outcome().await,
                WebTransportStreamWriteLeaseOutcome::Accepted {
                    accepted,
                    complete: true,
                    fin_accepted,
                    ..
                } if accepted == payload.len() && fin_accepted == fin
            );
        }

        async fn read_stream(
            &mut self, stream_id: u64, max_bytes: usize,
        ) -> WebTransportStreamReadOutcome {
            let selected = self.controller.selected();
            let session_id = self.session_id;
            let read = tokio::spawn(async move {
                selected.read_stream(session_id, stream_id, max_bytes).await
            });
            tokio::task::yield_now().await;
            self.drive();
            read.await.unwrap()
        }
    }

    fn encoded_associated_stream(
        direction: WebTransportStreamDirection, session_id: u64, payload: &[u8],
    ) -> Vec<u8> {
        let stream_type = match direction {
            WebTransportStreamDirection::Bidi => 0x41,
            WebTransportStreamDirection::Uni => 0x54,
        };
        let mut encoded = Vec::new();
        for value in [stream_type, session_id] {
            let mut varint = [0; 8];
            let written = {
                let mut out = octets::OctetsMut::with_slice(&mut varint);
                out.put_varint(value).unwrap();
                out.off()
            };
            encoded.extend_from_slice(&varint[..written]);
        }
        encoded.extend_from_slice(payload);
        encoded
    }

    #[derive(Debug)]
    struct TestLease {
        bytes: Arc<[u8]>,
    }

    impl WebTransportStreamWriteLease for TestLease {
        type Error = std::convert::Infallible;

        fn payload_len(&self) -> usize {
            self.bytes.len()
        }

        fn retained_bytes(&self) -> usize {
            self.bytes.len()
        }

        fn as_slice(&mut self) -> Result<&[u8], Self::Error> {
            Ok(&self.bytes)
        }
    }

    #[derive(Debug)]
    struct InlineLease<const N: usize> {
        bytes: [u8; N],
    }

    impl<const N: usize> WebTransportStreamWriteLease for InlineLease<N> {
        type Error = std::convert::Infallible;

        fn payload_len(&self) -> usize {
            0
        }

        fn retained_bytes(&self) -> usize {
            0
        }

        fn as_slice(&mut self) -> Result<&[u8], Self::Error> {
            Ok(&self.bytes[..0])
        }
    }

    #[test]
    fn default_profile_is_checked_and_datagram_disabled() {
        let settings = BoundedSelectedWebTransportSettings::default();
        let prepared = settings
            .prepare(BoundedWebTransportEndpoint::Server)
            .unwrap();
        let client = settings
            .prepare(BoundedWebTransportEndpoint::Client)
            .unwrap();
        assert_eq!(
            prepared.applied.mode,
            H3ConnectionMode::BoundedSelectedWebTransport
        );
        assert_eq!(
            prepared.applied.datagrams,
            BoundedWebTransportDatagrams::Disabled
        );
        assert_eq!(prepared.applied.datagram_send_items, 0);
        assert_eq!(prepared.applied.datagram_recv_items, 0);
        assert!(prepared.applied.retention_limits_frozen);
        assert_eq!(
            prepared.http3.webtransport_max_session_terminal_waiters,
            settings.selected.max_session_terminal_waiters,
        );
        assert_eq!(
            prepared
                .http3
                .webtransport_max_session_terminal_waiters_per_session,
            settings.selected.max_session_terminal_waiters_per_session,
        );
        assert_eq!(
            prepared
                .applied
                .dynamic_components
                .selected_write_lease_owners,
            settings.selected.selected_command_capacity *
                settings.selected.max_stream_write_lease_owner_bytes
        );
        assert!(
            prepared.applied.dynamic_components.total <=
                settings.dynamic_retained_memory_ceiling
        );
        assert_eq!(client.applied.selected.max_client_connect_owners, 1);
        assert!(
            client
                .applied
                .dynamic_components
                .bounded_client_connect_owner_metadata >
                0
        );
        assert_eq!(
            prepared
                .applied
                .dynamic_components
                .bounded_client_connect_owner_metadata,
            0
        );
        assert_eq!(
            prepared.applied.fixed_pools.shared_egress_bytes_per_worker,
            settings.io.send_buffer_pool_capacity_per_worker *
                crate::quic::SEND_BUFFER_SIZE
        );

        let mut one_more_waiter = settings;
        one_more_waiter.selected.max_session_terminal_waiters += 1;
        assert!(
            one_more_waiter
                .checked_memory_envelope(BoundedWebTransportEndpoint::Server)
                .unwrap()
                .dynamic_components
                .selected_state_metadata >
                prepared.applied.dynamic_components.selected_state_metadata
        );

        let mut extra_connect_owner = settings;
        extra_connect_owner.selected.max_client_connect_owners = 2;
        assert!(matches!(
            extra_connect_owner.prepare(BoundedWebTransportEndpoint::Client),
            Err(BoundedProfileError::InvalidSetting(
                "the one-session profile requires one client CONNECT owner"
            ))
        ));
    }

    #[test]
    fn general_quic_retention_defaults_remain_unbounded() {
        let (general_driver, _controller) =
            H3Driver::<ServerHooks>::new(Http3Settings::default());
        assert_eq!(general_driver.mode(), H3ConnectionMode::GeneralH3);

        let general = QuicSettings::default();
        assert_eq!(
            Http3Settings::default()
                .webtransport_max_stream_write_lease_owner_bytes,
            usize::MAX
        );
        assert_eq!(general.stream_send_max_retained_bytes, usize::MAX);
        assert_eq!(general.stream_send_max_retained_chunks, usize::MAX);
        assert_eq!(general.max_tracked_sent_packets_per_path, usize::MAX);
        assert_eq!(general.max_tracked_frames_per_packet, usize::MAX);
        assert_eq!(general.dgram_recv_max_queue_bytes, usize::MAX);
        assert!(!general.hard_bound_send_buffer_pool);

        let mut bounded = QuicSettings::default();
        let profile = BoundedSelectedWebTransportSettings::default();
        profile.apply_to_quic_settings(&mut bounded);
        assert_eq!(bounded.dgram_recv_max_queue_len, 0);
        assert_eq!(bounded.dgram_send_max_queue_len, 0);
        assert_eq!(bounded.dgram_recv_max_queue_allocation_bytes, 0);
        assert_eq!(bounded.dgram_send_max_queue_allocation_bytes, 0);
        assert_eq!(
            bounded.stream_send_max_retained_bytes,
            profile.selected.max_stream_send_retained_bytes
        );
        assert!(bounded.hard_bound_send_buffer_pool);

        let (bounded_driver, _controller) =
            H3Driver::<ServerHooks>::new_bounded_selected_webtransport(profile)
                .unwrap();
        assert_eq!(
            bounded_driver.mode(),
            H3ConnectionMode::BoundedSelectedWebTransport
        );
    }

    #[test]
    fn every_bounded_wire_value_rejects_max_varint_plus_one() {
        let invalid = octets::MAX_VAR_INT + 1;
        let cases = [
            "initial_max_data",
            "initial_max_stream_data_bidi_local",
            "initial_max_stream_data_bidi_remote",
            "initial_max_stream_data_uni",
            "initial_max_streams_bidi",
            "initial_max_streams_uni",
            "active_connection_id_limit",
            "max_connection_window",
            "max_stream_window",
            "max_recv_udp_payload_size",
        ];

        for (index, expected) in cases.into_iter().enumerate() {
            let mut settings = BoundedSelectedWebTransportSettings::default();
            match index {
                0 => settings.quic.initial_max_data = invalid,
                1 => settings.quic.initial_max_stream_data_bidi_local = invalid,
                2 => settings.quic.initial_max_stream_data_bidi_remote = invalid,
                3 => settings.quic.initial_max_stream_data_uni = invalid,
                4 => settings.quic.initial_max_streams_bidi = invalid,
                5 => settings.quic.initial_max_streams_uni = invalid,
                6 => settings.quic.active_connection_id_limit = invalid,
                7 => settings.quic.max_connection_window = invalid,
                8 => settings.quic.max_stream_window = invalid,
                9 => {
                    settings.quic.max_recv_udp_payload_size =
                        usize::try_from(invalid).unwrap();
                },
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    settings.prepare(BoundedWebTransportEndpoint::Server),
                    Err(BoundedProfileError::InvalidWireValue(actual))
                        if actual == expected
                ),
                "wire preflight for {expected}"
            );
            assert!(BoundedSelectedWebTransportSettings::default()
                .prepare(BoundedWebTransportEndpoint::Server)
                .is_ok());
        }
    }

    #[test]
    fn dynamic_envelope_accepts_exact_sum_and_rejects_cap_plus_one() {
        let mut settings = BoundedSelectedWebTransportSettings::default();
        let required = settings
            .prepare(BoundedWebTransportEndpoint::Server)
            .unwrap()
            .applied
            .dynamic_components
            .total;

        settings.dynamic_retained_memory_ceiling = required;
        let exact = settings
            .prepare(BoundedWebTransportEndpoint::Server)
            .unwrap();
        assert_eq!(exact.applied.dynamic_components.total, required);
        assert_eq!(exact.applied.dynamic_retained_memory_ceiling, required);

        settings.dynamic_retained_memory_ceiling = required - 1;
        assert!(matches!(
            settings.prepare(BoundedWebTransportEndpoint::Server),
            Err(BoundedProfileError::DynamicEnvelopeTooSmall {
                required: actual_required,
                configured,
            }) if actual_required == required && configured == required - 1
        ));
    }

    #[test]
    fn bounded_mode_rejects_internal_generic_commands_before_execution() {
        let settings = BoundedSelectedWebTransportSettings::default();
        let mut config = bounded_core_config(settings);
        let mut pipe = quiche::test_utils::Pipe::<
            crate::buf_factory::BufFactory,
        >::with_config_and_buf(&mut config)
        .unwrap();
        let (mut driver, _controller) =
            H3Driver::<ServerHooks>::new_bounded_selected_webtransport(settings)
                .unwrap();
        let executed = Arc::new(AtomicBool::new(false));
        let executed_in_command = Arc::clone(&executed);

        let result = driver.handle_core_command(
            &mut pipe.server,
            super::super::H3Command::QuicCmd(crate::quic::QuicCommand::Custom(
                Box::new(move |_| {
                    executed_in_command.store(true, Ordering::Release);
                }),
            )),
        );
        assert!(matches!(
            result,
            Err(H3ConnectionError::BoundedProfile(
                BoundedProfileError::ForbiddenOperation("generic H3 command")
            ))
        ));
        assert!(!executed.load(Ordering::Acquire));
    }

    #[test]
    fn bounded_mode_rejects_legacy_frames_but_allows_internal_control() {
        let limits = BoundedConnectHeaderLimits::default();
        let rejected = super::super::validate_bounded_outbound_frame(
            &OutboundFrame::Body(bytes::Bytes::from_static(b"payload"), false),
            limits,
        );
        assert!(matches!(
            rejected,
            Err(H3ConnectionError::BoundedProfile(
                BoundedProfileError::ForbiddenOperation("legacy OutboundFrame")
            ))
        ));

        assert!(super::super::validate_bounded_outbound_frame(
            &OutboundFrame::Headers(
                vec![quiche::h3::Header::new(b":status", b"200")],
                None,
            ),
            limits,
        )
        .is_ok());
        assert!(super::super::validate_bounded_outbound_frame(
            &OutboundFrame::Body(bytes::Bytes::new(), true),
            limits,
        )
        .is_ok());
    }

    #[test]
    fn bounded_event_lane_saturation_is_terminal_and_counted() {
        let mut settings = BoundedSelectedWebTransportSettings::default();
        settings.selected.h3_event_capacity = 1;
        let (driver, controller) =
            H3Driver::<ServerHooks>::new_bounded_selected_webtransport(settings)
                .unwrap();
        assert!(driver
            .h3_event_sender
            .send(ServerH3Event::Core(H3Event::GoAway { id: 0 }))
            .is_ok());
        assert_eq!(
            driver
                .h3_event_sender
                .send(ServerH3Event::Core(H3Event::GoAway { id: 4 })),
            Err(H3ConnectionError::EventQueueOverloaded)
        );
        assert_eq!(controller.event_queue_stats(), H3EventQueueStats {
            capacity: 1,
            admitted_total: 1,
            overload_total: 1,
            receiver_closed_total: 0,
            overloaded: true,
        });
    }

    #[test]
    fn bounded_close_discards_caller_overcapacity_before_queue_retention() {
        let settings = BoundedSelectedWebTransportSettings::default();
        let (mut driver, controller) =
            H3Driver::<ServerHooks>::new_bounded_selected_webtransport(settings)
                .unwrap();
        let mut message = String::with_capacity(1024 * 1024);
        message.push('x');
        controller.close_session(0, 7, message).unwrap();

        let command = driver.cmd_recv.try_recv().unwrap();
        let ServerH3Command::Core(
            super::super::H3Command::CloseWebTransportSession { message, .. },
        ) = command
        else {
            panic!("bounded close queued the wrong command");
        };
        assert_eq!(message, "x");
        assert_eq!(message.capacity(), message.len());
    }

    #[test]
    fn bounded_write_lease_owner_size_rejects_cap_plus_one_pre_admission() {
        let mut settings = BoundedSelectedWebTransportSettings::default();
        settings.selected.max_stream_write_lease_owner_bytes = 16;
        let (driver, controller) =
            H3Driver::<ServerHooks>::new_bounded_selected_webtransport(settings)
                .unwrap();
        let selected = controller.selected();

        let rejected = selected.try_write_stream_lease(
            0,
            4,
            InlineLease::<17> { bytes: [0; 17] },
            false,
        );
        assert_matches!(
            rejected,
            Err(WebTransportStreamWriteLeaseOutcome::TooLarge {
                limit: super::super::WebTransportStreamWriteLeaseLimit::OwnerBytes,
                max: 16,
                actual: 17,
                lease: InlineLease { bytes },
                fin: false,
            }) if bytes == [0; 17]
        );

        let admitted = selected
            .try_write_stream_lease(
                0,
                4,
                InlineLease::<16> { bytes: [0; 16] },
                false,
            )
            .unwrap();
        assert_eq!(admitted.retained_bytes(), 0);
        drop(admitted);
        drop(driver);
    }

    #[test]
    fn general_h3_establishment_preserves_core_retention_configuration() {
        let settings = BoundedSelectedWebTransportSettings::default();
        let mut config = bounded_core_config(settings);
        let stream_limits = quiche::StreamSendRetentionLimits {
            max_bytes: 12_345,
            max_chunks: 67,
        };
        let recv_dgram_limits = quiche::DatagramQueueLimits {
            max_items: 3,
            max_bytes: 45,
            max_allocation_bytes: 67,
        };
        let send_dgram_limits = quiche::DatagramQueueLimits {
            max_items: 4,
            max_bytes: 56,
            max_allocation_bytes: 78,
        };
        config.set_stream_send_retention_limits(stream_limits);
        config.set_dgram_queue_retention_limits(
            recv_dgram_limits,
            send_dgram_limits,
        );
        config.set_max_tracked_sent_packets_per_path(89);
        let mut pipe = quiche::test_utils::Pipe::<
            crate::buf_factory::BufFactory,
        >::with_config_and_buf(&mut config)
        .unwrap();
        pipe.handshake().unwrap();

        let h3 = Http3Settings {
            enable_webtransport: true,
            ..Default::default()
        };
        let (mut driver, _controller) = H3Driver::<ServerHooks>::new(h3);
        driver
            .on_conn_established(
                &mut pipe.server,
                &HandshakeInfo::new(Instant::now(), None),
            )
            .unwrap();

        assert_eq!(pipe.server.stream_send_retention_limits(), stream_limits);
        assert_eq!(pipe.server.dgram_recv_queue_limits(), recv_dgram_limits);
        assert_eq!(pipe.server.dgram_send_queue_limits(), send_dgram_limits);
        assert_eq!(pipe.server.max_tracked_sent_packets_per_path(), 89);
        assert!(!pipe.server.retention_limits_frozen());

        let changed = quiche::StreamSendRetentionLimits {
            max_bytes: stream_limits.max_bytes + 1,
            max_chunks: stream_limits.max_chunks + 1,
        };
        assert_eq!(
            pipe.server.set_stream_send_retention_limits(changed),
            Ok(())
        );
        assert_eq!(pipe.server.stream_send_retention_limits(), changed);
    }

    #[test]
    fn every_connect_header_bound_rejects_cap_plus_one() {
        let limits = BoundedConnectHeaderLimits {
            max_fields: 2,
            max_name_bytes: 3,
            max_value_bytes: 4,
            max_aggregate_bytes: 7,
        };
        let valid = [
            quiche::h3::Header::new(b"abc", b"d"),
            quiche::h3::Header::new(b"e", b"fg"),
        ];
        assert!(BoundedConnectHeaders::copy_from(&valid, limits).is_ok());

        let too_many = [
            quiche::h3::Header::new(b"a", b""),
            quiche::h3::Header::new(b"b", b""),
            quiche::h3::Header::new(b"c", b""),
        ];
        assert!(matches!(
            BoundedConnectHeaders::copy_from(&too_many, limits),
            Err(BoundedConnectHeaderError::FieldCount { actual: 3, .. })
        ));
        assert!(matches!(
            BoundedConnectHeaders::copy_from(
                &[quiche::h3::Header::new(b"abcd", b"")],
                limits,
            ),
            Err(BoundedConnectHeaderError::NameTooLarge { actual: 4, .. })
        ));
        assert!(matches!(
            BoundedConnectHeaders::copy_from(
                &[quiche::h3::Header::new(b"a", b"12345")],
                limits,
            ),
            Err(BoundedConnectHeaderError::ValueTooLarge { actual: 5, .. })
        ));
        assert!(matches!(
            BoundedConnectHeaders::copy_from(
                &[
                    quiche::h3::Header::new(b"abc", b"1234"),
                    quiche::h3::Header::new(b"a", b""),
                ],
                limits,
            ),
            Err(BoundedConnectHeaderError::AggregateTooLarge { actual: 8, .. })
        ));
    }

    #[test]
    fn invalid_connect_does_not_consume_single_session_admission() {
        let settings = BoundedSelectedWebTransportSettings::default();
        let (_driver, controller) =
            H3Driver::<ClientHooks>::new_bounded_selected_webtransport(settings)
                .unwrap();
        let invalid = BoundedConnectHeaders::copy_from(
            &[quiche::h3::Header::new(b":method", b"GET")],
            settings.connect_headers,
        )
        .unwrap();
        assert!(matches!(
            controller.try_connect(1, invalid),
            Err(BoundedConnectAdmissionError::Invalid { .. })
        ));

        let oversized_path =
            vec![b'/'; settings.connect_headers.max_value_bytes + 1];
        let oversized = [
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"webtransport-h3"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"example.test"),
            quiche::h3::Header::new(b":path", &oversized_path),
        ];
        let permissive = BoundedConnectHeaderLimits {
            max_value_bytes: settings.connect_headers.max_value_bytes + 1,
            max_aggregate_bytes: settings.connect_headers.max_aggregate_bytes,
            ..settings.connect_headers
        };
        let oversized =
            BoundedConnectHeaders::copy_from(&oversized, permissive).unwrap();
        assert!(matches!(
            controller.try_connect(2, oversized),
            Err(BoundedConnectAdmissionError::Invalid {
                error: BoundedConnectHeaderError::ValueTooLarge { .. },
                ..
            })
        ));

        let valid = BoundedConnectHeaders::copy_from(
            &connect_headers(),
            settings.connect_headers,
        )
        .unwrap();
        assert!(controller.try_connect(3, valid).is_ok());
        let duplicate = BoundedConnectHeaders::copy_from(
            &connect_headers(),
            settings.connect_headers,
        )
        .unwrap();
        assert!(matches!(
            controller.try_connect(4, duplicate),
            Err(BoundedConnectAdmissionError::SessionAlreadyRequested { .. })
        ));
        assert_eq!(controller.applied_profile().unwrap(), None);
    }

    #[test]
    fn full_client_command_lane_returns_connect_without_consuming_admission() {
        let mut settings = BoundedSelectedWebTransportSettings::default();
        settings.selected.h3_command_capacity = 1;
        let (mut driver, controller) =
            H3Driver::<ClientHooks>::new_bounded_selected_webtransport(settings)
                .unwrap();
        controller.close_session(0, 0, String::new()).unwrap();

        let headers = BoundedConnectHeaders::copy_from(
            &connect_headers(),
            settings.connect_headers,
        )
        .unwrap();
        let headers = assert_matches!(
            controller.try_connect(7, headers),
            Err(BoundedConnectAdmissionError::QueueFull { headers }) => headers
        );
        assert!(driver.cmd_recv.try_recv().is_ok());
        assert!(controller.try_connect(7, headers).is_ok());
    }

    #[test]
    fn full_server_response_lane_returns_headers_without_consuming_responder() {
        let limits = BoundedConnectHeaderLimits::default();
        let (mut stream, send, _recv) = super::super::StreamCtx::new(0, 1);
        send.get_ref()
            .unwrap()
            .try_send(OutboundFrame::Body(bytes::Bytes::new(), true))
            .unwrap();
        let mut responder = BoundedServerConnectResponder {
            send,
            connect_headers: limits,
            sent: false,
        };
        let headers = BoundedConnectHeaders::copy_from(
            &[quiche::h3::Header::new(b":status", b"200")],
            limits,
        )
        .unwrap();
        let headers = assert_matches!(
            responder.try_send_response(headers),
            Err(BoundedConnectResponseError::QueueFull { headers }) => headers
        );
        assert!(stream.recv.as_mut().unwrap().try_recv().is_ok());
        assert!(responder.try_send_response(headers).is_ok());
    }

    #[test]
    fn checked_arithmetic_rejects_an_impossible_envelope() {
        let mut settings = BoundedSelectedWebTransportSettings::default();
        settings.selected.max_concurrent_stream_reads = usize::MAX;
        assert!(matches!(
            settings.prepare(BoundedWebTransportEndpoint::Client),
            Err(BoundedProfileError::ArithmeticOverflow(
                "selected read results"
            ))
        ));

        let settings = BoundedSelectedWebTransportSettings {
            dynamic_retained_memory_ceiling: 1,
            ..Default::default()
        };
        assert!(matches!(
            settings.prepare(BoundedWebTransportEndpoint::Server),
            Err(BoundedProfileError::DynamicEnvelopeTooSmall { .. })
        ));

        let mut settings = BoundedSelectedWebTransportSettings::default();
        settings.selected.max_session_terminal_waiters_per_session =
            settings.selected.max_session_terminal_waiters + 1;
        assert!(matches!(
            settings.prepare(BoundedWebTransportEndpoint::Server),
            Err(BoundedProfileError::InvalidSetting(
                "per-session terminal waiter cap exceeds connection cap",
            )),
        ));
    }

    #[test]
    fn live_driver_applies_only_a_matching_preconstructed_profile() {
        let settings = BoundedSelectedWebTransportSettings::default();
        let mut config = bounded_core_config(settings);
        let mut pipe = quiche::test_utils::Pipe::<
            crate::buf_factory::BufFactory,
        >::with_config_and_buf(&mut config)
        .unwrap();
        pipe.handshake().unwrap();

        let (mut driver, controller) =
            H3Driver::<ServerHooks>::new_bounded_selected_webtransport(settings)
                .unwrap();
        let handshake = HandshakeInfo::new(Instant::now(), None)
            .with_io_worker_memory_profile(settings.io.expected_profile());
        driver
            .on_conn_established(&mut pipe.server, &handshake)
            .unwrap();
        let applied = controller.applied_profile().unwrap().unwrap();
        assert_eq!(applied.endpoint, BoundedWebTransportEndpoint::Server);
        assert_eq!(
            applied.selected.max_session_terminal_waiters,
            settings.selected.max_session_terminal_waiters,
        );
        assert_eq!(
            applied.selected.max_session_terminal_waiters_per_session,
            settings.selected.max_session_terminal_waiters_per_session,
        );
        assert!(applied.retention_limits_frozen);
        assert!(pipe.server.retention_limits_frozen());
        assert_eq!(
            pipe.server.stream_send_retention_limits(),
            quiche::StreamSendRetentionLimits {
                max_bytes: settings.selected.max_stream_send_retained_bytes,
                max_chunks: settings.selected.max_stream_send_retained_chunks,
            }
        );
        assert_eq!(
            pipe.server.dgram_send_queue_limits().max_allocation_bytes,
            0
        );

        let stream_limits = pipe.server.stream_send_retention_limits();
        let dgram_recv_limits = pipe.server.dgram_recv_queue_limits();
        let dgram_send_limits = pipe.server.dgram_send_queue_limits();
        let packet_limit = pipe.server.max_tracked_sent_packets_per_path();
        assert_eq!(
            pipe.server.set_stream_send_retention_limits(
                quiche::StreamSendRetentionLimits {
                    max_bytes: stream_limits.max_bytes + 1,
                    max_chunks: stream_limits.max_chunks + 1,
                }
            ),
            Err(quiche::Error::InvalidState)
        );
        assert_eq!(
            pipe.server.set_dgram_queue_retention_limits(
                quiche::DatagramQueueLimits {
                    max_items: 1,
                    max_bytes: 1,
                    max_allocation_bytes: 1,
                },
                quiche::DatagramQueueLimits {
                    max_items: 1,
                    max_bytes: 1,
                    max_allocation_bytes: 1,
                },
            ),
            Err(quiche::Error::InvalidState)
        );
        assert_eq!(
            pipe.server
                .set_max_tracked_sent_packets_per_path(packet_limit + 1),
            Err(quiche::Error::InvalidState)
        );
        assert_eq!(pipe.server.stream_send_retention_limits(), stream_limits);
        assert_eq!(pipe.server.dgram_recv_queue_limits(), dgram_recv_limits);
        assert_eq!(pipe.server.dgram_send_queue_limits(), dgram_send_limits);
        assert_eq!(
            pipe.server.max_tracked_sent_packets_per_path(),
            packet_limit
        );

        let mut mismatched_config = bounded_core_config(settings);
        mismatched_config.set_initial_max_data(
            settings.quic.initial_max_data.saturating_add(1),
        );
        let mut mismatched_pipe = quiche::test_utils::Pipe::<
            crate::buf_factory::BufFactory,
        >::with_config_and_buf(
            &mut mismatched_config
        )
        .unwrap();
        mismatched_pipe.handshake().unwrap();
        let (mut driver, controller) =
            H3Driver::<ServerHooks>::new_bounded_selected_webtransport(settings)
                .unwrap();
        assert!(driver
            .on_conn_established(&mut mismatched_pipe.server, &handshake)
            .is_err());
        assert!(matches!(
            controller.applied_profile(),
            Err(BoundedProfileError::AppliedSettingMismatch {
                setting: "initial_max_data"
            })
        ));
        assert!(driver.conn.is_none());
    }

    #[tokio::test]
    async fn bounded_server_connect_and_selected_lease_stay_restricted() {
        let settings = BoundedSelectedWebTransportSettings::default();
        let mut config = bounded_core_config(settings);
        let mut pipe = quiche::test_utils::Pipe::<
            crate::buf_factory::BufFactory,
        >::with_config_and_buf(&mut config)
        .unwrap();
        pipe.handshake().unwrap();

        let peer_settings = settings
            .prepare(BoundedWebTransportEndpoint::Client)
            .unwrap()
            .http3;
        let mut peer = quiche::h3::Connection::with_transport(
            &mut pipe.client,
            &quiche::h3::Config::from(&peer_settings),
        )
        .unwrap();
        let (mut driver, mut controller) =
            H3Driver::<ServerHooks>::new_bounded_selected_webtransport(settings)
                .unwrap();
        let handshake = HandshakeInfo::new(Instant::now(), None)
            .with_io_worker_memory_profile(settings.io.expected_profile());
        driver
            .on_conn_established(&mut pipe.server, &handshake)
            .unwrap();

        pipe.advance().unwrap();
        drive_server(&mut driver, &mut pipe);
        pipe.advance().unwrap();
        while peer.poll(&mut pipe.client).is_ok() {}

        let session_id = peer
            .send_request(&mut pipe.client, &connect_headers(), false)
            .unwrap();
        pipe.advance().unwrap();
        drive_server(&mut driver, &mut pipe);

        assert_matches!(
            controller.recv_event().await,
            Some(BoundedServerWebTransportEvent::Session(
                WebTransportSessionEvent::Pending { session_id: actual }
            )) if actual == session_id
        );
        let mut responder = assert_matches!(
            controller.recv_event().await,
            Some(BoundedServerWebTransportEvent::ConnectRequested {
                session_id: actual,
                headers,
                responder,
                ..
            }) if actual == session_id && webtransport::is_connect(headers.as_slice()) => responder
        );
        let oversized_response = BoundedConnectHeaders::copy_from(
            &[
                quiche::h3::Header::new(b":status", b"200"),
                quiche::h3::Header::new(b"x-test", &vec![
                    b'x';
                    settings
                        .connect_headers
                        .max_value_bytes +
                        1
                ]),
            ],
            BoundedConnectHeaderLimits {
                max_value_bytes: settings.connect_headers.max_value_bytes + 1,
                max_aggregate_bytes: settings.connect_headers.max_aggregate_bytes,
                ..settings.connect_headers
            },
        )
        .unwrap();
        assert_matches!(
            responder.try_send_response(oversized_response),
            Err(BoundedConnectResponseError::Invalid {
                error: BoundedConnectHeaderError::ValueTooLarge { .. },
                ..
            })
        );
        let response = BoundedConnectHeaders::copy_from(
            &[quiche::h3::Header::new(b":status", b"200")],
            settings.connect_headers,
        )
        .unwrap();
        responder.try_send_response(response).unwrap();
        drive_server(&mut driver, &mut pipe);
        pipe.advance().unwrap();
        assert_matches!(
            controller.recv_event().await,
            Some(BoundedServerWebTransportEvent::Session(
                WebTransportSessionEvent::Accepted { session_id: actual }
            )) if actual == session_id
        );
        assert_matches!(
            peer.poll(&mut pipe.client),
            Ok((actual, quiche::h3::Event::Headers { .. })) if actual == session_id
        );

        let selected = controller.selected();
        let selected_for_open = selected.clone();
        let open = tokio::spawn(async move {
            selected_for_open
                .open_unidirectional_stream(session_id)
                .await
        });
        tokio::task::yield_now().await;
        drive_server(&mut driver, &mut pipe);
        let stream_id = assert_matches!(
            open.await.unwrap(),
            WebTransportOpenStreamOutcome::Opened { stream_id } => stream_id
        );
        let write = selected
            .try_write_stream_lease(
                session_id,
                stream_id,
                TestLease {
                    bytes: Arc::from(b"bounded payload".as_slice()),
                },
                true,
            )
            .unwrap();
        drive_server(&mut driver, &mut pipe);
        assert_matches!(
            write.outcome().await,
            WebTransportStreamWriteLeaseOutcome::Accepted {
                accepted: 15,
                fin_accepted: true,
                ..
            }
        );
        assert_eq!(pipe.server.dgram_send_queue_len(), 0);
        assert_eq!(pipe.server.dgram_recv_queue_len(), 0);
    }

    #[tokio::test]
    async fn bounded_client_connect_owner_keeps_selected_streams_live() {
        let mut harness = BoundedClientHarness::active().await;
        let session_id = harness.session_id;

        let stats = harness.retention_stats().await;
        assert_eq!(stats.bounded_client_connect_owners, 1);
        assert_eq!(stats.max_bounded_client_connect_owners, 1);
        assert_eq!(stats.bounded_client_connect_owner_installed_total, 1);
        assert_eq!(stats.bounded_client_connect_owner_terminal_release_total, 0);

        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            harness.driver.wait_for_data(&mut harness.pipe.client),
        )
        .await
        .is_err());
        harness.drive();
        harness.pipe.advance().unwrap();
        assert!(!matches!(
            harness.peer.poll(&mut harness.pipe.server),
            Ok((actual, quiche::h3::Event::Reset(0x10c)))
                if actual == session_id
        ));
        assert!(harness.pipe.server.stream_capacity(session_id).is_ok());

        let bidi = harness.open_stream(WebTransportStreamDirection::Bidi).await;
        harness.write_stream(bidi, b"bidi payload", true).await;
        harness.pipe.advance().unwrap();
        let mut received = [0; 128];
        let (len, fin) = harness
            .pipe
            .server
            .stream_recv(bidi, &mut received)
            .unwrap();
        assert_eq!(
            &received[..len],
            encoded_associated_stream(
                WebTransportStreamDirection::Bidi,
                session_id,
                b"bidi payload",
            )
        );
        assert!(fin);

        harness
            .pipe
            .server
            .stream_send(bidi, b"bidi reply", true)
            .unwrap();
        harness.pipe.advance().unwrap();
        harness.drive();
        assert_matches!(
            harness.read_stream(bidi, 128).await,
            WebTransportStreamReadOutcome::Data { data, fin: true }
                if data.as_ref() == b"bidi reply"
        );

        let uni = harness.open_stream(WebTransportStreamDirection::Uni).await;
        harness.write_stream(uni, b"uni payload", true).await;
        harness.pipe.advance().unwrap();
        let (len, fin) =
            harness.pipe.server.stream_recv(uni, &mut received).unwrap();
        assert_eq!(
            &received[..len],
            encoded_associated_stream(
                WebTransportStreamDirection::Uni,
                session_id,
                b"uni payload",
            )
        );
        assert!(fin);

        assert_eq!(
            harness
                .controller
                .applied_profile()
                .unwrap()
                .unwrap()
                .endpoint,
            BoundedWebTransportEndpoint::Client
        );
        assert_eq!(harness.pipe.client.dgram_send_queue_len(), 0);
        assert_eq!(harness.pipe.client.dgram_recv_queue_len(), 0);
    }

    #[tokio::test]
    async fn bounded_client_close_capsules_preserve_first_terminal_reason() {
        let mut local = BoundedClientHarness::active().await;
        let session_id = local.session_id;
        local
            .controller
            .close_session(session_id, 17, "local close".to_string())
            .unwrap();
        local
            .driver
            .wait_for_data(&mut local.pipe.client)
            .await
            .unwrap();
        local.drive();
        assert_matches!(
            local.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Terminated {
                    session_id: actual,
                    reason: WebTransportSessionCloseReason::Local {
                        error_code: 17,
                        message,
                    },
                }
            )) if actual == session_id && message == "local close"
        );
        assert_eq!(local.controller.connect_ownership.stats().current, 0);
        assert_eq!(
            local
                .controller
                .connect_ownership
                .stats()
                .terminal_release_total,
            1
        );

        local.pipe.advance().unwrap();
        assert_matches!(
            local.peer.poll(&mut local.pipe.server),
            Ok((actual, quiche::h3::Event::Data)) if actual == session_id
        );
        let mut close = [0; 128];
        let len = local
            .peer
            .recv_body(&mut local.pipe.server, session_id, &mut close)
            .unwrap();
        assert_eq!(
            &close[..len],
            webtransport::CloseCapsule::new(17, "local close".to_string())
                .unwrap()
                .encode()
        );
        assert_matches!(
            local.peer.poll(&mut local.pipe.server),
            Ok((actual, quiche::h3::Event::Finished)) if actual == session_id
        );

        let mut peer = BoundedClientHarness::active().await;
        let session_id = peer.session_id;
        let capsule =
            webtransport::CloseCapsule::new(23, "peer close".to_string())
                .unwrap()
                .encode();
        peer.peer
            .send_body(&mut peer.pipe.server, session_id, &capsule, true)
            .unwrap();
        peer.pipe.advance().unwrap();
        peer.drive();
        assert_matches!(
            peer.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Terminated {
                    session_id: actual,
                    reason: WebTransportSessionCloseReason::Peer {
                        error_code: 23,
                        message,
                    },
                }
            )) if actual == session_id && message == "peer close"
        );
        let stats = peer.controller.connect_ownership.stats();
        assert_eq!(stats.current, 0);
        assert_eq!(stats.terminal_release_total, 1);
        peer.drive();
        peer.pipe.advance().unwrap();
        assert!(!matches!(
            peer.peer.poll(&mut peer.pipe.server),
            Ok((actual, quiche::h3::Event::Reset(0x10c)))
                if actual == session_id
        ));
    }

    #[tokio::test]
    async fn bounded_client_connect_reset_is_exact_before_and_after_response() {
        let mut before = BoundedClientHarness::pending().await;
        before.consume_request_events().await;
        before
            .pipe
            .server
            .stream_shutdown(before.session_id, quiche::Shutdown::Write, 0x51)
            .unwrap();
        before.pipe.advance().unwrap();
        before.drive();
        assert_matches!(
            before.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Terminated {
                    session_id,
                    reason: WebTransportSessionCloseReason::ConnectReset {
                        error_code: 0x51,
                    },
                }
            )) if session_id == before.session_id
        );
        assert_eq!(before.controller.connect_ownership.stats().current, 0);

        let mut after = BoundedClientHarness::active().await;
        after
            .pipe
            .server
            .stream_shutdown(after.session_id, quiche::Shutdown::Write, 0x52)
            .unwrap();
        after.pipe.advance().unwrap();
        after.drive();
        assert_matches!(
            after.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Terminated {
                    session_id,
                    reason: WebTransportSessionCloseReason::ConnectReset {
                        error_code: 0x52,
                    },
                }
            )) if session_id == after.session_id
        );
        let stats = after.controller.connect_ownership.stats();
        assert_eq!(stats.current, 0);
        assert_eq!(stats.terminal_release_total, 1);
        after.drive();
        after.pipe.advance().unwrap();
        assert!(!matches!(
            after.peer.poll(&mut after.pipe.server),
            Ok((actual, quiche::h3::Event::Reset(0x10c)))
                if actual == after.session_id
        ));
    }

    #[tokio::test]
    async fn bounded_client_event_cancellation_and_terminal_order_are_safe() {
        let mut cancelled = BoundedClientHarness::pending().await;
        cancelled.consume_request_events().await;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            cancelled.controller.recv_event(),
        )
        .await
        .is_err());
        cancelled.send_response(200, false);
        cancelled.consume_success_response(false).await;
        assert_eq!(cancelled.controller.connect_ownership.stats().current, 1);

        let mut queued = BoundedClientHarness::pending().await;
        queued.consume_request_events().await;
        let capsule = webtransport::CloseCapsule::new(31, "queued".to_string())
            .unwrap()
            .encode();
        queued
            .peer
            .send_response(
                &mut queued.pipe.server,
                queued.session_id,
                &[quiche::h3::Header::new(b":status", b"200")],
                false,
            )
            .unwrap();
        queued
            .peer
            .send_body(&mut queued.pipe.server, queued.session_id, &capsule, true)
            .unwrap();
        queued.pipe.advance().unwrap();
        queued.drive();
        queued.consume_success_response(false).await;
        assert_matches!(
            queued.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Terminated {
                    session_id,
                    reason: WebTransportSessionCloseReason::Peer {
                        error_code: 31,
                        message,
                    },
                }
            )) if session_id == queued.session_id && message == "queued"
        );
        let stats = queued.controller.connect_ownership.stats();
        assert_eq!(stats.current, 0);
        assert_eq!(stats.installed_total, 0);
        assert_eq!(stats.late_install_total, 1);
    }

    #[tokio::test]
    async fn bounded_client_fin_and_invalid_responses_fail_closed() {
        let mut finished = BoundedClientHarness::pending().await;
        finished.consume_request_events().await;
        finished.send_response(200, true);
        finished.consume_success_response(true).await;
        assert_matches!(
            finished.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Terminated {
                    session_id,
                    reason: WebTransportSessionCloseReason::Clean,
                }
            )) if session_id == finished.session_id
        );
        let stats = finished.controller.connect_ownership.stats();
        assert_eq!(stats.current, 0);
        assert_eq!(stats.installed_total, 0);
        assert_eq!(stats.late_install_total, 1);

        for headers in [
            vec![quiche::h3::Header::new(b"x-test", b"missing status")],
            vec![
                quiche::h3::Header::new(b":status", b"200"),
                quiche::h3::Header::new(b"x-test", &vec![
                    b'x';
                    BoundedConnectHeaderLimits::default().max_value_bytes +
                        1
                ]),
            ],
        ] {
            let settings = BoundedSelectedWebTransportSettings::default();
            let (driver, mut controller) =
                H3Driver::<ClientHooks>::new_bounded_selected_webtransport(
                    settings,
                )
                .unwrap();
            let (ctx, send, recv) = super::super::StreamCtx::new(0, 1);
            driver
                .h3_event_sender
                .send(ClientH3Event::Core(H3Event::IncomingHeaders(
                    IncomingH3Headers {
                        stream_id: 0,
                        headers,
                        send,
                        recv,
                        read_fin: false,
                        h3_audit_stats: Arc::clone(&ctx.audit_stats),
                    },
                )))
                .unwrap();
            assert_matches!(
                controller.recv_event().await,
                Some(BoundedClientWebTransportEvent::ProfileViolation)
            );
            assert_eq!(controller.connect_ownership.stats().current, 0);
        }
    }

    #[tokio::test]
    async fn bounded_client_connection_close_orders_with_response_delivery() {
        let mut before = BoundedClientHarness::pending().await;
        before.consume_request_events().await;
        crate::ApplicationOverQuic::on_conn_close(
            &mut before.driver,
            &mut before.pipe.client,
            &crate::metrics::DefaultMetrics,
            &Ok(()),
        );
        assert_matches!(
            before.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Terminated {
                    session_id,
                    reason: WebTransportSessionCloseReason::ConnectionClosed,
                }
            )) if session_id == before.session_id
        );
        assert_eq!(before.controller.connect_ownership.stats().current, 0);

        let mut queued = BoundedClientHarness::pending().await;
        queued.consume_request_events().await;
        queued.send_response(200, false);
        crate::ApplicationOverQuic::on_conn_close(
            &mut queued.driver,
            &mut queued.pipe.client,
            &crate::metrics::DefaultMetrics,
            &Ok(()),
        );
        queued.consume_success_response(false).await;
        assert_matches!(
            queued.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Terminated {
                    session_id,
                    reason: WebTransportSessionCloseReason::ConnectionClosed,
                }
            )) if session_id == queued.session_id
        );
        let stats = queued.controller.connect_ownership.stats();
        assert_eq!(stats.current, 0);
        assert_eq!(stats.installed_total, 0);
        assert_eq!(stats.late_install_total, 1);

        let mut after = BoundedClientHarness::active().await;
        crate::ApplicationOverQuic::on_conn_close(
            &mut after.driver,
            &mut after.pipe.client,
            &crate::metrics::DefaultMetrics,
            &Ok(()),
        );
        assert_matches!(
            after.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Terminated {
                    session_id,
                    reason: WebTransportSessionCloseReason::ConnectionClosed,
                }
            )) if session_id == after.session_id
        );
        let stats = after.controller.connect_ownership.stats();
        assert_eq!(stats.current, 0);
        assert_eq!(stats.installed_total, 1);
        assert_eq!(stats.terminal_release_total, 1);
    }

    #[tokio::test]
    async fn bounded_client_rejection_and_controller_drop_release_exactly_once() {
        let mut rejected = BoundedClientHarness::pending().await;
        rejected.consume_request_events().await;
        rejected.send_response(404, true);
        assert_matches!(
            rejected.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::Session(
                WebTransportSessionEvent::Rejected {
                    session_id,
                    status: 404,
                }
            )) if session_id == rejected.session_id
        );
        assert_matches!(
            rejected.controller.recv_event().await,
            Some(BoundedClientWebTransportEvent::ConnectResponse {
                session_id,
                fin: true,
                ..
            }) if session_id == rejected.session_id
        );
        rejected.drive();
        let stats = rejected.retention_stats().await;
        assert_eq!(stats.bounded_client_connect_owners, 0);
        assert_eq!(stats.bounded_client_connect_owner_installed_total, 0);
        assert_eq!(stats.bounded_client_connect_owner_terminal_release_total, 0);

        let active = BoundedClientHarness::active().await;
        let ownership = Arc::clone(&active.controller.connect_ownership);
        assert_eq!(ownership.stats().current, 1);
        let BoundedClientHarness {
            controller, driver, ..
        } = active;
        drop(controller);
        let stats = ownership.stats();
        assert_eq!(stats.current, 0);
        assert_eq!(stats.teardown_release_total, 1);
        drop(driver);
        assert_eq!(ownership.stats().teardown_release_total, 1);
    }

    #[test]
    fn bounded_client_owner_turnover_is_constant_and_general_h3_is_unchanged() {
        let mut peak = 0;
        for session_id in 0_u64..4096 {
            let ownership = BoundedClientConnectOwnership::new(1);
            let (ctx, send, recv) = super::super::StreamCtx::new(session_id, 1);
            let incoming = IncomingH3Headers {
                stream_id: session_id,
                headers: vec![quiche::h3::Header::new(b":status", b"200")],
                send,
                recv,
                read_fin: false,
                h3_audit_stats: Arc::clone(&ctx.audit_stats),
            };
            let (result, ..) = ownership.install(incoming, true);
            assert_eq!(result, BoundedClientConnectOwnerInstall::Installed);
            peak = peak.max(ownership.stats().current);
            ownership.observe_event(&WebTransportSessionEvent::Terminated {
                session_id,
                reason: WebTransportSessionCloseReason::Clean,
            });
            let stats = ownership.stats();
            assert_eq!(stats.current, 0);
            assert_eq!(stats.installed_total, 1);
            assert_eq!(stats.terminal_release_total, 1);
        }
        assert_eq!(peak, 1);

        let (driver, _controller) =
            H3Driver::<ClientHooks>::new(Http3Settings::default());
        assert_eq!(driver.mode(), H3ConnectionMode::GeneralH3);
        assert!(driver.bounded_profile.is_none());
        assert!(driver
            .h3_event_sender
            .bounded_client_connect_ownership
            .is_none());
    }
}
