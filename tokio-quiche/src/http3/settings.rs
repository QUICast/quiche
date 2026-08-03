// Copyright (C) 2025, Cloudflare, Inc.
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

use std::future::poll_fn;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use crate::http3::driver::H3ConnectionError;
use crate::quic::QuicheConnection;

use foundations::telemetry::log;
use tokio_util::time::delay_queue::DelayQueue;
use tokio_util::time::delay_queue::{
    self,
};

const SETTINGS_WT_ENABLED: u64 = 0x2c7c_f000;
#[cfg(test)]
const SETTINGS_WT_INITIAL_MAX_DATA: u64 = 0x2b61;
#[cfg(test)]
const SETTINGS_WT_INITIAL_MAX_STREAMS_UNI: u64 = 0x2b64;
#[cfg(test)]
const SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI: u64 = 0x2b65;

const DEFAULT_WEBTRANSPORT_MAX_PENDING_STREAMS: usize = 256;
const DEFAULT_WEBTRANSPORT_MAX_PENDING_STREAMS_PER_SESSION: usize = 64;
const DEFAULT_WEBTRANSPORT_MAX_ACTIVE_STREAMS: usize = usize::MAX;
const DEFAULT_WEBTRANSPORT_MAX_ACTIVE_STREAMS_PER_SESSION: usize = usize::MAX;
const DEFAULT_WEBTRANSPORT_MAX_STREAM_WAITERS: usize = 256;
const DEFAULT_WEBTRANSPORT_MAX_SESSION_TERMINAL_WAITERS: usize = 256;
const DEFAULT_WEBTRANSPORT_MAX_SESSION_TERMINAL_WAITERS_PER_SESSION: usize = 64;
const DEFAULT_WEBTRANSPORT_MAX_SEND_TERMINAL_WAITERS: usize = 256;
const DEFAULT_WEBTRANSPORT_MAX_SEND_TERMINAL_WAITERS_PER_SESSION: usize = 64;
const DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_STATES: usize = 256;
const DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_STATES_PER_SESSION: usize = 64;
const DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_WAITERS: usize = 256;
const DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_WAITERS_PER_SESSION: usize = 64;
const DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_BYTES_PER_SESSION: usize =
    4 * 1024 * 1024;
const DEFAULT_WEBTRANSPORT_MAX_DATAGRAM_WAITERS: usize = 2;
const DEFAULT_WEBTRANSPORT_MAX_SESSION_WORK_PER_CALLBACK: usize = 64;
const DEFAULT_WEBTRANSPORT_COMMAND_CAPACITY: usize = 256;
const DEFAULT_WEBTRANSPORT_MAX_STREAM_IO_BYTES: usize = 64 * 1024;
const DEFAULT_WEBTRANSPORT_MAX_STREAM_WRITE_LEASE_RETAINED_BYTES: usize =
    64 * 1024;
const DEFAULT_WEBTRANSPORT_MAX_STREAM_WRITE_LEASE_OWNER_BYTES: usize = usize::MAX;
const DEFAULT_WEBTRANSPORT_MAX_DATAGRAM_SEND_ALLOCATION_BYTES: usize = 64 * 1024;
const DEFAULT_WEBTRANSPORT_MAX_DATAGRAM_PREFIXED_ALLOCATION_BYTES: usize =
    64 * 1024 + 16;
const DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAMS: usize = 256;
const DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAMS_PER_SESSION: usize = 64;
const DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_BYTES: usize = 1024 * 1024;
const DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_BYTES_PER_SESSION: usize =
    256 * 1024;
const DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_ALLOCATION_BYTES: usize =
    1024 * 1024;
const DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_ALLOCATION_BYTES_PER_SESSION:
    usize = 256 * 1024;
const DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_AGE: Duration =
    Duration::from_secs(5);
const DEFAULT_H3_COMMAND_CAPACITY: usize = 256;
const DEFAULT_H3_EVENT_CAPACITY: usize = 256;

/// Unified configuration parameters for
/// [H3Driver](crate::http3::driver::H3Driver)s.
#[derive(Clone, Debug)]
pub struct Http3Settings {
    /// Capacity of the per-connection HTTP/3 command lane.
    ///
    /// Admission is nonblocking and returns ownership when full. A value of
    /// zero is clamped to one.
    pub command_capacity: usize,
    /// Capacity of the per-connection HTTP/3 application event lane.
    ///
    /// The QUIC driver never awaits this lane. Saturation closes the
    /// connection with `H3_EXCESSIVE_LOAD`. A value of zero is clamped to one.
    pub event_capacity: usize,
    /// Maximum number of requests a
    /// [ServerH3Driver](crate::http3::driver::ServerH3Driver) allows per
    /// connection.
    pub max_requests_per_connection: Option<u64>,
    /// Maximum size of a single HEADERS frame, in bytes.
    pub max_header_list_size: Option<u64>,
    /// Local maximum decoded field count in one HTTP field section.
    ///
    /// This is not advertised on the wire and defaults to no count limit.
    pub max_header_field_count: Option<usize>,
    /// Maximum value the QPACK encoder is permitted to set for the dynamic
    /// table capcity. See <https://www.rfc-editor.org/rfc/rfc9204.html#name-maximum-dynamic-table-capac>
    pub qpack_max_table_capacity: Option<u64>,
    /// Upper bound on the number of streams that can be blocked on the QPACK
    /// decoder. See <https://www.rfc-editor.org/rfc/rfc9204.html#name-blocked-streams>
    pub qpack_blocked_streams: Option<u64>,
    /// Timeout between starting the QUIC handshake and receiving the first
    /// request on a connection. Only applicable to
    /// [ServerH3Driver](crate::http3::driver::ServerH3Driver).
    pub post_accept_timeout: Option<Duration>,
    /// Set the `SETTINGS_ENABLE_CONNECT_PROTOCOL` HTTP/3 setting.
    /// See <https://www.rfc-editor.org/rfc/rfc9220#section-3-2>
    pub enable_extended_connect: bool,
    /// Set the WebTransport-over-HTTP/3 SETTINGS_ENABLE_WEB_TRANSPORT setting.
    ///
    /// Enabling this draft-16 V2 profile also transfers native stream
    /// classification to the Tokio H3 driver. The profile deliberately omits
    /// nonzero session-level flow-control SETTINGS and permits one pending or
    /// active session per HTTP/3 connection.
    pub enable_webtransport: bool,
    /// Aggregate maximum for optimistic inbound streams, local opens waiting
    /// for QUIC MAX_STREAMS credit, and local streams whose association prefix
    /// has not committed.
    pub webtransport_max_pending_streams: usize,
    /// Per-session aggregate maximum for optimistic inbound, credit-waiting,
    /// and prefix-opening streams.
    pub webtransport_max_pending_streams_per_session: usize,
    /// Maximum active associated streams retained by one connection.
    pub webtransport_max_active_streams: usize,
    /// Maximum active associated streams retained by the active session.
    pub webtransport_max_active_streams_per_session: usize,
    /// Maximum exact-stream readable and writable wait registrations.
    pub webtransport_max_stream_waiters: usize,
    /// Maximum pending session-terminal wait registrations per connection.
    /// A value of zero is clamped to one.
    pub webtransport_max_session_terminal_waiters: usize,
    /// Maximum pending session-terminal wait registrations for one session.
    /// A value of zero is clamped to one.
    pub webtransport_max_session_terminal_waiters_per_session: usize,
    /// Maximum pending send-terminal waiters and retained terminal facts.
    ///
    /// The bound applies independently to waiters and facts. A value of zero
    /// is clamped to one.
    pub webtransport_max_send_terminal_waiters: usize,
    /// Per-session bound for pending send-terminal waiters and retained facts.
    ///
    /// The bound applies independently to waiters and facts. A value of zero
    /// is clamped to one.
    pub webtransport_max_send_terminal_waiters_per_session: usize,
    /// Maximum receive-terminal observation slots and retained FIN/RESET facts.
    pub webtransport_max_receive_terminal_states: usize,
    /// Per-session receive-terminal observation and retained-fact bound.
    pub webtransport_max_receive_terminal_states_per_session: usize,
    /// Maximum pending readable waiters for receive-capable selected streams.
    pub webtransport_max_receive_terminal_waiters: usize,
    /// Per-session pending readable-waiter bound.
    pub webtransport_max_receive_terminal_waiters_per_session: usize,
    /// Maximum physical backing bytes retained with terminal stream reads.
    pub webtransport_max_receive_terminal_bytes: usize,
    /// Per-session terminal-read backing-byte bound.
    pub webtransport_max_receive_terminal_bytes_per_session: usize,
    /// Maximum exact-session Datagram-readable and send-capacity waiters.
    pub webtransport_max_datagram_waiters: usize,
    /// Work bound used independently by the native WebTransport runtime's
    /// selected-I/O, associated-stream maintenance, and Datagram receive
    /// passes.
    ///
    /// A selected-I/O work unit is one controller command, one credit-waiting
    /// open attempt, or one opening-prefix attempt. A maintenance work unit is
    /// one admission, teardown, or closed stream inspection. A Datagram work
    /// unit is one received QUIC Datagram. A value of zero is clamped to one.
    pub webtransport_max_session_work_per_callback: usize,
    /// Capacity of the dedicated native WebTransport controller command lane.
    /// A value of zero is clamped to one. Buffer-bearing async calls waiting to
    /// enter this lane remain caller-owned; use the controller's nonblocking
    /// `try_*` APIs when this capacity must be a hard aggregate ownership
    /// bound.
    pub webtransport_command_capacity: usize,
    /// Maximum payload bytes accepted by one selected-stream write command.
    pub webtransport_max_stream_write_bytes: usize,
    /// Maximum owner-declared bytes retained by one generic write lease.
    ///
    /// Outstanding leases, including completed results not yet consumed, are
    /// also bounded in count by `webtransport_command_capacity` and in bytes by
    /// that capacity multiplied by this value.
    pub webtransport_max_stream_write_lease_retained_bytes: usize,
    /// Maximum compiler-known inline size of one generic write-lease owner.
    ///
    /// This bounds the transport-owned `Arc` allocation used while an admitted
    /// operation crosses the driver. Heap backing referenced by the owner
    /// remains in the caller's accounting domain. The default is unbounded for
    /// compatibility.
    pub webtransport_max_stream_write_lease_owner_bytes: usize,
    /// Maximum payload bytes returned by one selected-stream read command.
    pub webtransport_max_stream_read_bytes: usize,
    /// Maximum physical `DgramBuffer` allocation accepted by one outgoing
    /// native WebTransport Datagram command.
    pub webtransport_max_datagram_send_allocation_bytes: usize,
    /// Maximum physical Datagram allocation after adding the H3 Quarter Stream
    /// ID prefix.
    pub webtransport_max_datagram_prefixed_allocation_bytes: usize,
    /// Maximum queued incoming native WebTransport Datagrams per connection.
    pub webtransport_max_pending_datagrams: usize,
    /// Maximum queued incoming native WebTransport Datagrams per session.
    pub webtransport_max_pending_datagrams_per_session: usize,
    /// Maximum queued incoming native WebTransport Datagram bytes per
    /// connection.
    pub webtransport_max_pending_datagram_bytes: usize,
    /// Maximum queued incoming native WebTransport Datagram bytes per session.
    pub webtransport_max_pending_datagram_bytes_per_session: usize,
    /// Maximum physical allocation retained by queued incoming native
    /// WebTransport Datagrams per connection.
    pub webtransport_max_pending_datagram_allocation_bytes: usize,
    /// Maximum physical allocation retained by queued incoming native
    /// WebTransport Datagrams per session.
    pub webtransport_max_pending_datagram_allocation_bytes_per_session: usize,
    /// Maximum time an incoming Datagram may await CONNECT classification.
    pub webtransport_max_pending_datagram_age: Duration,
    /// QUIC multicast channel ID used for HTTP/3 DATAGRAM unicast fallback.
    ///
    /// When set, outbound HTTP/3 DATAGRAMs are tagged as data for this MCQUIC
    /// channel. quiche sends them over ordinary unicast QUIC packets until the
    /// channel is proven viable by `MC_ACK`, and suppresses duplicate unicast
    /// delivery while multicast is green.
    pub multicast_datagram_channel_id: Option<Vec<u8>>,
    /// Experimental escape hatch for interop harnesses that need to read
    /// selected raw QUIC streams on an HTTP/3 connection.
    ///
    /// This is intentionally empty by default. When a stream ID is listed, the
    /// server driver treats that stream as raw QUIC data and does not pass it
    /// through the HTTP/3 parser.
    pub experimental_raw_quic_stream_ids: Vec<u64>,
}

impl Default for Http3Settings {
    fn default() -> Self {
        Self {
            command_capacity: DEFAULT_H3_COMMAND_CAPACITY,
            event_capacity: DEFAULT_H3_EVENT_CAPACITY,
            max_requests_per_connection: None,
            max_header_list_size: None,
            max_header_field_count: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            post_accept_timeout: None,
            enable_extended_connect: false,
            enable_webtransport: false,
            webtransport_max_pending_streams:
                DEFAULT_WEBTRANSPORT_MAX_PENDING_STREAMS,
            webtransport_max_pending_streams_per_session:
                DEFAULT_WEBTRANSPORT_MAX_PENDING_STREAMS_PER_SESSION,
            webtransport_max_active_streams:
                DEFAULT_WEBTRANSPORT_MAX_ACTIVE_STREAMS,
            webtransport_max_active_streams_per_session:
                DEFAULT_WEBTRANSPORT_MAX_ACTIVE_STREAMS_PER_SESSION,
            webtransport_max_stream_waiters:
                DEFAULT_WEBTRANSPORT_MAX_STREAM_WAITERS,
            webtransport_max_session_terminal_waiters:
                DEFAULT_WEBTRANSPORT_MAX_SESSION_TERMINAL_WAITERS,
            webtransport_max_session_terminal_waiters_per_session:
                DEFAULT_WEBTRANSPORT_MAX_SESSION_TERMINAL_WAITERS_PER_SESSION,
            webtransport_max_send_terminal_waiters:
                DEFAULT_WEBTRANSPORT_MAX_SEND_TERMINAL_WAITERS,
            webtransport_max_send_terminal_waiters_per_session:
                DEFAULT_WEBTRANSPORT_MAX_SEND_TERMINAL_WAITERS_PER_SESSION,
            webtransport_max_receive_terminal_states:
                DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_STATES,
            webtransport_max_receive_terminal_states_per_session:
                DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_STATES_PER_SESSION,
            webtransport_max_receive_terminal_waiters:
                DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_WAITERS,
            webtransport_max_receive_terminal_waiters_per_session:
                DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_WAITERS_PER_SESSION,
            webtransport_max_receive_terminal_bytes:
                DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_BYTES,
            webtransport_max_receive_terminal_bytes_per_session:
                DEFAULT_WEBTRANSPORT_MAX_RECEIVE_TERMINAL_BYTES_PER_SESSION,
            webtransport_max_datagram_waiters:
                DEFAULT_WEBTRANSPORT_MAX_DATAGRAM_WAITERS,
            webtransport_max_session_work_per_callback:
                DEFAULT_WEBTRANSPORT_MAX_SESSION_WORK_PER_CALLBACK,
            webtransport_command_capacity: DEFAULT_WEBTRANSPORT_COMMAND_CAPACITY,
            webtransport_max_stream_write_bytes:
                DEFAULT_WEBTRANSPORT_MAX_STREAM_IO_BYTES,
            webtransport_max_stream_write_lease_retained_bytes:
                DEFAULT_WEBTRANSPORT_MAX_STREAM_WRITE_LEASE_RETAINED_BYTES,
            webtransport_max_stream_write_lease_owner_bytes:
                DEFAULT_WEBTRANSPORT_MAX_STREAM_WRITE_LEASE_OWNER_BYTES,
            webtransport_max_stream_read_bytes:
                DEFAULT_WEBTRANSPORT_MAX_STREAM_IO_BYTES,
            webtransport_max_datagram_send_allocation_bytes:
                DEFAULT_WEBTRANSPORT_MAX_DATAGRAM_SEND_ALLOCATION_BYTES,
            webtransport_max_datagram_prefixed_allocation_bytes:
                DEFAULT_WEBTRANSPORT_MAX_DATAGRAM_PREFIXED_ALLOCATION_BYTES,
            webtransport_max_pending_datagrams:
                DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAMS,
            webtransport_max_pending_datagrams_per_session:
                DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAMS_PER_SESSION,
            webtransport_max_pending_datagram_bytes:
                DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_BYTES,
            webtransport_max_pending_datagram_bytes_per_session:
                DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_BYTES_PER_SESSION,
            webtransport_max_pending_datagram_allocation_bytes:
                DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_ALLOCATION_BYTES,
            webtransport_max_pending_datagram_allocation_bytes_per_session:
                DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_ALLOCATION_BYTES_PER_SESSION,
            webtransport_max_pending_datagram_age:
                DEFAULT_WEBTRANSPORT_MAX_PENDING_DATAGRAM_AGE,
            multicast_datagram_channel_id: None,
            experimental_raw_quic_stream_ids: Vec::new(),
        }
    }
}

impl From<&Http3Settings> for quiche::h3::Config {
    fn from(value: &Http3Settings) -> Self {
        let mut config = Self::new().unwrap();

        if let Some(v) = value.max_header_list_size {
            config.set_max_field_section_size(v);
        }

        if let Some(v) = value.max_header_field_count {
            config.set_max_field_count(v);
        }

        if let Some(v) = value.qpack_max_table_capacity {
            config.set_qpack_max_table_capacity(v);
        }

        if let Some(v) = value.qpack_blocked_streams {
            config.set_qpack_blocked_streams(v);
        }

        if value.enable_extended_connect || value.enable_webtransport {
            config.enable_extended_connect(true)
        }

        if value.enable_webtransport {
            config.enable_webtransport_stream_classification(true);
            config
                .set_additional_settings(vec![(SETTINGS_WT_ENABLED, 1)])
                .expect("WebTransport setting must not conflict with built-in H3 settings");
        }

        config
    }
}

/// Opaque handle to an entry in [`Http3Timeouts`].
pub(crate) struct TimeoutKey(delay_queue::Key);

pub(crate) struct Http3SettingsEnforcer {
    limits: Http3Limits,
    timeouts: Http3Timeouts,
}

impl From<&Http3Settings> for Http3SettingsEnforcer {
    fn from(value: &Http3Settings) -> Self {
        Self {
            limits: Http3Limits {
                max_requests_per_connection: value.max_requests_per_connection,
            },
            timeouts: Http3Timeouts {
                post_accept_timeout: value.post_accept_timeout,
                delay_queue: DelayQueue::new(),
            },
        }
    }
}

impl Http3SettingsEnforcer {
    /// Returns a boolean indicating whether or not the connection should be
    /// closed due to a violation of the request count limit.
    pub fn enforce_requests_limit(&self, request_count: u64) -> bool {
        if let Some(limit) = self.limits.max_requests_per_connection {
            return request_count >= limit;
        }

        false
    }

    /// Returns the configured post-accept timeout.
    pub fn post_accept_timeout(&self) -> Option<Duration> {
        self.timeouts.post_accept_timeout
    }

    /// Registers a timeout of `typ` in this [Http3SettingsEnforcer].
    pub fn add_timeout(
        &mut self, typ: Http3TimeoutType, duration: Duration,
    ) -> TimeoutKey {
        let key = self.timeouts.delay_queue.insert(typ, duration);
        TimeoutKey(key)
    }

    /// Checks whether the [Http3SettingsEnforcer] has any pending timeouts.
    /// This should be used to selectively poll `enforce_timeouts`.
    pub fn has_pending_timeouts(&self) -> bool {
        !self.timeouts.delay_queue.is_empty()
    }

    /// Checks which timeouts have expired.
    fn poll_timeouts(&mut self, cx: &mut Context) -> Poll<TimeoutCheckResult> {
        let mut changed = false;
        let mut result = TimeoutCheckResult::default();

        while let Poll::Ready(Some(exp)) =
            self.timeouts.delay_queue.poll_expired(cx)
        {
            changed |= result.set_expired(exp.into_inner());
        }

        if changed {
            return Poll::Ready(result);
        }
        Poll::Pending
    }

    /// Waits for at least one registered timeout to expire.
    ///
    /// This function will automatically call `close()` on the underlying
    /// [quiche::Connection].
    pub async fn enforce_timeouts(
        &mut self, qconn: &mut QuicheConnection,
    ) -> Result<(), H3ConnectionError> {
        let result = poll_fn(|cx| self.poll_timeouts(cx)).await;

        if result.connection_timed_out {
            log::debug!("connection timed out due to post-accept-timeout"; "scid" => ?qconn.source_id());
            qconn.close(true, quiche::h3::WireErrorCode::NoError as u64, &[])?;
        }

        Ok(())
    }

    /// Cancels a timeout that was previously registered with `add_timeout`.
    pub fn cancel_timeout(&mut self, key: TimeoutKey) {
        self.timeouts.delay_queue.remove(&key.0);
    }
}

// TODO(rmehra): explore if these should really be Options, or if we
// should enforce sane defaults
struct Http3Limits {
    max_requests_per_connection: Option<u64>,
}

struct Http3Timeouts {
    post_accept_timeout: Option<Duration>,
    delay_queue: DelayQueue<Http3TimeoutType>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Http3TimeoutType {
    PostAccept,
}

#[derive(Default, Eq, PartialEq)]
struct TimeoutCheckResult {
    connection_timed_out: bool,
}

impl TimeoutCheckResult {
    fn set_expired(&mut self, typ: Http3TimeoutType) -> bool {
        use Http3TimeoutType::*;
        let field = match typ {
            PostAccept => &mut self.connection_timed_out,
        };

        *field = true;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEST_CERT_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/",
        "../quiche/examples/cert.crt"
    );
    const TEST_KEY_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/",
        "../quiche/examples/cert.key"
    );

    fn h3_quiche_config() -> quiche::Result<quiche::Config> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.load_cert_chain_from_pem_file(TEST_CERT_FILE)?;
        config.load_priv_key_from_pem_file(TEST_KEY_FILE)?;
        config.set_application_protos(&[b"h3"])?;
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);
        config.grease(false);
        Ok(config)
    }

    #[test]
    fn enable_webtransport_emits_only_the_draft16_v2_profile() -> TestResult {
        let mut quic_config = h3_quiche_config()?;
        quic_config.enable_dgram(true, 10, 10);
        quic_config.enable_reset_stream_at(true);
        let mut pipe = quiche::test_utils::Pipe::with_config(&mut quic_config)?;
        pipe.handshake()?;

        let h3_settings = Http3Settings {
            enable_webtransport: true,
            ..Default::default()
        };
        let webtransport_h3_config = quiche::h3::Config::from(&h3_settings);
        let _client_h3 = quiche::h3::Connection::with_transport(
            &mut pipe.client,
            &webtransport_h3_config,
        )?;

        pipe.advance()?;

        let mut server_h3 = quiche::h3::Connection::with_transport(
            &mut pipe.server,
            &quiche::h3::Config::new()?,
        )?;
        assert_eq!(
            server_h3.poll(&mut pipe.server),
            Err(quiche::h3::Error::Done)
        );

        let received_settings = server_h3
            .peer_settings_raw()
            .expect("peer settings must be received");

        for (id, value) in [
            (quiche::h3::SETTINGS_WT_ENABLED, 1),
            (quiche::h3::frame::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
            (quiche::h3::frame::SETTINGS_H3_DATAGRAM, 1),
        ] {
            let received_value = received_settings.iter().find_map(
                |(received_id, received_value)| {
                    (*received_id == id).then_some(*received_value)
                },
            );

            assert_eq!(
                received_value,
                Some(value),
                "missing WebTransport setting {id:#x}"
            );
        }

        for id in [
            SETTINGS_WT_INITIAL_MAX_DATA,
            SETTINGS_WT_INITIAL_MAX_STREAMS_UNI,
            SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI,
        ] {
            assert!(
                received_settings
                    .iter()
                    .all(|(received_id, _)| *received_id != id),
                "unexpected session-level flow-control setting {id:#x}"
            );
        }

        Ok(())
    }

    #[test]
    fn tokio_webtransport_settings_enable_owned_native_classification(
    ) -> TestResult {
        let mut quic_config = h3_quiche_config()?;
        let mut pipe = quiche::test_utils::Pipe::with_config(&mut quic_config)?;
        pipe.handshake()?;

        let settings = Http3Settings {
            enable_webtransport: true,
            ..Default::default()
        };
        let h3_config = quiche::h3::Config::from(&settings);
        let _client_h3 =
            quiche::h3::Connection::with_transport(&mut pipe.client, &h3_config)?;
        let mut server_h3 =
            quiche::h3::Connection::with_transport(&mut pipe.server, &h3_config)?;
        pipe.advance()?;
        assert_eq!(
            server_h3.poll(&mut pipe.server),
            Err(quiche::h3::Error::Done)
        );

        pipe.client
            .stream_send(0, &[0x40, 0x41, 0x00, 0xff], true)?;
        pipe.advance()?;

        assert!(matches!(
            server_h3.poll(&mut pipe.server),
            Ok((0, quiche::h3::Event::WebTransportStream {
                session_id: 0,
                direction: quiche::h3::WebTransportStreamDirection::Bidirectional,
                prefix_len: 3,
            }))
        ));
        assert!(pipe.server.local_error().is_none());

        Ok(())
    }
}
