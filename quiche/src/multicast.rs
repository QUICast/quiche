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

//! Experimental QUIC multicast wire formats from
//! draft-jholland-quic-multicast-08.
//!
//! This module currently provides:
//! - codecs for the draft's multicast transport parameters; and
//! - codecs for the multicast control frames exchanged on the unicast QUIC
//!   connection; and
//! - send/receive helpers for multicast channel 1-RTT packets.
//!
//! The actual multicast channel packet processing, recovery, and socket
//! integration remain higher-level work.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use ring::digest;

use crate::crypto;
use crate::frame;
use crate::packet;
use crate::stream;
use crate::Error;
use crate::Result;

const IP_FLAG_V6_ALLOWED: u8 = 0x02;
const IP_FLAG_V4_ALLOWED: u8 = 0x01;
const MAX_TRACKED_ACK_RANGES: usize = 64;
const ACK_HISTORY_PACKET_WINDOW: u64 = 4 * 1024;
const MAX_VARINT: u64 = (1 << 62) - 1;
const DRAFT_OLD_KEY_MAX_RETENTION: Duration = Duration::from_secs(60);

/// Experimental transport parameter ID used by the draft for client multicast
/// capabilities.
pub const CLIENT_PARAMS_TRANSPORT_PARAMETER_ID: u64 = 0xff3e800;

/// Experimental transport parameter ID used by the draft for server multicast
/// support.
pub const SERVER_SUPPORT_TRANSPORT_PARAMETER_ID: u64 = 0xff3e808;

/// Experimental frame type used by the draft for `MC_KEY`.
pub const FRAME_TYPE_KEY: u64 = 0xff3e801;

/// Experimental frame type used by the draft for `MC_JOIN`.
pub const FRAME_TYPE_JOIN: u64 = 0xff3e802;

/// Experimental frame type used by the draft for `MC_LEAVE`.
pub const FRAME_TYPE_LEAVE: u64 = 0xff3e803;

/// Experimental frame type used by the draft for `MC_INTEGRITY` without an
/// explicit hash count.
pub const FRAME_TYPE_INTEGRITY: u64 = 0xff3e804;

/// Experimental frame type used by the draft for `MC_INTEGRITY` with an
/// explicit hash count.
pub const FRAME_TYPE_INTEGRITY_WITH_LENGTH: u64 = 0xff3e805;

/// Experimental frame type used by the draft for `MC_ACK` without ECN counts.
pub const FRAME_TYPE_ACK: u64 = 0xff3e806;

/// Experimental frame type used by the draft for `MC_ACK` with ECN counts.
pub const FRAME_TYPE_ACK_ECN: u64 = 0xff3e807;

/// Experimental frame type used by the draft for `MC_LIMITS`.
pub const FRAME_TYPE_LIMITS: u64 = 0xff3e809;

/// Experimental frame type used by the draft for `MC_RETIRE`.
pub const FRAME_TYPE_RETIRE: u64 = 0xff3e80a;

/// Experimental frame type used by the draft for transport-scoped
/// `MC_STATE` reasons.
pub const FRAME_TYPE_STATE: u64 = 0xff3e80b;

/// Experimental frame type used by the draft for application-scoped
/// `MC_STATE` reasons.
pub const FRAME_TYPE_STATE_APPLICATION: u64 = 0xff3e80c;

/// Experimental frame type used by the draft for IPv4 `MC_ANNOUNCE`.
pub const FRAME_TYPE_ANNOUNCE_V4: u64 = 0xff3e811;

/// Experimental frame type used by the draft for IPv6 `MC_ANNOUNCE`.
pub const FRAME_TYPE_ANNOUNCE_V6: u64 = 0xff3e812;

/// `MC_STATE` reason code used by the draft when a state transition was
/// requested by the server.
pub const STATE_REASON_REQUESTED_BY_SERVER: u64 = 0x1;

/// Default number of newer acknowledged channel packets required before an
/// unacknowledged packet is recovered over unicast.
pub const DEFAULT_STREAM_RECOVERY_REORDERING_THRESHOLD: u64 = 3;

/// Retention limits for one connection's multicast STREAM recovery state.
///
/// Reaching any limit releases the affected channel's retained ranges through
/// ordinary unicast QUIC and marks its multicast path recovery-limited until
/// the application starts a fresh probe generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamRecoveryLimits {
    /// Maximum retained channel-packet ranges across the connection.
    pub max_pending_ranges_per_connection: usize,

    /// Maximum retained channel-packet ranges for one multicast channel.
    pub max_pending_ranges_per_channel: usize,

    /// Maximum withheld STREAM payload bytes across the connection.
    pub max_withheld_bytes_per_connection: usize,

    /// Maximum withheld STREAM payload bytes for one multicast channel.
    pub max_withheld_bytes_per_channel: usize,
}

impl Default for StreamRecoveryLimits {
    fn default() -> Self {
        Self {
            max_pending_ranges_per_connection: 65_536,
            max_pending_ranges_per_channel: 16_384,
            max_withheld_bytes_per_connection: 64 * 1024 * 1024,
            max_withheld_bytes_per_channel: 16 * 1024 * 1024,
        }
    }
}

/// The subset of client-advertised multicast limits shared by the transport
/// parameter and `MC_LIMITS`.
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct ClientLimits {
    /// Whether the client is willing to join IPv6 multicast channels.
    pub ipv6_channels_allowed: bool,

    /// Whether the client is willing to join IPv4 multicast channels.
    pub ipv4_channels_allowed: bool,

    /// The maximum aggregate joined-channel receive rate, in Kibps.
    pub max_aggregate_rate_kibps: u64,

    /// The maximum number of channel IDs the client is willing to track.
    pub max_channel_ids: u64,
}

impl ClientLimits {
    fn flags(&self) -> u8 {
        let mut flags = 0;

        if self.ipv6_channels_allowed {
            flags |= IP_FLAG_V6_ALLOWED;
        }

        if self.ipv4_channels_allowed {
            flags |= IP_FLAG_V4_ALLOWED;
        }

        flags
    }

    fn encoded_len(&self, invalid: Error) -> Result<usize> {
        checked_len_add(
            1,
            checked_varint_len(self.max_aggregate_rate_kibps, invalid)?,
            invalid,
        )
        .and_then(|len| {
            checked_len_add(
                len,
                checked_varint_len(self.max_channel_ids, invalid)?,
                invalid,
            )
        })
    }

    fn encode(&self, b: &mut octets::OctetsMut) -> Result<()> {
        self.encoded_len(Error::InvalidFrame)?;
        b.put_u8(self.flags())?;
        b.put_varint(self.max_aggregate_rate_kibps)?;
        b.put_varint(self.max_channel_ids)?;

        Ok(())
    }

    fn decode_with_max_joined(b: &mut octets::Octets) -> Result<(Self, u64)> {
        let flags = b.get_u8()?;

        let limits = ClientLimits {
            ipv6_channels_allowed: flags & IP_FLAG_V6_ALLOWED != 0,
            ipv4_channels_allowed: flags & IP_FLAG_V4_ALLOWED != 0,
            max_aggregate_rate_kibps: b.get_varint()?,
            max_channel_ids: b.get_varint()?,
        };

        let max_joined_count = b.get_varint()?;

        Ok((limits, max_joined_count))
    }
}

/// The multicast client transport parameter carried by clients during the QUIC
/// handshake.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientTransportParams {
    /// The client's initial multicast limits.
    pub limits: ClientLimits,

    /// Supported packet hash algorithms, in preference order.
    pub hash_algorithms: Vec<u16>,

    /// Supported encryption algorithms, in preference order.
    pub encryption_algorithms: Vec<u16>,
}

impl ClientTransportParams {
    /// Returns the checked encoded wire length of the transport parameter.
    ///
    /// Invalid QUIC varint values are rejected before any output is mutated.
    pub fn encoded_len(&self) -> Result<usize> {
        let invalid = Error::InvalidTransportParam;
        let hash_count_len =
            checked_collection_varint_len(self.hash_algorithms.len(), invalid)?;
        let encryption_count_len = checked_collection_varint_len(
            self.encryption_algorithms.len(),
            invalid,
        )?;
        let hash_bytes =
            self.hash_algorithms.len().checked_mul(2).ok_or(invalid)?;
        let encryption_bytes = self
            .encryption_algorithms
            .len()
            .checked_mul(2)
            .ok_or(invalid)?;

        [
            self.limits.encoded_len(invalid)?,
            hash_count_len,
            encryption_count_len,
            hash_bytes,
            encryption_bytes,
        ]
        .into_iter()
        .try_fold(0, |total, len| checked_len_add(total, len, invalid))
    }

    /// Returns the encoded wire length of the transport parameter value.
    ///
    /// Invalid values return `usize::MAX`. Use
    /// [`encoded_len()`](Self::encoded_len) when handling untrusted or
    /// application-provided values.
    pub fn wire_len(&self) -> usize {
        self.encoded_len().unwrap_or(usize::MAX)
    }

    /// Decodes the transport parameter value from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut b = octets::Octets::with_slice(buf);

        let flags = b.get_u8()?;

        let limits = ClientLimits {
            ipv6_channels_allowed: flags & IP_FLAG_V6_ALLOWED != 0,
            ipv4_channels_allowed: flags & IP_FLAG_V4_ALLOWED != 0,
            max_aggregate_rate_kibps: b.get_varint()?,
            max_channel_ids: b.get_varint()?,
        };

        let hash_algorithm_count = b.get_varint()?;
        let encryption_algorithm_count = b.get_varint()?;

        let hash_algorithms =
            decode_u16_list(&mut b, hash_algorithm_count, false)?;
        let encryption_algorithms =
            decode_u16_list(&mut b, encryption_algorithm_count, false)?;

        if b.cap() != 0 {
            return Err(Error::InvalidTransportParam);
        }

        Ok(ClientTransportParams {
            limits,
            hash_algorithms,
            encryption_algorithms,
        })
    }

    /// Encodes the transport parameter value into the provided buffer.
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<usize> {
        let encoded_len = self.encoded_len()?;
        if out.len() < encoded_len {
            return Err(Error::BufferTooShort);
        }

        let mut b = octets::OctetsMut::with_slice(out);
        let before = b.cap();

        self.encode(&mut b)?;

        Ok(before - b.cap())
    }

    pub(crate) fn encode(&self, b: &mut octets::OctetsMut) -> Result<()> {
        self.encoded_len()?;
        self.limits.encode(b)?;
        b.put_varint(self.hash_algorithms.len() as u64)?;
        b.put_varint(self.encryption_algorithms.len() as u64)?;
        encode_u16_list(&self.hash_algorithms, b)?;
        encode_u16_list(&self.encryption_algorithms, b)?;

        Ok(())
    }
}

/// A full `MC_ANNOUNCE` frame payload.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Announce {
    /// The channel ID being announced.
    pub channel_id: Vec<u8>,

    /// The multicast source address.
    pub source: IpAddr,

    /// The multicast group address.
    pub group: IpAddr,

    /// The UDP port used for the channel.
    pub udp_port: u16,

    /// The header protection algorithm from the TLS cipher suite registry.
    pub header_protection_algorithm: u16,

    /// The secret used for header protection.
    pub header_secret: Vec<u8>,

    /// The AEAD algorithm from the TLS cipher suite registry.
    pub aead_algorithm: u16,

    /// The packet integrity hash algorithm.
    pub integrity_hash_algorithm: u16,

    /// The maximum multicast payload rate for the channel, in Kibps.
    pub max_rate_kibps: u64,

    /// The maximum delay before sending `MC_ACK`, in milliseconds.
    pub max_ack_delay_ms: u64,
}

impl fmt::Debug for Announce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Announce")
            .field("channel_id", &self.channel_id)
            .field("source", &self.source)
            .field("group", &self.group)
            .field("udp_port", &self.udp_port)
            .field(
                "header_protection_algorithm",
                &self.header_protection_algorithm,
            )
            .field(
                "header_secret",
                &format_args!("<redacted:{} bytes>", self.header_secret.len()),
            )
            .field("aead_algorithm", &self.aead_algorithm)
            .field("integrity_hash_algorithm", &self.integrity_hash_algorithm)
            .field("max_rate_kibps", &self.max_rate_kibps)
            .field("max_ack_delay_ms", &self.max_ack_delay_ms)
            .finish()
    }
}

impl Drop for Announce {
    fn drop(&mut self) {
        self.header_secret.fill(0);
    }
}

impl Announce {
    /// Validates all wire fields without mutating this announcement.
    pub fn validate(&self) -> Result<()> {
        announce_encoded_len(self).map(|_| ())
    }
}

/// A full `MC_KEY` frame payload.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Key {
    /// The channel ID being updated.
    pub channel_id: Vec<u8>,

    /// The key sequence number.
    pub key_sequence: u64,

    /// The first packet number the secret applies to.
    pub from_packet_number: u64,

    /// The channel payload protection secret.
    pub secret: Vec<u8>,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("channel_id", &self.channel_id)
            .field("key_sequence", &self.key_sequence)
            .field("from_packet_number", &self.from_packet_number)
            .field(
                "secret",
                &format_args!("<redacted:{} bytes>", self.secret.len()),
            )
            .finish()
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

impl Key {
    /// Validates all wire fields without mutating this key update.
    pub fn validate(&self) -> Result<()> {
        key_encoded_len(self).map(|_| ())
    }
}

/// A full `MC_JOIN` frame payload.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Join {
    /// The channel ID to join.
    pub channel_id: Vec<u8>,

    /// The latest `MC_LIMITS` sequence processed by the server.
    pub mc_limits_sequence: u64,

    /// The latest `MC_STATE` sequence processed by the server.
    pub mc_state_sequence: u64,

    /// The latest `MC_KEY` sequence processed by the server.
    pub mc_key_sequence: u64,
}

impl Join {
    /// Validates all wire fields without mutating this join request.
    pub fn validate(&self) -> Result<()> {
        join_encoded_len(self).map(|_| ())
    }
}

/// A full `MC_LEAVE` frame payload.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Leave {
    /// The channel ID to leave.
    pub channel_id: Vec<u8>,

    /// The latest `MC_STATE` sequence processed by the server.
    pub mc_state_sequence: u64,

    /// The packet number after which the client should leave.
    pub after_packet_number: u64,
}

/// A full `MC_INTEGRITY` frame payload.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Integrity {
    /// The channel ID covered by the hashes.
    pub channel_id: Vec<u8>,

    /// The first packet number described by `packet_hashes`.
    pub packet_number_start: u64,

    /// The optional explicit packet hash count used by `0xff3e805`.
    pub packet_hash_count: Option<u64>,

    /// The concatenated packet hashes.
    pub packet_hashes: Vec<u8>,
}

impl Integrity {
    /// Validates all wire fields without mutating this integrity frame.
    pub fn validate(&self) -> Result<()> {
        integrity_encoded_len(self).map(|_| ())
    }
}

/// A single non-initial ACK block from an `MC_ACK` frame.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AckRange {
    /// The gap from the previously acknowledged block.
    pub gap: u64,

    /// The encoded length of the acknowledged block.
    pub ack_range_length: u64,
}

/// ECN counters carried by `MC_ACK`.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AckEcnCounts {
    /// Count of packets marked `ECT(0)`.
    pub ect0_count: u64,

    /// Count of packets marked `ECT(1)`.
    pub ect1_count: u64,

    /// Count of packets marked `CE`.
    pub ecn_ce_count: u64,
}

/// A full `MC_ACK` frame payload.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Ack {
    /// The acknowledged channel ID.
    pub channel_id: Vec<u8>,

    /// The largest acknowledged packet number.
    pub largest_acknowledged: u64,

    /// The encoded ACK delay.
    pub ack_delay: u64,

    /// The first ACK range length.
    pub first_ack_range: u64,

    /// Additional ACK ranges.
    pub ack_ranges: Vec<AckRange>,

    /// Optional ECN counters.
    pub ecn_counts: Option<AckEcnCounts>,
}

impl Ack {
    /// Validates all wire fields and ACK range structure without mutation.
    pub fn validate(&self) -> Result<()> {
        frame_encoded_len(&Frame::Ack(self.clone())).map(|_| ())
    }
}

/// A full `MC_LIMITS` frame payload.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Limits {
    /// The client limits sequence number.
    pub sequence: u64,

    /// The current client limits.
    pub limits: ClientLimits,

    /// The maximum number of concurrently joined channels.
    pub max_joined_count: u64,
}

/// A full `MC_RETIRE` frame payload.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Retire {
    /// The retired channel ID.
    pub channel_id: Vec<u8>,

    /// The packet number after which retirement should happen.
    pub after_packet_number: u64,
}

/// The `MC_STATE` state value.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ChannelState {
    /// `LEFT`
    Left         = 0x1,

    /// `DECLINED_JOIN`
    DeclinedJoin = 0x2,

    /// `JOINED`
    Joined       = 0x3,

    /// `RETIRED`
    Retired      = 0x4,
}

impl ChannelState {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x1 => Ok(ChannelState::Left),
            0x2 => Ok(ChannelState::DeclinedJoin),
            0x3 => Ok(ChannelState::Joined),
            0x4 => Ok(ChannelState::Retired),
            _ => Err(Error::InvalidFrame),
        }
    }
}

/// Whether an `MC_STATE` reason code is transport-defined or application-
/// defined.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum StateReasonScope {
    /// Reason code defined by the multicast transport layer.
    Transport,

    /// Reason code defined by the application.
    Application,
}

/// A full `MC_STATE` frame payload.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct State {
    /// The channel ID whose state changed.
    pub channel_id: Vec<u8>,

    /// The client channel state sequence number.
    pub sequence: u64,

    /// The new channel state.
    pub state: ChannelState,

    /// Whether the reason code is transport-defined or application-defined.
    pub reason_scope: StateReasonScope,

    /// The reason code carried in the frame.
    pub reason_code: u64,

    /// The UTF-8-free-form reason phrase bytes.
    pub reason_phrase: Vec<u8>,
}

impl State {
    /// Validates all wire fields and state/reason combinations without
    /// mutation.
    pub fn validate(&self) -> Result<()> {
        frame_encoded_len(&Frame::State(self.clone())).map(|_| ())
    }
}

/// The current multicast viability status for one channel on one connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeStatus {
    /// Multicast probing is in progress for this channel.
    Probing,

    /// Multicast delivery has been proven viable for this channel.
    Viable,

    /// Local STREAM recovery retention reached its configured resource limit.
    ///
    /// The channel remains on ordinary unicast fallback until explicitly
    /// reprobed.
    RecoveryLimited,

    /// Multicast probing timed out before the channel became viable.
    TimedOut,

    /// The multicast join request failed for this channel.
    JoinFailed,

    /// The multicast channel was left before becoming retired.
    Left,

    /// The multicast channel is retired.
    Retired,
}

/// A multicast probe state transition for one channel on one connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeEvent {
    /// The channel whose probe state changed.
    pub channel_id: Vec<u8>,

    /// The new probe status for the channel.
    pub status: ProbeStatus,

    /// The optional state-reason scope that caused the transition.
    pub reason_scope: Option<StateReasonScope>,

    /// The optional state-reason code that caused the transition.
    pub reason_code: Option<u64>,

    /// The optional state-reason phrase that caused the transition.
    pub reason_phrase: Vec<u8>,
}

/// One decoded multicast DATAGRAM payload delivered by a channel packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelDatagram {
    /// The channel ID that delivered the DATAGRAM.
    pub channel_id: Vec<u8>,

    /// The multicast packet number that carried the DATAGRAM.
    pub packet_number: u64,

    /// The DATAGRAM payload bytes.
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProbeState {
    pub(crate) status: ProbeStatus,
    pub(crate) deadline: Option<Instant>,
    pub(crate) ack_timeout: Option<Duration>,
}

impl ProbeState {
    pub(crate) fn new(status: ProbeStatus, deadline: Option<Instant>) -> Self {
        Self {
            status,
            deadline,
            ack_timeout: None,
        }
    }
}

/// Multicast control frames defined by the draft.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Frame {
    /// `MC_ANNOUNCE`
    Announce(Announce),

    /// `MC_KEY`
    Key(Key),

    /// `MC_JOIN`
    Join(Join),

    /// `MC_LEAVE`
    Leave(Leave),

    /// `MC_INTEGRITY`
    Integrity(Integrity),

    /// `MC_ACK`
    Ack(Ack),

    /// `MC_LIMITS`
    Limits(Limits),

    /// `MC_RETIRE`
    Retire(Retire),

    /// `MC_STATE`
    State(State),
}

/// Owned multicast control-send failure.
///
/// The rejected frame is retained so callers can retry transient saturation
/// without cloning secret-bearing or potentially large control values.
#[derive(Debug)]
pub struct ControlSendError {
    kind: ControlSendErrorKind,
    frame: Frame,
}

impl ControlSendError {
    pub(crate) fn new(kind: ControlSendErrorKind, frame: Frame) -> Self {
        Self { kind, frame }
    }

    /// Returns the failure category.
    pub fn kind(&self) -> ControlSendErrorKind {
        self.kind
    }

    /// Returns the frame that was not admitted.
    pub fn frame(&self) -> &Frame {
        &self.frame
    }

    /// Recovers ownership of the frame that was not admitted.
    pub fn into_frame(self) -> Frame {
        self.frame
    }

    pub(crate) fn quiche_error(&self) -> Error {
        match self.kind {
            ControlSendErrorKind::Full => Error::Done,
            ControlSendErrorKind::Oversized => Error::BufferTooShort,
            ControlSendErrorKind::Closed | ControlSendErrorKind::Disabled =>
                Error::InvalidState,
            ControlSendErrorKind::ResourceLimit => Error::InvalidState,
            ControlSendErrorKind::InvalidFrame |
            ControlSendErrorKind::InvalidValue => Error::InvalidFrame,
        }
    }
}

impl fmt::Display for ControlSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "multicast control send failed: {}", self.kind)
    }
}

impl std::error::Error for ControlSendError {}

/// Category reported by [`ControlSendError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlSendErrorKind {
    /// The bounded queue is temporarily full and the frame can be retried.
    Full,

    /// The frame can never fit the configured queue or current packet bound.
    Oversized,

    /// The QUIC connection is closing or closed.
    Closed,

    /// The peer did not negotiate multicast control delivery.
    Disabled,

    /// The connection-lifetime Channel ID resource bound was reached.
    ResourceLimit,

    /// The frame is not permitted in this endpoint's sending direction.
    InvalidFrame,

    /// One or more frame fields cannot be represented on the wire.
    InvalidValue,
}

impl fmt::Display for ControlSendErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::Full => "queue full",
            Self::Oversized => "frame oversized",
            Self::Closed => "connection closed",
            Self::Disabled => "multicast disabled",
            Self::ResourceLimit => "Channel ID resource limit reached",
            Self::InvalidFrame => "invalid frame direction",
            Self::InvalidValue => "invalid frame value",
        };
        f.write_str(description)
    }
}

impl Frame {
    pub(crate) fn decode_from_type(
        ty: u64, b: &mut octets::Octets,
    ) -> Result<Self> {
        match ty {
            FRAME_TYPE_ANNOUNCE_V4 | FRAME_TYPE_ANNOUNCE_V6 => {
                let channel_id = decode_channel_id(b, true)?;
                let source = decode_ip_addr(b, ty)?;
                let group = decode_ip_addr(b, ty)?;

                Ok(Frame::Announce(Announce {
                    channel_id,
                    source,
                    group,
                    udp_port: b.get_u16()?,
                    header_protection_algorithm: b.get_u16()?,
                    header_secret: b.get_bytes_with_varint_length()?.to_vec(),
                    aead_algorithm: b.get_u16()?,
                    integrity_hash_algorithm: b.get_u16()?,
                    max_rate_kibps: b.get_varint()?,
                    max_ack_delay_ms: b.get_varint()?,
                }))
            },

            FRAME_TYPE_KEY => Ok(Frame::Key(Key {
                channel_id: decode_channel_id(b, true)?,
                key_sequence: b.get_varint()?,
                from_packet_number: b.get_varint()?,
                secret: b.get_bytes_with_varint_length()?.to_vec(),
            })),

            FRAME_TYPE_JOIN => Ok(Frame::Join(Join {
                channel_id: decode_channel_id(b, true)?,
                mc_limits_sequence: b.get_varint()?,
                mc_state_sequence: b.get_varint()?,
                mc_key_sequence: b.get_varint()?,
            })),

            FRAME_TYPE_LEAVE => Ok(Frame::Leave(Leave {
                channel_id: decode_channel_id(b, true)?,
                mc_state_sequence: b.get_varint()?,
                after_packet_number: b.get_varint()?,
            })),

            FRAME_TYPE_INTEGRITY | FRAME_TYPE_INTEGRITY_WITH_LENGTH =>
                decode_integrity_frame(ty, b, None, false),

            FRAME_TYPE_ACK | FRAME_TYPE_ACK_ECN => {
                let channel_id = decode_channel_id(b, true)?;
                let largest_acknowledged = b.get_varint()?;
                let ack_delay = b.get_varint()?;
                let ack_range_count = b.get_varint()?;
                let first_ack_range = b.get_varint()?;
                let ack_ranges = decode_ack_ranges(b, ack_range_count)?;

                let ecn_counts = if ty == FRAME_TYPE_ACK_ECN {
                    Some(AckEcnCounts {
                        ect0_count: b.get_varint()?,
                        ect1_count: b.get_varint()?,
                        ecn_ce_count: b.get_varint()?,
                    })
                } else {
                    None
                };

                Ok(Frame::Ack(Ack {
                    channel_id,
                    largest_acknowledged,
                    ack_delay,
                    first_ack_range,
                    ack_ranges,
                    ecn_counts,
                }))
            },

            FRAME_TYPE_LIMITS => {
                let sequence = b.get_varint()?;
                let (limits, max_joined_count) =
                    ClientLimits::decode_with_max_joined(b)?;

                Ok(Frame::Limits(Limits {
                    sequence,
                    limits,
                    max_joined_count,
                }))
            },

            FRAME_TYPE_RETIRE => Ok(Frame::Retire(Retire {
                channel_id: decode_channel_id(b, true)?,
                after_packet_number: b.get_varint()?,
            })),

            FRAME_TYPE_STATE | FRAME_TYPE_STATE_APPLICATION => {
                let channel_id = decode_channel_id(b, true)?;
                let sequence = b.get_varint()?;
                let state = ChannelState::from_u8(b.get_u8()?)?;
                let reason_scope = if ty == FRAME_TYPE_STATE {
                    StateReasonScope::Transport
                } else {
                    StateReasonScope::Application
                };
                let reason_code = b.get_varint()?;
                let reason_phrase = b.get_bytes_with_varint_length()?.to_vec();

                validate_state_reason(state, reason_scope, reason_code)?;

                Ok(Frame::State(State {
                    channel_id,
                    sequence,
                    state,
                    reason_scope,
                    reason_code,
                    reason_phrase,
                }))
            },

            _ => Err(Error::InvalidFrame),
        }
    }

    pub(crate) fn decode_from_type_with_integrity_hash_len(
        ty: u64, b: &mut octets::Octets, integrity_hash_len: usize,
    ) -> Result<Self> {
        match ty {
            FRAME_TYPE_INTEGRITY | FRAME_TYPE_INTEGRITY_WITH_LENGTH =>
                decode_integrity_frame(ty, b, Some(integrity_hash_len), true),

            _ => Self::decode_from_type(ty, b),
        }
    }

    /// Decodes a multicast frame from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut b = octets::Octets::with_slice(buf);

        let ty = b.get_varint()?;
        let frame = Self::decode_from_type(ty, &mut b)?;

        if b.cap() != 0 {
            return Err(Error::InvalidFrame);
        }

        Ok(frame)
    }

    /// Encodes a multicast frame into the provided buffer.
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<usize> {
        let encoded_len = self.encoded_len()?;
        if out.len() < encoded_len {
            return Err(Error::BufferTooShort);
        }

        let mut b = octets::OctetsMut::with_slice(out);
        let before = b.cap();

        self.encode(&mut b)?;

        Ok(before - b.cap())
    }

    pub(crate) fn encode(&self, b: &mut octets::OctetsMut) -> Result<()> {
        self.encoded_len()?;

        match self {
            Frame::Announce(frame) => {
                b.put_varint(announce_frame_type(frame)?)?;
                encode_channel_id(&frame.channel_id, b)?;
                encode_ip_addr(&frame.source, b)?;
                encode_ip_addr(&frame.group, b)?;
                b.put_u16(frame.udp_port)?;
                b.put_u16(frame.header_protection_algorithm)?;
                b.put_varint(frame.header_secret.len() as u64)?;
                b.put_bytes(&frame.header_secret)?;
                b.put_u16(frame.aead_algorithm)?;
                b.put_u16(frame.integrity_hash_algorithm)?;
                b.put_varint(frame.max_rate_kibps)?;
                b.put_varint(frame.max_ack_delay_ms)?;
            },

            Frame::Key(frame) => {
                b.put_varint(FRAME_TYPE_KEY)?;
                encode_channel_id(&frame.channel_id, b)?;
                b.put_varint(frame.key_sequence)?;
                b.put_varint(frame.from_packet_number)?;
                b.put_varint(frame.secret.len() as u64)?;
                b.put_bytes(&frame.secret)?;
            },

            Frame::Join(frame) => {
                b.put_varint(FRAME_TYPE_JOIN)?;
                encode_channel_id(&frame.channel_id, b)?;
                b.put_varint(frame.mc_limits_sequence)?;
                b.put_varint(frame.mc_state_sequence)?;
                b.put_varint(frame.mc_key_sequence)?;
            },

            Frame::Leave(frame) => {
                b.put_varint(FRAME_TYPE_LEAVE)?;
                encode_channel_id(&frame.channel_id, b)?;
                b.put_varint(frame.mc_state_sequence)?;
                b.put_varint(frame.after_packet_number)?;
            },

            Frame::Integrity(frame) => {
                if let Some(packet_hash_count) = frame.packet_hash_count {
                    b.put_varint(FRAME_TYPE_INTEGRITY_WITH_LENGTH)?;
                    encode_channel_id(&frame.channel_id, b)?;
                    b.put_varint(frame.packet_number_start)?;
                    b.put_varint(packet_hash_count)?;
                    b.put_bytes(&frame.packet_hashes)?;
                } else {
                    b.put_varint(FRAME_TYPE_INTEGRITY)?;
                    encode_channel_id(&frame.channel_id, b)?;
                    b.put_varint(frame.packet_number_start)?;
                    b.put_bytes(&frame.packet_hashes)?;
                }
            },

            Frame::Ack(frame) => {
                if frame.ecn_counts.is_some() {
                    b.put_varint(FRAME_TYPE_ACK_ECN)?;
                } else {
                    b.put_varint(FRAME_TYPE_ACK)?;
                }

                encode_channel_id(&frame.channel_id, b)?;
                b.put_varint(frame.largest_acknowledged)?;
                b.put_varint(frame.ack_delay)?;
                b.put_varint(frame.ack_ranges.len() as u64)?;
                b.put_varint(frame.first_ack_range)?;

                for range in &frame.ack_ranges {
                    b.put_varint(range.gap)?;
                    b.put_varint(range.ack_range_length)?;
                }

                if let Some(ecn_counts) = &frame.ecn_counts {
                    b.put_varint(ecn_counts.ect0_count)?;
                    b.put_varint(ecn_counts.ect1_count)?;
                    b.put_varint(ecn_counts.ecn_ce_count)?;
                }
            },

            Frame::Limits(frame) => {
                b.put_varint(FRAME_TYPE_LIMITS)?;
                b.put_varint(frame.sequence)?;
                frame.limits.encode(b)?;
                b.put_varint(frame.max_joined_count)?;
            },

            Frame::Retire(frame) => {
                b.put_varint(FRAME_TYPE_RETIRE)?;
                encode_channel_id(&frame.channel_id, b)?;
                b.put_varint(frame.after_packet_number)?;
            },

            Frame::State(frame) => {
                match frame.reason_scope {
                    StateReasonScope::Transport =>
                        b.put_varint(FRAME_TYPE_STATE)?,

                    StateReasonScope::Application =>
                        b.put_varint(FRAME_TYPE_STATE_APPLICATION)?,
                };

                encode_channel_id(&frame.channel_id, b)?;
                b.put_varint(frame.sequence)?;
                b.put_u8(frame.state as u8)?;
                b.put_varint(frame.reason_code)?;
                b.put_varint(frame.reason_phrase.len() as u64)?;
                b.put_bytes(&frame.reason_phrase)?;
            },
        }

        Ok(())
    }

    pub(crate) fn frame_type(&self) -> u64 {
        match self {
            Frame::Announce(frame) => match frame.source {
                IpAddr::V4(_) => FRAME_TYPE_ANNOUNCE_V4,
                IpAddr::V6(_) => FRAME_TYPE_ANNOUNCE_V6,
            },

            Frame::Key(..) => FRAME_TYPE_KEY,
            Frame::Join(..) => FRAME_TYPE_JOIN,
            Frame::Leave(..) => FRAME_TYPE_LEAVE,

            Frame::Integrity(frame) =>
                if frame.packet_hash_count.is_some() {
                    FRAME_TYPE_INTEGRITY_WITH_LENGTH
                } else {
                    FRAME_TYPE_INTEGRITY
                },

            Frame::Ack(frame) =>
                if frame.ecn_counts.is_some() {
                    FRAME_TYPE_ACK_ECN
                } else {
                    FRAME_TYPE_ACK
                },

            Frame::Limits(..) => FRAME_TYPE_LIMITS,
            Frame::Retire(..) => FRAME_TYPE_RETIRE,

            Frame::State(frame) => match frame.reason_scope {
                StateReasonScope::Transport => FRAME_TYPE_STATE,
                StateReasonScope::Application => FRAME_TYPE_STATE_APPLICATION,
            },
        }
    }

    /// Returns the checked encoded wire length of this frame.
    ///
    /// This validates every QUIC varint, Channel ID, and structural field
    /// before an encoder or queue mutates state.
    pub fn encoded_len(&self) -> Result<usize> {
        frame_encoded_len(self)
    }

    pub(crate) fn sender(&self) -> Sender {
        match self {
            Frame::Announce(..) |
            Frame::Key(..) |
            Frame::Join(..) |
            Frame::Leave(..) |
            Frame::Integrity(..) |
            Frame::Retire(..) => Sender::Server,

            Frame::Ack(..) | Frame::Limits(..) | Frame::State(..) =>
                Sender::Client,
        }
    }

    pub(crate) fn channel_id(&self) -> Option<&[u8]> {
        match self {
            Frame::Announce(frame) => Some(&frame.channel_id),
            Frame::Key(frame) => Some(&frame.channel_id),
            Frame::Join(frame) => Some(&frame.channel_id),
            Frame::Leave(frame) => Some(&frame.channel_id),
            Frame::Integrity(frame) => Some(&frame.channel_id),
            Frame::Ack(frame) => Some(&frame.channel_id),
            Frame::Limits(..) => None,
            Frame::Retire(frame) => Some(&frame.channel_id),
            Frame::State(frame) => Some(&frame.channel_id),
        }
    }

    pub(crate) fn ack_eliciting(&self) -> bool {
        !matches!(self, Frame::Ack(..))
    }

    pub(crate) fn retransmit_on_loss(&self) -> bool {
        !matches!(self, Frame::Ack(..))
    }

    pub(crate) fn requires_packet_end(&self) -> bool {
        matches!(
            self,
            Frame::Integrity(Integrity {
                packet_hash_count: None,
                ..
            })
        )
    }
}

/// A multicast channel frame carried in a multicast 1-RTT packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelFrame {
    /// `PADDING`
    Padding {
        /// The number of padding bytes.
        len: usize,
    },

    /// `PING`
    Ping,

    /// `RESET_STREAM`
    ResetStream {
        /// The stream ID being reset.
        stream_id: u64,

        /// The application error code.
        error_code: u64,

        /// The stream's final size.
        final_size: u64,
    },

    /// `RESET_STREAM_AT`
    ResetStreamAt {
        /// The stream ID being reset.
        stream_id: u64,

        /// The application error code.
        error_code: u64,

        /// The stream's final size.
        final_size: u64,

        /// The prefix that still requires reliable delivery.
        reliable_size: u64,
    },

    /// `STREAM`
    Stream {
        /// The stream ID carried by the frame.
        stream_id: u64,

        /// The byte offset of the stream data.
        offset: u64,

        /// Whether this frame carries the stream FIN marker.
        fin: bool,

        /// The stream data bytes.
        data: Vec<u8>,
    },

    /// `DATAGRAM`
    Datagram {
        /// The datagram payload bytes.
        data: Vec<u8>,
    },

    /// A permitted multicast control frame carried in the channel packet.
    Multicast(Frame),
}

impl ChannelFrame {
    /// Returns the checked encoded length of this channel frame.
    pub fn encoded_len(&self) -> Result<usize> {
        channel_frame_wire_len(self)
    }
}

/// A decoded multicast 1-RTT packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelPacket {
    /// The channel ID carried in the short header in place of a DCID.
    pub channel_id: Vec<u8>,

    /// The decoded packet number from the channel packet number space.
    pub packet_number: u64,

    /// The key sequence used to decrypt the packet payload.
    pub key_sequence: u64,

    /// The decoded short-header key phase bit.
    pub key_phase: bool,

    /// The decoded and validated channel frames.
    pub frames: Vec<ChannelFrame>,
}

impl ChannelPacket {
    /// Validates all programmatically supplied channel packet wire fields.
    pub fn validate(&self) -> Result<()> {
        validate_channel_id(&self.channel_id)?;
        validate_varint(self.packet_number)?;
        validate_varint(self.key_sequence)?;

        for frame in &self.frames {
            frame.encoded_len()?;
        }

        Ok(())
    }
}

/// The result of encoding one multicast channel packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSendOutput {
    /// The packet number used in the encoded channel packet.
    pub packet_number: u64,

    /// The key sequence used to encrypt the packet.
    pub key_sequence: u64,

    /// The short-header key phase bit encoded into the packet.
    pub key_phase: bool,

    /// The number of bytes written into the caller's output buffer.
    pub packet_len: usize,

    /// The matching `MC_INTEGRITY` payload for the encoded packet.
    pub integrity: Integrity,
}

/// A point-in-time snapshot of multicast channel send metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelSendMetricsSnapshot {
    /// Total calls made to [`ChannelSendState::write_packet()`].
    pub write_calls: u64,

    /// Total multicast channel packets encoded successfully.
    pub packets_encoded: u64,

    /// Total encoded multicast channel bytes produced.
    pub bytes_encoded: u64,

    /// Total channel frames encoded into multicast packets.
    pub frames_encoded: u64,

    /// Total successful payload-protection key updates.
    pub key_updates: u64,

    /// Total failed packet-sizing or packet-encoding attempts.
    pub encode_errors: u64,

    /// Total valid `MC_ACK` frames processed by [`ChannelSendState::on_ack()`].
    pub ack_frames_processed: u64,

    /// Total acknowledged blocks processed across all `MC_ACK` frames.
    pub ack_blocks_processed: u64,

    /// Total packet numbers reported as acknowledged by peer `MC_ACK` frames.
    pub acked_packets_reported: u64,

    /// Total invalid `MC_ACK` frames rejected by
    /// [`ChannelSendState::on_ack()`].
    pub ack_errors: u64,

    /// The largest multicast packet number acknowledged so far, if any.
    pub largest_acknowledged: Option<u64>,

    /// The most recently assigned multicast packet number, if any.
    pub last_packet_number: Option<u64>,

    /// The next multicast packet number that will be assigned.
    pub next_packet_number: u64,
}

/// The difference between two send metrics snapshots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelSendMetricsDelta {
    /// Change in [`ChannelSendMetricsSnapshot::write_calls`].
    pub write_calls: u64,

    /// Change in [`ChannelSendMetricsSnapshot::packets_encoded`].
    pub packets_encoded: u64,

    /// Change in [`ChannelSendMetricsSnapshot::bytes_encoded`].
    pub bytes_encoded: u64,

    /// Change in [`ChannelSendMetricsSnapshot::frames_encoded`].
    pub frames_encoded: u64,

    /// Change in [`ChannelSendMetricsSnapshot::key_updates`].
    pub key_updates: u64,

    /// Change in [`ChannelSendMetricsSnapshot::encode_errors`].
    pub encode_errors: u64,

    /// Change in [`ChannelSendMetricsSnapshot::ack_frames_processed`].
    pub ack_frames_processed: u64,

    /// Change in [`ChannelSendMetricsSnapshot::ack_blocks_processed`].
    pub ack_blocks_processed: u64,

    /// Change in [`ChannelSendMetricsSnapshot::acked_packets_reported`].
    pub acked_packets_reported: u64,

    /// Change in [`ChannelSendMetricsSnapshot::ack_errors`].
    pub ack_errors: u64,

    /// The largest packet number acknowledged at the end of the interval.
    pub largest_acknowledged: Option<u64>,

    /// The latest assigned packet number sampled at the end of the interval.
    pub last_packet_number: Option<u64>,

    /// The next packet number sampled at the end of the interval.
    pub next_packet_number: u64,
}

/// Cumulative per-connection send-path metrics for one multicast STREAM
/// channel.
///
/// These counters measure unique STREAM payload ranges successfully scheduled
/// through ordinary QUIC. They exclude QUIC framing, encryption,
/// retransmissions, control frames, and socket overhead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamDeliveryMetricsSnapshot {
    /// Ranges sent directly over ordinary QUIC while multicast was not viable.
    pub direct_fallback_ranges_total: u64,

    /// Unique payload bytes in directly scheduled fallback ranges.
    pub direct_fallback_bytes_total: u64,

    /// Withheld ranges released after an advancing `MC_ACK` exposed a gap.
    pub ack_gap_recovery_ranges_total: u64,

    /// Unique payload bytes released for ACK-gap recovery.
    pub ack_gap_recovery_bytes_total: u64,

    /// Withheld ranges released when the channel became non-viable.
    pub fallback_reentry_ranges_total: u64,

    /// Unique payload bytes released after fallback re-entry.
    pub fallback_reentry_bytes_total: u64,

    /// Times local recovery retention forced the channel back to unicast.
    pub recovery_limit_fallbacks_total: u64,
}

/// The saturating difference between two STREAM delivery metrics snapshots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamDeliveryMetricsDelta {
    /// Change in
    /// [`StreamDeliveryMetricsSnapshot::direct_fallback_ranges_total`].
    pub direct_fallback_ranges_total: u64,

    /// Change in
    /// [`StreamDeliveryMetricsSnapshot::direct_fallback_bytes_total`].
    pub direct_fallback_bytes_total: u64,

    /// Change in
    /// [`StreamDeliveryMetricsSnapshot::ack_gap_recovery_ranges_total`].
    pub ack_gap_recovery_ranges_total: u64,

    /// Change in
    /// [`StreamDeliveryMetricsSnapshot::ack_gap_recovery_bytes_total`].
    pub ack_gap_recovery_bytes_total: u64,

    /// Change in
    /// [`StreamDeliveryMetricsSnapshot::fallback_reentry_ranges_total`].
    pub fallback_reentry_ranges_total: u64,

    /// Change in
    /// [`StreamDeliveryMetricsSnapshot::fallback_reentry_bytes_total`].
    pub fallback_reentry_bytes_total: u64,

    /// Change in
    /// [`StreamDeliveryMetricsSnapshot::recovery_limit_fallbacks_total`].
    pub recovery_limit_fallbacks_total: u64,
}

impl StreamDeliveryMetricsDelta {
    /// Computes a saturating delta between two delivery snapshots.
    pub fn between(
        before: StreamDeliveryMetricsSnapshot,
        after: StreamDeliveryMetricsSnapshot,
    ) -> Self {
        Self {
            direct_fallback_ranges_total: after
                .direct_fallback_ranges_total
                .saturating_sub(before.direct_fallback_ranges_total),
            direct_fallback_bytes_total: after
                .direct_fallback_bytes_total
                .saturating_sub(before.direct_fallback_bytes_total),
            ack_gap_recovery_ranges_total: after
                .ack_gap_recovery_ranges_total
                .saturating_sub(before.ack_gap_recovery_ranges_total),
            ack_gap_recovery_bytes_total: after
                .ack_gap_recovery_bytes_total
                .saturating_sub(before.ack_gap_recovery_bytes_total),
            fallback_reentry_ranges_total: after
                .fallback_reentry_ranges_total
                .saturating_sub(before.fallback_reentry_ranges_total),
            fallback_reentry_bytes_total: after
                .fallback_reentry_bytes_total
                .saturating_sub(before.fallback_reentry_bytes_total),
            recovery_limit_fallbacks_total: after
                .recovery_limit_fallbacks_total
                .saturating_sub(before.recovery_limit_fallbacks_total),
        }
    }
}

impl ChannelSendMetricsDelta {
    /// Computes the delta between two send metrics snapshots.
    pub fn between(
        before: ChannelSendMetricsSnapshot, after: ChannelSendMetricsSnapshot,
    ) -> Self {
        Self {
            write_calls: after.write_calls.saturating_sub(before.write_calls),
            packets_encoded: after
                .packets_encoded
                .saturating_sub(before.packets_encoded),
            bytes_encoded: after
                .bytes_encoded
                .saturating_sub(before.bytes_encoded),
            frames_encoded: after
                .frames_encoded
                .saturating_sub(before.frames_encoded),
            key_updates: after.key_updates.saturating_sub(before.key_updates),
            encode_errors: after
                .encode_errors
                .saturating_sub(before.encode_errors),
            ack_frames_processed: after
                .ack_frames_processed
                .saturating_sub(before.ack_frames_processed),
            ack_blocks_processed: after
                .ack_blocks_processed
                .saturating_sub(before.ack_blocks_processed),
            acked_packets_reported: after
                .acked_packets_reported
                .saturating_sub(before.acked_packets_reported),
            ack_errors: after.ack_errors.saturating_sub(before.ack_errors),
            largest_acknowledged: after.largest_acknowledged,
            last_packet_number: after.last_packet_number,
            next_packet_number: after.next_packet_number,
        }
    }
}

/// Summary returned after processing one peer `MC_ACK`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelSendAckSummary {
    /// Total acknowledged blocks carried by the frame.
    pub ack_blocks: u64,

    /// Total packet numbers covered by all acknowledged blocks.
    pub acked_packets: u64,

    /// The largest packet number acknowledged by the frame.
    pub largest_acknowledged: u64,

    /// The smallest packet number acknowledged by the frame.
    pub smallest_acknowledged: u64,
}

/// Send-side state for one multicast channel's encrypted 1-RTT packets.
///
/// This tracks the immutable channel properties from [`Announce`], the active
/// [`Key`] used for payload protection, and the next packet number in the
/// channel's packet number space.
pub struct ChannelSendState {
    announce: Announce,
    key: Key,
    seal: crypto::Seal,
    integrity_hash: IntegrityHashAlgorithm,
    next_packet_number: u64,
    metrics: ChannelSendMetricsState,
}

impl ChannelSendState {
    /// Creates send-side state for the announced channel and active key.
    ///
    /// The current implementation supports the QUIC v1 TLS cipher suite values
    /// `0x1301`, `0x1302`, and `0x1303`, and the named-information hash IDs
    /// `1..=8`. Other algorithm identifiers are reserved for future work.
    pub fn new(announce: Announce, key: Key) -> Result<Self> {
        announce.validate()?;
        key.validate()?;

        if key.channel_id != announce.channel_id {
            return Err(Error::InvalidState);
        }

        let integrity_hash =
            IntegrityHashAlgorithm::from_id(announce.integrity_hash_algorithm)?;
        let seal = build_channel_packet_seal(&announce, &key)?;

        Ok(Self {
            seal,
            integrity_hash,
            next_packet_number: key.from_packet_number,
            metrics: ChannelSendMetricsState::default(),
            announce,
            key,
        })
    }

    /// Returns the announced channel properties used by this sender.
    pub fn announce(&self) -> &Announce {
        &self.announce
    }

    /// Returns the active payload-protection key.
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Returns the next packet number that will be assigned.
    pub fn next_packet_number(&self) -> u64 {
        self.next_packet_number
    }

    /// Returns the number of integrity-hash bytes emitted per channel packet.
    pub fn integrity_hash_len(&self) -> usize {
        self.integrity_hash.output_len()
    }

    /// Returns a snapshot of the sender's current metrics.
    pub fn metrics_snapshot(&self) -> ChannelSendMetricsSnapshot {
        self.metrics.snapshot(self.next_packet_number)
    }

    /// Updates the sender with a retransmitted `MC_ANNOUNCE`.
    ///
    /// Since the draft treats channel properties as immutable for a channel's
    /// lifetime, any announce that differs from the current one is rejected.
    pub fn update_announce(&mut self, mut announce: Announce) -> Result<()> {
        announce.validate()?;

        if self.announce.channel_id != announce.channel_id {
            announce.header_secret.fill(0);
            return Err(Error::InvalidState);
        }

        if self.announce != announce {
            announce.header_secret.fill(0);
            return Err(Error::InvalidState);
        }

        announce.header_secret.fill(0);
        Ok(())
    }

    /// Replaces the active `MC_KEY` used to protect newly encoded packets.
    pub fn update_key(&mut self, key: Key) -> Result<()> {
        key.validate()?;

        if key.channel_id != self.announce.channel_id {
            return Err(Error::InvalidState);
        }

        if key.key_sequence < self.key.key_sequence {
            return Err(Error::InvalidState);
        }

        if key.key_sequence == self.key.key_sequence {
            if key.from_packet_number != self.key.from_packet_number ||
                key.secret != self.key.secret
            {
                return Err(Error::InvalidState);
            }

            return Ok(());
        }

        if self
            .key
            .key_sequence
            .checked_add(1)
            .ok_or(Error::InvalidState)? !=
            key.key_sequence
        {
            return Err(Error::InvalidState);
        }

        if key.from_packet_number < self.key.from_packet_number {
            return Err(Error::InvalidState);
        }

        self.seal = build_channel_packet_seal(&self.announce, &key)?;

        if self.next_packet_number < key.from_packet_number {
            self.next_packet_number = key.from_packet_number;
        }

        let mut old_key = std::mem::replace(&mut self.key, key);
        old_key.secret.fill(0);
        self.metrics.key_updates = self.metrics.key_updates.saturating_add(1);

        Ok(())
    }

    /// Processes one peer `MC_ACK` for this channel.
    ///
    /// This validates the acknowledged ranges against the sender's channel ID
    /// and the packet number space already assigned by this sender, then
    /// updates sender-side ACK metrics.
    pub fn on_ack(&mut self, ack: &Ack) -> Result<ChannelSendAckSummary> {
        if ack.channel_id != self.announce.channel_id {
            self.metrics.ack_errors = self.metrics.ack_errors.saturating_add(1);
            return Err(Error::InvalidState);
        }

        let summary = match summarize_ack(ack, self.next_packet_number) {
            Ok(summary) => summary,

            Err(error) => {
                self.metrics.ack_errors =
                    self.metrics.ack_errors.saturating_add(1);
                return Err(error);
            },
        };

        self.metrics.ack_frames_processed =
            self.metrics.ack_frames_processed.saturating_add(1);
        self.metrics.ack_blocks_processed = self
            .metrics
            .ack_blocks_processed
            .saturating_add(summary.ack_blocks);
        self.metrics.acked_packets_reported = self
            .metrics
            .acked_packets_reported
            .saturating_add(summary.acked_packets);
        self.metrics.largest_acknowledged = Some(
            self.metrics
                .largest_acknowledged
                .map_or(summary.largest_acknowledged, |largest| {
                    largest.max(summary.largest_acknowledged)
                }),
        );

        Ok(summary)
    }

    /// Returns the exact output size required to encode `frames`.
    ///
    /// A sizing failure increments the sender's `encode_errors` metric.
    pub fn packet_len(&mut self, frames: &[ChannelFrame]) -> Result<usize> {
        let result = self.checked_packet_len(frames);
        self.record_encode_result(result)
    }

    fn checked_packet_len(&self, frames: &[ChannelFrame]) -> Result<usize> {
        let result = frames.iter().try_fold(0_usize, |total, frame| {
            total
                .checked_add(channel_frame_wire_len(frame)?)
                .ok_or(Error::InvalidState)
        });

        result.and_then(|payload_len| {
            channel_packet_len(
                &self.announce,
                self.seal.alg().tag_len(),
                payload_len,
            )
        })
    }

    /// Returns the exact output size required for one borrowed STREAM frame.
    ///
    /// A sizing failure increments the sender's `encode_errors` metric.
    pub fn stream_packet_len(
        &mut self, stream_id: u64, offset: u64, data_len: usize,
    ) -> Result<usize> {
        let result = self.checked_stream_packet_len(stream_id, offset, data_len);
        self.record_encode_result(result)
    }

    fn checked_stream_packet_len(
        &self, stream_id: u64, offset: u64, data_len: usize,
    ) -> Result<usize> {
        channel_stream_frame_wire_len(stream_id, offset, data_len).and_then(
            |payload_len| {
                channel_packet_len(
                    &self.announce,
                    self.seal.alg().tag_len(),
                    payload_len,
                )
            },
        )
    }

    fn record_encode_result(&mut self, result: Result<usize>) -> Result<usize> {
        if result.is_err() {
            self.metrics.encode_errors =
                self.metrics.encode_errors.saturating_add(1);
        }
        result
    }

    /// Encodes one multicast packet carrying the provided channel frames.
    ///
    /// The encoded bytes are written into `out`. On success, the returned
    /// [`ChannelSendOutput`] includes the matching [`Integrity`] payload that
    /// should be sent to receivers on the unicast control channel.
    pub fn write_packet(
        &mut self, frames: &[ChannelFrame], out: &mut [u8],
    ) -> Result<ChannelSendOutput> {
        let required = self.checked_packet_len(frames);
        self.preflight_write(required, out.len())?;

        self.write_packet_inner(
            out,
            frames.len(),
            |announce, seal, pn, phase, out| {
                encode_channel_packet_bytes(
                    announce, seal, pn, phase, frames, out,
                )
            },
        )
    }

    /// Encodes one borrowed STREAM frame without copying its payload.
    ///
    /// Use [`ChannelSendState::stream_packet_len()`] to allocate the exact
    /// output size before calling this method.
    pub fn write_stream_packet(
        &mut self, stream_id: u64, offset: u64, fin: bool, data: &[u8],
        out: &mut [u8],
    ) -> Result<ChannelSendOutput> {
        let required =
            self.checked_stream_packet_len(stream_id, offset, data.len());
        self.preflight_write(required, out.len())?;

        let frame = BorrowedChannelStreamFrame {
            stream_id,
            offset,
            fin,
            data,
        };
        self.write_packet_inner(out, 1, |announce, seal, pn, phase, out| {
            encode_channel_stream_packet_bytes(
                announce, seal, pn, phase, &frame, out,
            )
        })
    }

    fn preflight_write(
        &mut self, required: Result<usize>, output_len: usize,
    ) -> Result<()> {
        let required = match required {
            Ok(required) if required <= output_len => return Ok(()),
            Ok(_) => Err(Error::BufferTooShort),
            Err(error) => Err(error),
        };

        self.metrics.write_calls = self.metrics.write_calls.saturating_add(1);
        self.metrics.encode_errors = self.metrics.encode_errors.saturating_add(1);
        required
    }

    fn write_packet_inner(
        &mut self, out: &mut [u8], frame_count: usize,
        encode: impl FnOnce(
            &Announce,
            &mut crypto::Seal,
            u64,
            bool,
            &mut [u8],
        ) -> Result<usize>,
    ) -> Result<ChannelSendOutput> {
        self.metrics.write_calls = self.metrics.write_calls.saturating_add(1);
        let packet_number = self.next_packet_number;
        if packet_number > MAX_VARINT {
            self.metrics.encode_errors =
                self.metrics.encode_errors.saturating_add(1);
            return Err(Error::InvalidState);
        }
        let next_packet_number =
            packet_number.checked_add(1).ok_or(Error::InvalidState)?;
        let key_phase = self.key.key_sequence % 2 == 1;
        let packet_len = match encode(
            &self.announce,
            &mut self.seal,
            packet_number,
            key_phase,
            out,
        ) {
            Ok(packet_len) => packet_len,

            Err(error) => {
                self.metrics.encode_errors =
                    self.metrics.encode_errors.saturating_add(1);
                return Err(error);
            },
        };
        let packet = &out[..packet_len];

        self.next_packet_number = next_packet_number;
        self.metrics.packets_encoded =
            self.metrics.packets_encoded.saturating_add(1);
        self.metrics.bytes_encoded =
            self.metrics.bytes_encoded.saturating_add(packet_len as u64);
        self.metrics.frames_encoded = self
            .metrics
            .frames_encoded
            .saturating_add(frame_count as u64);
        self.metrics.last_packet_number = Some(packet_number);

        Ok(ChannelSendOutput {
            packet_number,
            key_sequence: self.key.key_sequence,
            key_phase,
            packet_len,
            integrity: Integrity {
                channel_id: self.announce.channel_id.clone(),
                packet_number_start: packet_number,
                packet_hash_count: Some(1),
                packet_hashes: self.integrity_hash.hash(packet),
            },
        })
    }
}

impl Drop for ChannelSendState {
    fn drop(&mut self) {
        self.announce.header_secret.fill(0);
        self.key.secret.fill(0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AckSpan {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

/// Tracks cumulative multicast packet acknowledgments for a channel.
///
/// This helper records packet numbers that have been validated and decoded,
/// merges them into disjoint contiguous ranges, and can synthesize the next
/// `MC_ACK` payload to send back over the control connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AckTracker {
    ranges: Vec<AckSpan>,
    pending: bool,
    retired_before: u64,
}

impl AckTracker {
    /// Returns whether a new ACK can be synthesized without building it.
    pub fn has_pending_ack(&self) -> bool {
        self.pending && !self.ranges.is_empty()
    }

    /// Records a decoded multicast packet number.
    pub fn record_packet(&mut self, packet_number: u64) {
        if packet_number < self.retired_before ||
            self.ranges.iter().any(|range| {
                range.start <= packet_number && packet_number <= range.end
            })
        {
            return;
        }

        let mut start = packet_number;
        let mut end = packet_number;
        let mut insert_at = 0;

        while insert_at < self.ranges.len() {
            let existing = self.ranges[insert_at];

            if end.saturating_add(1) < existing.start {
                break;
            }

            if existing.end.saturating_add(1) < start {
                insert_at += 1;
                continue;
            }

            start = start.min(existing.start);
            end = end.max(existing.end);
            self.ranges.remove(insert_at);
        }

        self.ranges.insert(insert_at, AckSpan { start, end });
        self.trim_history();
        self.pending = true;
    }

    /// Builds the pending `MC_ACK` frame for `channel_id`, if any.
    pub fn pending_ack(&self, channel_id: &[u8]) -> Option<Ack> {
        if !self.pending || self.ranges.is_empty() {
            return None;
        }

        let newest = self.ranges.last().copied()?;
        let mut smallest_ack = newest.start;
        let mut ack_ranges =
            Vec::with_capacity(self.ranges.len().saturating_sub(1));

        for span in self.ranges[..self.ranges.len().saturating_sub(1)]
            .iter()
            .rev()
        {
            let gap = smallest_ack
                .checked_sub(span.end)
                .and_then(|delta| delta.checked_sub(2))
                .expect("ack spans must be ordered and disjoint");

            ack_ranges.push(AckRange {
                gap,
                ack_range_length: span.end - span.start,
            });

            smallest_ack = span.start;
        }

        Some(Ack {
            channel_id: channel_id.to_vec(),
            largest_acknowledged: newest.end,
            ack_delay: 0,
            first_ack_range: newest.end - newest.start,
            ack_ranges,
            ecn_counts: None,
        })
    }

    /// Marks the currently pending `MC_ACK` state as sent.
    pub fn mark_sent(&mut self) {
        self.pending = false;
    }

    fn trim_history(&mut self) {
        let Some(largest) = self.ranges.last().map(|range| range.end) else {
            return;
        };
        self.retired_before = self.retired_before.max(
            largest.saturating_sub(ACK_HISTORY_PACKET_WINDOW.saturating_sub(1)),
        );
        self.ranges.retain(|range| range.end >= self.retired_before);
        if let Some(first) = self.ranges.first_mut() {
            first.start = first.start.max(self.retired_before);
        }

        if self.ranges.len() > MAX_TRACKED_ACK_RANGES {
            let remove = self.ranges.len() - MAX_TRACKED_ACK_RANGES;
            self.ranges.drain(..remove);
            if let Some(first) = self.ranges.first() {
                self.retired_before = self.retired_before.max(first.start);
            }
        }
    }
}

fn summarize_ack(
    ack: &Ack, next_packet_number: u64,
) -> Result<ChannelSendAckSummary> {
    if ack.largest_acknowledged >= next_packet_number {
        return Err(Error::InvalidAckRange);
    }

    let spans = ack_spans(ack)?;
    let acked_packets = spans.iter().try_fold(0_u64, |total, span| {
        total
            .checked_add(span.end - span.start + 1)
            .ok_or(Error::InvalidAckRange)
    })?;

    let smallest_acknowledged = spans
        .last()
        .map(|span| span.start)
        .ok_or(Error::InvalidAckRange)?;

    Ok(ChannelSendAckSummary {
        ack_blocks: spans.len() as u64,
        acked_packets,
        largest_acknowledged: ack.largest_acknowledged,
        smallest_acknowledged,
    })
}

pub(crate) fn ack_spans(ack: &Ack) -> Result<Vec<AckSpan>> {
    let first_start = ack
        .largest_acknowledged
        .checked_sub(ack.first_ack_range)
        .ok_or(Error::InvalidAckRange)?;
    let mut spans = Vec::with_capacity(ack.ack_ranges.len() + 1);
    spans.push(AckSpan {
        start: first_start,
        end: ack.largest_acknowledged,
    });

    let mut previous_smallest = first_start;

    for range in &ack.ack_ranges {
        let largest = previous_smallest
            .checked_sub(range.gap)
            .and_then(|value| value.checked_sub(2))
            .ok_or(Error::InvalidAckRange)?;
        let start = largest
            .checked_sub(range.ack_range_length)
            .ok_or(Error::InvalidAckRange)?;

        spans.push(AckSpan {
            start,
            end: largest,
        });
        previous_smallest = start;
    }

    Ok(spans)
}

/// Local resource and work limits for one multicast channel receiver.
///
/// These limits are independent from draft-defined wire and packet-number
/// limits. Exceeding a local retention limit fails the channel decoder closed;
/// required metadata is never evicted to make room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelReceiveLimits {
    /// Maximum encrypted packets retained while waiting for metadata.
    pub max_pending_packets: usize,

    /// Maximum encrypted packet bytes retained while waiting for metadata.
    pub max_pending_packet_bytes: usize,

    /// Maximum integrity hash entries, including entries awaiting processing.
    pub max_pending_integrity_entries: usize,

    /// Maximum integrity bytes retained while processing and indexing hashes.
    pub max_pending_integrity_bytes: usize,

    /// Maximum accepted distance above the receiver's packet-number anchor.
    pub max_future_packet_number_distance: u64,

    /// Maximum simultaneously retained payload-key generations.
    pub max_key_generations: usize,

    /// Age after supersession at which an old key is normally deleted.
    pub old_key_delete_after: Duration,

    /// Idle time after supersession at which an old key is deleted.
    pub old_key_idle_timeout: Duration,

    /// Unconditional maximum retention after a key is superseded.
    ///
    /// Draft-08 requires this value to be no greater than 60 seconds.
    pub old_key_max_retention: Duration,

    /// Maximum indexed operations performed by one public input call.
    pub max_work_per_call: usize,

    /// Maximum packet or error events returned by one public input call.
    pub max_events_per_call: usize,
}

impl Default for ChannelReceiveLimits {
    fn default() -> Self {
        Self {
            max_pending_packets: 4096,
            max_pending_packet_bytes: 8 * 1024 * 1024,
            max_pending_integrity_entries: 8192,
            max_pending_integrity_bytes: 1024 * 1024,
            max_future_packet_number_distance: 1024 * 1024,
            max_key_generations: 8,
            old_key_delete_after: Duration::from_secs(10),
            old_key_idle_timeout: Duration::from_secs(3),
            old_key_max_retention: DRAFT_OLD_KEY_MAX_RETENTION,
            max_work_per_call: 256,
            max_events_per_call: 128,
        }
    }
}

impl ChannelReceiveLimits {
    fn validate(self) -> Result<Self> {
        if self.max_pending_packets == 0 ||
            self.max_pending_packet_bytes == 0 ||
            self.max_pending_integrity_entries == 0 ||
            self.max_pending_integrity_bytes == 0 ||
            self.max_future_packet_number_distance == 0 ||
            self.max_key_generations == 0 ||
            self.old_key_delete_after.is_zero() ||
            self.old_key_idle_timeout.is_zero() ||
            self.old_key_max_retention.is_zero() ||
            self.old_key_max_retention > DRAFT_OLD_KEY_MAX_RETENTION ||
            self.max_work_per_call == 0 ||
            self.max_events_per_call == 0
        {
            return Err(Error::InvalidState);
        }

        Ok(self)
    }
}

/// Terminal fail-closed outcome for a multicast channel receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelReceiveFailure {
    /// The pending encrypted-packet item limit was exceeded.
    PendingPacketCount,

    /// The pending encrypted-packet byte limit was exceeded.
    PendingPacketBytes,

    /// The pending integrity-entry limit was exceeded.
    PendingIntegrityEntries,

    /// The pending integrity byte limit was exceeded.
    PendingIntegrityBytes,

    /// A packet number exceeded the configured future-distance limit.
    FuturePacketNumber,

    /// The retained key-generation limit was exceeded before expiry.
    KeyGenerations,

    /// Authenticated control supplied different hashes for one packet number.
    ConflictingIntegrity,
}

impl ChannelReceiveFailure {
    fn error(self) -> Error {
        match self {
            Self::ConflictingIntegrity => Error::InvalidFrame,
            _ => Error::InvalidState,
        }
    }
}

/// An outcome emitted by [`ChannelReceiveState`] when a packet becomes ready.
#[derive(Debug)]
pub enum ChannelReceiveEvent<M> {
    /// A multicast packet was fully validated and decoded.
    Packet {
        /// The decoded multicast packet.
        packet: ChannelPacket,

        /// Caller-supplied metadata attached to the received datagram.
        metadata: M,
    },

    /// A received datagram could be associated with the channel but could not
    /// be validated or decoded.
    Error {
        /// The decoding failure.
        error: Error,

        /// Caller-supplied metadata attached to the received datagram.
        metadata: M,
    },
}

/// Bounded receive maintenance completed by one caller-provided work budget.
#[derive(Debug)]
pub struct ChannelReceiveWorkBatch<M> {
    /// Packet or failure events released by this maintenance call.
    pub events: Vec<ChannelReceiveEvent<M>>,

    /// Aggregate work units consumed from the caller's budget.
    pub work_performed: usize,
}

/// Receive-side state for a multicast channel's encrypted 1-RTT packets.
///
/// This tracks the immutable channel properties from [`Announce`], any
/// received [`Key`] and [`Integrity`] metadata, and encrypted datagrams that
/// are waiting on either of those before they can be released.
///
/// Packet buffering is intentionally owned by the caller. Accepted packet
/// history is retained for a bounded packet-number window so duplicate
/// suppression and late integrity processing cannot grow for the lifetime of
/// a channel.
///
/// The `M` type parameter allows callers to attach arbitrary metadata to each
/// received datagram and receive it back once the packet is decoded, or when
/// the buffered datagram ultimately fails validation.
///
/// [`recv()`]: Self::recv
pub struct ChannelReceiveState<M = ()> {
    announce: Announce,
    header_open: crypto::Open,
    integrity_hash: IntegrityHashAlgorithm,
    limits: ChannelReceiveLimits,
    keys: Vec<ChannelKey>,
    integrity_packets: BTreeMap<u64, Vec<u8>>,
    pending_integrity_inputs: VecDeque<PendingIntegrityInput>,
    pending_integrity_input_entries: usize,
    pending_integrity_entries: usize,
    pending_integrity_bytes: usize,
    pending_packets: BTreeMap<u64, PendingChannelPacket<M>>,
    pending_packet_bytes: usize,
    waiting_for_integrity_packets: usize,
    waiting_for_key_packets: [BTreeSet<u64>; 2],
    key_readiness_scans: VecDeque<KeyReadinessScan>,
    ready_packets: VecDeque<ReadyPacket>,
    ready_packet_numbers: BTreeSet<u64>,
    accepted_packets: BTreeSet<u64>,
    trusted_packet_number_frontier: Option<u64>,
    retired_before: u64,
    prune_pending: bool,
    work_cursor: u8,
    terminal_failure: Option<ChannelReceiveFailure>,
    highest_expired_key_sequence: Option<u64>,
    metrics: ChannelReceiveMetricsState,
}

impl<M> ChannelReceiveState<M> {
    /// Creates receive-side state for the announced channel.
    ///
    /// The current implementation supports the QUIC v1 TLS cipher suite values
    /// `0x1301`, `0x1302`, and `0x1303`, and the named-information hash IDs
    /// `1..=8`. Other algorithm identifiers are reserved for future work.
    pub fn new(announce: Announce) -> Result<Self> {
        Self::with_limits(announce, ChannelReceiveLimits::default())
    }

    /// Creates receive-side state with explicit local resource limits.
    pub fn with_limits(
        announce: Announce, limits: ChannelReceiveLimits,
    ) -> Result<Self> {
        announce.validate()?;
        let limits = limits.validate()?;
        let integrity_hash =
            IntegrityHashAlgorithm::from_id(announce.integrity_hash_algorithm)?;
        let header_open = build_header_open(&announce)?;

        Ok(Self {
            header_open,
            integrity_hash,
            limits,
            announce,
            keys: Vec::new(),
            integrity_packets: BTreeMap::new(),
            pending_integrity_inputs: VecDeque::new(),
            pending_integrity_input_entries: 0,
            pending_integrity_entries: 0,
            pending_integrity_bytes: 0,
            pending_packets: BTreeMap::new(),
            pending_packet_bytes: 0,
            waiting_for_integrity_packets: 0,
            waiting_for_key_packets: [BTreeSet::new(), BTreeSet::new()],
            key_readiness_scans: VecDeque::new(),
            ready_packets: VecDeque::new(),
            ready_packet_numbers: BTreeSet::new(),
            accepted_packets: BTreeSet::new(),
            trusted_packet_number_frontier: None,
            retired_before: 0,
            prune_pending: false,
            work_cursor: 0,
            terminal_failure: None,
            highest_expired_key_sequence: None,
            metrics: ChannelReceiveMetricsState::default(),
        })
    }

    /// Returns the announced channel properties used by this receiver.
    pub fn announce(&self) -> &Announce {
        &self.announce
    }

    /// Returns a snapshot of the receiver's current metrics.
    pub fn metrics_snapshot(&self) -> ChannelReceiveMetricsSnapshot {
        self.metrics.snapshot(self)
    }

    /// Returns the terminal local failure, if this decoder failed closed.
    pub fn terminal_failure(&self) -> Option<ChannelReceiveFailure> {
        self.terminal_failure
    }

    /// Returns whether bounded continuation work remains.
    pub fn has_pending_work(&self) -> bool {
        !self.pending_integrity_inputs.is_empty() ||
            !self.key_readiness_scans.is_empty() ||
            !self.ready_packets.is_empty() ||
            self.prune_pending
    }

    /// Performs another bounded unit of deferred receive work.
    ///
    /// Callers should schedule another invocation while
    /// [`has_pending_work()`](Self::has_pending_work) remains true.
    pub fn continue_processing(&mut self) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.continue_processing_at(Instant::now())
    }

    fn continue_processing_at(
        &mut self, now: Instant,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.ensure_active()?;
        self.expire_old_keys_at(now);
        self.drain_work(now)
    }

    /// Returns the next old-key deletion deadline.
    pub fn next_key_expiry(&self) -> Option<Instant> {
        self.keys
            .iter()
            .filter_map(|key| key.expiry_deadline(self.limits))
            .min()
    }

    /// Deletes old key generations whose draft-08 deadline has elapsed.
    pub fn expire_keys(&mut self) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.expire_keys_at(Instant::now())
    }

    /// Performs key expiry and deferred receive work within caller bounds.
    ///
    /// One work unit covers one bounded channel-maintenance attempt and at
    /// most one indexed readiness operation. This lets an outer scheduler
    /// share a single budget fairly across multiple channels.
    pub fn maintain_with_budget(
        &mut self, max_work: usize, max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        if max_work == 0 || max_events == 0 {
            return Err(Error::InvalidState);
        }

        let now = Instant::now();
        self.ensure_active()?;
        self.expire_old_keys_at(now);
        let (events, work_performed) =
            self.drain_work_with_budget(now, max_work, max_events)?;

        Ok(ChannelReceiveWorkBatch {
            events,
            work_performed: work_performed.max(1),
        })
    }

    fn expire_keys_at(
        &mut self, now: Instant,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.ensure_active()?;
        self.expire_old_keys_at(now);
        self.drain_work(now)
    }

    /// Updates the receiver with a retransmitted `MC_ANNOUNCE`.
    ///
    /// Since the draft treats channel properties as immutable for a channel's
    /// lifetime, any announce that differs from the current one is rejected.
    pub fn update_announce(&mut self, mut announce: Announce) -> Result<()> {
        announce.validate()?;
        self.ensure_active()?;

        if self.announce.channel_id != announce.channel_id {
            announce.header_secret.fill(0);
            return Err(Error::InvalidState);
        }

        if self.announce != announce {
            announce.header_secret.fill(0);
            return Err(Error::InvalidState);
        }

        announce.header_secret.fill(0);
        Ok(())
    }

    /// Stores a new `MC_KEY` frame and releases any buffered packets that can
    /// now be decrypted and validated.
    pub fn insert_key(
        &mut self, key: Key,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.insert_key_at(key, Instant::now())
    }

    /// Stores a new `MC_KEY` within one caller-provided aggregate work budget.
    ///
    /// Admitting the key consumes one work unit. Any remaining units are used
    /// for indexed readiness work, and at most `max_events` packet events are
    /// released. Callers should continue maintenance while
    /// [`has_pending_work()`](Self::has_pending_work) remains true.
    pub fn insert_key_with_budget(
        &mut self, key: Key, max_work: usize, max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        self.insert_key_with_budget_at(key, Instant::now(), max_work, max_events)
    }

    fn insert_key_at(
        &mut self, mut key: Key, now: Instant,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        let max_work = self.limits.max_work_per_call;
        let max_events = self.limits.max_events_per_call;
        let result = self
            .insert_key_ref_with_budget_at(&key, now, max_work, max_events)
            .map(|batch| batch.events);
        key.secret.fill(0);
        result
    }

    fn insert_key_with_budget_at(
        &mut self, mut key: Key, now: Instant, max_work: usize, max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        let result =
            self.insert_key_ref_with_budget_at(&key, now, max_work, max_events);
        key.secret.fill(0);
        result
    }

    fn insert_key_ref_with_budget_at(
        &mut self, key: &Key, now: Instant, max_work: usize, max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        Self::validate_admission_budget(max_work, max_events)?;
        key.validate()?;
        self.ensure_active()?;

        if key.channel_id != self.announce.channel_id {
            return Err(Error::InvalidState);
        }

        self.expire_old_keys_at(now);

        if self
            .highest_expired_key_sequence
            .is_some_and(|sequence| key.key_sequence <= sequence)
        {
            self.metrics.keys_received =
                self.metrics.keys_received.saturating_add(1);
            self.metrics.duplicate_keys =
                self.metrics.duplicate_keys.saturating_add(1);
            return self.finish_admission(now, max_work, max_events);
        }

        if let Some(existing) = self
            .keys
            .iter()
            .find(|existing| existing.key_sequence == key.key_sequence)
        {
            if existing.from_packet_number != key.from_packet_number ||
                existing.secret != key.secret
            {
                return Err(Error::InvalidFrame);
            }

            self.metrics.keys_received =
                self.metrics.keys_received.saturating_add(1);
            self.metrics.duplicate_keys =
                self.metrics.duplicate_keys.saturating_add(1);
            return self.finish_admission(now, max_work, max_events);
        }

        if self.keys.iter().any(|existing| {
            (key.key_sequence > existing.key_sequence &&
                key.from_packet_number < existing.from_packet_number) ||
                (key.key_sequence < existing.key_sequence &&
                    key.from_packet_number > existing.from_packet_number)
        }) {
            return Err(Error::InvalidFrame);
        }

        if self.keys.len() >= self.limits.max_key_generations {
            return Err(self.fail(ChannelReceiveFailure::KeyGenerations));
        }

        // Derive all fallible backend state before advancing packet-number or
        // key-lifecycle state.
        let open = build_packet_open(&self.announce, key)?;

        self.advance_trusted_packet_number_range(
            key.from_packet_number,
            key.from_packet_number,
        )?;

        let superseded_at = self
            .keys
            .iter()
            .filter(|existing| existing.key_sequence > key.key_sequence)
            .map(|existing| existing.received_at)
            .min();

        for existing in self
            .keys
            .iter_mut()
            .filter(|existing| existing.key_sequence < key.key_sequence)
        {
            let superseded_at =
                existing.superseded_at.map_or(now, |at| at.min(now));
            existing.superseded_at = Some(superseded_at);
            existing.last_used_at = existing.last_used_at.max(superseded_at);
        }

        self.keys.push(ChannelKey {
            key_sequence: key.key_sequence,
            key_phase: key.key_sequence % 2 == 1,
            from_packet_number: key.from_packet_number,
            secret: key.secret.clone(),
            open,
            received_at: now,
            superseded_at,
            last_used_at: superseded_at.unwrap_or(now),
        });
        self.metrics.keys_received = self.metrics.keys_received.saturating_add(1);

        self.keys
            .sort_by_key(|key| (key.from_packet_number, key.key_sequence));
        self.key_readiness_scans.push_back(KeyReadinessScan {
            key_phase: key.key_sequence % 2 == 1,
            from_packet_number: key.from_packet_number,
        });
        self.expire_old_keys_at(now);

        self.finish_admission(now, max_work, max_events)
    }

    /// Stores packet hashes from an `MC_INTEGRITY` frame and releases any
    /// buffered packets that now have matching integrity metadata.
    ///
    /// Counted integrity frames must carry exactly `packet_hash_count` hashes
    /// of the announced algorithm's output length. Uncounted frames infer that
    /// count from the payload length and are rejected if the length is not an
    /// exact multiple.
    pub fn insert_integrity(
        &mut self, integrity: Integrity,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.insert_integrity_at(integrity, Instant::now())
    }

    /// Stores `MC_INTEGRITY` metadata within an aggregate work budget.
    ///
    /// Admitting the integrity frame consumes one work unit. Remaining units
    /// incrementally index hashes and release ready packets.
    pub fn insert_integrity_with_budget(
        &mut self, integrity: Integrity, max_work: usize, max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        self.insert_integrity_with_budget_at(
            integrity,
            Instant::now(),
            max_work,
            max_events,
        )
    }

    fn insert_integrity_at(
        &mut self, integrity: Integrity, now: Instant,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        let max_work = self.limits.max_work_per_call;
        let max_events = self.limits.max_events_per_call;
        self.insert_integrity_with_budget_at(integrity, now, max_work, max_events)
            .map(|batch| batch.events)
    }

    fn insert_integrity_with_budget_at(
        &mut self, integrity: Integrity, now: Instant, max_work: usize,
        max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        Self::validate_admission_budget(max_work, max_events)?;
        integrity.validate()?;

        if integrity.channel_id != self.announce.channel_id {
            return Err(Error::InvalidState);
        }

        let hash_len = self.integrity_hash.output_len();
        let hash_count = integrity.packet_hash_count.unwrap_or_else(|| {
            u64::try_from(integrity.packet_hashes.len() / hash_len)
                .unwrap_or(u64::MAX)
        });

        let expected_len = hash_count
            .checked_mul(hash_len as u64)
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(Error::InvalidFrame)?;

        if expected_len != integrity.packet_hashes.len() {
            return Err(Error::InvalidFrame);
        }

        let hash_count =
            usize::try_from(hash_count).map_err(|_| Error::InvalidFrame)?;

        let last_packet_number = if hash_count > 0 {
            Some(
                integrity
                    .packet_number_start
                    .checked_add((hash_count - 1) as u64)
                    .filter(|packet_number| *packet_number <= MAX_VARINT)
                    .ok_or(Error::InvalidFrame)?,
            )
        } else {
            None
        };

        self.ensure_active()?;
        self.expire_old_keys_at(now);
        self.metrics.integrity_frames_received =
            self.metrics.integrity_frames_received.saturating_add(1);

        if let Some(last_packet_number) = last_packet_number {
            self.advance_trusted_packet_number_range(
                integrity.packet_number_start,
                last_packet_number,
            )?;
        }

        let retained_entries = self
            .pending_integrity_entries
            .checked_add(hash_count)
            .ok_or_else(|| {
                self.fail(ChannelReceiveFailure::PendingIntegrityEntries)
            })?;
        if retained_entries > self.limits.max_pending_integrity_entries {
            return Err(self.fail(ChannelReceiveFailure::PendingIntegrityEntries));
        }

        // Hashes are copied into the searchable index incrementally. Reserve
        // both the input frame and the worst-case indexed representation so a
        // bounded work call can never transiently exceed the byte limit.
        let retained_bytes = integrity
            .packet_hashes
            .len()
            .checked_mul(2)
            .and_then(|bytes| self.pending_integrity_bytes.checked_add(bytes))
            .ok_or_else(|| {
                self.fail(ChannelReceiveFailure::PendingIntegrityBytes)
            })?;
        if retained_bytes > self.limits.max_pending_integrity_bytes {
            return Err(self.fail(ChannelReceiveFailure::PendingIntegrityBytes));
        }

        self.metrics.integrity_hashes_received = self
            .metrics
            .integrity_hashes_received
            .saturating_add(hash_count as u64);

        if hash_count == 0 {
            return self.finish_admission(now, max_work, max_events);
        }

        self.pending_integrity_entries = retained_entries;
        self.pending_integrity_input_entries += hash_count;
        self.pending_integrity_bytes = self
            .pending_integrity_bytes
            .saturating_add(integrity.packet_hashes.len());
        self.pending_integrity_inputs
            .push_back(PendingIntegrityInput {
                packet_number_start: integrity.packet_number_start,
                packet_hashes: integrity.packet_hashes,
                hash_count,
                next_index: 0,
            });

        self.finish_admission(now, max_work, max_events)
    }

    /// Feeds a received encrypted multicast datagram into the channel state.
    ///
    /// If the datagram has the required `MC_KEY` and `MC_INTEGRITY` metadata
    /// available, it is decoded immediately. Otherwise it is buffered until
    /// those prerequisites arrive in later control frames.
    ///
    /// Successfully decoded packet numbers are retained in a bounded window
    /// for duplicate suppression.
    pub fn recv(
        &mut self, buf: &[u8], metadata: M,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.recv_buf_at(Bytes::copy_from_slice(buf), metadata, Instant::now())
    }

    /// Feeds a copied encrypted datagram within an aggregate work budget.
    ///
    /// Datagram admission consumes one work unit. Remaining units perform
    /// indexed receive work and release at most `max_events` events.
    pub fn recv_with_budget(
        &mut self, buf: &[u8], metadata: M, max_work: usize, max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        self.recv_buf_with_budget(
            Bytes::copy_from_slice(buf),
            metadata,
            max_work,
            max_events,
        )
    }

    /// Feeds an owned encrypted multicast datagram into the channel state.
    ///
    /// This is equivalent to [`recv()`](Self::recv), but transfers an existing
    /// [`Bytes`] allocation when the datagram needs to be retained.
    pub fn recv_buf(
        &mut self, buf: Bytes, metadata: M,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.recv_buf_at(buf, metadata, Instant::now())
    }

    /// Feeds an owned encrypted datagram within an aggregate work budget.
    ///
    /// This is the owned-buffer variant of
    /// [`recv_with_budget()`](Self::recv_with_budget).
    pub fn recv_buf_with_budget(
        &mut self, buf: Bytes, metadata: M, max_work: usize, max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        self.recv_buf_with_budget_at(
            buf,
            metadata,
            Instant::now(),
            max_work,
            max_events,
        )
    }

    fn recv_buf_at(
        &mut self, buf: Bytes, metadata: M, now: Instant,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        let max_work = self.limits.max_work_per_call;
        let max_events = self.limits.max_events_per_call;
        self.recv_buf_with_budget_at(buf, metadata, now, max_work, max_events)
            .map(|batch| batch.events)
    }

    fn recv_buf_with_budget_at(
        &mut self, buf: Bytes, metadata: M, now: Instant, max_work: usize,
        max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        Self::validate_admission_budget(max_work, max_events)?;
        self.ensure_active()?;
        self.expire_old_keys_at(now);
        self.metrics.recv_calls = self.metrics.recv_calls.saturating_add(1);
        self.metrics.recv_bytes =
            self.metrics.recv_bytes.saturating_add(buf.len() as u64);
        let packet = match self.parse_packet_metadata(&buf) {
            Ok(packet) => packet,

            Err(error) => {
                self.metrics.record_error(error);
                self.record_admission_work(1);
                return Ok(ChannelReceiveWorkBatch {
                    events: vec![ChannelReceiveEvent::Error { error, metadata }],
                    work_performed: 1,
                });
            },
        };

        self.validate_provisional_packet_number(packet.packet_number)?;

        if packet.packet_number < self.retired_before {
            self.metrics.duplicate_packets =
                self.metrics.duplicate_packets.saturating_add(1);
            return self.finish_admission(now, max_work, max_events);
        }

        if self.accepted_packets.contains(&packet.packet_number) ||
            self.pending_packets.contains_key(&packet.packet_number)
        {
            self.metrics.duplicate_packets =
                self.metrics.duplicate_packets.saturating_add(1);
            return self.finish_admission(now, max_work, max_events);
        }

        if self.pending_packets.len() >= self.limits.max_pending_packets {
            return Err(self.fail(ChannelReceiveFailure::PendingPacketCount));
        }

        let pending_packet_bytes = self
            .pending_packet_bytes
            .checked_add(buf.len())
            .ok_or_else(|| {
                self.fail(ChannelReceiveFailure::PendingPacketBytes)
            })?;
        if pending_packet_bytes > self.limits.max_pending_packet_bytes {
            return Err(self.fail(ChannelReceiveFailure::PendingPacketBytes));
        }

        let readiness =
            if !self.integrity_packets.contains_key(&packet.packet_number) {
                PacketReadiness::Integrity
            } else if self
                .select_key_index(packet.packet_number, packet.key_phase)
                .is_none()
            {
                PacketReadiness::Key
            } else {
                PacketReadiness::Ready
            };

        self.metrics.packets_buffered =
            self.metrics.packets_buffered.saturating_add(1);
        self.pending_packet_bytes = pending_packet_bytes;
        self.pending_packets
            .insert(packet.packet_number, PendingChannelPacket {
                buf,
                key_phase: packet.key_phase,
                readiness,
                metadata,
            });

        match readiness {
            PacketReadiness::Integrity => {
                self.waiting_for_integrity_packets += 1;
            },

            PacketReadiness::Key => {
                self.waiting_for_key_packets[usize::from(packet.key_phase)]
                    .insert(packet.packet_number);
            },

            PacketReadiness::Ready => {
                self.queue_ready(packet.packet_number, ReleaseTrigger::Recv);
            },
        }

        self.finish_admission(now, max_work, max_events)
    }

    fn validate_admission_budget(
        max_work: usize, max_events: usize,
    ) -> Result<()> {
        if max_work == 0 || max_events == 0 {
            return Err(Error::InvalidState);
        }

        Ok(())
    }

    fn finish_admission(
        &mut self, now: Instant, max_work: usize, max_events: usize,
    ) -> Result<ChannelReceiveWorkBatch<M>> {
        let (events, deferred_work) = if max_work > 1 {
            self.drain_work_with_budget(now, max_work - 1, max_events)?
        } else {
            (Vec::new(), 0)
        };
        let work_performed = deferred_work.saturating_add(1);
        self.record_admission_work(work_performed);

        Ok(ChannelReceiveWorkBatch {
            events,
            work_performed,
        })
    }

    fn record_admission_work(&mut self, work_performed: usize) {
        self.metrics.work_performed =
            self.metrics.work_performed.saturating_add(1);
        self.metrics.max_work_per_call =
            self.metrics.max_work_per_call.max(work_performed as u64);
    }

    fn drain_work(
        &mut self, now: Instant,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.drain_work_with_budget(
            now,
            self.limits.max_work_per_call,
            self.limits.max_events_per_call,
        )
        .map(|(events, _)| events)
    }

    fn drain_work_with_budget(
        &mut self, now: Instant, max_work: usize, max_events: usize,
    ) -> Result<(Vec<ChannelReceiveEvent<M>>, usize)> {
        self.ensure_active()?;
        let mut events = Vec::new();
        let mut work = 0;

        while work < max_work && events.len() < max_events {
            let Some(event) = self.process_one_work(now)? else {
                break;
            };

            work += 1;
            if let Some(event) = event {
                events.push(event);
            }
        }

        self.metrics.work_performed =
            self.metrics.work_performed.saturating_add(work as u64);
        self.metrics.max_work_per_call =
            self.metrics.max_work_per_call.max(work as u64);
        self.metrics.events_emitted = self
            .metrics
            .events_emitted
            .saturating_add(events.len() as u64);
        self.metrics.max_events_per_call =
            self.metrics.max_events_per_call.max(events.len() as u64);

        Ok((events, work))
    }

    fn process_one_work(
        &mut self, now: Instant,
    ) -> Result<Option<Option<ChannelReceiveEvent<M>>>> {
        const WORK_KINDS: u8 = 4;

        for _ in 0..WORK_KINDS {
            let work_kind = self.work_cursor;
            self.work_cursor = (self.work_cursor + 1) % WORK_KINDS;

            let event = match work_kind {
                0 => self.process_one_integrity_hash()?.map(|()| None),
                1 => self.process_one_key_candidate().map(|()| None),
                2 => self.process_one_ready_packet(now)?,
                3 => self.process_one_pruned_packet(),
                _ => unreachable!(),
            };

            if event.is_some() {
                return Ok(event);
            }
        }

        Ok(None)
    }

    fn process_one_integrity_hash(&mut self) -> Result<Option<()>> {
        let Some(mut input) = self.pending_integrity_inputs.pop_front() else {
            return Ok(None);
        };

        let index = input.next_index;
        let packet_number = input
            .packet_number_start
            .checked_add(index as u64)
            .ok_or(Error::InvalidFrame)?;
        let hash_len = self.integrity_hash.output_len();
        let start = index.checked_mul(hash_len).ok_or(Error::InvalidFrame)?;
        let end = start.checked_add(hash_len).ok_or(Error::InvalidFrame)?;
        let packet_hash = input.packet_hashes[start..end].to_vec();

        input.next_index += 1;
        self.pending_integrity_input_entries =
            self.pending_integrity_input_entries.saturating_sub(1);
        self.pending_integrity_entries =
            self.pending_integrity_entries.saturating_sub(1);

        if input.next_index < input.hash_count {
            self.pending_integrity_inputs.push_front(input);
        } else {
            self.pending_integrity_bytes = self
                .pending_integrity_bytes
                .saturating_sub(input.packet_hashes.len());
        }

        if packet_number < self.retired_before {
            return Ok(Some(()));
        }

        if let Some(existing) = self.integrity_packets.get(&packet_number) {
            if existing != &packet_hash {
                return Err(
                    self.fail(ChannelReceiveFailure::ConflictingIntegrity)
                );
            }

            self.metrics.integrity_hash_overwrites =
                self.metrics.integrity_hash_overwrites.saturating_add(1);
            return Ok(Some(()));
        }

        self.pending_integrity_entries += 1;
        self.pending_integrity_bytes += packet_hash.len();
        self.integrity_packets.insert(packet_number, packet_hash);

        if self
            .pending_packets
            .get(&packet_number)
            .is_some_and(|pending| {
                pending.readiness == PacketReadiness::Integrity
            })
        {
            self.waiting_for_integrity_packets =
                self.waiting_for_integrity_packets.saturating_sub(1);

            let key_phase = self.pending_packets[&packet_number].key_phase;
            if self.select_key_index(packet_number, key_phase).is_some() {
                self.pending_packets
                    .get_mut(&packet_number)
                    .expect("pending packet exists")
                    .readiness = PacketReadiness::Ready;
                self.queue_ready(packet_number, ReleaseTrigger::Integrity);
            } else {
                self.pending_packets
                    .get_mut(&packet_number)
                    .expect("pending packet exists")
                    .readiness = PacketReadiness::Key;
                self.waiting_for_key_packets[usize::from(key_phase)]
                    .insert(packet_number);
            }
        }

        Ok(Some(()))
    }

    fn process_one_key_candidate(&mut self) -> Option<()> {
        let scan = self.key_readiness_scans.front().copied()?;
        let phase_index = usize::from(scan.key_phase);
        let packet_number = self.waiting_for_key_packets[phase_index]
            .range(scan.from_packet_number..)
            .next()
            .copied();

        let Some(packet_number) = packet_number else {
            self.key_readiness_scans.pop_front();
            return Some(());
        };

        self.waiting_for_key_packets[phase_index].remove(&packet_number);
        if self
            .pending_packets
            .get(&packet_number)
            .is_some_and(|pending| pending.readiness == PacketReadiness::Key) &&
            self.select_key_index(packet_number, scan.key_phase)
                .is_some()
        {
            self.pending_packets
                .get_mut(&packet_number)
                .expect("pending packet exists")
                .readiness = PacketReadiness::Ready;
            self.queue_ready(packet_number, ReleaseTrigger::Key);
        }

        Some(())
    }

    fn process_one_ready_packet(
        &mut self, now: Instant,
    ) -> Result<Option<Option<ChannelReceiveEvent<M>>>> {
        let Some(ready) = self.ready_packets.pop_front() else {
            return Ok(None);
        };

        if !self.ready_packet_numbers.remove(&ready.packet_number) {
            return Ok(Some(None));
        }

        self.try_release_packet(ready.packet_number, ready.trigger, now)
            .map(Some)
    }

    fn process_one_pruned_packet(
        &mut self,
    ) -> Option<Option<ChannelReceiveEvent<M>>> {
        if !self.prune_pending {
            return None;
        }

        let packet_number = [
            self.accepted_packets.first().copied(),
            self.integrity_packets.first_key_value().map(|(pn, _)| *pn),
            self.pending_packets.first_key_value().map(|(pn, _)| *pn),
        ]
        .into_iter()
        .flatten()
        .filter(|packet_number| *packet_number < self.retired_before)
        .min();

        let Some(packet_number) = packet_number else {
            self.prune_pending = false;
            return Some(None);
        };

        self.accepted_packets.remove(&packet_number);
        self.remove_integrity(packet_number);

        Some(self.remove_pending(packet_number).map(|pending| {
            ChannelReceiveEvent::Error {
                error: Error::InvalidState,
                metadata: pending.metadata,
            }
        }))
    }

    fn try_release_packet(
        &mut self, packet_number: u64, trigger: ReleaseTrigger, now: Instant,
    ) -> Result<Option<ChannelReceiveEvent<M>>> {
        if packet_number < self.retired_before {
            let pending = self.remove_pending(packet_number);
            self.remove_integrity(packet_number);
            return Ok(pending.map(|pending| ChannelReceiveEvent::Error {
                error: Error::InvalidState,
                metadata: pending.metadata,
            }));
        }

        let Some(key_phase) = self
            .pending_packets
            .get(&packet_number)
            .map(|pending| pending.key_phase)
        else {
            return Ok(None);
        };

        let Some(key_index) = self.select_key_index(packet_number, key_phase)
        else {
            if let Some(pending) = self.pending_packets.get_mut(&packet_number) {
                pending.readiness = PacketReadiness::Key;
                self.waiting_for_key_packets[usize::from(key_phase)]
                    .insert(packet_number);
            }
            return Ok(None);
        };

        let packet_hash = self
            .integrity_packets
            .get(&packet_number)
            .cloned()
            .expect("checked above");
        let actual_hash = self.integrity_hash.hash(
            &self
                .pending_packets
                .get(&packet_number)
                .expect("pending packet exists")
                .buf,
        );

        if actual_hash != packet_hash {
            let pending =
                self.remove_pending(packet_number).expect("packet exists");
            self.remove_integrity(packet_number);
            self.metrics.integrity_mismatch_errors =
                self.metrics.integrity_mismatch_errors.saturating_add(1);

            return Ok(Some(ChannelReceiveEvent::Error {
                error: Error::CryptoFail,
                metadata: pending.metadata,
            }));
        }

        let pending = self.remove_pending(packet_number).expect("packet exists");

        let packet = match self.decrypt_packet(
            &pending.buf,
            packet_number,
            &self.keys[key_index],
        ) {
            Ok(packet) => packet,

            Err(error) => {
                self.remove_integrity(packet_number);
                self.metrics.record_error(error);
                return Ok(Some(ChannelReceiveEvent::Error {
                    error,
                    metadata: pending.metadata,
                }));
            },
        };

        self.keys[key_index].last_used_at = now;
        self.advance_trusted_packet_number_range(packet_number, packet_number)?;
        self.accepted_packets.insert(packet_number);
        self.remove_integrity(packet_number);
        self.prune_receive_history();
        self.metrics.packets_delivered =
            self.metrics.packets_delivered.saturating_add(1);
        self.metrics.record_release_success(trigger);

        Ok(Some(ChannelReceiveEvent::Packet {
            packet,
            metadata: pending.metadata,
        }))
    }

    fn prune_receive_history(&mut self) {
        let Some(largest) = self.accepted_packets.last().copied() else {
            return;
        };
        self.retired_before = self.retired_before.max(
            largest.saturating_sub(ACK_HISTORY_PACKET_WINDOW.saturating_sub(1)),
        );
        if self.retired_before == 0 {
            return;
        }

        while self.accepted_packets.len() > ACK_HISTORY_PACKET_WINDOW as usize {
            let Some(packet_number) = self.accepted_packets.first().copied()
            else {
                break;
            };
            self.accepted_packets.remove(&packet_number);
        }

        self.prune_pending = true;
    }

    fn select_key_index(
        &self, packet_number: u64, key_phase: bool,
    ) -> Option<usize> {
        self.keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.from_packet_number <= packet_number)
            .max_by_key(|(_, key)| (key.from_packet_number, key.key_sequence))
            .filter(|(_, key)| key.key_phase == key_phase)
            .map(|(index, _)| index)
    }

    fn expire_old_keys_at(&mut self, now: Instant) {
        let highest_expired_sequence = self
            .keys
            .iter()
            .filter(|key| {
                key.expiry_deadline(self.limits)
                    .is_some_and(|deadline| deadline <= now)
            })
            .map(|key| key.key_sequence)
            .max();
        let Some(highest_expired_sequence) = highest_expired_sequence else {
            return;
        };

        let successor_from_packet_number = self
            .keys
            .iter()
            .filter(|key| key.key_sequence > highest_expired_sequence)
            .min_by_key(|key| key.key_sequence)
            .map(|key| key.from_packet_number);
        let before = self.keys.len();
        self.keys
            .retain(|key| key.key_sequence > highest_expired_sequence);
        let expired = before.saturating_sub(self.keys.len());

        self.highest_expired_key_sequence = Some(
            self.highest_expired_key_sequence
                .unwrap_or(highest_expired_sequence)
                .max(highest_expired_sequence),
        );
        self.metrics.keys_expired =
            self.metrics.keys_expired.saturating_add(expired as u64);

        if let Some(packet_number) = successor_from_packet_number {
            self.retired_before = self.retired_before.max(packet_number);
            self.prune_pending = true;
        }

        self.key_readiness_scans.clear();
        self.key_readiness_scans.extend(self.keys.iter().map(|key| {
            KeyReadinessScan {
                key_phase: key.key_phase,
                from_packet_number: key.from_packet_number,
            }
        }));
    }

    fn queue_ready(&mut self, packet_number: u64, trigger: ReleaseTrigger) {
        if self.ready_packet_numbers.insert(packet_number) {
            self.ready_packets.push_back(ReadyPacket {
                packet_number,
                trigger,
            });
        }
    }

    fn remove_integrity(&mut self, packet_number: u64) {
        let Some(hash) = self.integrity_packets.remove(&packet_number) else {
            return;
        };

        self.pending_integrity_entries =
            self.pending_integrity_entries.saturating_sub(1);
        self.pending_integrity_bytes =
            self.pending_integrity_bytes.saturating_sub(hash.len());
    }

    fn remove_pending(
        &mut self, packet_number: u64,
    ) -> Option<PendingChannelPacket<M>> {
        let pending = self.pending_packets.remove(&packet_number)?;
        self.pending_packet_bytes =
            self.pending_packet_bytes.saturating_sub(pending.buf.len());

        match pending.readiness {
            PacketReadiness::Integrity => {
                self.waiting_for_integrity_packets =
                    self.waiting_for_integrity_packets.saturating_sub(1);
            },

            PacketReadiness::Key => {
                self.waiting_for_key_packets[usize::from(pending.key_phase)]
                    .remove(&packet_number);
            },

            PacketReadiness::Ready => {
                self.ready_packet_numbers.remove(&packet_number);
            },
        }

        Some(pending)
    }

    fn validate_provisional_packet_number(
        &mut self, packet_number: u64,
    ) -> Result<()> {
        if packet_number > MAX_VARINT {
            return Err(Error::InvalidFrame);
        }

        let frontier = self.trusted_packet_number_frontier.unwrap_or(0);
        let maximum = frontier
            .saturating_add(self.limits.max_future_packet_number_distance)
            .min(MAX_VARINT);
        if packet_number > maximum {
            return Err(self.fail(ChannelReceiveFailure::FuturePacketNumber));
        }

        Ok(())
    }

    fn advance_trusted_packet_number_range(
        &mut self, start: u64, end: u64,
    ) -> Result<()> {
        if start > end || end > MAX_VARINT {
            return Err(Error::InvalidFrame);
        }

        if let Some(frontier) = self.trusted_packet_number_frontier {
            let maximum = frontier
                .saturating_add(self.limits.max_future_packet_number_distance)
                .min(MAX_VARINT);
            if end > maximum {
                return Err(self.fail(ChannelReceiveFailure::FuturePacketNumber));
            }
        }

        self.trusted_packet_number_frontier = Some(
            self.trusted_packet_number_frontier
                .unwrap_or(start)
                .max(end),
        );
        Ok(())
    }

    fn ensure_active(&self) -> Result<()> {
        match self.terminal_failure {
            Some(failure) => Err(failure.error()),
            None => Ok(()),
        }
    }

    fn fail(&mut self, failure: ChannelReceiveFailure) -> Error {
        if self.terminal_failure.is_none() {
            self.terminal_failure = Some(failure);
            self.metrics.resource_failures =
                self.metrics.resource_failures.saturating_add(1);
            self.announce.header_secret.fill(0);
            self.keys.clear();
            self.integrity_packets.clear();
            self.pending_integrity_inputs.clear();
            self.pending_integrity_input_entries = 0;
            self.pending_integrity_entries = 0;
            self.pending_integrity_bytes = 0;
            self.pending_packets.clear();
            self.pending_packet_bytes = 0;
            self.waiting_for_integrity_packets = 0;
            self.waiting_for_key_packets
                .iter_mut()
                .for_each(BTreeSet::clear);
            self.key_readiness_scans.clear();
            self.ready_packets.clear();
            self.ready_packet_numbers.clear();
            self.accepted_packets.clear();
            self.prune_pending = false;
        }

        failure.error()
    }

    fn parse_packet_metadata(&self, buf: &[u8]) -> Result<ParsedChannelPacket> {
        let mut pkt = buf.to_vec();
        let mut b = octets::OctetsMut::with_slice(&mut pkt);

        let mut hdr =
            packet::Header::from_bytes(&mut b, self.announce.channel_id.len())?;

        if hdr.ty != packet::Type::Short {
            return Err(Error::InvalidPacket);
        }

        if hdr.dcid.as_ref() != self.announce.channel_id.as_slice() {
            return Err(Error::InvalidPacket);
        }

        packet::decrypt_hdr(&mut b, &mut hdr, &self.header_open)?;

        let packet_number = packet::decode_pkt_num(
            self.trusted_packet_number_frontier.unwrap_or(0),
            hdr.pkt_num,
            hdr.pkt_num_len,
        );

        Ok(ParsedChannelPacket {
            packet_number,
            key_phase: hdr.key_phase,
        })
    }

    fn decrypt_packet(
        &self, buf: &[u8], packet_number: u64, key: &ChannelKey,
    ) -> Result<ChannelPacket> {
        let mut pkt = buf.to_vec();
        let mut b = octets::OctetsMut::with_slice(&mut pkt);

        let mut hdr =
            packet::Header::from_bytes(&mut b, self.announce.channel_id.len())?;

        if hdr.ty != packet::Type::Short {
            return Err(Error::InvalidPacket);
        }

        if hdr.dcid.as_ref() != self.announce.channel_id.as_slice() {
            return Err(Error::InvalidPacket);
        }

        let payload_len = b.cap();

        packet::decrypt_hdr(&mut b, &mut hdr, &self.header_open)?;

        let mut payload = packet::decrypt_pkt(
            &mut b,
            packet_number,
            hdr.pkt_num_len,
            payload_len,
            &key.open,
        )?;

        if payload.cap() == 0 {
            return Err(Error::InvalidPacket);
        }

        let mut frames = Vec::new();

        while payload.cap() > 0 {
            let frame =
                frame::Frame::from_bytes(&mut payload, packet::Type::Short)?;
            frames.push(self.decode_channel_frame(frame)?);
        }

        Ok(ChannelPacket {
            channel_id: self.announce.channel_id.clone(),
            packet_number,
            key_sequence: key.key_sequence,
            key_phase: hdr.key_phase,
            frames,
        })
    }

    fn decode_channel_frame(&self, frame: frame::Frame) -> Result<ChannelFrame> {
        match frame {
            frame::Frame::Padding { len } => Ok(ChannelFrame::Padding { len }),

            frame::Frame::Ping { .. } => Ok(ChannelFrame::Ping),

            frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                validate_channel_stream_id(stream_id)?;

                Ok(ChannelFrame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                })
            },

            frame::Frame::ResetStreamAt {
                stream_id,
                error_code,
                final_size,
                reliable_size,
            } => {
                validate_channel_stream_id(stream_id)?;

                Ok(ChannelFrame::ResetStreamAt {
                    stream_id,
                    error_code,
                    final_size,
                    reliable_size,
                })
            },

            frame::Frame::Stream { stream_id, data } => {
                validate_channel_stream_id(stream_id)?;

                Ok(ChannelFrame::Stream {
                    stream_id,
                    offset: data.off(),
                    fin: data.fin(),
                    data: data.as_ref().to_vec(),
                })
            },

            frame::Frame::Datagram { data } =>
                Ok(ChannelFrame::Datagram { data }),

            frame::Frame::Multicast(Frame::Key(frame)) =>
                Ok(ChannelFrame::Multicast(Frame::Key(frame))),

            frame::Frame::Multicast(Frame::Leave(frame)) =>
                Ok(ChannelFrame::Multicast(Frame::Leave(frame))),

            frame::Frame::Multicast(Frame::Integrity(frame)) => {
                if frame.channel_id == self.announce.channel_id {
                    return Err(Error::InvalidFrame);
                }

                Ok(ChannelFrame::Multicast(Frame::Integrity(frame)))
            },

            frame::Frame::Multicast(Frame::Retire(frame)) =>
                Ok(ChannelFrame::Multicast(Frame::Retire(frame))),

            _ => Err(Error::InvalidFrame),
        }
    }
}

impl<M> Drop for ChannelReceiveState<M> {
    fn drop(&mut self) {
        self.announce.header_secret.fill(0);
    }
}

#[derive(Debug)]
struct ParsedChannelPacket {
    packet_number: u64,
    key_phase: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PacketReadiness {
    Integrity,
    Key,
    Ready,
}

#[derive(Debug)]
struct PendingChannelPacket<M> {
    buf: Bytes,
    key_phase: bool,
    readiness: PacketReadiness,
    metadata: M,
}

#[derive(Debug)]
struct PendingIntegrityInput {
    packet_number_start: u64,
    packet_hashes: Vec<u8>,
    hash_count: usize,
    next_index: usize,
}

#[derive(Clone, Copy, Debug)]
struct KeyReadinessScan {
    key_phase: bool,
    from_packet_number: u64,
}

#[derive(Clone, Copy, Debug)]
struct ReadyPacket {
    packet_number: u64,
    trigger: ReleaseTrigger,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ChannelSendMetricsState {
    write_calls: u64,
    packets_encoded: u64,
    bytes_encoded: u64,
    frames_encoded: u64,
    key_updates: u64,
    encode_errors: u64,
    ack_frames_processed: u64,
    ack_blocks_processed: u64,
    acked_packets_reported: u64,
    ack_errors: u64,
    largest_acknowledged: Option<u64>,
    last_packet_number: Option<u64>,
}

impl ChannelSendMetricsState {
    fn snapshot(self, next_packet_number: u64) -> ChannelSendMetricsSnapshot {
        ChannelSendMetricsSnapshot {
            write_calls: self.write_calls,
            packets_encoded: self.packets_encoded,
            bytes_encoded: self.bytes_encoded,
            frames_encoded: self.frames_encoded,
            key_updates: self.key_updates,
            encode_errors: self.encode_errors,
            ack_frames_processed: self.ack_frames_processed,
            ack_blocks_processed: self.ack_blocks_processed,
            acked_packets_reported: self.acked_packets_reported,
            ack_errors: self.ack_errors,
            largest_acknowledged: self.largest_acknowledged,
            last_packet_number: self.last_packet_number,
            next_packet_number,
        }
    }
}

/// A point-in-time snapshot of multicast channel receive metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelReceiveMetricsSnapshot {
    /// Total datagrams fed into [`ChannelReceiveState::recv()`].
    pub recv_calls: u64,

    /// Total encrypted bytes fed into [`ChannelReceiveState::recv()`].
    pub recv_bytes: u64,

    /// Total unique packets buffered while waiting on metadata or keys.
    pub packets_buffered: u64,

    /// Total duplicate packet numbers ignored by the receiver.
    pub duplicate_packets: u64,

    /// Total multicast packets delivered successfully.
    pub packets_delivered: u64,

    /// Total packets delivered immediately during
    /// [`ChannelReceiveState::recv()`].
    pub packets_released_on_recv: u64,

    /// Total packets released after a matching `MC_KEY`.
    pub packets_released_on_key: u64,

    /// Total packets released after matching `MC_INTEGRITY`.
    pub packets_released_on_integrity: u64,

    /// Total `MC_KEY` frames processed.
    pub keys_received: u64,

    /// Total duplicate `MC_KEY` frames accepted as retransmissions.
    pub duplicate_keys: u64,

    /// Total old key generations deleted after supersession.
    pub keys_expired: u64,

    /// Total `MC_INTEGRITY` frames processed.
    pub integrity_frames_received: u64,

    /// Total packet hashes learned from `MC_INTEGRITY`.
    pub integrity_hashes_received: u64,

    /// Total hash entries overwritten by later `MC_INTEGRITY` frames.
    pub integrity_hash_overwrites: u64,

    /// Total integrity hash mismatches detected before decryption.
    pub integrity_mismatch_errors: u64,

    /// Total decryption failures after integrity validation.
    pub decrypt_errors: u64,

    /// Total invalid short-header or packet-format errors.
    pub invalid_packet_errors: u64,

    /// Total invalid frame decode errors after decryption.
    pub invalid_frame_errors: u64,

    /// Current number of installed payload-protection keys.
    pub active_keys: usize,

    /// Current number of buffered integrity hash entries.
    pub buffered_integrity_entries: usize,

    /// Current number of buffered encrypted packets.
    pub pending_packets: usize,

    /// Current encrypted packet bytes retained by the receiver.
    pub pending_packet_bytes: usize,

    /// Current integrity entries retained in input or indexed form.
    pub pending_integrity_entries: usize,

    /// Current integrity bytes retained in input or indexed form.
    pub pending_integrity_bytes: usize,

    /// Current number of accepted packet numbers tracked by the receiver.
    pub accepted_packets: usize,

    /// Current number of buffered packets waiting on a key.
    pub waiting_for_key_packets: usize,

    /// Current number of buffered packets waiting on integrity.
    pub waiting_for_integrity_packets: usize,

    /// The largest packet number observed so far.
    pub largest_observed_packet_number: u64,

    /// Current number of bounded continuation queue entries.
    pub continuation_queue_entries: usize,

    /// Total indexed work units performed.
    pub work_performed: u64,

    /// Largest number of work units performed by one public call.
    pub max_work_per_call: u64,

    /// Total packet or error events returned to the caller.
    pub events_emitted: u64,

    /// Largest number of events returned by one public call.
    pub max_events_per_call: u64,

    /// Total terminal local resource or consistency failures.
    pub resource_failures: u64,

    /// Terminal fail-closed outcome, when present.
    pub terminal_failure: Option<ChannelReceiveFailure>,
}

/// The difference between two receive metrics snapshots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelReceiveMetricsDelta {
    /// Change in [`ChannelReceiveMetricsSnapshot::recv_calls`].
    pub recv_calls: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::recv_bytes`].
    pub recv_bytes: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::packets_buffered`].
    pub packets_buffered: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::duplicate_packets`].
    pub duplicate_packets: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::packets_delivered`].
    pub packets_delivered: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::packets_released_on_recv`].
    pub packets_released_on_recv: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::packets_released_on_key`].
    pub packets_released_on_key: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::packets_released_on_integrity`].
    pub packets_released_on_integrity: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::keys_received`].
    pub keys_received: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::duplicate_keys`].
    pub duplicate_keys: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::keys_expired`].
    pub keys_expired: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::integrity_frames_received`].
    pub integrity_frames_received: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::integrity_hashes_received`].
    pub integrity_hashes_received: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::integrity_hash_overwrites`].
    pub integrity_hash_overwrites: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::integrity_mismatch_errors`].
    pub integrity_mismatch_errors: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::decrypt_errors`].
    pub decrypt_errors: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::invalid_packet_errors`].
    pub invalid_packet_errors: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::invalid_frame_errors`].
    pub invalid_frame_errors: u64,

    /// Current number of installed payload-protection keys.
    pub active_keys: usize,

    /// Current number of buffered integrity hash entries.
    pub buffered_integrity_entries: usize,

    /// Current number of buffered encrypted packets.
    pub pending_packets: usize,

    /// Current encrypted packet bytes retained by the receiver.
    pub pending_packet_bytes: usize,

    /// Current integrity entries retained in input or indexed form.
    pub pending_integrity_entries: usize,

    /// Current integrity bytes retained in input or indexed form.
    pub pending_integrity_bytes: usize,

    /// Current number of accepted packet numbers tracked by the receiver.
    pub accepted_packets: usize,

    /// Current number of buffered packets waiting on a key.
    pub waiting_for_key_packets: usize,

    /// Current number of buffered packets waiting on integrity.
    pub waiting_for_integrity_packets: usize,

    /// The largest packet number observed at the end of the interval.
    pub largest_observed_packet_number: u64,

    /// Current number of bounded continuation queue entries.
    pub continuation_queue_entries: usize,

    /// Change in [`ChannelReceiveMetricsSnapshot::work_performed`].
    pub work_performed: u64,

    /// Largest observed work count at the end of the interval.
    pub max_work_per_call: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::events_emitted`].
    pub events_emitted: u64,

    /// Largest observed event count at the end of the interval.
    pub max_events_per_call: u64,

    /// Change in [`ChannelReceiveMetricsSnapshot::resource_failures`].
    pub resource_failures: u64,

    /// Terminal fail-closed outcome at the end of the interval.
    pub terminal_failure: Option<ChannelReceiveFailure>,
}

impl ChannelReceiveMetricsDelta {
    /// Computes the delta between two receive metrics snapshots.
    pub fn between(
        before: ChannelReceiveMetricsSnapshot,
        after: ChannelReceiveMetricsSnapshot,
    ) -> Self {
        Self {
            recv_calls: after.recv_calls.saturating_sub(before.recv_calls),
            recv_bytes: after.recv_bytes.saturating_sub(before.recv_bytes),
            packets_buffered: after
                .packets_buffered
                .saturating_sub(before.packets_buffered),
            duplicate_packets: after
                .duplicate_packets
                .saturating_sub(before.duplicate_packets),
            packets_delivered: after
                .packets_delivered
                .saturating_sub(before.packets_delivered),
            packets_released_on_recv: after
                .packets_released_on_recv
                .saturating_sub(before.packets_released_on_recv),
            packets_released_on_key: after
                .packets_released_on_key
                .saturating_sub(before.packets_released_on_key),
            packets_released_on_integrity: after
                .packets_released_on_integrity
                .saturating_sub(before.packets_released_on_integrity),
            keys_received: after
                .keys_received
                .saturating_sub(before.keys_received),
            duplicate_keys: after
                .duplicate_keys
                .saturating_sub(before.duplicate_keys),
            keys_expired: after.keys_expired.saturating_sub(before.keys_expired),
            integrity_frames_received: after
                .integrity_frames_received
                .saturating_sub(before.integrity_frames_received),
            integrity_hashes_received: after
                .integrity_hashes_received
                .saturating_sub(before.integrity_hashes_received),
            integrity_hash_overwrites: after
                .integrity_hash_overwrites
                .saturating_sub(before.integrity_hash_overwrites),
            integrity_mismatch_errors: after
                .integrity_mismatch_errors
                .saturating_sub(before.integrity_mismatch_errors),
            decrypt_errors: after
                .decrypt_errors
                .saturating_sub(before.decrypt_errors),
            invalid_packet_errors: after
                .invalid_packet_errors
                .saturating_sub(before.invalid_packet_errors),
            invalid_frame_errors: after
                .invalid_frame_errors
                .saturating_sub(before.invalid_frame_errors),
            active_keys: after.active_keys,
            buffered_integrity_entries: after.buffered_integrity_entries,
            pending_packets: after.pending_packets,
            pending_packet_bytes: after.pending_packet_bytes,
            pending_integrity_entries: after.pending_integrity_entries,
            pending_integrity_bytes: after.pending_integrity_bytes,
            accepted_packets: after.accepted_packets,
            waiting_for_key_packets: after.waiting_for_key_packets,
            waiting_for_integrity_packets: after.waiting_for_integrity_packets,
            largest_observed_packet_number: after.largest_observed_packet_number,
            continuation_queue_entries: after.continuation_queue_entries,
            work_performed: after
                .work_performed
                .saturating_sub(before.work_performed),
            max_work_per_call: after.max_work_per_call,
            events_emitted: after
                .events_emitted
                .saturating_sub(before.events_emitted),
            max_events_per_call: after.max_events_per_call,
            resource_failures: after
                .resource_failures
                .saturating_sub(before.resource_failures),
            terminal_failure: after.terminal_failure,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ChannelReceiveMetricsState {
    recv_calls: u64,
    recv_bytes: u64,
    packets_buffered: u64,
    duplicate_packets: u64,
    packets_delivered: u64,
    packets_released_on_recv: u64,
    packets_released_on_key: u64,
    packets_released_on_integrity: u64,
    keys_received: u64,
    duplicate_keys: u64,
    keys_expired: u64,
    integrity_frames_received: u64,
    integrity_hashes_received: u64,
    integrity_hash_overwrites: u64,
    integrity_mismatch_errors: u64,
    decrypt_errors: u64,
    invalid_packet_errors: u64,
    invalid_frame_errors: u64,
    work_performed: u64,
    max_work_per_call: u64,
    events_emitted: u64,
    max_events_per_call: u64,
    resource_failures: u64,
}

impl ChannelReceiveMetricsState {
    fn record_error(&mut self, error: Error) {
        match error {
            Error::InvalidPacket => {
                self.invalid_packet_errors =
                    self.invalid_packet_errors.saturating_add(1);
            },

            Error::InvalidFrame => {
                self.invalid_frame_errors =
                    self.invalid_frame_errors.saturating_add(1);
            },

            Error::CryptoFail => {
                self.decrypt_errors = self.decrypt_errors.saturating_add(1);
            },

            _ => (),
        }
    }

    fn record_release_success(&mut self, trigger: ReleaseTrigger) {
        match trigger {
            ReleaseTrigger::Recv => {
                self.packets_released_on_recv =
                    self.packets_released_on_recv.saturating_add(1);
            },

            ReleaseTrigger::Key => {
                self.packets_released_on_key =
                    self.packets_released_on_key.saturating_add(1);
            },

            ReleaseTrigger::Integrity => {
                self.packets_released_on_integrity =
                    self.packets_released_on_integrity.saturating_add(1);
            },
        }
    }

    fn snapshot<M>(
        self, state: &ChannelReceiveState<M>,
    ) -> ChannelReceiveMetricsSnapshot {
        ChannelReceiveMetricsSnapshot {
            recv_calls: self.recv_calls,
            recv_bytes: self.recv_bytes,
            packets_buffered: self.packets_buffered,
            duplicate_packets: self.duplicate_packets,
            packets_delivered: self.packets_delivered,
            packets_released_on_recv: self.packets_released_on_recv,
            packets_released_on_key: self.packets_released_on_key,
            packets_released_on_integrity: self.packets_released_on_integrity,
            keys_received: self.keys_received,
            duplicate_keys: self.duplicate_keys,
            keys_expired: self.keys_expired,
            integrity_frames_received: self.integrity_frames_received,
            integrity_hashes_received: self.integrity_hashes_received,
            integrity_hash_overwrites: self.integrity_hash_overwrites,
            integrity_mismatch_errors: self.integrity_mismatch_errors,
            decrypt_errors: self.decrypt_errors,
            invalid_packet_errors: self.invalid_packet_errors,
            invalid_frame_errors: self.invalid_frame_errors,
            active_keys: state.keys.len(),
            buffered_integrity_entries: state.integrity_packets.len(),
            pending_packets: state.pending_packets.len(),
            pending_packet_bytes: state.pending_packet_bytes,
            pending_integrity_entries: state.pending_integrity_entries,
            pending_integrity_bytes: state.pending_integrity_bytes,
            accepted_packets: state.accepted_packets.len(),
            waiting_for_key_packets: state
                .waiting_for_key_packets
                .iter()
                .map(BTreeSet::len)
                .sum(),
            waiting_for_integrity_packets: state.waiting_for_integrity_packets,
            largest_observed_packet_number: state
                .trusted_packet_number_frontier
                .unwrap_or(0),
            continuation_queue_entries: state
                .pending_integrity_input_entries
                .saturating_add(state.key_readiness_scans.len())
                .saturating_add(state.ready_packet_numbers.len())
                .saturating_add(usize::from(state.prune_pending)),
            work_performed: self.work_performed,
            max_work_per_call: self.max_work_per_call,
            events_emitted: self.events_emitted,
            max_events_per_call: self.max_events_per_call,
            resource_failures: self.resource_failures,
            terminal_failure: state.terminal_failure,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReleaseTrigger {
    Recv,
    Key,
    Integrity,
}

struct ChannelKey {
    key_sequence: u64,
    key_phase: bool,
    from_packet_number: u64,
    secret: Vec<u8>,
    open: crypto::Open,
    received_at: Instant,
    superseded_at: Option<Instant>,
    last_used_at: Instant,
}

impl ChannelKey {
    fn expiry_deadline(&self, limits: ChannelReceiveLimits) -> Option<Instant> {
        let superseded_at = self.superseded_at?;
        let age_deadline =
            superseded_at.checked_add(limits.old_key_delete_after)?;
        let idle_deadline =
            self.last_used_at.checked_add(limits.old_key_idle_timeout)?;
        let maximum_deadline =
            superseded_at.checked_add(limits.old_key_max_retention)?;

        Some(age_deadline.min(idle_deadline).min(maximum_deadline))
    }
}

impl Drop for ChannelKey {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

#[derive(Clone, Copy, Debug)]
enum IntegrityHashAlgorithm {
    Sha256(usize),
    Sha384(usize),
    Sha512(usize),
}

impl IntegrityHashAlgorithm {
    fn from_id(id: u16) -> Result<Self> {
        match id {
            1 => Ok(IntegrityHashAlgorithm::Sha256(32)),
            2 => Ok(IntegrityHashAlgorithm::Sha256(16)),
            3 => Ok(IntegrityHashAlgorithm::Sha256(15)),
            4 => Ok(IntegrityHashAlgorithm::Sha256(12)),
            5 => Ok(IntegrityHashAlgorithm::Sha256(8)),
            6 => Ok(IntegrityHashAlgorithm::Sha256(4)),
            7 => Ok(IntegrityHashAlgorithm::Sha384(48)),
            8 => Ok(IntegrityHashAlgorithm::Sha512(64)),
            _ => Err(Error::InvalidState),
        }
    }

    fn output_len(self) -> usize {
        match self {
            IntegrityHashAlgorithm::Sha256(len) |
            IntegrityHashAlgorithm::Sha384(len) |
            IntegrityHashAlgorithm::Sha512(len) => len,
        }
    }

    fn hash(self, payload: &[u8]) -> Vec<u8> {
        let full = match self {
            IntegrityHashAlgorithm::Sha256(_) =>
                digest::digest(&digest::SHA256, payload),

            IntegrityHashAlgorithm::Sha384(_) =>
                digest::digest(&digest::SHA384, payload),

            IntegrityHashAlgorithm::Sha512(_) =>
                digest::digest(&digest::SHA512, payload),
        };

        full.as_ref()[..self.output_len()].to_vec()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sender {
    Client,
    Server,
}

#[derive(Default)]
pub(crate) struct BoundedQueue<T> {
    queue: VecDeque<T>,
    queue_max_len: usize,
}

impl<T> BoundedQueue<T> {
    pub(crate) fn new(queue_max_len: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            queue_max_len,
        }
    }

    pub(crate) fn push(&mut self, item: T) -> Result<()> {
        if self.is_full() {
            return Err(Error::Done);
        }

        self.queue.push_back(item);

        Ok(())
    }

    pub(crate) fn push_drop_oldest(&mut self, item: T) -> Result<()> {
        if self.is_full() {
            self.queue.pop_front();
        }

        self.push(item)
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    pub(crate) fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.queue.len() == self.queue_max_len
    }

    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }
}

/// A bounded, reliable handoff queue for received multicast control frames.
///
/// Exact retransmissions can share one queued occurrence. Distinct frames are
/// never evicted because QUIC might already have acknowledged their packet by
/// the time the application notices the loss.
#[derive(Default)]
pub(crate) struct ControlFrameQueue {
    queue: VecDeque<Frame>,
    queue_max_len: usize,
}

impl ControlFrameQueue {
    pub(crate) fn new(queue_max_len: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            queue_max_len,
        }
    }

    pub(crate) fn push(&mut self, frame: Frame) -> Result<()> {
        if self.queue.iter().any(|queued| queued == &frame) {
            return Ok(());
        }

        if self.queue.len() >= self.queue_max_len {
            return Err(Error::Done);
        }

        self.queue.push_back(frame);

        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<Frame> {
        self.queue.pop_front()
    }

    pub(crate) fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }
}

/// Bounded reliable control-frame send handoff.
pub(crate) struct ControlSendQueue {
    frames: VecDeque<QueuedControlFrame>,
    reliable: BTreeMap<u64, ReliableControlFrame>,
    reliable_by_fingerprint: HashMap<u64, Vec<u64>>,
    next_reliable_id: u64,
    max_frames: usize,
    max_bytes: usize,
    retained_bytes: usize,
}

enum QueuedControlFrame {
    Reliable(u64),
    Unreliable { frame: Frame, encoded_len: usize },
}

struct ReliableControlFrame {
    frame: Frame,
    encoded_len: usize,
    queued: bool,
    in_flight_copies: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ControlSendQueueError {
    Full(Frame),
    Oversized(Frame),
    Invalid(Frame),
}

impl ControlSendQueue {
    pub(crate) fn new(max_frames: usize, max_bytes: usize) -> Self {
        Self {
            frames: VecDeque::new(),
            reliable: BTreeMap::new(),
            reliable_by_fingerprint: HashMap::new(),
            next_reliable_id: 0,
            max_frames,
            max_bytes,
            retained_bytes: 0,
        }
    }

    pub(crate) fn push_back(
        &mut self, frame: Frame,
    ) -> std::result::Result<(), ControlSendQueueError> {
        self.push(frame, false)
    }

    fn push(
        &mut self, frame: Frame, front: bool,
    ) -> std::result::Result<(), ControlSendQueueError> {
        let frame_bytes = match frame.encoded_len() {
            Ok(frame_bytes) => frame_bytes,
            Err(_) => return Err(ControlSendQueueError::Invalid(frame)),
        };
        if frame_bytes > self.max_bytes || self.max_frames == 0 {
            return Err(ControlSendQueueError::Oversized(frame));
        }

        if frame.retransmit_on_loss() && self.find_reliable_id(&frame).is_some() {
            return Ok(());
        }

        let Some(retained_bytes) = self.retained_bytes.checked_add(frame_bytes)
        else {
            return Err(ControlSendQueueError::Full(frame));
        };

        if self.accounted_len() >= self.max_frames ||
            retained_bytes > self.max_bytes
        {
            return Err(ControlSendQueueError::Full(frame));
        }

        let queued = if frame.retransmit_on_loss() {
            let Some(next_reliable_id) = self.next_reliable_id.checked_add(1)
            else {
                return Err(ControlSendQueueError::Full(frame));
            };
            let id = self.next_reliable_id;
            self.next_reliable_id = next_reliable_id;
            self.reliable.insert(id, ReliableControlFrame {
                frame,
                encoded_len: frame_bytes,
                queued: true,
                in_flight_copies: 0,
            });
            self.reliable_by_fingerprint
                .entry(control_frame_fingerprint(
                    &self
                        .reliable
                        .get(&id)
                        .expect("inserted reliable reservation exists")
                        .frame,
                ))
                .or_default()
                .push(id);
            QueuedControlFrame::Reliable(id)
        } else {
            QueuedControlFrame::Unreliable {
                frame,
                encoded_len: frame_bytes,
            }
        };

        if front {
            self.frames.push_front(queued);
        } else {
            self.frames.push_back(queued);
        }
        self.retained_bytes = retained_bytes;
        Ok(())
    }

    pub(crate) fn front(&self) -> Option<&Frame> {
        match self.frames.front()? {
            QueuedControlFrame::Reliable(id) =>
                self.reliable.get(id).map(|reservation| &reservation.frame),

            QueuedControlFrame::Unreliable { frame, .. } => Some(frame),
        }
    }

    pub(crate) fn pop_front_for_send(&mut self) -> Option<Frame> {
        match self.frames.pop_front()? {
            QueuedControlFrame::Reliable(id) => {
                let reservation = self
                    .reliable
                    .get_mut(&id)
                    .expect("queued reliable control reservation exists");
                reservation.queued = false;
                reservation.in_flight_copies =
                    reservation.in_flight_copies.saturating_add(1);
                Some(reservation.frame.clone())
            },

            QueuedControlFrame::Unreliable { frame, encoded_len } => {
                self.retained_bytes =
                    self.retained_bytes.saturating_sub(encoded_len);
                Some(frame)
            },
        }
    }

    pub(crate) fn release_acked(&mut self, frame: &Frame) {
        if !frame.retransmit_on_loss() {
            return;
        }

        let Some(id) = self.find_reliable_id(frame) else {
            return;
        };
        let reservation = self
            .reliable
            .remove(&id)
            .expect("matched reliable control reservation exists");
        self.remove_reliable_fingerprint(id, &reservation.frame);
        if reservation.queued {
            self.frames.retain(
                |queued| !matches!(queued, QueuedControlFrame::Reliable(queued_id) if *queued_id == id),
            );
        }
        self.retained_bytes =
            self.retained_bytes.saturating_sub(reservation.encoded_len);
    }

    pub(crate) fn requeue_lost(&mut self, frame: Frame) {
        debug_assert!(frame.retransmit_on_loss());

        let Some(id) = self.find_reliable_id(&frame) else {
            return;
        };
        let reservation = self
            .reliable
            .get_mut(&id)
            .expect("matched reliable control reservation exists");
        reservation.in_flight_copies =
            reservation.in_flight_copies.saturating_sub(1);
        if !reservation.queued {
            reservation.queued = true;
            self.frames.push_front(QueuedControlFrame::Reliable(id));
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.frames.len()
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    fn accounted_len(&self) -> usize {
        self.reliable.len().saturating_add(
            self.frames
                .iter()
                .filter(|frame| {
                    matches!(frame, QueuedControlFrame::Unreliable { .. })
                })
                .count(),
        )
    }

    fn find_reliable_id(&self, frame: &Frame) -> Option<u64> {
        self.reliable_by_fingerprint
            .get(&control_frame_fingerprint(frame))?
            .iter()
            .copied()
            .find(|id| {
                self.reliable
                    .get(id)
                    .is_some_and(|reservation| reservation.frame == *frame)
            })
    }

    fn remove_reliable_fingerprint(&mut self, id: u64, frame: &Frame) {
        let fingerprint = control_frame_fingerprint(frame);
        let mut remove_bucket = false;
        if let Some(ids) = self.reliable_by_fingerprint.get_mut(&fingerprint) {
            ids.retain(|candidate| *candidate != id);
            remove_bucket = ids.is_empty();
        }
        if remove_bucket {
            self.reliable_by_fingerprint.remove(&fingerprint);
        }
    }

    #[cfg(test)]
    pub(crate) fn in_flight_len(&self) -> usize {
        self.reliable.values().fold(0, |total, reservation| {
            total.saturating_add(reservation.in_flight_copies)
        })
    }

    #[cfg(test)]
    pub(crate) fn in_flight_retained_bytes(&self) -> usize {
        self.reliable.values().fold(0, |total, reservation| {
            total.saturating_add(
                reservation
                    .encoded_len
                    .saturating_mul(reservation.in_flight_copies),
            )
        })
    }
}

fn control_frame_fingerprint(frame: &Frame) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    frame.hash(&mut hasher);
    hasher.finish()
}

pub(crate) type ProbeEventQueue = BoundedQueue<ProbeEvent>;
pub(crate) type ChannelDatagramQueue = BoundedQueue<ChannelDatagram>;

pub(crate) fn is_frame_type(ty: u64) -> bool {
    matches!(
        ty,
        FRAME_TYPE_KEY |
            FRAME_TYPE_JOIN |
            FRAME_TYPE_LEAVE |
            FRAME_TYPE_INTEGRITY |
            FRAME_TYPE_INTEGRITY_WITH_LENGTH |
            FRAME_TYPE_ACK |
            FRAME_TYPE_ACK_ECN |
            FRAME_TYPE_LIMITS |
            FRAME_TYPE_RETIRE |
            FRAME_TYPE_STATE |
            FRAME_TYPE_STATE_APPLICATION |
            FRAME_TYPE_ANNOUNCE_V4 |
            FRAME_TYPE_ANNOUNCE_V6
    )
}

fn checked_varint_len(value: u64, invalid: Error) -> Result<usize> {
    if value > MAX_VARINT {
        return Err(invalid);
    }

    Ok(octets::varint_len(value))
}

fn checked_collection_varint_len(len: usize, invalid: Error) -> Result<usize> {
    let len = u64::try_from(len).map_err(|_| invalid)?;
    checked_varint_len(len, invalid)
}

fn checked_len_add(left: usize, right: usize, invalid: Error) -> Result<usize> {
    left.checked_add(right).ok_or(invalid)
}

fn checked_len_sum(
    lengths: impl IntoIterator<Item = usize>, invalid: Error,
) -> Result<usize> {
    lengths
        .into_iter()
        .try_fold(0, |total, len| checked_len_add(total, len, invalid))
}

fn channel_id_encoded_len(channel_id: &[u8]) -> Result<usize> {
    validate_channel_id(channel_id)?;
    checked_len_add(1, channel_id.len(), Error::InvalidFrame)
}

fn announce_encoded_len(frame: &Announce) -> Result<usize> {
    let invalid = Error::InvalidFrame;
    announce_frame_type(frame)?;

    checked_len_sum(
        [
            checked_varint_len(
                match frame.source {
                    IpAddr::V4(_) => FRAME_TYPE_ANNOUNCE_V4,
                    IpAddr::V6(_) => FRAME_TYPE_ANNOUNCE_V6,
                },
                invalid,
            )?,
            channel_id_encoded_len(&frame.channel_id)?,
            ip_addr_len(&frame.source),
            ip_addr_len(&frame.group),
            2,
            2,
            checked_collection_varint_len(frame.header_secret.len(), invalid)?,
            frame.header_secret.len(),
            2,
            2,
            checked_varint_len(frame.max_rate_kibps, invalid)?,
            checked_varint_len(frame.max_ack_delay_ms, invalid)?,
        ],
        invalid,
    )
}

fn key_encoded_len(frame: &Key) -> Result<usize> {
    let invalid = Error::InvalidFrame;
    checked_len_sum(
        [
            checked_varint_len(FRAME_TYPE_KEY, invalid)?,
            channel_id_encoded_len(&frame.channel_id)?,
            checked_varint_len(frame.key_sequence, invalid)?,
            checked_varint_len(frame.from_packet_number, invalid)?,
            checked_collection_varint_len(frame.secret.len(), invalid)?,
            frame.secret.len(),
        ],
        invalid,
    )
}

fn join_encoded_len(frame: &Join) -> Result<usize> {
    let invalid = Error::InvalidFrame;
    checked_len_sum(
        [
            checked_varint_len(FRAME_TYPE_JOIN, invalid)?,
            channel_id_encoded_len(&frame.channel_id)?,
            checked_varint_len(frame.mc_limits_sequence, invalid)?,
            checked_varint_len(frame.mc_state_sequence, invalid)?,
            checked_varint_len(frame.mc_key_sequence, invalid)?,
        ],
        invalid,
    )
}

fn integrity_encoded_len(frame: &Integrity) -> Result<usize> {
    let invalid = Error::InvalidFrame;
    checked_len_sum(
        [
            checked_varint_len(
                if frame.packet_hash_count.is_some() {
                    FRAME_TYPE_INTEGRITY_WITH_LENGTH
                } else {
                    FRAME_TYPE_INTEGRITY
                },
                invalid,
            )?,
            channel_id_encoded_len(&frame.channel_id)?,
            checked_varint_len(frame.packet_number_start, invalid)?,
            frame
                .packet_hash_count
                .map(|count| checked_varint_len(count, invalid))
                .transpose()?
                .unwrap_or_default(),
            frame.packet_hashes.len(),
        ],
        invalid,
    )
}

fn validate_ack_structure(frame: &Ack) -> Result<()> {
    let mut smallest = frame
        .largest_acknowledged
        .checked_sub(frame.first_ack_range)
        .ok_or(Error::InvalidFrame)?;

    for range in &frame.ack_ranges {
        let gap = range.gap.checked_add(2).ok_or(Error::InvalidFrame)?;
        let largest = smallest.checked_sub(gap).ok_or(Error::InvalidFrame)?;
        smallest = largest
            .checked_sub(range.ack_range_length)
            .ok_or(Error::InvalidFrame)?;
    }

    Ok(())
}

fn frame_encoded_len(frame: &Frame) -> Result<usize> {
    let invalid = Error::InvalidFrame;

    match frame {
        Frame::Announce(frame) => announce_encoded_len(frame),
        Frame::Key(frame) => key_encoded_len(frame),

        Frame::Join(frame) => join_encoded_len(frame),

        Frame::Leave(frame) => checked_len_sum(
            [
                checked_varint_len(FRAME_TYPE_LEAVE, invalid)?,
                channel_id_encoded_len(&frame.channel_id)?,
                checked_varint_len(frame.mc_state_sequence, invalid)?,
                checked_varint_len(frame.after_packet_number, invalid)?,
            ],
            invalid,
        ),

        Frame::Integrity(frame) => integrity_encoded_len(frame),

        Frame::Ack(frame) => {
            validate_ack_structure(frame)?;
            let ranges_len =
                frame.ack_ranges.iter().try_fold(0_usize, |total, range| {
                    checked_len_sum(
                        [
                            total,
                            checked_varint_len(range.gap, invalid)?,
                            checked_varint_len(range.ack_range_length, invalid)?,
                        ],
                        invalid,
                    )
                })?;
            let ecn_len = frame.ecn_counts.as_ref().map_or(Ok(0), |ecn| {
                checked_len_sum(
                    [
                        checked_varint_len(ecn.ect0_count, invalid)?,
                        checked_varint_len(ecn.ect1_count, invalid)?,
                        checked_varint_len(ecn.ecn_ce_count, invalid)?,
                    ],
                    invalid,
                )
            })?;

            checked_len_sum(
                [
                    checked_varint_len(
                        if frame.ecn_counts.is_some() {
                            FRAME_TYPE_ACK_ECN
                        } else {
                            FRAME_TYPE_ACK
                        },
                        invalid,
                    )?,
                    channel_id_encoded_len(&frame.channel_id)?,
                    checked_varint_len(frame.largest_acknowledged, invalid)?,
                    checked_varint_len(frame.ack_delay, invalid)?,
                    checked_collection_varint_len(
                        frame.ack_ranges.len(),
                        invalid,
                    )?,
                    checked_varint_len(frame.first_ack_range, invalid)?,
                    ranges_len,
                    ecn_len,
                ],
                invalid,
            )
        },

        Frame::Limits(frame) => checked_len_sum(
            [
                checked_varint_len(FRAME_TYPE_LIMITS, invalid)?,
                checked_varint_len(frame.sequence, invalid)?,
                frame.limits.encoded_len(invalid)?,
                checked_varint_len(frame.max_joined_count, invalid)?,
            ],
            invalid,
        ),

        Frame::Retire(frame) => checked_len_sum(
            [
                checked_varint_len(FRAME_TYPE_RETIRE, invalid)?,
                channel_id_encoded_len(&frame.channel_id)?,
                checked_varint_len(frame.after_packet_number, invalid)?,
            ],
            invalid,
        ),

        Frame::State(frame) => {
            validate_state_reason(
                frame.state,
                frame.reason_scope,
                frame.reason_code,
            )?;

            checked_len_sum(
                [
                    checked_varint_len(
                        match frame.reason_scope {
                            StateReasonScope::Transport => FRAME_TYPE_STATE,
                            StateReasonScope::Application =>
                                FRAME_TYPE_STATE_APPLICATION,
                        },
                        invalid,
                    )?,
                    channel_id_encoded_len(&frame.channel_id)?,
                    checked_varint_len(frame.sequence, invalid)?,
                    1,
                    checked_varint_len(frame.reason_code, invalid)?,
                    checked_collection_varint_len(
                        frame.reason_phrase.len(),
                        invalid,
                    )?,
                    frame.reason_phrase.len(),
                ],
                invalid,
            )
        },
    }
}

fn announce_frame_type(frame: &Announce) -> Result<u64> {
    match (&frame.source, &frame.group) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Ok(FRAME_TYPE_ANNOUNCE_V4),

        (IpAddr::V6(_), IpAddr::V6(_)) => Ok(FRAME_TYPE_ANNOUNCE_V6),

        _ => Err(Error::InvalidFrame),
    }
}

fn decode_ack_ranges(
    b: &mut octets::Octets, ack_range_count: u64,
) -> Result<Vec<AckRange>> {
    let ack_range_count =
        usize::try_from(ack_range_count).map_err(|_| Error::InvalidFrame)?;

    if ack_range_count > b.cap() / 2 {
        return Err(Error::InvalidFrame);
    }

    let mut ack_ranges = Vec::with_capacity(ack_range_count);

    for _ in 0..ack_range_count {
        ack_ranges.push(AckRange {
            gap: b.get_varint()?,
            ack_range_length: b.get_varint()?,
        });
    }

    Ok(ack_ranges)
}

pub(crate) fn decode_channel_id(
    b: &mut octets::Octets, invalid_frame: bool,
) -> Result<Vec<u8>> {
    let channel_id_len = b.get_u8()?;

    if !(1..=packet::MAX_CID_LEN).contains(&channel_id_len) {
        if invalid_frame {
            return Err(Error::InvalidFrame);
        }

        return Err(Error::InvalidTransportParam);
    }

    Ok(b.get_bytes(channel_id_len as usize)?.to_vec())
}

pub(crate) fn integrity_hash_len_from_id(id: u16) -> Result<usize> {
    Ok(IntegrityHashAlgorithm::from_id(id)?.output_len())
}

fn decode_integrity_frame(
    ty: u64, b: &mut octets::Octets, integrity_hash_len: Option<usize>,
    require_integrity_hash_len: bool,
) -> Result<Frame> {
    let channel_id = decode_channel_id(b, true)?;
    let packet_number_start = b.get_varint()?;
    let packet_hash_count = if ty == FRAME_TYPE_INTEGRITY_WITH_LENGTH {
        Some(b.get_varint()?)
    } else {
        None
    };

    let packet_hashes = match packet_hash_count {
        Some(packet_hash_count) => {
            let hash_len = match integrity_hash_len {
                Some(hash_len) => hash_len,

                None => {
                    if require_integrity_hash_len {
                        return Err(Error::InvalidFrame);
                    }

                    return Ok(Frame::Integrity(Integrity {
                        channel_id,
                        packet_number_start,
                        packet_hash_count: Some(packet_hash_count),
                        packet_hashes: b.get_bytes(b.cap())?.to_vec(),
                    }));
                },
            };

            let packet_hashes_len = packet_hash_count
                .checked_mul(hash_len as u64)
                .and_then(|len| usize::try_from(len).ok())
                .ok_or(Error::InvalidFrame)?;

            b.get_bytes(packet_hashes_len)?.to_vec()
        },

        None => b.get_bytes(b.cap())?.to_vec(),
    };

    Ok(Frame::Integrity(Integrity {
        channel_id,
        packet_number_start,
        packet_hash_count,
        packet_hashes,
    }))
}

fn decode_ip_addr(b: &mut octets::Octets, ty: u64) -> Result<IpAddr> {
    match ty {
        FRAME_TYPE_ANNOUNCE_V4 => {
            let addr = b.get_bytes(4)?.to_vec();

            Ok(IpAddr::V4(Ipv4Addr::new(
                addr[0], addr[1], addr[2], addr[3],
            )))
        },

        FRAME_TYPE_ANNOUNCE_V6 => {
            let addr = b.get_bytes(16)?.to_vec();
            let mut octets = [0; 16];
            octets.copy_from_slice(&addr);

            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        },

        _ => Err(Error::InvalidFrame),
    }
}

fn decode_u16_list(
    b: &mut octets::Octets, count: u64, invalid_frame: bool,
) -> Result<Vec<u16>> {
    let count = usize::try_from(count).map_err(|_| {
        if invalid_frame {
            Error::InvalidFrame
        } else {
            Error::InvalidTransportParam
        }
    })?;

    if count > b.cap() / 2 {
        return Err(if invalid_frame {
            Error::InvalidFrame
        } else {
            Error::InvalidTransportParam
        });
    }

    let mut out = Vec::with_capacity(count);

    for _ in 0..count {
        out.push(b.get_u16()?);
    }

    Ok(out)
}

fn encode_channel_id(channel_id: &[u8], b: &mut octets::OctetsMut) -> Result<()> {
    if channel_id.is_empty() || channel_id.len() > packet::MAX_CID_LEN as usize {
        return Err(Error::InvalidFrame);
    }

    b.put_u8(channel_id.len() as u8)?;
    b.put_bytes(channel_id)?;

    Ok(())
}

fn encode_ip_addr(addr: &IpAddr, b: &mut octets::OctetsMut) -> Result<()> {
    match addr {
        IpAddr::V4(addr) => {
            b.put_bytes(&addr.octets())?;
        },

        IpAddr::V6(addr) => {
            b.put_bytes(&addr.octets())?;
        },
    }

    Ok(())
}

fn encode_u16_list(values: &[u16], b: &mut octets::OctetsMut) -> Result<()> {
    for value in values {
        b.put_u16(*value)?;
    }

    Ok(())
}

fn ip_addr_len(addr: &IpAddr) -> usize {
    match addr {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

fn validate_state_reason(
    state: ChannelState, reason_scope: StateReasonScope, reason_code: u64,
) -> Result<()> {
    match state {
        ChannelState::Joined | ChannelState::Retired
            if reason_code != STATE_REASON_REQUESTED_BY_SERVER =>
            Err(Error::InvalidFrame),

        ChannelState::Left | ChannelState::DeclinedJoin
            if reason_scope == StateReasonScope::Transport &&
                !matches!(
                    reason_code,
                    0x0 | 0x1 |
                        0x2 |
                        0x3 |
                        0x4 |
                        0x5 |
                        0x6 |
                        0x10 |
                        0x12 |
                        0x13 |
                        0x14 |
                        0x15 |
                        0x16
                ) =>
            Err(Error::InvalidFrame),

        _ => Ok(()),
    }
}

fn build_header_open(announce: &Announce) -> Result<crypto::Open> {
    let alg = tls_cipher_to_algorithm(announce.header_protection_algorithm)?;

    let mut pkt_key = vec![0; alg.key_len()];
    let mut pkt_iv = vec![0; alg.nonce_len()];
    let mut hp_key = vec![0; alg.key_len()];

    crypto::derive_pkt_key(alg, &announce.header_secret, &mut pkt_key)?;
    crypto::derive_pkt_iv(alg, &announce.header_secret, &mut pkt_iv)?;
    crypto::derive_hdr_key(alg, &announce.header_secret, &mut hp_key)?;

    crypto::Open::new(
        alg,
        pkt_key,
        pkt_iv,
        hp_key,
        announce.header_secret.clone(),
    )
}

fn build_packet_open(announce: &Announce, key: &Key) -> Result<crypto::Open> {
    let header_alg =
        tls_cipher_to_algorithm(announce.header_protection_algorithm)?;
    let payload_alg = tls_cipher_to_algorithm(announce.aead_algorithm)?;

    if header_alg != payload_alg {
        return Err(Error::InvalidState);
    }

    let mut pkt_key = vec![0; payload_alg.key_len()];
    let mut pkt_iv = vec![0; payload_alg.nonce_len()];
    let mut hp_key = vec![0; payload_alg.key_len()];

    crypto::derive_pkt_key(payload_alg, &key.secret, &mut pkt_key)?;
    crypto::derive_pkt_iv(payload_alg, &key.secret, &mut pkt_iv)?;
    crypto::derive_hdr_key(payload_alg, &announce.header_secret, &mut hp_key)?;

    let mut open = crypto::Open::new(
        payload_alg,
        pkt_key,
        pkt_iv,
        hp_key,
        key.secret.clone(),
    )?;

    if key.from_packet_number > 0 {
        open.prime_for_nonzero_packet_number_space()?;
    }

    Ok(open)
}

fn build_channel_packet_seal(
    announce: &Announce, key: &Key,
) -> Result<crypto::Seal> {
    let header_alg =
        tls_cipher_to_algorithm(announce.header_protection_algorithm)?;
    let payload_alg = tls_cipher_to_algorithm(announce.aead_algorithm)?;

    if header_alg != payload_alg {
        return Err(Error::InvalidState);
    }

    let mut pkt_key = vec![0; payload_alg.key_len()];
    let mut pkt_iv = vec![0; payload_alg.nonce_len()];
    let mut hp_key = vec![0; payload_alg.key_len()];

    crypto::derive_pkt_key(payload_alg, &key.secret, &mut pkt_key)?;
    crypto::derive_pkt_iv(payload_alg, &key.secret, &mut pkt_iv)?;
    crypto::derive_hdr_key(payload_alg, &announce.header_secret, &mut hp_key)?;

    let mut seal = crypto::Seal::new(
        payload_alg,
        pkt_key,
        pkt_iv,
        hp_key,
        key.secret.clone(),
    )?;

    if key.from_packet_number > 0 {
        seal.prime_for_nonzero_packet_number_space()?;
    }

    Ok(seal)
}

fn encode_channel_packet_bytes(
    announce: &Announce, seal: &mut crypto::Seal, packet_number: u64,
    key_phase: bool, frames: &[ChannelFrame], out: &mut [u8],
) -> Result<usize> {
    let (mut b, payload_offset) =
        encode_channel_packet_header(announce, packet_number, key_phase, out)?;

    for frame in frames {
        encode_channel_frame_bytes(frame, &mut b)?;
    }

    let payload_len = b.off() - payload_offset;

    packet::encrypt_pkt(
        &mut b,
        packet_number,
        4,
        payload_len,
        payload_offset,
        None,
        seal,
    )
}

fn encode_channel_stream_packet_bytes(
    announce: &Announce, seal: &mut crypto::Seal, packet_number: u64,
    key_phase: bool, frame: &BorrowedChannelStreamFrame<'_>, out: &mut [u8],
) -> Result<usize> {
    channel_stream_frame_wire_len(
        frame.stream_id,
        frame.offset,
        frame.data.len(),
    )?;
    let (mut b, payload_offset) =
        encode_channel_packet_header(announce, packet_number, key_phase, out)?;
    frame::encode_stream_header(
        frame.stream_id,
        frame.offset,
        frame.data.len() as u64,
        frame.fin,
        &mut b,
    )?;
    b.put_bytes(frame.data)?;
    let payload_len = b.off() - payload_offset;

    packet::encrypt_pkt(
        &mut b,
        packet_number,
        4,
        payload_len,
        payload_offset,
        None,
        seal,
    )
}

struct BorrowedChannelStreamFrame<'a> {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: &'a [u8],
}

fn encode_channel_packet_header<'a>(
    announce: &Announce, packet_number: u64, key_phase: bool, out: &'a mut [u8],
) -> Result<(octets::OctetsMut<'a>, usize)> {
    validate_channel_id(&announce.channel_id)?;

    let mut b = octets::OctetsMut::with_slice(out);
    let packet_number_len = 4;
    let first = 0x40 |
        (((key_phase as u8) << 2) & 0x04) |
        ((packet_number_len as u8) - 1);

    b.put_u8(first)?;
    b.put_bytes(&announce.channel_id)?;
    packet::encode_pkt_num(packet_number, packet_number_len, &mut b)?;
    let payload_offset = b.off();

    Ok((b, payload_offset))
}

fn encode_channel_frame_bytes(
    channel_frame: &ChannelFrame, b: &mut octets::OctetsMut,
) -> Result<()> {
    match channel_frame {
        ChannelFrame::Stream {
            stream_id,
            offset,
            fin,
            data,
        } => {
            channel_stream_frame_wire_len(*stream_id, *offset, data.len())?;
            frame::encode_stream_header(
                *stream_id,
                *offset,
                data.len() as u64,
                *fin,
                b,
            )?;
            b.put_bytes(data)?;
        },

        ChannelFrame::Datagram { data } => {
            validate_two_byte_length(data.len())?;
            frame::encode_dgram_header(data.len() as u64, b)?;
            b.put_bytes(data)?;
        },

        ChannelFrame::Multicast(frame) => {
            validate_channel_control_frame(frame)?;
            frame.encode(b)?;
        },

        frame => {
            encode_non_data_channel_frame(frame)?.to_bytes(b)?;
        },
    }

    Ok(())
}

fn encode_non_data_channel_frame(
    channel_frame: &ChannelFrame,
) -> Result<frame::Frame> {
    match channel_frame {
        ChannelFrame::Padding { len } => Ok(frame::Frame::Padding { len: *len }),

        ChannelFrame::Ping => Ok(frame::Frame::Ping { mtu_probe: None }),

        ChannelFrame::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => {
            validate_channel_stream_id(*stream_id)?;
            checked_varint_len(*error_code, Error::InvalidFrame)?;
            checked_varint_len(*final_size, Error::InvalidFrame)?;

            Ok(frame::Frame::ResetStream {
                stream_id: *stream_id,
                error_code: *error_code,
                final_size: *final_size,
            })
        },

        ChannelFrame::ResetStreamAt {
            stream_id,
            error_code,
            final_size,
            reliable_size,
        } => {
            validate_channel_stream_id(*stream_id)?;
            checked_varint_len(*error_code, Error::InvalidFrame)?;
            checked_varint_len(*final_size, Error::InvalidFrame)?;
            checked_varint_len(*reliable_size, Error::InvalidFrame)?;

            Ok(frame::Frame::ResetStreamAt {
                stream_id: *stream_id,
                error_code: *error_code,
                final_size: *final_size,
                reliable_size: *reliable_size,
            })
        },

        ChannelFrame::Stream { .. } |
        ChannelFrame::Datagram { .. } |
        ChannelFrame::Multicast(..) => Err(Error::InvalidFrame),
    }
}

fn channel_packet_len(
    announce: &Announce, tag_len: usize, payload_len: usize,
) -> Result<usize> {
    validate_channel_id(&announce.channel_id)?;

    1_usize
        .checked_add(announce.channel_id.len())
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(payload_len))
        .and_then(|len| len.checked_add(tag_len))
        .ok_or(Error::InvalidState)
}

fn channel_frame_wire_len(channel_frame: &ChannelFrame) -> Result<usize> {
    match channel_frame {
        ChannelFrame::Stream {
            stream_id,
            offset,
            data,
            ..
        } => channel_stream_frame_wire_len(*stream_id, *offset, data.len()),

        ChannelFrame::Datagram { data } => {
            validate_two_byte_length(data.len())?;
            Ok(1 + 2 + data.len())
        },

        ChannelFrame::Multicast(frame) => {
            validate_channel_control_frame(frame)?;
            frame.encoded_len()
        },

        frame => Ok(encode_non_data_channel_frame(frame)?.wire_len()),
    }
}

fn channel_stream_frame_wire_len(
    stream_id: u64, offset: u64, data_len: usize,
) -> Result<usize> {
    validate_channel_stream_id(stream_id)?;
    if offset > MAX_VARINT {
        return Err(Error::InvalidFrame);
    }
    validate_two_byte_length(data_len)?;

    1_usize
        .checked_add(octets::varint_len(stream_id))
        .and_then(|len| len.checked_add(octets::varint_len(offset)))
        .and_then(|len| len.checked_add(2))
        .and_then(|len| len.checked_add(data_len))
        .ok_or(Error::InvalidState)
}

pub(crate) fn validate_channel_stream_publication(
    channel_id: &[u8], packet_number: u64, stream_id: u64, offset: u64,
    data_len: usize,
) -> Result<()> {
    validate_channel_id(channel_id)?;
    validate_varint(packet_number)?;
    channel_stream_frame_wire_len(stream_id, offset, data_len).map(|_| ())
}

/// Validates a draft-08 multicast Channel ID.
pub fn validate_channel_id(channel_id: &[u8]) -> Result<()> {
    if channel_id.is_empty() || channel_id.len() > packet::MAX_CID_LEN as usize {
        return Err(Error::InvalidFrame);
    }

    Ok(())
}

fn validate_varint(value: u64) -> Result<()> {
    if value > MAX_VARINT {
        return Err(Error::InvalidFrame);
    }

    Ok(())
}

fn validate_two_byte_length(len: usize) -> Result<()> {
    if len > 16383 {
        return Err(Error::InvalidFrame);
    }

    Ok(())
}

fn validate_channel_control_frame(frame: &Frame) -> Result<()> {
    match frame {
        Frame::Key(..) |
        Frame::Leave(..) |
        Frame::Integrity(..) |
        Frame::Retire(..) => Ok(()),

        _ => Err(Error::InvalidFrame),
    }
}

fn validate_channel_stream_id(stream_id: u64) -> Result<()> {
    if stream_id > MAX_VARINT ||
        stream::is_bidi(stream_id) ||
        stream_id & 0x3 != 0x3
    {
        return Err(Error::InvalidFrame);
    }

    Ok(())
}

fn tls_cipher_to_algorithm(id: u16) -> Result<crypto::Algorithm> {
    match id {
        0x1301 => Ok(crypto::Algorithm::AES128_GCM),
        0x1302 => Ok(crypto::Algorithm::AES256_GCM),
        0x1303 => Ok(crypto::Algorithm::ChaCha20_Poly1305),
        _ => Err(Error::InvalidState),
    }
}

#[cfg(test)]
mod tests;
