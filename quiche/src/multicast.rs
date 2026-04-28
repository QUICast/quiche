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
use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use ring::digest;

use crate::crypto;
use crate::frame;
use crate::packet;
use crate::range_buf::RangeBuf;
use crate::stream;
use crate::Error;
use crate::Result;

const IP_FLAG_V6_ALLOWED: u8 = 0x02;
const IP_FLAG_V4_ALLOWED: u8 = 0x01;

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

/// The subset of client-advertised multicast limits shared by the transport
/// parameter and `MC_LIMITS`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

    fn wire_len(&self) -> usize {
        1 + octets::varint_len(self.max_aggregate_rate_kibps) +
            octets::varint_len(self.max_channel_ids)
    }

    fn encode(&self, b: &mut octets::OctetsMut) -> Result<()> {
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
    /// Returns the encoded wire length of the transport parameter value.
    pub fn wire_len(&self) -> usize {
        self.limits.wire_len() +
            octets::varint_len(self.hash_algorithms.len() as u64) +
            octets::varint_len(self.encryption_algorithms.len() as u64) +
            self.hash_algorithms.len() * 2 +
            self.encryption_algorithms.len() * 2
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
        let mut b = octets::OctetsMut::with_slice(out);
        let before = b.cap();

        self.encode(&mut b)?;

        Ok(before - b.cap())
    }

    pub(crate) fn encode(&self, b: &mut octets::OctetsMut) -> Result<()> {
        self.limits.encode(b)?;
        b.put_varint(self.hash_algorithms.len() as u64)?;
        b.put_varint(self.encryption_algorithms.len() as u64)?;
        encode_u16_list(&self.hash_algorithms, b)?;
        encode_u16_list(&self.encryption_algorithms, b)?;

        Ok(())
    }
}

/// A full `MC_ANNOUNCE` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// A full `MC_KEY` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// A full `MC_JOIN` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// A full `MC_LEAVE` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leave {
    /// The channel ID to leave.
    pub channel_id: Vec<u8>,

    /// The latest `MC_STATE` sequence processed by the server.
    pub mc_state_sequence: u64,

    /// The packet number after which the client should leave.
    pub after_packet_number: u64,
}

/// A full `MC_INTEGRITY` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// A single non-initial ACK block from an `MC_ACK` frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckRange {
    /// The gap from the previously acknowledged block.
    pub gap: u64,

    /// The encoded length of the acknowledged block.
    pub ack_range_length: u64,
}

/// ECN counters carried by `MC_ACK`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckEcnCounts {
    /// Count of packets marked `ECT(0)`.
    pub ect0_count: u64,

    /// Count of packets marked `ECT(1)`.
    pub ect1_count: u64,

    /// Count of packets marked `CE`.
    pub ecn_ce_count: u64,
}

/// A full `MC_ACK` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// A full `MC_LIMITS` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The client limits sequence number.
    pub sequence: u64,

    /// The current client limits.
    pub limits: ClientLimits,

    /// The maximum number of concurrently joined channels.
    pub max_joined_count: u64,
}

/// A full `MC_RETIRE` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retire {
    /// The retired channel ID.
    pub channel_id: Vec<u8>,

    /// The packet number after which retirement should happen.
    pub after_packet_number: u64,
}

/// The `MC_STATE` state value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateReasonScope {
    /// Reason code defined by the multicast transport layer.
    Transport,

    /// Reason code defined by the application.
    Application,
}

/// A full `MC_STATE` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Multicast control frames defined by the draft.
#[derive(Clone, Debug, PartialEq, Eq)]
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

                validate_state_reason(state, reason_code)?;

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
        let mut b = octets::OctetsMut::with_slice(out);
        let before = b.cap();

        self.encode(&mut b)?;

        Ok(before - b.cap())
    }

    pub(crate) fn encode(&self, b: &mut octets::OctetsMut) -> Result<()> {
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
                validate_state_reason(frame.state, frame.reason_code)?;

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

    pub(crate) fn wire_len(&self) -> usize {
        match self {
            Frame::Announce(frame) =>
                octets::varint_len(self.frame_type()) +
                    1 +
                    frame.channel_id.len() +
                    ip_addr_len(&frame.source) +
                    ip_addr_len(&frame.group) +
                    2 +
                    2 +
                    octets::varint_len(frame.header_secret.len() as u64) +
                    frame.header_secret.len() +
                    2 +
                    2 +
                    octets::varint_len(frame.max_rate_kibps) +
                    octets::varint_len(frame.max_ack_delay_ms),

            Frame::Key(frame) =>
                octets::varint_len(self.frame_type()) +
                    1 +
                    frame.channel_id.len() +
                    octets::varint_len(frame.key_sequence) +
                    octets::varint_len(frame.from_packet_number) +
                    octets::varint_len(frame.secret.len() as u64) +
                    frame.secret.len(),

            Frame::Join(frame) =>
                octets::varint_len(self.frame_type()) +
                    1 +
                    frame.channel_id.len() +
                    octets::varint_len(frame.mc_limits_sequence) +
                    octets::varint_len(frame.mc_state_sequence) +
                    octets::varint_len(frame.mc_key_sequence),

            Frame::Leave(frame) =>
                octets::varint_len(self.frame_type()) +
                    1 +
                    frame.channel_id.len() +
                    octets::varint_len(frame.mc_state_sequence) +
                    octets::varint_len(frame.after_packet_number),

            Frame::Integrity(frame) =>
                octets::varint_len(self.frame_type()) +
                    1 +
                    frame.channel_id.len() +
                    octets::varint_len(frame.packet_number_start) +
                    frame
                        .packet_hash_count
                        .map(octets::varint_len)
                        .unwrap_or_default() +
                    frame.packet_hashes.len(),

            Frame::Ack(frame) =>
                octets::varint_len(self.frame_type()) +
                    1 +
                    frame.channel_id.len() +
                    octets::varint_len(frame.largest_acknowledged) +
                    octets::varint_len(frame.ack_delay) +
                    octets::varint_len(frame.ack_ranges.len() as u64) +
                    octets::varint_len(frame.first_ack_range) +
                    frame.ack_ranges.iter().fold(0, |len, range| {
                        len + octets::varint_len(range.gap) +
                            octets::varint_len(range.ack_range_length)
                    }) +
                    frame
                        .ecn_counts
                        .as_ref()
                        .map(|ecn_counts| {
                            octets::varint_len(ecn_counts.ect0_count) +
                                octets::varint_len(ecn_counts.ect1_count) +
                                octets::varint_len(ecn_counts.ecn_ce_count)
                        })
                        .unwrap_or_default(),

            Frame::Limits(frame) =>
                octets::varint_len(self.frame_type()) +
                    octets::varint_len(frame.sequence) +
                    frame.limits.wire_len() +
                    octets::varint_len(frame.max_joined_count),

            Frame::Retire(frame) =>
                octets::varint_len(self.frame_type()) +
                    1 +
                    frame.channel_id.len() +
                    octets::varint_len(frame.after_packet_number),

            Frame::State(frame) =>
                octets::varint_len(self.frame_type()) +
                    1 +
                    frame.channel_id.len() +
                    octets::varint_len(frame.sequence) +
                    1 +
                    octets::varint_len(frame.reason_code) +
                    octets::varint_len(frame.reason_phrase.len() as u64) +
                    frame.reason_phrase.len(),
        }
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

    /// Total failed encode attempts from [`ChannelSendState::write_packet()`].
    pub encode_errors: u64,

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

    /// The latest assigned packet number sampled at the end of the interval.
    pub last_packet_number: Option<u64>,

    /// The next packet number sampled at the end of the interval.
    pub next_packet_number: u64,
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
            last_packet_number: after.last_packet_number,
            next_packet_number: after.next_packet_number,
        }
    }
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
        if key.channel_id != announce.channel_id {
            return Err(Error::InvalidState);
        }

        Ok(Self {
            seal: build_channel_packet_seal(&announce, &key)?,
            integrity_hash: IntegrityHashAlgorithm::from_id(
                announce.integrity_hash_algorithm,
            )?,
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

    /// Returns a snapshot of the sender's current metrics.
    pub fn metrics_snapshot(&self) -> ChannelSendMetricsSnapshot {
        self.metrics.snapshot(self.next_packet_number)
    }

    /// Updates the sender with a retransmitted `MC_ANNOUNCE`.
    ///
    /// Since the draft treats channel properties as immutable for a channel's
    /// lifetime, any announce that differs from the current one is rejected.
    pub fn update_announce(&mut self, announce: Announce) -> Result<()> {
        if self.announce.channel_id != announce.channel_id {
            return Err(Error::InvalidState);
        }

        if self.announce != announce {
            return Err(Error::InvalidState);
        }

        Ok(())
    }

    /// Replaces the active `MC_KEY` used to protect newly encoded packets.
    pub fn update_key(&mut self, key: Key) -> Result<()> {
        if key.channel_id != self.announce.channel_id {
            return Err(Error::InvalidState);
        }

        if key.key_sequence == self.key.key_sequence &&
            (key.from_packet_number != self.key.from_packet_number ||
                key.secret != self.key.secret)
        {
            return Err(Error::InvalidState);
        }

        self.seal = build_channel_packet_seal(&self.announce, &key)?;

        if self.next_packet_number < key.from_packet_number {
            self.next_packet_number = key.from_packet_number;
        }

        self.key = key;
        self.metrics.key_updates = self.metrics.key_updates.saturating_add(1);

        Ok(())
    }

    /// Encodes one multicast packet carrying the provided channel frames.
    ///
    /// The encoded bytes are written into `out`. On success, the returned
    /// [`ChannelSendOutput`] includes the matching [`Integrity`] payload that
    /// should be sent to receivers on the unicast control channel.
    pub fn write_packet(
        &mut self, frames: &[ChannelFrame], out: &mut [u8],
    ) -> Result<ChannelSendOutput> {
        self.metrics.write_calls = self.metrics.write_calls.saturating_add(1);
        let packet_number = self.next_packet_number;
        let key_phase = self.key.key_sequence % 2 == 1;
        let packet_len = match encode_channel_packet_bytes(
            &self.announce,
            &mut self.seal,
            packet_number,
            key_phase,
            frames,
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

        self.next_packet_number += 1;
        self.metrics.packets_encoded =
            self.metrics.packets_encoded.saturating_add(1);
        self.metrics.bytes_encoded =
            self.metrics.bytes_encoded.saturating_add(packet_len as u64);
        self.metrics.frames_encoded = self
            .metrics
            .frames_encoded
            .saturating_add(frames.len() as u64);
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

/// Receive-side state for a multicast channel's encrypted 1-RTT packets.
///
/// This tracks the immutable channel properties from [`Announce`], any
/// received [`Key`] and [`Integrity`] metadata, and encrypted datagrams that
/// are waiting on either of those before they can be released.
///
/// The `M` type parameter allows callers to attach arbitrary metadata to each
/// received datagram and receive it back once the packet is decoded, or when
/// the buffered datagram ultimately fails validation.
pub struct ChannelReceiveState<M = ()> {
    announce: Announce,
    header_open: crypto::Open,
    integrity_hash: IntegrityHashAlgorithm,
    keys: Vec<ChannelKey>,
    integrity_packets: BTreeMap<u64, Vec<u8>>,
    pending_packets: BTreeMap<u64, PendingChannelPacket<M>>,
    accepted_packets: BTreeSet<u64>,
    largest_observed_pkt_num: u64,
    metrics: ChannelReceiveMetricsState,
}

impl<M> ChannelReceiveState<M> {
    /// Creates receive-side state for the announced channel.
    ///
    /// The current implementation supports the QUIC v1 TLS cipher suite values
    /// `0x1301`, `0x1302`, and `0x1303`, and the named-information hash IDs
    /// `1..=8`. Other algorithm identifiers are reserved for future work.
    pub fn new(announce: Announce) -> Result<Self> {
        Ok(Self {
            header_open: build_header_open(&announce)?,
            integrity_hash: IntegrityHashAlgorithm::from_id(
                announce.integrity_hash_algorithm,
            )?,
            announce,
            keys: Vec::new(),
            integrity_packets: BTreeMap::new(),
            pending_packets: BTreeMap::new(),
            accepted_packets: BTreeSet::new(),
            largest_observed_pkt_num: 0,
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

    /// Updates the receiver with a retransmitted `MC_ANNOUNCE`.
    ///
    /// Since the draft treats channel properties as immutable for a channel's
    /// lifetime, any announce that differs from the current one is rejected.
    pub fn update_announce(&mut self, announce: Announce) -> Result<()> {
        if self.announce.channel_id != announce.channel_id {
            return Err(Error::InvalidState);
        }

        if self.announce != announce {
            return Err(Error::InvalidState);
        }

        Ok(())
    }

    /// Stores a new `MC_KEY` frame and releases any buffered packets that can
    /// now be decrypted and validated.
    pub fn insert_key(
        &mut self, key: Key,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        if key.channel_id != self.announce.channel_id {
            return Err(Error::InvalidState);
        }

        self.metrics.keys_received = self.metrics.keys_received.saturating_add(1);

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

            self.metrics.duplicate_keys =
                self.metrics.duplicate_keys.saturating_add(1);
            return self.release_ready_packets(ReleaseTrigger::Key);
        }

        self.keys.push(ChannelKey {
            key_sequence: key.key_sequence,
            key_phase: key.key_sequence % 2 == 1,
            from_packet_number: key.from_packet_number,
            secret: key.secret.clone(),
            open: build_packet_open(&self.announce, &key)?,
        });

        self.keys.sort_by_key(|key| key.from_packet_number);

        self.release_ready_packets(ReleaseTrigger::Key)
    }

    /// Stores packet hashes from an `MC_INTEGRITY` frame and releases any
    /// buffered packets that now have matching integrity metadata.
    pub fn insert_integrity(
        &mut self, integrity: Integrity,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        if integrity.channel_id != self.announce.channel_id {
            return Err(Error::InvalidState);
        }

        self.metrics.integrity_frames_received =
            self.metrics.integrity_frames_received.saturating_add(1);
        let hash_len = self.integrity_hash.output_len();
        let hash_count = integrity
            .packet_hash_count
            .unwrap_or_else(|| (integrity.packet_hashes.len() / hash_len) as u64);

        let expected_len = hash_count
            .checked_mul(hash_len as u64)
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(Error::InvalidFrame)?;

        if expected_len != integrity.packet_hashes.len() {
            return Err(Error::InvalidFrame);
        }

        self.metrics.integrity_hashes_received = self
            .metrics
            .integrity_hashes_received
            .saturating_add(hash_count);

        for idx in 0..hash_count {
            let pn = integrity
                .packet_number_start
                .checked_add(idx)
                .ok_or(Error::InvalidFrame)?;
            let start = usize::try_from(idx)
                .ok()
                .and_then(|idx| idx.checked_mul(hash_len))
                .ok_or(Error::InvalidFrame)?;
            let end = start.checked_add(hash_len).ok_or(Error::InvalidFrame)?;

            if self
                .integrity_packets
                .insert(pn, integrity.packet_hashes[start..end].to_vec())
                .is_some()
            {
                self.metrics.integrity_hash_overwrites =
                    self.metrics.integrity_hash_overwrites.saturating_add(1);
            }
        }

        self.release_ready_packets(ReleaseTrigger::Integrity)
    }

    /// Feeds a received encrypted multicast datagram into the channel state.
    ///
    /// If the datagram has the required `MC_KEY` and `MC_INTEGRITY` metadata
    /// available, it is decoded immediately. Otherwise it is buffered until
    /// those prerequisites arrive in later control frames.
    pub fn recv(
        &mut self, buf: &[u8], metadata: M,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        self.metrics.recv_calls = self.metrics.recv_calls.saturating_add(1);
        self.metrics.recv_bytes =
            self.metrics.recv_bytes.saturating_add(buf.len() as u64);
        let packet = match self.parse_packet_metadata(buf) {
            Ok(packet) => packet,

            Err(error) => {
                self.metrics.record_error(error);
                return Ok(vec![ChannelReceiveEvent::Error { error, metadata }]);
            },
        };

        self.largest_observed_pkt_num =
            self.largest_observed_pkt_num.max(packet.packet_number);

        if self.accepted_packets.contains(&packet.packet_number) ||
            self.pending_packets.contains_key(&packet.packet_number)
        {
            self.metrics.duplicate_packets =
                self.metrics.duplicate_packets.saturating_add(1);
            return Ok(Vec::new());
        }

        self.metrics.packets_buffered =
            self.metrics.packets_buffered.saturating_add(1);
        self.pending_packets
            .insert(packet.packet_number, PendingChannelPacket {
                buf: buf.to_vec(),
                key_phase: packet.key_phase,
                metadata,
            });

        let mut events = Vec::new();

        if let Some(event) =
            self.try_release_packet(packet.packet_number, ReleaseTrigger::Recv)?
        {
            events.push(event);
        }

        Ok(events)
    }

    fn release_ready_packets(
        &mut self, trigger: ReleaseTrigger,
    ) -> Result<Vec<ChannelReceiveEvent<M>>> {
        let packet_numbers =
            self.pending_packets.keys().copied().collect::<Vec<_>>();
        let mut events = Vec::new();

        for packet_number in packet_numbers {
            if let Some(event) =
                self.try_release_packet(packet_number, trigger)?
            {
                events.push(event);
            }
        }

        Ok(events)
    }

    fn try_release_packet(
        &mut self, packet_number: u64, trigger: ReleaseTrigger,
    ) -> Result<Option<ChannelReceiveEvent<M>>> {
        if !self.integrity_packets.contains_key(&packet_number) {
            return Ok(None);
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
            let pending = self
                .pending_packets
                .remove(&packet_number)
                .expect("pending packet exists");
            self.metrics.integrity_mismatch_errors =
                self.metrics.integrity_mismatch_errors.saturating_add(1);

            return Ok(Some(ChannelReceiveEvent::Error {
                error: Error::CryptoFail,
                metadata: pending.metadata,
            }));
        }

        let pending = self
            .pending_packets
            .remove(&packet_number)
            .expect("pending packet exists");

        let packet = match self.decrypt_packet(
            &pending.buf,
            packet_number,
            &self.keys[key_index],
        ) {
            Ok(packet) => packet,

            Err(error) => {
                self.metrics.record_error(error);
                return Ok(Some(ChannelReceiveEvent::Error {
                    error,
                    metadata: pending.metadata,
                }));
            },
        };

        self.accepted_packets.insert(packet_number);
        self.metrics.packets_delivered =
            self.metrics.packets_delivered.saturating_add(1);
        self.metrics.record_release_success(trigger);

        Ok(Some(ChannelReceiveEvent::Packet {
            packet,
            metadata: pending.metadata,
        }))
    }

    fn select_key_index(
        &self, packet_number: u64, key_phase: bool,
    ) -> Option<usize> {
        self.keys
            .iter()
            .enumerate()
            .rev()
            .find(|(_, key)| {
                key.key_phase == key_phase &&
                    key.from_packet_number <= packet_number
            })
            .map(|(idx, _)| idx)
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
            self.largest_observed_pkt_num,
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
            } => Ok(ChannelFrame::ResetStream {
                stream_id,
                error_code,
                final_size,
            }),

            frame::Frame::Stream { stream_id, data } => {
                if stream::is_bidi(stream_id) || stream_id & 0x3 != 0x3 {
                    return Err(Error::InvalidFrame);
                }

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

#[derive(Debug)]
struct ParsedChannelPacket {
    packet_number: u64,
    key_phase: bool,
}

#[derive(Debug)]
struct PendingChannelPacket<M> {
    buf: Vec<u8>,
    key_phase: bool,
    metadata: M,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ChannelSendMetricsState {
    write_calls: u64,
    packets_encoded: u64,
    bytes_encoded: u64,
    frames_encoded: u64,
    key_updates: u64,
    encode_errors: u64,
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

    /// Current number of accepted packet numbers tracked by the receiver.
    pub accepted_packets: usize,

    /// Current number of buffered packets waiting on a key.
    pub waiting_for_key_packets: usize,

    /// Current number of buffered packets waiting on integrity.
    pub waiting_for_integrity_packets: usize,

    /// The largest packet number observed so far.
    pub largest_observed_packet_number: u64,
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

    /// Current number of accepted packet numbers tracked by the receiver.
    pub accepted_packets: usize,

    /// Current number of buffered packets waiting on a key.
    pub waiting_for_key_packets: usize,

    /// Current number of buffered packets waiting on integrity.
    pub waiting_for_integrity_packets: usize,

    /// The largest packet number observed at the end of the interval.
    pub largest_observed_packet_number: u64,
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
            accepted_packets: after.accepted_packets,
            waiting_for_key_packets: after.waiting_for_key_packets,
            waiting_for_integrity_packets: after.waiting_for_integrity_packets,
            largest_observed_packet_number: after.largest_observed_packet_number,
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
    integrity_frames_received: u64,
    integrity_hashes_received: u64,
    integrity_hash_overwrites: u64,
    integrity_mismatch_errors: u64,
    decrypt_errors: u64,
    invalid_packet_errors: u64,
    invalid_frame_errors: u64,
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
        let waiting_for_integrity_packets = state
            .pending_packets
            .keys()
            .filter(|packet_number| {
                !state.integrity_packets.contains_key(packet_number)
            })
            .count();
        let waiting_for_key_packets = state
            .pending_packets
            .iter()
            .filter(|(packet_number, pending)| {
                state.integrity_packets.contains_key(packet_number) &&
                    state
                        .select_key_index(**packet_number, pending.key_phase)
                        .is_none()
            })
            .count();

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
            accepted_packets: state.accepted_packets.len(),
            waiting_for_key_packets,
            waiting_for_integrity_packets,
            largest_observed_packet_number: state.largest_observed_pkt_num,
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
pub(crate) struct ControlFrameQueue {
    queue: VecDeque<Frame>,
    queue_max_len: usize,
}

impl ControlFrameQueue {
    pub(crate) fn new(queue_max_len: usize) -> Self {
        ControlFrameQueue {
            queue: VecDeque::new(),
            queue_max_len,
        }
    }

    pub(crate) fn push(&mut self, frame: Frame) -> Result<()> {
        if self.is_full() {
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

    pub(crate) fn is_full(&self) -> bool {
        self.queue.len() == self.queue_max_len
    }

    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }
}

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
    let mut ack_ranges = Vec::with_capacity(ack_range_count as usize);

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

fn validate_state_reason(state: ChannelState, reason_code: u64) -> Result<()> {
    match state {
        ChannelState::Joined | ChannelState::Retired
            if reason_code != STATE_REASON_REQUESTED_BY_SERVER =>
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

    crypto::Open::new(payload_alg, pkt_key, pkt_iv, hp_key, key.secret.clone())
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

    crypto::Seal::new(payload_alg, pkt_key, pkt_iv, hp_key, key.secret.clone())
}

fn encode_channel_packet_bytes(
    announce: &Announce, seal: &mut crypto::Seal, packet_number: u64,
    key_phase: bool, frames: &[ChannelFrame], out: &mut [u8],
) -> Result<usize> {
    if announce.channel_id.is_empty() ||
        announce.channel_id.len() > packet::MAX_CID_LEN as usize
    {
        return Err(Error::InvalidState);
    }

    let mut b = octets::OctetsMut::with_slice(out);
    let packet_number_len = 4;
    let first = 0x40 |
        (((key_phase as u8) << 2) & 0x04) |
        ((packet_number_len as u8) - 1);

    b.put_u8(first)?;
    b.put_bytes(&announce.channel_id)?;
    packet::encode_pkt_num(packet_number, packet_number_len, &mut b)?;

    let payload_offset = b.off();

    for frame in frames {
        encode_channel_frame(frame)?.to_bytes(&mut b)?;
    }

    let payload_len = b.off() - payload_offset;

    packet::encrypt_pkt(
        &mut b,
        packet_number,
        packet_number_len,
        payload_len,
        payload_offset,
        None,
        seal,
    )
}

fn encode_channel_frame(frame: &ChannelFrame) -> Result<frame::Frame> {
    match frame {
        ChannelFrame::Padding { len } => Ok(frame::Frame::Padding { len: *len }),

        ChannelFrame::Ping => Ok(frame::Frame::Ping { mtu_probe: None }),

        ChannelFrame::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => Ok(frame::Frame::ResetStream {
            stream_id: *stream_id,
            error_code: *error_code,
            final_size: *final_size,
        }),

        ChannelFrame::Stream {
            stream_id,
            offset,
            fin,
            data,
        } => Ok(frame::Frame::Stream {
            stream_id: *stream_id,
            data: RangeBuf::from(data.as_ref(), *offset, *fin),
        }),

        ChannelFrame::Datagram { data } =>
            Ok(frame::Frame::Datagram { data: data.clone() }),

        ChannelFrame::Multicast(frame) => match frame {
            Frame::Key(..) |
            Frame::Leave(..) |
            Frame::Integrity(..) |
            Frame::Retire(..) => Ok(frame::Frame::Multicast(frame.clone())),

            _ => Err(Error::InvalidFrame),
        },
    }
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
mod tests {
    use super::*;

    #[test]
    fn client_transport_params_roundtrip() {
        let params = ClientTransportParams {
            limits: ClientLimits {
                ipv6_channels_allowed: true,
                ipv4_channels_allowed: true,
                max_aggregate_rate_kibps: 1024,
                max_channel_ids: 16,
            },
            hash_algorithms: vec![1, 2, 3],
            encryption_algorithms: vec![0x1301, 0x1302],
        };

        let mut out = [0; 128];
        let written = params.to_bytes(&mut out).unwrap();
        let decoded = ClientTransportParams::from_bytes(&out[..written]).unwrap();

        assert_eq!(decoded, params);
    }

    #[test]
    fn announce_ipv4_roundtrip() {
        let frame = Frame::Announce(Announce {
            channel_id: vec![1, 2, 3, 4],
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            udp_port: 4433,
            header_protection_algorithm: 0x1301,
            header_secret: vec![0xaa; 12],
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 2500,
            max_ack_delay_ms: 25,
        });

        let mut out = [0; 256];
        let written = frame.to_bytes(&mut out).unwrap();
        let decoded = Frame::from_bytes(&out[..written]).unwrap();

        assert_eq!(decoded, frame);
    }

    #[test]
    fn announce_ipv6_roundtrip() {
        let frame = Frame::Announce(Announce {
            channel_id: vec![7, 7, 7, 7],
            source: IpAddr::V6("2001:db8::1".parse().unwrap()),
            group: IpAddr::V6("ff3e::8000:1".parse().unwrap()),
            udp_port: 8443,
            header_protection_algorithm: 0x1302,
            header_secret: vec![0xbb; 24],
            aead_algorithm: 0x1302,
            integrity_hash_algorithm: 2,
            max_rate_kibps: 9000,
            max_ack_delay_ms: 7,
        });

        let mut out = [0; 256];
        let written = frame.to_bytes(&mut out).unwrap();
        let decoded = Frame::from_bytes(&out[..written]).unwrap();

        assert_eq!(decoded, frame);
    }

    #[test]
    fn ack_with_ecn_roundtrip() {
        let frame = Frame::Ack(Ack {
            channel_id: vec![1, 3, 3, 7],
            largest_acknowledged: 1234,
            ack_delay: 25,
            first_ack_range: 12,
            ack_ranges: vec![
                AckRange {
                    gap: 1,
                    ack_range_length: 4,
                },
                AckRange {
                    gap: 3,
                    ack_range_length: 2,
                },
            ],
            ecn_counts: Some(AckEcnCounts {
                ect0_count: 10,
                ect1_count: 11,
                ecn_ce_count: 12,
            }),
        });

        let mut out = [0; 256];
        let written = frame.to_bytes(&mut out).unwrap();
        let decoded = Frame::from_bytes(&out[..written]).unwrap();

        assert_eq!(decoded, frame);
    }

    #[test]
    fn state_roundtrip() {
        let frame = Frame::State(State {
            channel_id: vec![9, 9, 9, 9],
            sequence: 44,
            state: ChannelState::Joined,
            reason_scope: StateReasonScope::Transport,
            reason_code: STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: b"joined".to_vec(),
        });

        let mut out = [0; 256];
        let written = frame.to_bytes(&mut out).unwrap();
        let decoded = Frame::from_bytes(&out[..written]).unwrap();

        assert_eq!(decoded, frame);
    }

    fn test_announce() -> Announce {
        Announce {
            channel_id: vec![1, 2, 3, 4],
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            udp_port: 4433,
            header_protection_algorithm: 0x1301,
            header_secret: vec![0xaa; 16],
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 2500,
            max_ack_delay_ms: 25,
        }
    }

    fn test_key(channel_id: &[u8]) -> Key {
        Key {
            channel_id: channel_id.to_vec(),
            key_sequence: 1,
            from_packet_number: 0,
            secret: vec![0xcc; 16],
        }
    }

    fn build_packet_seal(announce: &Announce, key: &Key) -> crypto::Seal {
        let alg = tls_cipher_to_algorithm(announce.aead_algorithm).unwrap();
        let mut pkt_key = vec![0; alg.key_len()];
        let mut pkt_iv = vec![0; alg.nonce_len()];
        let mut hp_key = vec![0; alg.key_len()];

        crypto::derive_pkt_key(alg, &key.secret, &mut pkt_key).unwrap();
        crypto::derive_pkt_iv(alg, &key.secret, &mut pkt_iv).unwrap();
        crypto::derive_hdr_key(alg, &announce.header_secret, &mut hp_key)
            .unwrap();

        crypto::Seal::new(alg, pkt_key, pkt_iv, hp_key, key.secret.clone())
            .unwrap()
    }

    fn encode_channel_packet(
        announce: &Announce, key: &Key, packet_number: u64, key_phase: bool,
        frames: &[frame::Frame],
    ) -> Vec<u8> {
        let mut out = vec![0; 256];
        let mut b = octets::OctetsMut::with_slice(&mut out);
        let mut seal = build_packet_seal(announce, key);
        let packet_number_len = 4;
        let first = 0x40 |
            (((key_phase as u8) << 2) & 0x04) |
            ((packet_number_len as u8) - 1);

        b.put_u8(first).unwrap();
        b.put_bytes(&announce.channel_id).unwrap();
        packet::encode_pkt_num(packet_number, packet_number_len, &mut b).unwrap();

        let payload_offset = b.off();

        for frame in frames {
            frame.to_bytes(&mut b).unwrap();
        }

        let payload_len = b.off() - payload_offset;

        let written = packet::encrypt_pkt(
            &mut b,
            packet_number,
            packet_number_len,
            payload_len,
            payload_offset,
            None,
            &mut seal,
        )
        .unwrap();

        out.truncate(written);
        out
    }

    fn integrity_frame(
        announce: &Announce, packet_number: u64, packet: &[u8],
    ) -> Integrity {
        Integrity {
            channel_id: announce.channel_id.clone(),
            packet_number_start: packet_number,
            packet_hash_count: Some(1),
            packet_hashes: IntegrityHashAlgorithm::from_id(
                announce.integrity_hash_algorithm,
            )
            .unwrap()
            .hash(packet),
        }
    }

    #[test]
    fn channel_send_state_roundtrip() {
        let announce = test_announce();
        let key = test_key(&announce.channel_id);
        let mut sender =
            ChannelSendState::new(announce.clone(), key.clone()).unwrap();
        let mut receiver = ChannelReceiveState::new(announce).unwrap();
        let mut out = [0; 256];

        receiver.insert_key(key).unwrap();

        let sent = sender
            .write_packet(
                &[ChannelFrame::Datagram {
                    data: b"hello multicast".to_vec(),
                }],
                &mut out,
            )
            .unwrap();
        let events = receiver.insert_integrity(sent.integrity.clone()).unwrap();

        assert!(events.is_empty());

        let events = receiver.recv(&out[..sent.packet_len], ()).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            ChannelReceiveEvent::Packet {
                packet,
                metadata: (),
            } => {
                assert_eq!(packet.packet_number, sent.packet_number);
                assert_eq!(packet.key_sequence, sent.key_sequence);
                assert!(packet.key_phase);
                assert_eq!(packet.frames, vec![ChannelFrame::Datagram {
                    data: b"hello multicast".to_vec(),
                }]);
            },

            ChannelReceiveEvent::Error { error, .. } => {
                panic!("unexpected receive error: {error:?}");
            },
        }

        let send_metrics = sender.metrics_snapshot();
        assert_eq!(send_metrics, ChannelSendMetricsSnapshot {
            write_calls: 1,
            packets_encoded: 1,
            bytes_encoded: send_metrics.bytes_encoded,
            frames_encoded: 1,
            key_updates: 0,
            encode_errors: 0,
            last_packet_number: Some(0),
            next_packet_number: 1,
        });

        let recv_metrics = receiver.metrics_snapshot();
        assert_eq!(recv_metrics.recv_calls, 1);
        assert_eq!(recv_metrics.recv_bytes, send_metrics.bytes_encoded);
        assert_eq!(recv_metrics.packets_buffered, 1);
        assert_eq!(recv_metrics.packets_delivered, 1);
        assert_eq!(recv_metrics.packets_released_on_recv, 1);
        assert_eq!(recv_metrics.packets_released_on_key, 0);
        assert_eq!(recv_metrics.packets_released_on_integrity, 0);
        assert_eq!(recv_metrics.keys_received, 1);
        assert_eq!(recv_metrics.integrity_frames_received, 1);
        assert_eq!(recv_metrics.integrity_hashes_received, 1);
        assert_eq!(recv_metrics.pending_packets, 0);
        assert_eq!(recv_metrics.waiting_for_key_packets, 0);
        assert_eq!(recv_metrics.waiting_for_integrity_packets, 0);
    }

    #[test]
    fn channel_receive_state_releases_packet_after_integrity() {
        let announce = test_announce();
        let key = test_key(&announce.channel_id);
        let packet = encode_channel_packet(&announce, &key, 1, true, &[
            frame::Frame::Ping { mtu_probe: None },
        ]);
        let integrity = integrity_frame(&announce, 1, &packet);
        let mut state = ChannelReceiveState::new(announce.clone()).unwrap();

        assert!(state.insert_key(key).unwrap().is_empty());
        assert!(state.recv(&packet, ()).unwrap().is_empty());

        let events = state.insert_integrity(integrity).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            ChannelReceiveEvent::Packet { packet, .. } => {
                assert_eq!(packet.channel_id, announce.channel_id);
                assert_eq!(packet.packet_number, 1);
                assert_eq!(packet.key_sequence, 1);
                assert!(packet.key_phase);
                assert_eq!(packet.frames, vec![ChannelFrame::Ping]);
            },

            ChannelReceiveEvent::Error { error, .. } =>
                panic!("unexpected decode error: {error:?}"),
        }

        let metrics = state.metrics_snapshot();
        assert_eq!(metrics.packets_released_on_recv, 0);
        assert_eq!(metrics.packets_released_on_key, 0);
        assert_eq!(metrics.packets_released_on_integrity, 1);
    }

    #[test]
    fn channel_receive_state_releases_packet_after_key() {
        let announce = test_announce();
        let key = test_key(&announce.channel_id);
        let packet = encode_channel_packet(&announce, &key, 7, true, &[
            frame::Frame::Ping { mtu_probe: None },
        ]);
        let integrity = integrity_frame(&announce, 7, &packet);
        let mut state = ChannelReceiveState::new(announce.clone()).unwrap();

        assert!(state.insert_integrity(integrity).unwrap().is_empty());
        assert!(state.recv(&packet, "late-key").unwrap().is_empty());

        let events = state.insert_key(key).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            ChannelReceiveEvent::Packet { packet, metadata } => {
                assert_eq!(packet.channel_id, announce.channel_id);
                assert_eq!(packet.packet_number, 7);
                assert_eq!(*metadata, "late-key");
            },

            ChannelReceiveEvent::Error { error, .. } =>
                panic!("unexpected decode error: {error:?}"),
        }

        let metrics = state.metrics_snapshot();
        assert_eq!(metrics.packets_released_on_recv, 0);
        assert_eq!(metrics.packets_released_on_key, 1);
        assert_eq!(metrics.packets_released_on_integrity, 0);
    }

    #[test]
    fn channel_receive_state_rejects_forbidden_frame() {
        let announce = test_announce();
        let key = test_key(&announce.channel_id);
        let packet = encode_channel_packet(&announce, &key, 11, true, &[
            frame::Frame::ConnectionClose {
                error_code: 0,
                frame_type: 0,
                reason: Vec::new(),
            },
        ]);
        let integrity = integrity_frame(&announce, 11, &packet);
        let mut state = ChannelReceiveState::new(announce).unwrap();

        assert!(state.insert_key(key).unwrap().is_empty());
        assert!(state.insert_integrity(integrity).unwrap().is_empty());

        let events = state.recv(&packet, "bad-frame").unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            ChannelReceiveEvent::Packet { .. } =>
                panic!("unexpected decoded packet"),

            ChannelReceiveEvent::Error { error, metadata } => {
                assert_eq!(*error, Error::InvalidFrame);
                assert_eq!(*metadata, "bad-frame");
            },
        }

        let metrics = state.metrics_snapshot();
        assert_eq!(metrics.invalid_frame_errors, 1);
        assert_eq!(metrics.packets_delivered, 0);
    }

    #[test]
    fn channel_send_metrics_delta_tracks_changes() {
        let announce = test_announce();
        let key = test_key(&announce.channel_id);
        let mut sender = ChannelSendState::new(announce, key).unwrap();
        let before = sender.metrics_snapshot();
        let mut out = [0; 256];

        sender
            .write_packet(&[ChannelFrame::Ping], &mut out)
            .unwrap();

        let after = sender.metrics_snapshot();
        let delta = ChannelSendMetricsDelta::between(before, after);

        assert_eq!(delta, ChannelSendMetricsDelta {
            write_calls: 1,
            packets_encoded: 1,
            bytes_encoded: after.bytes_encoded,
            frames_encoded: 1,
            key_updates: 0,
            encode_errors: 0,
            last_packet_number: Some(0),
            next_packet_number: 1,
        });
    }

    #[test]
    fn channel_receive_metrics_delta_tracks_changes() {
        let announce = test_announce();
        let key = test_key(&announce.channel_id);
        let mut sender =
            ChannelSendState::new(announce.clone(), key.clone()).unwrap();
        let mut receiver = ChannelReceiveState::new(announce).unwrap();
        let before = receiver.metrics_snapshot();
        let mut out = [0; 256];

        receiver.insert_key(key).unwrap();
        let sent = sender
            .write_packet(&[ChannelFrame::Ping], &mut out)
            .unwrap();
        receiver.insert_integrity(sent.integrity).unwrap();
        receiver.recv(&out[..sent.packet_len], ()).unwrap();

        let after = receiver.metrics_snapshot();
        let delta = ChannelReceiveMetricsDelta::between(before, after);

        assert_eq!(delta.recv_calls, 1);
        assert_eq!(delta.recv_bytes, sent.packet_len as u64);
        assert_eq!(delta.packets_buffered, 1);
        assert_eq!(delta.packets_delivered, 1);
        assert_eq!(delta.packets_released_on_recv, 1);
        assert_eq!(delta.keys_received, 1);
        assert_eq!(delta.integrity_frames_received, 1);
        assert_eq!(delta.integrity_hashes_received, 1);
        assert_eq!(delta.pending_packets, 0);
    }
}
