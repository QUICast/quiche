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

const SETTINGS_ENABLE_WEBTRANSPORT_LEGACY: u64 = 0x2b60_3742;
const SETTINGS_WT_ENABLED: u64 = 0x2c7c_f000;
const SETTINGS_H3_DATAGRAM_DRAFT04: u64 = 0xffd277;
const SETTINGS_WEBTRANSPORT_MAX_SESSIONS_DRAFT07: u64 = 0xc671_706a;
const SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64 = 0x14e9_cd29;
const SETTINGS_WT_INITIAL_MAX_DATA: u64 = 0x2b61;
const SETTINGS_WT_INITIAL_MAX_STREAMS_UNI: u64 = 0x2b64;
const SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI: u64 = 0x2b65;

const WT_INITIAL_MAX_DATA: u64 = 8_388_608;
const WT_INITIAL_MAX_STREAMS_UNI: u64 = 100;
const WT_INITIAL_MAX_STREAMS_BIDI: u64 = 100;

/// Unified configuration parameters for
/// [H3Driver](crate::http3::driver::H3Driver)s.
#[derive(Default, Clone, Debug)]
pub struct Http3Settings {
    /// Maximum number of requests a
    /// [ServerH3Driver](crate::http3::driver::ServerH3Driver) allows per
    /// connection.
    pub max_requests_per_connection: Option<u64>,
    /// Maximum size of a single HEADERS frame, in bytes.
    pub max_header_list_size: Option<u64>,
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
    /// Chrome requires this in addition to extended CONNECT before it considers
    /// WebTransport sessions negotiated.
    pub enable_webtransport: bool,
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

impl From<&Http3Settings> for quiche::h3::Config {
    fn from(value: &Http3Settings) -> Self {
        let mut config = Self::new().unwrap();

        if let Some(v) = value.max_header_list_size {
            config.set_max_field_section_size(v);
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
            config
                .set_additional_settings(vec![
                    (SETTINGS_ENABLE_WEBTRANSPORT_LEGACY, 1),
                    (SETTINGS_WT_ENABLED, 1),
                    (SETTINGS_H3_DATAGRAM_DRAFT04, 1),
                    (SETTINGS_WEBTRANSPORT_MAX_SESSIONS_DRAFT07, 1),
                    (SETTINGS_WEBTRANSPORT_MAX_SESSIONS, 1),
                    (SETTINGS_WT_INITIAL_MAX_DATA, WT_INITIAL_MAX_DATA),
                    (
                        SETTINGS_WT_INITIAL_MAX_STREAMS_UNI,
                        WT_INITIAL_MAX_STREAMS_UNI,
                    ),
                    (
                        SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI,
                        WT_INITIAL_MAX_STREAMS_BIDI,
                    ),
                ])
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
    fn enable_webtransport_emits_all_webtransport_settings() -> TestResult {
        let mut quic_config = h3_quiche_config()?;
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
            (SETTINGS_ENABLE_WEBTRANSPORT_LEGACY, 1),
            (SETTINGS_WT_ENABLED, 1),
            (SETTINGS_H3_DATAGRAM_DRAFT04, 1),
            (SETTINGS_WEBTRANSPORT_MAX_SESSIONS_DRAFT07, 1),
            (SETTINGS_WEBTRANSPORT_MAX_SESSIONS, 1),
            (SETTINGS_WT_INITIAL_MAX_DATA, WT_INITIAL_MAX_DATA),
            (
                SETTINGS_WT_INITIAL_MAX_STREAMS_UNI,
                WT_INITIAL_MAX_STREAMS_UNI,
            ),
            (
                SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI,
                WT_INITIAL_MAX_STREAMS_BIDI,
            ),
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

        Ok(())
    }
}
