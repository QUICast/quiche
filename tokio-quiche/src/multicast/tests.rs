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

use super::bounded_queue::bounded_channel;
use super::bounded_queue::retained_queue_budget;
use super::bounded_queue::BoundedReceiver;
use super::bounded_queue::BoundedSender;
use super::bounded_queue::RetainedQueueObserver;
use super::event_stream::client_event_channel;
use super::event_stream::server_event_channel;
use super::event_stream::EventQueueObserver;
use super::event_stream::ManagedEventSender;
use super::server::ServerEventCoalescer;
use super::server_control::PendingStreamIntegrityBatch;
use super::server_control::ServerControlChannel;
use super::server_control::ServerControlCommand;
use super::server_control::ServerControlRuntime;
use super::server_publish::PendingPublication;
use super::server_publish::PublishBackend;
use super::server_publish::ServerCommand;
use super::server_publish::ServerPendingControl;
use super::server_publish::ServerRuntime;
use super::*;
use std::collections::VecDeque;
use std::future::pending;
use std::future::Future;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;
use std::time::Duration;

use bytes::Bytes;
use mcrx_core::PacketWithMetadata;
use mctx_core::MctxError;
use mctx_core::PublicationConfig;
use mctx_core::SendReport;
use tokio::time::Instant;

use crate::buf_factory::BufFactory;
use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

type Pipe = quiche::test_utils::Pipe<BufFactory>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct JoinRequest {
    channel_id: Vec<u8>,
    source: Ipv4Addr,
    group: Ipv4Addr,
    udp_port: u16,
    interface: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Default)]
struct FakeJoinBackend {
    joins: Arc<Mutex<Vec<JoinRequest>>>,
}

#[derive(Debug)]
struct FakeHandle;

impl JoinBackend for FakeJoinBackend {
    type Handle = FakeHandle;

    fn join_ipv4(
        &mut self, channel_id: &[u8], source: Ipv4Addr, group: Ipv4Addr,
        udp_port: u16, interface: Option<Ipv4Addr>,
        _ingress_sender: BoundedSender<IngressEvent>,
    ) -> Result<Self::Handle, JoinError> {
        self.joins.lock().unwrap().push(JoinRequest {
            channel_id: channel_id.to_vec(),
            source,
            group,
            udp_port,
            interface,
        });

        Ok(FakeHandle)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublishRecord {
    source: Ipv4Addr,
    group: Ipv4Addr,
    udp_port: u16,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct FakePublishBackend {
    sent: Arc<Mutex<Vec<PublishRecord>>>,
}

#[derive(Clone, Debug)]
struct FakePublication {
    source: Ipv4Addr,
    group: Ipv4Addr,
    udp_port: u16,
}

impl PublishBackend for FakePublishBackend {
    type Publication = FakePublication;

    fn open(
        &mut self, config: &PublicationConfig,
    ) -> Result<Self::Publication, MctxError> {
        Ok(FakePublication {
            source: match config.source_addr {
                Some(IpAddr::V4(source)) => source,
                _ => Ipv4Addr::new(10, 0, 0, 1),
            },
            group: match config.group {
                IpAddr::V4(group) => group,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            },
            udp_port: config.dst_port,
        })
    }

    fn announce_tuple(
        &self, publication: &Self::Publication,
    ) -> Result<(Ipv4Addr, Ipv4Addr, u16), MctxError> {
        Ok((publication.source, publication.group, publication.udp_port))
    }

    fn send(
        &self, publication: &Self::Publication, payload: &[u8],
    ) -> Result<SendReport, MctxError> {
        self.sent.lock().unwrap().push(PublishRecord {
            source: publication.source,
            group: publication.group,
            udp_port: publication.udp_port,
            payload: payload.to_vec(),
        });

        Ok(SendReport {
            publication_id: mctx_core::PublicationId(0),
            destination: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                publication.group,
                publication.udp_port,
            )),
            local_addr: Some(std::net::SocketAddr::V4(
                std::net::SocketAddrV4::new(publication.source, 0),
            )),
            source_addr: Some(IpAddr::V4(publication.source)),
            bytes_sent: payload.len(),
        })
    }
}

fn test_transport_params() -> quiche::multicast::ClientTransportParams {
    quiche::multicast::ClientTransportParams {
        limits: quiche::multicast::ClientLimits {
            ipv6_channels_allowed: false,
            ipv4_channels_allowed: true,
            max_aggregate_rate_kibps: 8192,
            max_channel_ids: 16,
        },
        hash_algorithms: vec![1],
        encryption_algorithms: vec![0x1301],
    }
}

fn test_settings() -> ClientSettings {
    ClientSettings {
        transport_params: test_transport_params(),
        max_joined_channels: 4,
        ipv4_interface: None,
        ipv6_interface: None,
    }
}

fn test_pipe(settings: &ClientSettings) -> Pipe {
    test_pipe_with_server_control_queue(settings, 1024, 2 * 1024 * 1024)
}

fn test_pipe_with_server_control_queue(
    settings: &ClientSettings, max_frames: usize, max_bytes: usize,
) -> Pipe {
    let mut client_config =
        quiche::test_utils::Pipe::default_config("cubic").unwrap();
    client_config.enable_dgram(true, 10, 10);
    client_config
        .set_multicast_client_params(Some(settings.transport_params.clone()))
        .unwrap();

    let mut server_config =
        quiche::test_utils::Pipe::default_config("cubic").unwrap();
    server_config.enable_dgram(true, 10, 10);
    server_config.enable_multicast_server_support(true);
    server_config.set_multicast_send_queue_limits(max_frames, max_bytes);

    let mut pipe = Pipe::with_client_and_server_config_and_buf(
        &mut client_config,
        &mut server_config,
    )
    .unwrap();
    pipe.handshake().unwrap();

    pipe
}

fn test_stream_pipe(settings: &ClientSettings) -> Pipe {
    test_stream_pipe_with_max_streams_uni(settings, 3)
}

fn test_stream_pipe_with_max_streams_uni(
    settings: &ClientSettings, max_streams_uni: u64,
) -> Pipe {
    test_stream_pipe_with_flow_control(settings, max_streams_uni, 4096)
}

fn test_stream_pipe_with_flow_control(
    settings: &ClientSettings, max_streams_uni: u64, max_data: u64,
) -> Pipe {
    let mut client_config =
        quiche::test_utils::Pipe::default_config("cubic").unwrap();
    client_config.enable_dgram(true, 10, 10);
    client_config.set_initial_max_data(max_data);
    client_config.set_initial_max_stream_data_uni(max_data);
    client_config.set_initial_max_streams_uni(max_streams_uni);
    client_config
        .set_multicast_client_params(Some(settings.transport_params.clone()))
        .unwrap();

    let mut server_config =
        quiche::test_utils::Pipe::default_config("cubic").unwrap();
    server_config.enable_dgram(true, 10, 10);
    server_config.enable_multicast_server_support(true);
    server_config.set_initial_max_data(max_data);
    server_config.set_initial_max_stream_data_uni(max_data);

    let mut pipe = Pipe::with_client_and_server_config_and_buf(
        &mut client_config,
        &mut server_config,
    )
    .unwrap();
    pipe.handshake().unwrap();

    pipe
}

fn test_ipv4_announce() -> quiche::multicast::Announce {
    quiche::multicast::Announce {
        channel_id: vec![1, 2, 3, 4],
        source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
        udp_port: 4444,
        header_protection_algorithm: 0x1301,
        header_secret: vec![0xaa; 16],
        aead_algorithm: 0x1301,
        integrity_hash_algorithm: 1,
        max_rate_kibps: 1024,
        max_ack_delay_ms: 25,
    }
}

fn test_ipv6_announce() -> quiche::multicast::Announce {
    quiche::multicast::Announce {
        channel_id: vec![7, 8, 9, 0],
        source: IpAddr::V6("2001:db8::1".parse().unwrap()),
        group: IpAddr::V6("ff3e::8000:1".parse().unwrap()),
        udp_port: 5555,
        header_protection_algorithm: 0x1301,
        header_secret: vec![0xbb; 16],
        aead_algorithm: 0x1301,
        integrity_hash_algorithm: 1,
        max_rate_kibps: 2048,
        max_ack_delay_ms: 25,
    }
}

fn test_key(channel_id: &[u8]) -> quiche::multicast::Key {
    quiche::multicast::Key {
        channel_id: channel_id.to_vec(),
        key_sequence: 1,
        from_packet_number: 0,
        secret: vec![0xcc; 16],
    }
}

fn test_limits() -> quiche::multicast::Limits {
    quiche::multicast::Limits {
        sequence: 1,
        limits: test_transport_params().limits,
        max_joined_count: 4,
    }
}

fn test_server_settings() -> ServerSettings {
    ServerSettings {
        channels: vec![ServerChannelConfig {
            channel_id: vec![1, 2, 3, 4],
            publication: PublicationConfig::new(
                Ipv4Addr::new(232, 1, 2, 3),
                4444,
            )
            .with_source_addr(Ipv4Addr::new(10, 0, 0, 1)),
            header_protection_algorithm: 0x1301,
            header_secret: vec![0xaa; 16],
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 1024,
            max_ack_delay_ms: 25,
            key_sequence: 1,
            from_packet_number: 0,
            secret: vec![0xcc; 16],
        }],
    }
}

fn test_server_control_settings() -> ServerControlSettings {
    ServerControlSettings {
        mode: ServerControlMode::Automatic,
        channels: vec![ServerControlChannelConfig {
            announce: test_ipv4_announce(),
            key: test_key(&[1, 2, 3, 4]),
        }],
        stream_integrity_batching: StreamIntegrityBatchingSettings::default(),
    }
}

fn test_client_event_channel() -> (
    ManagedEventSender<ClientEvent>,
    ClientEventStream,
    EventQueueObserver<ClientEvent>,
) {
    client_event_channel(EventQueueLimits::default())
}

fn test_server_event_channel() -> (
    ManagedEventSender<ServerEvent>,
    ServerEventStream,
    EventQueueObserver<ServerEvent>,
) {
    server_event_channel(EventQueueLimits::default())
}

include!("tests/runtime.rs");
include!("tests/client.rs");
include!("tests/server_stream.rs");
include!("tests/server_control.rs");
include!("tests/server_publish.rs");
include!("tests/server_event.rs");
