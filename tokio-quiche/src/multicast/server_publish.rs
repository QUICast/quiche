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

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::future::pending;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use mctx_core::MctxError;
use mctx_core::Publication;
use mctx_core::PublicationConfig;
use mctx_core::SendReport;
use tokio::select;
use tokio::time::sleep_until;
use tokio::time::Instant;

use crate::quic::connection::ConnectionOwnerDropHook;
use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

use super::bounded_queue::bounded_channel;
use super::bounded_queue::BoundedReceiver;
use super::bounded_queue::BoundedSender;
use super::bounded_queue::Queued;
use super::bounded_queue::RetainedDeque;
use super::bounded_queue::RetainedQueueBudget;
use super::bounded_queue::RetainedQueueObserver;
use super::bounded_queue::RetainedQueueStats;
use super::bounded_queue::RetainedSize;
use super::event_stream::server_event_channel;
use super::event_stream::EventQueueLimits;
use super::event_stream::EventQueueObserver;
use super::event_stream::EventQueueStats;
use super::event_stream::ManagedEventSender;
use super::event_stream::ServerEventStream;
use super::runtime::run_callback_work;
use super::runtime::server_ack_freshness_timeout;
use super::runtime::PUBLISH_RETRY_DELAY;
use super::server::announce_retained_size;
use super::server::integrity_retained_size;
use super::server::key_retained_size;
use super::server::ServerError;
use super::server::ServerEvent;
use super::server::ServerEventCoalescer;
use super::server::ServerSettings;
use super::ControllerSendError;
use super::RuntimeLimits;
use super::RuntimeLimitsError;
use super::ServerChannelSendError;
use super::ServerRuntimeQueueStats;

/// Handle for consuming multicast events and publishing packets.
pub struct ServerController {
    command_sender: BoundedSender<ServerCommand>,
    command_observer: RetainedQueueObserver,
    pending_publication_observer: RetainedQueueObserver,
    pending_integrity_observer: RetainedQueueObserver,
    event_receiver: Option<ServerEventStream>,
    event_observer: EventQueueObserver<ServerEvent>,
}

impl ServerController {
    /// Queues one multicast packet for the given channel.
    pub fn send_on_channel(
        &self, channel_id: Vec<u8>, frames: Vec<quiche::multicast::ChannelFrame>,
    ) -> Result<(), ServerChannelSendError> {
        if quiche::multicast::validate_channel_id(&channel_id).is_err() ||
            frames.iter().any(|frame| frame.encoded_len().is_err())
        {
            return Err(ControllerSendError::invalid((channel_id, frames)));
        }

        self.command_sender
            .try_send(ServerCommand::Send { channel_id, frames })
            .map_err(|error| {
                ControllerSendError::from_queue(error.map(|command| {
                    let ServerCommand::Send { channel_id, frames } = command
                    else {
                        unreachable!("send command changed while queued");
                    };
                    (channel_id, frames)
                }))
            })
    }

    /// Queues one externally generated `MC_INTEGRITY` frame for relay on the
    /// client-facing QUIC control connection.
    pub fn send_integrity(
        &self, frame: quiche::multicast::Integrity,
    ) -> Result<(), ControllerSendError<quiche::multicast::Integrity>> {
        if frame.validate().is_err() {
            return Err(ControllerSendError::invalid(frame));
        }

        self.command_sender
            .try_send(ServerCommand::RelayIntegrity { frame })
            .map_err(|error| {
                ControllerSendError::from_queue(error.map(|command| {
                    let ServerCommand::RelayIntegrity { frame } = command else {
                        unreachable!("integrity command changed while queued");
                    };
                    frame
                }))
            })
    }

    /// Returns the multicast event receiver if it has not been taken.
    pub fn event_receiver_mut(&mut self) -> Option<&mut ServerEventStream> {
        self.event_receiver.as_mut()
    }

    /// Takes ownership of the event receiver.
    ///
    /// A receiver can be taken only once. Later calls return `None` and do not
    /// create a replacement queue.
    pub fn take_event_receiver(&mut self) -> Option<ServerEventStream> {
        self.event_receiver.take()
    }

    /// Returns event queue counters without consuming the receiver.
    pub fn event_queue_stats(&self) -> EventQueueStats {
        self.event_observer.stats()
    }

    /// Returns command queue counters without consuming commands.
    pub fn command_queue_stats(&self) -> RetainedQueueStats {
        self.command_observer.stats()
    }

    /// Returns all retained runtime queue counters.
    pub fn runtime_queue_stats(&self) -> ServerRuntimeQueueStats {
        ServerRuntimeQueueStats {
            commands: self.command_observer.stats(),
            pending_publications: self.pending_publication_observer.stats(),
            pending_integrity: self.pending_integrity_observer.stats(),
        }
    }
}

/// Wraps another [`ApplicationOverQuic`] with multicast server send logic.
///
/// The wrapped application continues to own the regular QUIC and HTTP/3
/// behavior while this wrapper announces configured multicast channels, reacts
/// to client `MC_LIMITS` / `MC_STATE` frames, and publishes encoded multicast
/// packets via `mctx-core`.
pub struct ServerDriver<A> {
    inner: A,
    runtime: ServerRuntime<MctxPublishBackend>,
}

impl<A> ServerDriver<A> {
    /// Creates a new multicast server wrapper and its controller.
    pub fn new(
        inner: A, settings: ServerSettings,
    ) -> Result<(Self, ServerController), RuntimeLimitsError> {
        Self::new_with_runtime_limits(inner, settings, RuntimeLimits::default())
    }

    /// Creates a multicast server wrapper with explicit event queue limits.
    pub fn new_with_event_queue_limits(
        inner: A, settings: ServerSettings, event_limits: EventQueueLimits,
    ) -> Result<(Self, ServerController), RuntimeLimitsError> {
        let limits = RuntimeLimits {
            events: event_limits,
            ..RuntimeLimits::default()
        };
        Self::new_with_runtime_limits(inner, settings, limits)
    }

    /// Creates a multicast server wrapper with explicit runtime limits.
    pub fn new_with_runtime_limits(
        inner: A, settings: ServerSettings, limits: RuntimeLimits,
    ) -> Result<(Self, ServerController), RuntimeLimitsError> {
        settings
            .validate()
            .map_err(RuntimeLimitsError::InvalidMulticastSettings)?;
        let limits = limits.validate()?;
        let (command_sender, command_receiver, command_observer) =
            bounded_channel(limits.commands);
        let (event_sender, event_receiver, event_observer) =
            server_event_channel(limits.events);
        let runtime =
            ServerRuntime::new(settings, event_sender, command_receiver, limits);
        let pending_publication_observer =
            runtime.pending_publications.observer();
        let pending_integrity_observer = runtime.pending_integrities.observer();

        Ok((Self { inner, runtime }, ServerController {
            command_sender,
            command_observer,
            pending_publication_observer,
            pending_integrity_observer,
            event_receiver: Some(event_receiver),
            event_observer,
        }))
    }

    /// Returns a shared reference to the wrapped application.
    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped application.
    pub fn inner_mut(&mut self) -> &mut A {
        &mut self.inner
    }

    /// Consumes the wrapper and returns the wrapped application.
    pub fn into_inner(self) -> A {
        self.inner
    }
}

impl<A: ApplicationOverQuic> ApplicationOverQuic for ServerDriver<A> {
    fn connection_owner_drop_hook(&self) -> Option<ConnectionOwnerDropHook> {
        self.inner.connection_owner_drop_hook()
    }

    fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection,
        handshake_info: &crate::quic::HandshakeInfo,
    ) -> QuicResult<()> {
        self.runtime.on_conn_established(qconn)?;
        self.inner.on_conn_established(qconn, handshake_info)
    }

    fn should_act(&self) -> bool {
        true
    }

    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if self.runtime.has_pending_work() {
            return Ok(());
        }

        if self.inner.should_act() {
            select! {
                res = self.inner.wait_for_data(qconn) => res,
                res = self.runtime.wait_for_work() => res,
            }
        } else {
            self.runtime.wait_for_work().await
        }
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.runtime.process_reads(qconn)?;

        if self.inner.should_act() {
            self.inner.process_reads(qconn)?;
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.runtime.process_writes(qconn)?;

        if self.inner.should_act() {
            self.inner.process_writes(qconn)?;
        }

        Ok(())
    }

    fn on_conn_close<M: crate::metrics::Metrics>(
        &mut self, qconn: &mut QuicheConnection, metrics: &M,
        connection_result: &QuicResult<()>,
    ) {
        self.runtime.clear();
        self.runtime.event_sender.finish();
        self.inner.on_conn_close(qconn, metrics, connection_result);
    }
}

#[derive(Debug)]
pub(super) enum ServerCommand {
    Send {
        channel_id: Vec<u8>,
        frames: Vec<quiche::multicast::ChannelFrame>,
    },

    RelayIntegrity {
        frame: quiche::multicast::Integrity,
    },
}

impl RetainedSize for ServerCommand {
    fn retained_size(&self) -> usize {
        match self {
            Self::Send { channel_id, frames } => frames.iter().fold(
                channel_id.len().saturating_add(128),
                |total, frame| {
                    let frame_size = match frame {
                        quiche::multicast::ChannelFrame::Stream {
                            data, ..
                        } |
                        quiche::multicast::ChannelFrame::Datagram { data } =>
                            data.len().saturating_add(64),

                        quiche::multicast::ChannelFrame::Multicast(frame) =>
                            match frame {
                                quiche::multicast::Frame::Announce(frame) =>
                                    announce_retained_size(frame),

                                quiche::multicast::Frame::Key(frame) =>
                                    key_retained_size(frame),

                                quiche::multicast::Frame::Integrity(frame) =>
                                    integrity_retained_size(frame),

                                _ => 128,
                            },

                        _ => 64,
                    };
                    total.saturating_add(frame_size)
                },
            ),

            Self::RelayIntegrity { frame } => integrity_retained_size(frame),
        }
    }
}

#[derive(Debug)]
pub(super) enum ServerPendingControl {
    AnnounceAndKey {
        announce: Option<quiche::multicast::Announce>,
        key: quiche::multicast::Key,
    },
    Join(quiche::multicast::Join),
}

impl RetainedSize for ServerPendingControl {
    fn retained_size(&self) -> usize {
        match self {
            Self::AnnounceAndKey { announce, key } => announce
                .as_ref()
                .map_or(0, announce_retained_size)
                .saturating_add(key_retained_size(key)),

            Self::Join(frame) => frame.channel_id.len().saturating_add(64),
        }
    }
}

pub(super) struct PendingServerControl {
    command: Queued<ServerPendingControl>,
    blocked_since: Option<Instant>,
}

#[derive(Debug)]
pub(super) struct PendingPublication {
    pub(super) channel_id: Vec<u8>,
    pub(super) packet: Vec<u8>,
    pub(super) packet_number: u64,
    pub(super) integrity: quiche::multicast::Integrity,
}

impl RetainedSize for PendingPublication {
    fn retained_size(&self) -> usize {
        self.channel_id
            .len()
            .saturating_add(self.packet.len())
            .saturating_add(integrity_retained_size(&self.integrity))
            .saturating_add(128)
    }
}

pub(super) struct ServerRuntime<B: PublishBackend> {
    pub(super) settings: ServerSettings,
    pub(super) limits: RuntimeLimits,
    pub(super) event_sender: ManagedEventSender<ServerEvent>,
    pub(super) command_receiver: BoundedReceiver<ServerCommand>,
    pub(super) control_budget: RetainedQueueBudget<ServerPendingControl>,
    pub(super) pending_commands: VecDeque<Queued<ServerCommand>>,
    pub(super) pending_controls: VecDeque<PendingServerControl>,
    pub(super) pending_publications: RetainedDeque<PendingPublication>,
    pub(super) pending_integrities: RetainedDeque<quiche::multicast::Integrity>,
    pub(super) control_retry_deadline: Option<Instant>,
    pub(super) publish_retry_deadline: Option<Instant>,
    pub(super) integrity_retry_blocked: bool,
    pub(super) channels: BTreeMap<Vec<u8>, ServerChannel<B::Publication>>,
    pub(super) backend: B,
    pub(super) event_coalescer: ServerEventCoalescer,
    pub(super) control_read_pending: bool,
    pub(super) read_work_cursor: usize,
    pub(super) write_work_cursor: usize,
    #[cfg(test)]
    pub(super) callback_read_work_last_call: usize,
    #[cfg(test)]
    pub(super) callback_write_work_last_call: usize,
}

impl ServerRuntime<MctxPublishBackend> {
    pub(super) fn new(
        settings: ServerSettings, event_sender: ManagedEventSender<ServerEvent>,
        command_receiver: BoundedReceiver<ServerCommand>, limits: RuntimeLimits,
    ) -> Self {
        Self::with_backend_and_limits(
            settings,
            event_sender,
            command_receiver,
            MctxPublishBackend,
            limits,
        )
    }
}

impl<B: PublishBackend> ServerRuntime<B> {
    #[cfg(test)]
    pub(super) fn with_backend(
        settings: ServerSettings, event_sender: ManagedEventSender<ServerEvent>,
        command_receiver: BoundedReceiver<ServerCommand>, backend: B,
    ) -> Self {
        Self::with_backend_and_limits(
            settings,
            event_sender,
            command_receiver,
            backend,
            RuntimeLimits::default(),
        )
    }

    pub(super) fn with_backend_and_limits(
        settings: ServerSettings, event_sender: ManagedEventSender<ServerEvent>,
        command_receiver: BoundedReceiver<ServerCommand>, backend: B,
        limits: RuntimeLimits,
    ) -> Self {
        let control_budget = command_receiver.budget().cast();
        Self {
            settings,
            limits,
            event_sender,
            command_receiver,
            control_budget,
            pending_commands: VecDeque::new(),
            pending_controls: VecDeque::new(),
            pending_publications: RetainedDeque::new(limits.pending_publications),
            pending_integrities: RetainedDeque::new(limits.pending_integrity),
            control_retry_deadline: None,
            publish_retry_deadline: None,
            integrity_retry_blocked: false,
            channels: BTreeMap::new(),
            backend,
            event_coalescer: ServerEventCoalescer::default(),
            control_read_pending: false,
            read_work_cursor: 0,
            write_work_cursor: 0,
            #[cfg(test)]
            callback_read_work_last_call: 0,
            #[cfg(test)]
            callback_write_work_last_call: 0,
        }
    }

    pub(super) fn clear(&mut self) {
        self.command_receiver.close();
        self.pending_commands.clear();
        self.pending_controls.clear();
        self.pending_publications.clear();
        self.pending_integrities.clear();
        self.control_retry_deadline = None;
        self.publish_retry_deadline = None;
        self.integrity_retry_blocked = false;
        self.channels.clear();
        self.event_coalescer.clear();
        self.control_read_pending = false;
        self.read_work_cursor = 0;
        self.write_work_cursor = 0;

        while self.command_receiver.try_recv().is_ok() {}
    }

    pub(super) fn has_pending_work(&self) -> bool {
        let publication_ready = !self.pending_publications.is_empty() &&
            self.publish_retry_deadline
                .is_none_or(|deadline| deadline <= Instant::now());
        self.control_read_pending ||
            self.event_coalescer.has_pending_client_acks() ||
            !self.pending_commands.is_empty() ||
            (!self.pending_controls.is_empty() &&
                self.control_retry_deadline
                    .is_none_or(|deadline| deadline <= Instant::now())) ||
            publication_ready ||
            (!self.pending_integrities.is_empty() &&
                !self.integrity_retry_blocked)
    }

    pub(super) async fn wait_for_work(&mut self) -> QuicResult<()> {
        let deadline =
            match (self.control_retry_deadline, self.publish_retry_deadline) {
                (Some(control), Some(publication)) =>
                    Some(control.min(publication)),
                (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
                (None, None) => None,
            };
        if let Some(deadline) = deadline {
            select! {
                command = self.command_receiver.recv() => {
                    match command {
                        Some(command) => {
                            self.pending_commands.push_back(command);
                            Ok(())
                        },

                        None => {
                            #[allow(unreachable_code)]
                            {
                                pending::<()>().await;
                                Ok(())
                            }
                        },
                    }
                },

                _ = sleep_until(deadline) => Ok(()),
            }
        } else {
            match self.command_receiver.recv().await {
                Some(command) => {
                    self.pending_commands.push_back(command);
                    Ok(())
                },

                None => {
                    #[allow(unreachable_code)]
                    {
                        pending::<()>().await;
                        Ok(())
                    }
                },
            }
        }
    }

    pub(super) fn on_conn_established(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if !qconn.is_server() {
            return Err(Box::new(ServerError::ClientConnectionUnsupported));
        }

        if self.peer_supports_multicast(qconn) {
            self.initialize_channels(qconn)?;
            self.flush_pending_controls(qconn)?;
        }

        Ok(())
    }

    pub(super) fn process_reads(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let mut cursor = self.read_work_cursor;
        let work = run_callback_work(
            self.limits.max_work_per_call,
            &mut cursor,
            3,
            |class| match class {
                0 => self.process_one_control_frame(qconn),
                1 => self
                    .event_coalescer
                    .flush_client_acks(&self.event_sender, 1)
                    .map(|work| work > 0)
                    .map_err(Into::into),
                2 => self.flush_one_pending_server_control(qconn),
                _ => unreachable!("server read work class is in range"),
            },
        )?;
        self.read_work_cursor = cursor;
        self.control_read_pending = qconn.is_multicast_readable();

        #[cfg(test)]
        {
            self.callback_read_work_last_call = work;
        }

        debug_assert!(work <= self.limits.max_work_per_call);
        Ok(())
    }

    pub(super) fn process_writes(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        self.integrity_retry_blocked = false;
        let mut cursor = self.write_work_cursor;
        let work = run_callback_work(
            self.limits.max_work_per_call,
            &mut cursor,
            5,
            |class| match class {
                0 => Ok(self.transfer_one_server_command()),
                1 => self.flush_one_pending_server_control(qconn),
                2 => self.encode_one_pending_command(qconn),
                3 => self.flush_one_pending_publication(),
                4 => self.flush_one_pending_server_integrity(qconn),
                _ => unreachable!("server write work class is in range"),
            },
        )?;
        self.write_work_cursor = cursor;

        #[cfg(test)]
        {
            self.callback_write_work_last_call = work;
        }

        debug_assert!(work <= self.limits.max_work_per_call);
        Ok(())
    }

    pub(super) fn transfer_one_server_command(&mut self) -> bool {
        let Ok(command) = self.command_receiver.try_recv() else {
            return false;
        };
        self.pending_commands.push_back(command);
        true
    }

    pub(super) fn process_one_control_frame(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        match qconn.multicast_recv() {
            Ok(frame) => {
                self.handle_frame(qconn, frame)?;
                Ok(true)
            },

            Err(quiche::Error::Done) => {
                self.control_read_pending = false;
                Ok(false)
            },

            Err(err) => Err(err.into()),
        }
    }

    pub(super) fn initialize_channels(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if !self.channels.is_empty() {
            return Ok(());
        }

        for index in 0..self.settings.channels.len() {
            let channel_id = self.settings.channels[index].channel_id.clone();
            if !self.channels.contains_key(&channel_id) &&
                self.channels.len() >= self.limits.max_tracked_channel_ids
            {
                return Err(Box::new(ServerError::TrackedChannelIdLimit(
                    self.limits.max_tracked_channel_ids,
                )));
            }

            let (channel_id, max_ack_delay_ms, publication, control, send_state) = {
                let config = &self.settings.channels[index];
                let publication = self.backend.open(&config.publication)?;
                let (source, group, udp_port) =
                    self.backend.announce_tuple(&publication)?;
                let control =
                    config.control_channel_from(source, group, udp_port)?;
                let send_state = quiche::multicast::ChannelSendState::new(
                    control.announce.clone(),
                    control.key.clone(),
                )?;
                (
                    config.channel_id.clone(),
                    config.max_ack_delay_ms,
                    publication,
                    control,
                    send_state,
                )
            };

            if qconn.multicast_default_dgram_channel().is_none() {
                qconn.multicast_set_default_dgram_channel(Some(
                    channel_id.clone(),
                ))?;
            }
            qconn.multicast_set_ack_timeout(
                &channel_id,
                Some(server_ack_freshness_timeout(max_ack_delay_ms)),
            )?;

            self.queue_server_control(ServerPendingControl::AnnounceAndKey {
                announce: Some(control.announce),
                key: control.key,
            })?;

            self.channels.insert(channel_id, ServerChannel {
                publication,
                send_state,
                join_sent: false,
                join_pending: false,
            });
        }

        Ok(())
    }

    pub(super) fn handle_frame(
        &mut self, qconn: &mut QuicheConnection, frame: quiche::multicast::Frame,
    ) -> QuicResult<()> {
        match frame {
            quiche::multicast::Frame::Limits(frame) => {
                self.handle_limits(qconn, frame)?;
            },

            quiche::multicast::Frame::State(frame) => {
                if frame.state == quiche::multicast::ChannelState::Retired {
                    self.event_coalescer.reset_channel(&frame.channel_id);
                }
                self.event_sender
                    .try_send(ServerEvent::ClientState(frame))?;
            },

            quiche::multicast::Frame::Ack(frame) => {
                if let Some(channel) = self.channels.get_mut(&frame.channel_id) {
                    channel.send_state.on_ack(&frame)?;
                    qconn.multicast_process_peer_ack(frame.clone())?;
                    self.event_coalescer
                        .queue_client_ack(&self.event_sender, frame);
                } else {
                    self.event_sender.try_send(ServerEvent::ClientAck(frame))?;
                }
            },

            quiche::multicast::Frame::Announce(..) |
            quiche::multicast::Frame::Key(..) |
            quiche::multicast::Frame::Join(..) |
            quiche::multicast::Frame::Leave(..) |
            quiche::multicast::Frame::Integrity(..) |
            quiche::multicast::Frame::Retire(..) => (),
        }

        Ok(())
    }

    pub(super) fn handle_limits(
        &mut self, _qconn: &mut QuicheConnection,
        frame: quiche::multicast::Limits,
    ) -> QuicResult<()> {
        let sequence = frame.sequence;
        self.event_sender
            .try_send(ServerEvent::ClientLimits(frame))?;

        let channel_ids: Vec<Vec<u8>> = self.channels.keys().cloned().collect();
        for channel_id in channel_ids {
            let Some(channel) = self.channels.get(&channel_id) else {
                continue;
            };
            if channel.join_sent || channel.join_pending {
                continue;
            }

            let frame = quiche::multicast::Join {
                channel_id: channel.send_state.announce().channel_id.clone(),
                mc_limits_sequence: sequence,
                mc_state_sequence: 0,
                mc_key_sequence: channel.send_state.key().key_sequence,
            };
            self.queue_server_control(ServerPendingControl::Join(frame))?;
            self.channels
                .get_mut(&channel_id)
                .expect("channel was collected above")
                .join_pending = true;
        }

        Ok(())
    }

    pub(super) fn queue_server_control(
        &mut self, command: ServerPendingControl,
    ) -> QuicResult<()> {
        let command = self.control_budget.wrap(command).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("control"))
                as crate::result::BoxError
        })?;
        self.pending_controls.push_back(PendingServerControl {
            command,
            blocked_since: None,
        });
        Ok(())
    }

    pub(super) fn flush_pending_controls(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        self.flush_pending_controls_with_limit(
            qconn,
            self.limits.max_work_per_call,
        )
        .map(|_| ())
    }

    pub(super) fn flush_one_pending_server_control(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_controls_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    pub(super) fn flush_pending_controls_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        if self
            .control_retry_deadline
            .is_some_and(|deadline| deadline > Instant::now())
        {
            return Ok(0);
        }
        self.control_retry_deadline = None;
        let mut work = 0;

        for _ in 0..max_work {
            let Some(mut pending) = self.pending_controls.pop_front() else {
                break;
            };
            work += 1;
            let command = pending.command.take();

            match command {
                ServerPendingControl::AnnounceAndKey {
                    announce: Some(announce),
                    key,
                } => match qconn.multicast_try_send(
                    quiche::multicast::Frame::Announce(announce),
                ) {
                    Ok(()) => {
                        pending.command.restore(
                            ServerPendingControl::AnnounceAndKey {
                                announce: None,
                                key,
                            },
                        );
                        pending.blocked_since = None;
                        self.pending_controls.push_front(pending);
                    },

                    Err(error)
                        if error.kind() ==
                            quiche::multicast::ControlSendErrorKind::Full =>
                    {
                        let quiche::multicast::Frame::Announce(announce) =
                            error.into_frame()
                        else {
                            unreachable!("core returned another frame");
                        };
                        pending.command.restore(
                            ServerPendingControl::AnnounceAndKey {
                                announce: Some(announce),
                                key,
                            },
                        );
                        self.retry_server_control(pending)?;
                        break;
                    },

                    Err(error) => return Err(Box::new(error)),
                },

                ServerPendingControl::AnnounceAndKey {
                    announce: None,
                    key,
                } => match qconn
                    .multicast_try_send(quiche::multicast::Frame::Key(key))
                {
                    Ok(()) => (),

                    Err(error)
                        if error.kind() ==
                            quiche::multicast::ControlSendErrorKind::Full =>
                    {
                        let quiche::multicast::Frame::Key(key) =
                            error.into_frame()
                        else {
                            unreachable!("core returned another frame");
                        };
                        pending.command.restore(
                            ServerPendingControl::AnnounceAndKey {
                                announce: None,
                                key,
                            },
                        );
                        self.retry_server_control(pending)?;
                        break;
                    },

                    Err(error) => return Err(Box::new(error)),
                },

                ServerPendingControl::Join(frame) => {
                    let channel_id = frame.channel_id.clone();
                    match qconn
                        .multicast_try_send(quiche::multicast::Frame::Join(frame))
                    {
                        Ok(()) => {
                            if let Some(channel) =
                                self.channels.get_mut(&channel_id)
                            {
                                channel.join_sent = true;
                                channel.join_pending = false;
                            }
                        },

                        Err(error)
                            if error.kind() ==
                                quiche::multicast::ControlSendErrorKind::Full =>
                        {
                            let quiche::multicast::Frame::Join(frame) =
                                error.into_frame()
                            else {
                                unreachable!("core returned another frame");
                            };
                            pending
                                .command
                                .restore(ServerPendingControl::Join(frame));
                            self.retry_server_control(pending)?;
                            break;
                        },

                        Err(error) => return Err(Box::new(error)),
                    }
                },
            }
        }

        Ok(work)
    }

    pub(super) fn retry_server_control(
        &mut self, mut pending: PendingServerControl,
    ) -> QuicResult<()> {
        let now = Instant::now();
        let retry_deadline = now
            .checked_add(self.limits.control_retry_delay)
            .ok_or(quiche::Error::InvalidState)?;
        let blocked_since = *pending.blocked_since.get_or_insert(now);
        if now.saturating_duration_since(blocked_since) >=
            self.limits.control_backpressure_timeout
        {
            return Err(Box::new(ServerError::ControlBackpressureTimeout(
                self.limits.control_backpressure_timeout,
            )));
        }

        self.pending_controls.push_front(pending);
        self.control_retry_deadline = Some(retry_deadline);
        Ok(())
    }

    pub(super) fn encode_one_pending_command(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        if !self.pending_controls.is_empty() {
            return Ok(false);
        }

        self.encode_pending_commands_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    pub(super) fn encode_pending_commands_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        let mut work = 0;
        for _ in 0..max_work {
            let Some(command) = self.pending_commands.pop_front() else {
                break;
            };
            work += 1;
            match command.into_inner() {
                ServerCommand::Send { channel_id, frames } => {
                    let Some(channel) = self.channels.get_mut(&channel_id) else {
                        self.event_sender.try_send(ServerEvent::EncodeError {
                            channel_id,
                            error: quiche::Error::InvalidState,
                        })?;
                        continue;
                    };

                    for frame in &frames {
                        let quiche::multicast::ChannelFrame::Datagram { data } =
                            frame
                        else {
                            continue;
                        };

                        // DATAGRAM fallback is best-effort, matching the QUIC
                        // DATAGRAM API. Multicast publication and integrity
                        // relay still proceed even if the unicast queue is full.
                        let _ = qconn.multicast_dgram_send(&channel_id, data);
                    }

                    let packet_len = match channel.send_state.packet_len(&frames)
                    {
                        Ok(packet_len) => packet_len,

                        Err(error) => {
                            self.event_sender.try_send(
                                ServerEvent::EncodeError { channel_id, error },
                            )?;
                            continue;
                        },
                    };
                    let mut packet = vec![0; packet_len];

                    match channel.send_state.write_packet(&frames, &mut packet) {
                        Ok(output) => {
                            debug_assert_eq!(output.packet_len, packet_len);
                            packet.truncate(output.packet_len);
                            self.queue_publication(PendingPublication {
                                channel_id,
                                packet,
                                packet_number: output.packet_number,
                                integrity: output.integrity,
                            })?;
                        },

                        Err(error) => {
                            self.event_sender.try_send(
                                ServerEvent::EncodeError { channel_id, error },
                            )?;
                        },
                    }
                },

                ServerCommand::RelayIntegrity { frame } => {
                    self.queue_integrity(frame)?;
                },
            }
        }

        Ok(work)
    }

    pub(super) fn flush_one_pending_publication(&mut self) -> QuicResult<bool> {
        self.flush_pending_publications_with_limit(1)
            .map(|work| work > 0)
    }

    pub(super) fn flush_pending_publications_with_limit(
        &mut self, max_work: usize,
    ) -> QuicResult<usize> {
        if self
            .publish_retry_deadline
            .is_some_and(|deadline| deadline > Instant::now())
        {
            return Ok(0);
        }

        let mut work = 0;
        for _ in 0..max_work {
            let Some(pending) = self.pending_publications.pop_front() else {
                break;
            };
            work += 1;
            let Some(channel) = self.channels.get(&pending.channel_id) else {
                self.event_sender.try_send(ServerEvent::EncodeError {
                    channel_id: pending.channel_id,
                    error: quiche::Error::InvalidState,
                })?;
                continue;
            };

            match self.backend.send(&channel.publication, &pending.packet) {
                Ok(report) => {
                    self.queue_integrity(pending.integrity)?;
                    self.event_sender.try_send(ServerEvent::Published {
                        channel_id: pending.channel_id,
                        packet_number: pending.packet_number,
                        report,
                    })?;
                },

                Err(error) if publish_would_block(&error) => {
                    let retry_deadline = Instant::now()
                        .checked_add(PUBLISH_RETRY_DELAY)
                        .ok_or(quiche::Error::InvalidState)?;
                    self.pending_publications.push_front(pending).map_err(
                        |_| {
                            Box::new(ServerError::RuntimeQueueExhausted(
                                "publication",
                            ))
                                as crate::result::BoxError
                        },
                    )?;
                    self.publish_retry_deadline = Some(retry_deadline);
                    return Ok(work);
                },

                Err(error) => {
                    self.event_sender.try_send(ServerEvent::PublishError {
                        channel_id: pending.channel_id,
                        error,
                    })?;
                },
            }
        }

        if self.pending_publications.is_empty() {
            self.publish_retry_deadline = None;
        }

        Ok(work)
    }

    pub(super) fn queue_publication(
        &mut self, pending: PendingPublication,
    ) -> QuicResult<()> {
        self.pending_publications.push_back(pending).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("publication"))
                as crate::result::BoxError
        })
    }

    pub(super) fn queue_integrity(
        &mut self, frame: quiche::multicast::Integrity,
    ) -> QuicResult<()> {
        self.pending_integrities.push_back(frame).map_err(|_| {
            Box::new(ServerError::RuntimeQueueExhausted("integrity"))
                as crate::result::BoxError
        })
    }

    pub(super) fn flush_one_pending_server_integrity(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<bool> {
        self.flush_pending_integrities_with_limit(qconn, 1)
            .map(|work| work > 0)
    }

    pub(super) fn flush_pending_integrities_with_limit(
        &mut self, qconn: &mut QuicheConnection, max_work: usize,
    ) -> QuicResult<usize> {
        let mut work = 0;
        for _ in 0..max_work {
            let Some(frame) = self.pending_integrities.pop_front() else {
                break;
            };
            work += 1;
            if let Err(error) = qconn
                .multicast_try_send(quiche::multicast::Frame::Integrity(frame))
            {
                if error.kind() != quiche::multicast::ControlSendErrorKind::Full {
                    return Err(Box::new(error));
                }
                let quiche::multicast::Frame::Integrity(frame) =
                    error.into_frame()
                else {
                    unreachable!("core returned another frame");
                };
                self.pending_integrities.push_front(frame).map_err(|_| {
                    Box::new(ServerError::RuntimeQueueExhausted("integrity"))
                        as crate::result::BoxError
                })?;
                self.integrity_retry_blocked = true;
                break;
            }
        }

        Ok(work)
    }

    pub(super) fn peer_supports_multicast(
        &self, qconn: &QuicheConnection,
    ) -> bool {
        qconn
            .peer_transport_params()
            .and_then(|params| params.multicast_client_params.as_ref())
            .is_some()
    }
}

pub(super) struct ServerChannel<P> {
    publication: P,
    pub(super) send_state: quiche::multicast::ChannelSendState,
    join_sent: bool,
    join_pending: bool,
}

pub(super) trait PublishBackend {
    type Publication;

    fn open(
        &mut self, config: &PublicationConfig,
    ) -> Result<Self::Publication, MctxError>;

    fn announce_tuple(
        &self, publication: &Self::Publication,
    ) -> Result<(Ipv4Addr, Ipv4Addr, u16), MctxError>;

    fn send(
        &self, publication: &Self::Publication, payload: &[u8],
    ) -> Result<SendReport, MctxError>;
}

struct MctxPublishBackend;

impl PublishBackend for MctxPublishBackend {
    type Publication = Publication;

    fn open(
        &mut self, config: &PublicationConfig,
    ) -> Result<Self::Publication, MctxError> {
        mctx_core::Publication::new(mctx_core::PublicationId(0), config.clone())
    }

    fn announce_tuple(
        &self, publication: &Self::Publication,
    ) -> Result<(Ipv4Addr, Ipv4Addr, u16), MctxError> {
        match publication.announce_tuple()? {
            (IpAddr::V4(source), IpAddr::V4(group), udp_port) =>
                Ok((source, group, udp_port)),

            _ => Err(MctxError::OutgoingInterfaceFamilyMismatch),
        }
    }

    fn send(
        &self, publication: &Self::Publication, payload: &[u8],
    ) -> Result<SendReport, MctxError> {
        publication.send(payload)
    }
}

fn publish_would_block(error: &MctxError) -> bool {
    matches!(error, MctxError::SendFailed(err) if err.kind() == std::io::ErrorKind::WouldBlock)
}
