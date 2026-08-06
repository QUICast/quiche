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

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use datagram_socket::StreamClosureKind;
use foundations::telemetry::log;
use quiche::h3;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot;

use super::datagram;
use super::response_status;
use super::webtransport;
use super::webtransport_connect_requirements;
use super::DriverHooks;
use super::H3Command;
use super::H3ConnectionError;
use super::H3ConnectionResult;
use super::H3Controller;
use super::H3Driver;
use super::H3Event;
use super::InboundFrameStream;
use super::InboundHeaders;
use super::IncomingH3Headers;
use super::OutboundFrameSender;
use super::RequestSender;
use super::StreamCtx;
use super::WebTransportRequirements;
use super::WebTransportSessionCloseReason;
use crate::http3::settings::Http3Settings;
use crate::quic::HandshakeInfo;
use crate::quic::QuicCommand;
use crate::quic::QuicheConnection;

/// An [H3Driver] for a client-side HTTP/3 connection. See [H3Driver] for
/// details. Emits [`ClientH3Event`]s and expects [`ClientH3Command`]s for
/// control.
pub type ClientH3Driver = H3Driver<ClientHooks>;
/// The [H3Controller] type paired with [ClientH3Driver]. See [H3Controller] for
/// details.
pub type ClientH3Controller = H3Controller<ClientHooks>;
/// Receives [`ClientH3Event`]s from a [ClientH3Driver]. This is the control
/// stream which describes what is happening on the connection, but does not
/// transfer data.
pub type ClientEventStream = mpsc::Receiver<ClientH3Event>;
/// A [RequestSender] to send HTTP requests over a [ClientH3Driver]'s
/// connection.
pub type ClientRequestSender = RequestSender<ClientH3Command, NewClientRequest>;

/// An HTTP request sent using a [ClientRequestSender] to the [ClientH3Driver].
#[derive(Debug)]
pub struct NewClientRequest {
    /// A user-defined identifier to match [`ClientH3Event::NewOutboundRequest`]
    /// to its original [`NewClientRequest`]. This ID is not used anywhere else.
    pub request_id: u64,
    /// The [`h3::Header`]s that make up this request.
    pub headers: Vec<h3::Header>,
    /// A sender to pass the request's [`OutboundFrameSender`] to the request
    /// body.
    pub body_writer: Option<oneshot::Sender<OutboundFrameSender>>,
}

/// Events produced by [ClientH3Driver].
#[derive(Debug)]
pub enum ClientH3Event {
    Core(H3Event),
    /// Headers for the request with the given `request_id` were sent on
    /// `stream_id`. The body, if there is one, could still be sending.
    NewOutboundRequest {
        stream_id: u64,
        request_id: u64,
    },
    /// A native WebTransport CONNECT was not sent because the peer or local
    /// transport did not satisfy draft-16's required negotiation settings.
    WebTransportRequestRejected {
        /// User-provided request identifier from [`NewClientRequest`].
        request_id: u64,
    },
}

impl From<H3Event> for ClientH3Event {
    fn from(ev: H3Event) -> Self {
        Self::Core(ev)
    }
}

/// Commands accepted by [ClientH3Driver].
#[derive(Debug)]
pub enum ClientH3Command {
    Core(H3Command),
    /// Send a new HTTP request over the [`quiche::h3::Connection`]. The driver
    /// will allocate a stream ID and report it back to the controller via
    /// [`ClientH3Event::NewOutboundRequest`].
    ClientRequest(NewClientRequest),
}

impl From<H3Command> for ClientH3Command {
    fn from(cmd: H3Command) -> Self {
        Self::Core(cmd)
    }
}

impl From<QuicCommand> for ClientH3Command {
    fn from(cmd: QuicCommand) -> Self {
        Self::Core(H3Command::QuicCmd(cmd))
    }
}

impl From<NewClientRequest> for ClientH3Command {
    fn from(req: NewClientRequest) -> Self {
        Self::ClientRequest(req)
    }
}

/// A [`PendingClientRequest`] is a request which has not yet received a
/// response.
///
/// The `send` and `recv` halves are passed to the [ClientH3Controller] in an
/// [`H3Event::IncomingHeaders`] once the server's response has been received.
struct PendingClientRequest {
    send: OutboundFrameSender,
    recv: InboundFrameStream,
}

/// Retry delay when `StreamBlocked` or `StreamLimit` is returned by
/// `send_request`. Both errors are transient: the peer will open more
/// stream credit or flow-control window within a few milliseconds.
const BLOCKED_RETRY_DELAY: Duration = Duration::from_millis(5);

pub struct ClientHooks {
    /// Mapping from stream IDs to the associated [`PendingClientRequest`].
    pending_requests: BTreeMap<u64, PendingClientRequest>,
    /// Requests that could not be sent yet due to `StreamBlocked` or
    /// `StreamLimit`. They will be retried after [`BLOCKED_RETRY_DELAY`].
    queued_requests: VecDeque<NewClientRequest>,
    /// Native CONNECTs waiting for the server SETTINGS frame.
    queued_webtransport_requests: VecDeque<NewClientRequest>,
    /// A sender back into the driver's own command channel, used to
    /// re-enqueue blocked requests after the retry delay.
    ///
    /// Initialised in `conn_established`; `None` before the connection
    /// is established.
    self_cmd_sender: Option<mpsc::Sender<ClientH3Command>>,
}

impl ClientHooks {
    #[cfg(test)]
    pub(crate) fn queued_webtransport_request_count(&self) -> usize {
        self.queued_webtransport_requests.len()
    }

    /// Returns `true` when `err` from `h3::Connection::send_request` means the
    /// request should be retried after a short delay rather than treated as a
    /// fatal connection error.
    ///
    /// `send_request` rolls back any partial stream state before returning
    /// these errors, so retrying the call with the same arguments is safe.
    ///
    /// * `StreamBlocked` — the QUIC stream's flow-control window is temporarily
    ///   exhausted; the stream entry is removed by `send_request` before
    ///   returning, so the stream ID is not consumed.
    /// * `TransportError(StreamLimit)` — the peer's concurrent-stream limit has
    ///   been reached; QUIC will deliver a MAX_STREAMS frame when credit opens
    ///   up.
    fn is_retriable_send_error(err: &h3::Error) -> bool {
        matches!(
            err,
            h3::Error::StreamBlocked |
                h3::Error::TransportError(quiche::Error::StreamLimit)
        )
    }

    /// Initiates a client-side request. This sends the request, stores the
    /// [`PendingClientRequest`] and allocates a new stream plus potential
    /// DATAGRAM flow (CONNECT-{UDP,IP}).
    ///
    /// If the connection temporarily cannot open a new stream (`StreamBlocked`
    /// or `StreamLimit`), the request is pushed onto `queued_requests` and
    /// will be retried after [`BLOCKED_RETRY_DELAY`].
    fn initiate_request(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        request: NewClientRequest,
    ) -> H3ConnectionResult<()> {
        if let Some(limits) = driver.bounded_connect_header_limits() {
            if limits.validate(&request.headers).is_err() ||
                !driver.is_webtransport_connect_candidate(&request.headers)
            {
                return Err(H3ConnectionError::H3(h3::Error::MessageError));
            }
        }
        let body_finished = request.body_writer.is_none();
        let is_webtransport = driver.webtransport.is_some() &&
            driver.is_webtransport_connect_candidate(&request.headers);
        if is_webtransport {
            let queued_candidate =
                !driver.hooks.queued_webtransport_requests.is_empty() ||
                    driver.hooks.queued_requests.iter().any(|queued| {
                        driver.is_webtransport_connect_candidate(&queued.headers)
                    });
            if queued_candidate {
                driver.h3_event_sender.send(
                    ClientH3Event::WebTransportRequestRejected {
                        request_id: request.request_id,
                    },
                )?;
                return Ok(());
            }
            if !driver
                .webtransport
                .as_ref()
                .is_some_and(webtransport::Runtime::can_start_session)
            {
                driver.h3_event_sender.send(
                    ClientH3Event::WebTransportRequestRejected {
                        request_id: request.request_id,
                    },
                )?;
                return Ok(());
            }
            match webtransport_connect_requirements(
                driver
                    .conn
                    .as_ref()
                    .ok_or_else(H3Driver::<Self>::connection_not_present)?,
                qconn,
                &request.headers,
                driver.allows_standard_webtransport_reset(),
            ) {
                WebTransportRequirements::Pending => {
                    driver.hooks.queued_webtransport_requests.push_back(request);
                    return Ok(());
                },
                WebTransportRequirements::Failed => {
                    driver.h3_event_sender.send(
                        ClientH3Event::WebTransportRequestRejected {
                            request_id: request.request_id,
                        },
                    )?;
                    return Ok(());
                },
                WebTransportRequirements::Met(_) => {},
            }
        }

        let stream_id = match driver.conn_mut()?.send_request(
            qconn,
            &request.headers,
            body_finished,
        ) {
            Ok(id) => id,
            Err(ref err) if Self::is_retriable_send_error(err) => {
                log::debug!(
                    "send_request blocked, queuing for retry";
                    "request_id" => request.request_id,
                    "error" => %err,
                );
                driver.hooks.queued_requests.push_back(request);
                return Ok(());
            },
            Err(err) => return Err(H3ConnectionError::from(err)),
        };

        // log::info!("sent h3 request"; "stream_id" => stream_id);
        let (mut stream_ctx, send, recv) =
            StreamCtx::new(stream_id, driver.stream_channel_capacity());

        if body_finished {
            // `send_request()` already sent FIN for bodyless requests, so
            // mark the send side complete and drop the outbound-frame receiver
            // since no body will be sent.
            stream_ctx.fin_or_reset_sent = true;
            stream_ctx.recv = None;
            stream_ctx
                .audit_stats
                .set_sent_stream_fin(StreamClosureKind::Explicit);
        }

        if !is_webtransport {
            if let Some(quarter_stream_id) =
                datagram::extract_quarter_stream_id(stream_id, &request.headers)
            {
                log::info!(
                    "creating new flow for MASQUE request";
                    "stream_id" => stream_id,
                    "quarter_stream_id" => quarter_stream_id,
                );
                let _ = driver.get_or_insert_flow(quarter_stream_id)?;
                stream_ctx.associated_dgram_flow_id = Some(quarter_stream_id);
            }
        }

        if let Some(body_writer) = request.body_writer {
            let _ = body_writer.send(send.clone());
            driver
                .waiting_streams
                .push(stream_ctx.wait_for_recv(stream_id));
        }

        driver.insert_stream(stream_id, stream_ctx);
        driver
            .hooks
            .pending_requests
            .insert(stream_id, PendingClientRequest { send, recv });

        if let Some(runtime) = driver.webtransport.as_mut() {
            let mut events =
                match runtime.observe_request(stream_id, is_webtransport) {
                    webtransport::RequestObservation::Observed(events) => events,
                    webtransport::RequestObservation::Excessive => {
                        let _ = driver.h3_event_sender.send(
                            ClientH3Event::WebTransportRequestRejected {
                                request_id: request.request_id,
                            },
                        );
                        return Ok(());
                    },
                };
            if is_webtransport && body_finished {
                events.extend(
                    runtime.terminate(
                        stream_id,
                        WebTransportSessionCloseReason::Clean,
                    ),
                );
                runtime.mark_connect_send_closed(stream_id);
            }
            H3Driver::<Self>::emit_webtransport_events(
                &driver.h3_event_sender,
                events,
            )?;
        }

        // Notify the H3Controller that we've allocated a stream_id for a
        // given request_id.
        let _ = driver
            .h3_event_sender
            .send(ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id: request.request_id,
            });

        Ok(())
    }

    /// Handles a response from the peer by sending a relevant [`H3Event`] to
    /// the [ClientH3Controller] for application-level processing.
    fn handle_response(
        driver: &mut H3Driver<Self>, headers: InboundHeaders,
        pending_request: PendingClientRequest,
    ) -> H3ConnectionResult<()> {
        let InboundHeaders {
            stream_id,
            headers,
            has_body,
        } = headers;

        let Some(stream_ctx) = driver.stream_map.get(&stream_id) else {
            // todo(fisher): send better error to client
            return Err(H3ConnectionError::NonexistentStream);
        };

        let headers = IncomingH3Headers {
            stream_id,
            headers,
            send: pending_request.send,
            recv: pending_request.recv,
            read_fin: !has_body,
            h3_audit_stats: Arc::clone(&stream_ctx.audit_stats),
        };

        driver
            .h3_event_sender
            .send(H3Event::IncomingHeaders(headers).into())
    }
}

#[allow(private_interfaces)]
impl DriverHooks for ClientHooks {
    type Command = ClientH3Command;
    type Event = ClientH3Event;

    fn new(_settings: &Http3Settings) -> Self {
        Self {
            pending_requests: BTreeMap::new(),
            queued_requests: VecDeque::new(),
            queued_webtransport_requests: VecDeque::new(),
            self_cmd_sender: None,
        }
    }

    fn conn_established(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> H3ConnectionResult<()> {
        assert!(
            !qconn.is_server(),
            "ClientH3Driver requires a client-side QUIC connection"
        );
        driver.hooks.self_cmd_sender = Some(driver.self_cmd_sender().clone());
        Ok(())
    }

    fn headers_received(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        headers: InboundHeaders,
    ) -> H3ConnectionResult<()> {
        if driver
            .bounded_connect_header_limits()
            .is_some_and(|limits| limits.validate(&headers.headers).is_err())
        {
            if let Some(runtime) = driver.webtransport.as_mut() {
                let events = runtime.terminate(
                    headers.stream_id,
                    WebTransportSessionCloseReason::ProtocolError,
                );
                H3Driver::<Self>::emit_webtransport_events(
                    &driver.h3_event_sender,
                    events,
                )?;
            }
            driver.hooks.pending_requests.remove(&headers.stream_id);
            return driver.shutdown_stream(
                qconn,
                headers.stream_id,
                super::StreamShutdown::Both {
                    read_error_code: h3::WireErrorCode::MessageError as u64,
                    write_error_code: h3::WireErrorCode::MessageError as u64,
                },
            );
        }
        let is_webtransport = driver
            .webtransport
            .as_ref()
            .is_some_and(|runtime| runtime.is_session(headers.stream_id));

        if is_webtransport {
            let Some(status) = response_status(&headers.headers) else {
                let events = driver
                    .webtransport
                    .as_mut()
                    .expect("native runtime was checked above")
                    .terminate(
                        headers.stream_id,
                        WebTransportSessionCloseReason::ProtocolError,
                    );
                H3Driver::<Self>::emit_webtransport_events(
                    &driver.h3_event_sender,
                    events,
                )?;
                driver.hooks.pending_requests.remove(&headers.stream_id);
                return driver.shutdown_stream(
                    qconn,
                    headers.stream_id,
                    super::StreamShutdown::Both {
                        read_error_code: h3::WireErrorCode::MessageError as u64,
                        write_error_code: h3::WireErrorCode::MessageError as u64,
                    },
                );
            };

            if (100..200).contains(&status) {
                return Ok(());
            }

            let events = driver
                .webtransport
                .as_mut()
                .expect("native runtime was checked above")
                .response_accepted(headers.stream_id, status);
            H3Driver::<Self>::emit_webtransport_events(
                &driver.h3_event_sender,
                events,
            )?;
        }

        let Some(pending_request) =
            driver.hooks.pending_requests.remove(&headers.stream_id)
        else {
            // todo(fisher): better handling when an unknown stream_id is
            // encountered.
            return Ok(());
        };
        Self::handle_response(driver, headers, pending_request)
    }

    fn settings_received(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        let mut requests =
            std::mem::take(&mut driver.hooks.queued_webtransport_requests);
        while let Some(request) = requests.pop_front() {
            let requirements = webtransport_connect_requirements(
                driver
                    .conn
                    .as_ref()
                    .ok_or_else(H3Driver::<Self>::connection_not_present)?,
                qconn,
                &request.headers,
                driver.allows_standard_webtransport_reset(),
            );
            match requirements {
                WebTransportRequirements::Met(_) => {
                    let Some(sender) = &driver.hooks.self_cmd_sender else {
                        continue;
                    };
                    match sender.try_send(ClientH3Command::ClientRequest(request))
                    {
                        Ok(()) => {},
                        Err(TrySendError::Full(
                            ClientH3Command::ClientRequest(request),
                        )) => {
                            driver
                                .hooks
                                .queued_webtransport_requests
                                .push_back(request);
                            driver
                                .hooks
                                .queued_webtransport_requests
                                .append(&mut requests);
                            break;
                        },
                        Err(TrySendError::Closed(_)) =>
                            return Err(H3ConnectionError::ControllerWentAway),
                        Err(TrySendError::Full(ClientH3Command::Core(_))) =>
                            unreachable!("a client request changed variant"),
                    }
                },
                WebTransportRequirements::Pending => {
                    driver.hooks.queued_webtransport_requests.push_back(request);
                    driver
                        .hooks
                        .queued_webtransport_requests
                        .append(&mut requests);
                    break;
                },
                WebTransportRequirements::Failed => {
                    driver.h3_event_sender.send(
                        ClientH3Event::WebTransportRequestRejected {
                            request_id: request.request_id,
                        },
                    )?;
                },
            }
        }
        Ok(())
    }

    fn conn_command(
        driver: &mut H3Driver<Self>, qconn: &mut QuicheConnection,
        cmd: Self::Command,
    ) -> H3ConnectionResult<()> {
        match cmd {
            ClientH3Command::Core(c) => driver.handle_core_command(qconn, c),
            ClientH3Command::ClientRequest(req) =>
                Self::initiate_request(driver, qconn, req),
        }
    }

    fn has_wait_action(driver: &mut H3Driver<Self>) -> bool {
        !driver.hooks.queued_requests.is_empty()
    }

    async fn wait_for_action(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        // Sleep briefly to let the peer open stream credit or raise the
        // MAX_STREAMS limit, then re-enqueue waiting requests back into
        // the driver's command channel so that `conn_command` can retry them
        // with a full `&mut H3Driver` on the next loop iteration.
        //
        // Only drain up to the number of available bidi streams to avoid
        // re-queueing requests that would immediately fail.
        tokio::time::sleep(BLOCKED_RETRY_DELAY).await;

        let Some(sender) = self.self_cmd_sender.clone() else {
            // Should not happen: `conn_established` always sets this.
            return Ok(());
        };

        let streams_left = qconn.peer_streams_left_bidi() as usize;
        let to_drain = streams_left.min(self.queued_requests.len());

        for _ in 0..to_drain {
            let permit = match sender.try_reserve() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Full(())) => break,
                Err(mpsc::error::TrySendError::Closed(())) =>
                    return Err(H3ConnectionError::ControllerWentAway),
            };
            let request = self
                .queued_requests
                .pop_front()
                .expect("the retry count is bounded by the queue length");
            log::debug!(
                "retrying queued request after stream-blocked delay";
                "request_id" => request.request_id,
            );
            permit.send(ClientH3Command::ClientRequest(request));
        }

        Ok(())
    }
}

impl ClientH3Controller {
    /// Creates a [`NewClientRequest`] sender for the paired [ClientH3Driver].
    pub fn request_sender(&self) -> ClientRequestSender {
        RequestSender {
            sender: self.cmd_sender.clone(),
            _r: Default::default(),
        }
    }
}
