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

use std::time::Duration;

use tokio::time::timeout;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicListenerCompletion;
use tokio_quiche::QuicListenerTerminalOutcome;

use crate::fixtures::TEST_CERT_FILE;
use crate::fixtures::TEST_KEY_FILE;

fn server_params() -> ConnectionParams<'static> {
    ConnectionParams::new_server(
        QuicSettings::default(),
        TlsCertificatePaths {
            cert: TEST_CERT_FILE,
            private_key: TEST_KEY_FILE,
            kind: tokio_quiche::settings::CertificateKind::X509,
        },
        Hooks::default(),
    )
}

async fn terminal_result(
    terminal: tokio_quiche::QuicListenerTerminal,
) -> QuicListenerTerminalOutcome {
    timeout(Duration::from_secs(2), terminal.wait())
        .await
        .expect("listener terminal wait timed out")
}

#[tokio::test]
async fn idle_listener_close_wakes_and_completes_once() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut listener = listen([socket], server_params(), DefaultMetrics)
        .unwrap()
        .remove(0);
    let terminal = listener.listener_terminal();
    let waiter_terminal = terminal.clone();
    let waiter = tokio::spawn(async move { waiter_terminal.wait().await });
    tokio::task::yield_now().await;

    listener.close();
    listener.close();
    assert_eq!(
        timeout(Duration::from_secs(2), waiter)
            .await
            .expect("listener terminal task timed out")
            .unwrap(),
        QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Clean)
    );
    assert_eq!(
        terminal.try_take(),
        QuicListenerTerminalOutcome::AlreadyTaken
    );
}

#[tokio::test]
async fn dropping_idle_listener_requests_authoritative_completion() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let listener = listen([socket], server_params(), DefaultMetrics)
        .unwrap()
        .remove(0);
    let terminal = listener.listener_terminal();

    drop(listener);
    assert_eq!(
        terminal_result(terminal).await,
        QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Clean)
    );
}

#[tokio::test]
async fn multiple_listener_terminals_are_independent() {
    let first_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let second_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut listeners = listen(
        [first_socket, second_socket],
        server_params(),
        DefaultMetrics,
    )
    .unwrap();
    let second = listeners.pop().unwrap();
    let first = listeners.pop().unwrap();
    let first_terminal = first.listener_terminal();
    let second_terminal = second.listener_terminal();

    drop(first);
    assert_eq!(
        terminal_result(first_terminal).await,
        QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Clean)
    );
    assert_eq!(
        second_terminal.try_take(),
        QuicListenerTerminalOutcome::Pending
    );

    drop(second);
    assert_eq!(
        terminal_result(second_terminal).await,
        QuicListenerTerminalOutcome::Taken(QuicListenerCompletion::Clean)
    );
}
