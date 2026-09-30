# Bounded WebTransport accepted-close ownership

## Contract

`BoundedServerWebTransportController::close_session(session_id, error_code,
message)` and the bounded client equivalent retain their existing signatures
and admission errors. For an active exact session, `Ok(())` transfers its bounded
close obligation to the provider, independently of the CONNECT responder and
controller. A later responder drop cannot turn that close into abandonment.

Admission is not transmission, peer receipt, a session-terminal observation, or
connection final zero. Pending, unknown, duplicate and stale operations retain
the existing driver validation. `QueueFull`, `DriverGone` and invalid messages
do not acquire a close hold. An earlier peer terminal, STOP, transport/output
failure, or event overload is not relabelled successful local closure.

No new completion authority is needed. Existing session events and
`wait_session_terminal` preserve the first terminal reason. Existing take-once
terminal-retention claims become available only at their actual runtime,
core-owner and external-lease settlement boundaries.

## Ownership and ordering

1. Construction preallocates one exact-session close slot for the one-session
   bounded profile. It initially stores only a weak CONNECT output sender.
2. An Accepted event marks that session active. Successful close admission
   reserves the existing command-lane slot, upgrades the exact output sender,
   then publishes the command synchronously. No await separates these steps.
3. Processing the command transitions Active to Closing. If stream readiness
   holds the output receiver, it is closed and explicitly awakened. Previously
   admitted frames return to the stream owner and drain before the close capsule.
   Stale readiness cannot overwrite partial capsule output.
4. Flow-control retries retain the remaining capsule, without replay. Only full
   capsule/FIN commitment yields Local. A peer terminal during partial output
   stays first; later suffix commitment still records CONNECT-send closure.
5. Terminal events release the close slot. Driver closure/drop also clears it.
   Normal idle connection shutdown still waits for peer CONNECT closure and
   unrelated H3 streams/flows. Independent selected-I/O owners remain charged.

Without an admitted close, responder abandonment remains abrupt. For an active
session the bounded runtime records OutputFailed (AdmissionFailed while pending;
an existing terminal reason remains first), resets CONNECT output and stops
input. It follows existing cleanup rather than leaving an Active session
awaiting peer action.

Dropping a bounded event receiver is observer loss, not cancellation of protocol
work. Rejected delivery increments `receiver_closed_total`; GOAWAY, headers and
session notifications cannot turn it into an early connection close. A full
lane still records terminal EventQueueOverloaded. GeneralH3 notification and
abandonment behavior are unchanged.

## Bounds and standards

`AppliedBoundedWebTransportProfile::dynamic_components` includes
`bounded_connect_close_metadata`: one mutex-protected slot and its Arc header.
It stores IDs and channel handles, not a second payload or queue. Existing
command-message and stream-frame bounds cover the close bytes. The saved
readiness waker is included by the existing `WaitForStream` metadata calculation.
There is no per-close allocation for the hold, permanent ID history, new timer,
polling loop, connection-wide shutdown capability, or change to Datagram storage.

[Draft-16 section 6](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-16.html#section-6)
requires capsule plus FIN and recommends waiting for peer CONNECT closure before
CONNECTION_CLOSE, so close metadata is not overtaken. [Draft-02 section 5](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-02.html#section-5)
also requires capsule plus FIN and a peer close response. This correction changes
neither profile's wire format. Existing associated-stream teardown ordering is
retained; broader review of that policy is not part of this correction.

## Regression mapping

- `accepted_close_survives_responder_and_controller_drop`: both scheduling
  orders, exact capsule and FIN, duplicate completion and receive-last retirement.
- `accepted_close_preserves_partial_output_and_duplicate_order`: stale commands,
  duplicate close, controller loss, restored credit and exact non-replayed bytes.
- `accepted_close_peer_fin_during_partial_output_retires_runtime`: first Clean
  reason and complete runtime collection while the controller remains live.
- `accepted_close_peer_capsule_and_stop_keep_exact_failure` and
  `accepted_close_peer_reset_wins_and_abandonment_is_failure`: authentic peer
  terminal precedence, exact codes, explicit abandonment and output failure.
- `accepted_close_dropped_observer_goaway_is_not_cancellation`: GOAWAY before
  command processing, while blocked and after capsule commitment.
- `accepted_close_full_event_lane_remains_terminal_overload` and
  `accepted_close_saturation_and_stale_ids_do_not_acquire_output`: bounded
  rejection and closed-versus-full event behavior.
- `accepted_close_hold_is_exact_bounded_and_released_on_terminal`: 1,000 exact
  slot turnovers, duplicate admission and complete channel release.
- `accepted_close_{service,client}_first_udp_preserves_exact_reason`: public
  bounded APIs, real UDP, dropped initiating controller/responder, exact peer
  close metadata, held-owner negative controls, authentic final zero and sibling
  progress. Existing both-FIN-order and ordinary H3 backpressure controls remain.

Base: `fc4cbadff959044e89d7ab93e8febba48404fb36`, tree
`553d9e5998fb2c5e88d0b99f4c37915c55e2f25e`. This provider correction alone does
not establish incident or matched complete-call closure. Downstream adoption and
maintained provenance-gated browser validation remain separate gates.
