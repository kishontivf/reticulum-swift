// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  LinkLifecyclePhyTests.swift
//  ReticulumSwift
//
//  Coverage for the accessor / branch surface of Link.swift that the
//  existing Link suites (LinkMtu / LinkProve / LinkDataSend / LinkQueueDrain)
//  do NOT touch:
//
//    * physical-layer statistics (setTrackPhyStats / isTrackingPhyStats /
//      updatePhyStats / getRssi / getSnr / getQ) and their track-flag gate
//      (RNS Link.py:559-595, Link.swift:1397-1424).
//    * diagnostic setters setRtt (raw assignment, no keepalive recompute)
//      and setWatchdog (override keepalive + stale window).
//    * noInboundForMs() inbound-idle baseline (RNS no_inbound_for,
//      Link.py:657-663).
//    * processKeepalive() role-gated inbound handling, stale->active
//      recovery, and responder 0xFE echo byte (RNS Link.py:1149-1153).
//    * close() / handleClose() teardown-reason derivation by role
//      (RNS teardown vs teardown_packet, Link.py:706-717) + close callback.
//    * LinkState / TeardownReason pure predicates and descriptions.
//    * keepalive-interval derivation (LinkConstants.keepaliveInterval).
//    * resource-strategy + packet-callback + remote-identity accessors.
//
//  Every test drives REAL production code on a real Link actor (or the real
//  LinkState/TeardownReason/LinkConstants production types) and asserts its
//  observable behavior — no logic is reimplemented in the test.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

// `_setStateForTesting` (used to stand a Link up in `.active`/`.stale`
// without running the LRRTT handshake) is wrapped in `#if DEBUG` on the
// implementation side. Wrap the test class in the same guard so a
// release-configuration build of the suite still compiles. Default
// `swift test` runs the debug configuration, so all tests execute.
#if DEBUG
final class LinkLifecyclePhyTests: XCTestCase {

    // MARK: - Helpers

    /// Build a fresh INITIATOR link in its default `.pending` state.
    /// `Link(destination:identity:)` generates ephemeral keypairs and a
    /// non-empty `linkId` derived from `request`, which the teardown tests
    /// need for the `plaintext == linkId` guard in `handleClose`.
    private func makeInitiatorLink() -> Link {
        let identity = Identity()
        let dest = Destination(
            identity: identity, appName: "test", aspects: ["link-lifecycle-phy"]
        )
        return Link(destination: dest, identity: identity)
    }

    /// Build a RESPONDER link (initiator == false) forced into `.active`.
    /// Mirrors the `makeActiveLink` fixture in LinkDataSendTests: synthesize
    /// a LINKREQUEST, construct the responder Link from it, then force state.
    private func makeActiveResponderLink() async throws -> Link {
        let identity = Identity()
        let dest = Destination(
            identity: identity, appName: "test", aspects: ["link-lifecycle-phy"]
        )

        let encKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let sigKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let signaling = IncomingLinkRequest.encodeSignaling(
            mtu: 500, mode: LinkConstants.MODE_DEFAULT
        )
        var requestData = Data()
        requestData.append(encKey)
        requestData.append(sigKey)
        requestData.append(signaling)
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .linkRequest,
            hopCount: 0
        )
        let lrPacket = Packet(
            header: header,
            destination: dest.hash,
            context: 0x00,
            data: requestData
        )
        let incoming = try IncomingLinkRequest(data: requestData, packet: lrPacket)
        let link = Link(incomingRequest: incoming, destination: dest, identity: identity)
        await link._setStateForTesting(.active)
        return link
    }

    /// Minimal HEADER_1 link DATA packet (no encryption needed — only used as
    /// the `packet` argument to `deliverToPacketCallback`).
    private func makeDummyPacket() -> Packet {
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hopCount: 0
        )
        return Packet(
            header: header,
            destination: Data(repeating: 0x01, count: 16),
            context: 0x00,
            data: Data()
        )
    }

    /// Sendable sink for verifying an async @Sendable callback fired with the
    /// expected payload. Private nested type — no global collision risk.
    private actor PayloadSink {
        private(set) var last: Data?
        private(set) var count: Int = 0
        func record(_ data: Data) { last = data; count += 1 }
    }

    // MARK: - Physical-layer statistics

    /// A fresh link does NOT track phy stats (RNS __track_phy_stats default
    /// False). The gated getters must return nil even before any value is
    /// recorded.
    func testPhyStatsUntrackedByDefault() async throws {
        let link = makeInitiatorLink()

        let tracking = await link.isTrackingPhyStats
        XCTAssertFalse(tracking,
            "A fresh Link must default to phy-stat tracking DISABLED " +
            "(RNS Link.__track_phy_stats default False).")

        let rssi = await link.getRssi()
        let snr = await link.getSnr()
        let q = await link.getQ()
        XCTAssertNil(rssi, "getRssi() must be nil while tracking is off.")
        XCTAssertNil(snr, "getSnr() must be nil while tracking is off.")
        XCTAssertNil(q, "getQ() must be nil while tracking is off.")
    }

    /// `updatePhyStats` STORES values regardless of the track flag (RNS sets
    /// link.rssi/snr/q directly from the interface), but the get_* accessors
    /// GATE on the flag. Verifies both: stored-but-hidden while off, exposed
    /// once enabled.
    func testPhyStatsGatedOnTrackFlag() async throws {
        let link = makeInitiatorLink()
        await link.updatePhyStats(rssi: -55.0, snr: 7.5, q: 0.9)

        // Stored regardless of the gate (public read-back props).
        let storedRssi = await link.rssi
        XCTAssertEqual(storedRssi, -55.0,
            "updatePhyStats must store rssi even while tracking is off " +
            "(the gate lives in the getters, not the setter).")

        // ...but the gated getters hide it while tracking is off.
        let gatedRssi = await link.getRssi()
        XCTAssertNil(gatedRssi,
            "getRssi() must return nil while tracking is off even though a " +
            "value was recorded.")

        // Enable tracking — now the getters expose the stored values.
        await link.setTrackPhyStats(true)
        let trackingNow = await link.isTrackingPhyStats
        XCTAssertTrue(trackingNow, "setTrackPhyStats(true) must enable tracking.")

        let rssi = await link.getRssi()
        let snr = await link.getSnr()
        let q = await link.getQ()
        XCTAssertEqual(rssi, -55.0, "getRssi() must expose stored rssi once tracked.")
        XCTAssertEqual(snr, 7.5, "getSnr() must expose stored snr once tracked.")
        XCTAssertEqual(q, 0.9, "getQ() must expose stored q once tracked.")
    }

    /// `updatePhyStats` only overwrites the fields it is GIVEN — a later
    /// rssi-only update must not clobber a previously recorded snr/q
    /// (each assignment is guarded by `if let`).
    func testPhyStatsPartialUpdatePreservesOthers() async throws {
        let link = makeInitiatorLink()
        await link.setTrackPhyStats(true)
        await link.updatePhyStats(rssi: -60.0, snr: 3.0, q: 0.5)
        // rssi-only update; snr/q omitted (default nil) must be preserved.
        await link.updatePhyStats(rssi: -42.0)

        let rssi = await link.getRssi()
        let snr = await link.getSnr()
        let q = await link.getQ()
        XCTAssertEqual(rssi, -42.0, "rssi must reflect the latest update.")
        XCTAssertEqual(snr, 3.0,
            "snr must be PRESERVED across a partial update that omitted it.")
        XCTAssertEqual(q, 0.5,
            "q must be PRESERVED across a partial update that omitted it.")
    }

    /// Toggling tracking back off re-hides the stored values (the gate is
    /// re-evaluated on every getter call).
    func testPhyStatsToggleOffRehidesValues() async throws {
        let link = makeInitiatorLink()
        await link.setTrackPhyStats(true)
        await link.updatePhyStats(rssi: -70.0, snr: 1.0, q: 0.25)

        let visible = await link.getRssi()
        XCTAssertEqual(visible, -70.0, "Sanity: visible while tracked.")

        await link.setTrackPhyStats(false)
        let trackingNow = await link.isTrackingPhyStats
        XCTAssertFalse(trackingNow,
            "setTrackPhyStats(false) must disable tracking.")
        let rssiGated = await link.getRssi()
        let snrGated = await link.getSnr()
        let qGated = await link.getQ()
        XCTAssertNil(rssiGated,
            "getRssi() must return nil again after tracking is disabled.")
        XCTAssertNil(snrGated,
            "getSnr() must return nil again after tracking is disabled.")
        XCTAssertNil(qGated,
            "getQ() must return nil again after tracking is disabled.")
        // The stored value still exists — only the gate changed.
        let storedRssi = await link.rssi
        XCTAssertEqual(storedRssi, -70.0,
            "Disabling tracking must not erase the stored rssi value.")
    }

    // MARK: - setRtt / setWatchdog

    /// `setRtt` is a RAW assignment (RNS link.rtt settable attribute). It must
    /// NOT recompute the keepalive interval — that is what distinguishes it
    /// from the handshake's updateKeepalive path.
    func testSetRttRawAssignmentDoesNotRecomputeKeepalive() async throws {
        let link = makeInitiatorLink()
        let rtt0 = await link.rtt
        XCTAssertEqual(rtt0, 0.0, accuracy: 1e-9, "Fresh link rtt defaults to 0.")
        let ka0 = await link.keepaliveInterval
        XCTAssertEqual(ka0, LinkConstants.KEEPALIVE_MIN, accuracy: 1e-9,
            "Fresh link keepaliveInterval defaults to KEEPALIVE_MIN.")

        await link.setRtt(1.234)

        let rtt1 = await link.rtt
        XCTAssertEqual(rtt1, 1.234, accuracy: 1e-9, "setRtt must store the value.")
        let ka1 = await link.keepaliveInterval
        XCTAssertEqual(ka1, LinkConstants.KEEPALIVE_MIN, accuracy: 1e-9,
            "setRtt must NOT recompute keepaliveInterval (raw assignment, " +
            "matching RNS where setting rtt is a plain attribute write).")
    }

    /// `setWatchdog` overrides BOTH the keepalive cadence and the stale window
    /// at runtime (RNS link.keepalive / link.stale_time settable attributes).
    func testSetWatchdogOverridesKeepaliveAndStaleWindow() async throws {
        let link = makeInitiatorLink()
        // Default stale window == KEEPALIVE_MIN * STALE_FACTOR(2.0).
        let stale0 = await link.staleTime
        XCTAssertEqual(stale0, LinkConstants.KEEPALIVE_MIN * 2.0, accuracy: 1e-9,
            "Default staleTime must be keepaliveInterval * STALE_FACTOR.")

        await link.setWatchdog(keepalive: 2.0, staleTime: 7.0)

        let ka = await link.keepaliveInterval
        let stale = await link.staleTime
        XCTAssertEqual(ka, 2.0, accuracy: 1e-9,
            "setWatchdog must override keepaliveInterval.")
        XCTAssertEqual(stale, 7.0, accuracy: 1e-9,
            "setWatchdog must override staleTime independently of keepalive.")
    }

    // MARK: - noInboundForMs

    /// Before any inbound traffic AND before activation, the idle baseline is
    /// undefined — `noInboundForMs()` must return nil rather than a spuriously
    /// huge value (RNS no_inbound_for has no reference yet).
    func testNoInboundForMsNilWithoutReference() async throws {
        let link = makeInitiatorLink()
        let idle = await link.noInboundForMs()
        XCTAssertNil(idle,
            "noInboundForMs() must be nil on a pending link with neither " +
            "lastInbound nor activatedAt set.")
    }

    // MARK: - processKeepalive

    /// An initiator that receives the responder's 0xFE keepalive must bump
    /// lastInbound — which then makes noInboundForMs() resolve to a small,
    /// finite value.
    func testProcessKeepaliveInitiatorBumpsInbound() async throws {
        let link = makeInitiatorLink()
        await link._setStateForTesting(.active)

        let inboundBefore = await link.lastInboundAt
        XCTAssertNil(inboundBefore,
            "Sanity: no inbound recorded before the keepalive.")

        await link.processKeepalive(Data([LinkConstants.KEEPALIVE_RESPONDER]))

        let inboundAfter = await link.lastInboundAt
        XCTAssertNotNil(inboundAfter,
            "Initiator receiving 0xFE must set lastInbound.")
        let idle = await link.noInboundForMs()
        XCTAssertNotNil(idle, "noInboundForMs() must be finite once lastInbound is set.")
        XCTAssertLessThan(idle ?? Int.max, 5000,
            "Idle time must be near-zero immediately after the keepalive.")
    }

    /// A keepalive byte that does NOT match this side's expected direction is
    /// ignored (an initiator must ignore another 0xFF). lastInbound stays nil.
    func testProcessKeepaliveWrongDirectionIgnored() async throws {
        let link = makeInitiatorLink()
        await link._setStateForTesting(.active)

        // Initiator receiving 0xFF (an initiator byte) does not match the
        // (initiator && byte == RESPONDER) guard, so nothing is recorded.
        await link.processKeepalive(Data([LinkConstants.KEEPALIVE_INITIATOR]))

        let inbound = await link.lastInboundAt
        XCTAssertNil(inbound,
            "An initiator must ignore a 0xFF keepalive (wrong direction); " +
            "lastInbound must remain unset.")
    }

    /// A keepalive payload that is not exactly one byte is rejected outright
    /// (RNS keepalive content is a single byte).
    func testProcessKeepaliveWrongLengthIgnored() async throws {
        let link = makeInitiatorLink()
        await link._setStateForTesting(.active)

        await link.processKeepalive(Data([
            LinkConstants.KEEPALIVE_RESPONDER, LinkConstants.KEEPALIVE_RESPONDER
        ]))

        let inbound = await link.lastInboundAt
        XCTAssertNil(inbound,
            "A 2-byte keepalive payload must be rejected (count != 1 guard).")
    }

    /// A matching keepalive received while STALE must recover the link to
    /// ACTIVE (RNS stale recovery), and that transition records activatedAt
    /// for the first time.
    func testProcessKeepaliveRecoversStaleToActive() async throws {
        let link = makeInitiatorLink()
        await link._setStateForTesting(.stale)
        let activatedBefore = await link.activatedAt
        XCTAssertNil(activatedBefore,
            "Sanity: forced-stale link never ran the activation transition.")

        await link.processKeepalive(Data([LinkConstants.KEEPALIVE_RESPONDER]))

        let state = await link.state
        XCTAssertEqual(state, .active,
            "A matching keepalive while STALE must recover the link to ACTIVE.")
        let activatedAfter = await link.activatedAt
        XCTAssertNotNil(activatedAfter,
            "The stale->active recovery transition must set activatedAt.")
    }

    /// A responder receiving the initiator's 0xFF must record the answered
    /// echo byte (0xFE) synchronously for the wire_last_keepalive read-back
    /// (RNS Link.py:1149-1153) and bump lastInbound.
    func testProcessKeepaliveResponderRecordsEchoByte() async throws {
        let link = try await makeActiveResponderLink()
        let echoBefore = await link.lastKeepaliveByte
        XCTAssertNil(echoBefore,
            "Sanity: no keepalive emitted yet.")

        await link.processKeepalive(Data([LinkConstants.KEEPALIVE_INITIATOR]))

        let echo = await link.lastKeepaliveByte
        XCTAssertEqual(echo, LinkConstants.KEEPALIVE_RESPONDER,
            "A responder answering a 0xFF must record the 0xFE echo byte.")
        let inbound = await link.lastInboundAt
        XCTAssertNotNil(inbound,
            "Responder receiving 0xFF must also bump lastInbound.")
    }

    // MARK: - close / handleClose teardown-reason derivation

    /// `close(reason:)` on a pending link transitions it to the terminal
    /// `.closed(reason)` state carrying the EXACT reason passed.
    func testCloseTransitionsToClosedWithExplicitReason() async throws {
        let link = makeInitiatorLink()
        await link.close(reason: .transportError)

        let state = await link.state
        XCTAssertEqual(state, .closed(reason: .transportError),
            "close(reason:) must transition to .closed with the given reason.")
        XCTAssertTrue(state.isTerminal,
            "A closed link must report isTerminal == true.")
    }

    /// `close()` with no argument defaults to `.initiatorClosed` (RNS
    /// teardown for a locally-initiated close).
    func testCloseDefaultReasonIsInitiatorClosed() async throws {
        let link = makeInitiatorLink()
        await link.close()

        let state = await link.state
        XCTAssertEqual(state, .closed(reason: .initiatorClosed),
            "close() default reason must be .initiatorClosed.")
    }

    /// An INITIATOR that RECEIVES a LINKCLOSE records `.destinationClosed`
    /// (RNS teardown_packet: initiator role => DESTINATION_CLOSED,
    /// Link.py:714-717) — the inverse of the locally-initiated reason.
    func testHandleCloseInitiatorRecordsDestinationClosed() async throws {
        let link = makeInitiatorLink()
        await link._setStateForTesting(.active)
        let linkId = await link.linkId

        await link.handleClose(linkId)

        let state = await link.state
        XCTAssertEqual(state, .closed(reason: .destinationClosed),
            "An initiator receiving a LINKCLOSE must record .destinationClosed.")
    }

    /// A RESPONDER that RECEIVES a LINKCLOSE records `.initiatorClosed`
    /// (RNS teardown_packet: responder role => INITIATOR_CLOSED).
    func testHandleCloseResponderRecordsInitiatorClosed() async throws {
        let link = try await makeActiveResponderLink()
        let linkId = await link.linkId

        await link.handleClose(linkId)

        let state = await link.state
        XCTAssertEqual(state, .closed(reason: .initiatorClosed),
            "A responder receiving a LINKCLOSE must record .initiatorClosed.")
    }

    /// `handleClose` only acts when the decrypted payload equals our linkId
    /// (RNS teardown_packet guard). A mismatched payload is ignored and the
    /// link stays open.
    func testHandleClosePayloadMismatchIgnored() async throws {
        let link = try await makeActiveResponderLink()

        await link.handleClose(Data([0x00, 0x01, 0x02]))

        let state = await link.state
        XCTAssertEqual(state, .active,
            "handleClose with a payload != linkId must be ignored; the link " +
            "must remain ACTIVE.")
    }

    /// `handleClose` on an already-terminal link is a no-op — it must not
    /// overwrite the recorded teardown reason.
    func testHandleCloseOnTerminalLinkIgnored() async throws {
        let link = makeInitiatorLink()
        await link.close(reason: .timeout)
        let linkId = await link.linkId

        await link.handleClose(linkId)

        let state = await link.state
        XCTAssertEqual(state, .closed(reason: .timeout),
            "handleClose on a closed link must not change its existing reason.")
    }

    /// The close callback fires asynchronously with the teardown reason
    /// (RNS link_closed callback). Verifies the callback is invoked AND
    /// receives the correct reason.
    func testCloseCallbackFiresWithReason() async throws {
        let link = makeInitiatorLink()

        let received: TeardownReason = await withCheckedContinuation { cont in
            Task {
                await link.setCloseCallback { reason in
                    cont.resume(returning: reason)
                }
                await link.close(reason: .cryptoError)
            }
        }

        XCTAssertEqual(received, .cryptoError,
            "The close callback must fire with the exact teardown reason.")
    }

    // MARK: - Resource-strategy / packet-callback / identity accessors

    /// Fresh-link resource bookkeeping defaults, and that setResourceStrategy
    /// mutates the observable strategy.
    func testResourceStrategyDefaultAndMutation() async throws {
        let link = makeInitiatorLink()

        let initial = await link.resourceStrategy
        guard case .acceptNone = initial else {
            XCTFail("Default resourceStrategy must be .acceptNone, got \(initial).")
            return
        }
        let lastWindow = await link.getLastResourceWindow()
        XCTAssertNil(lastWindow,
            "getLastResourceWindow() must be nil before any inbound resource.")
        let inCount = await link.incomingResourceCount
        XCTAssertEqual(inCount, 0,
            "A fresh link must have zero inbound resources.")

        await link.setResourceStrategy(.acceptAll)
        let updated = await link.resourceStrategy
        guard case .acceptAll = updated else {
            XCTFail("setResourceStrategy(.acceptAll) must update the strategy, " +
                    "got \(updated).")
            return
        }
    }

    /// Packet-callback registration toggles `hasPacketCallback`, and
    /// `deliverToPacketCallback` returns true + invokes the callback only
    /// while one is registered.
    func testPacketCallbackRegistrationAndDelivery() async throws {
        let link = makeInitiatorLink()
        let packet = makeDummyPacket()

        let hasCallbackInitially = await link.hasPacketCallback
        XCTAssertFalse(hasCallbackInitially,
            "A fresh link must report no packet callback.")
        let deliveredNone = await link.deliverToPacketCallback(
            data: Data([0x01]), packet: packet
        )
        XCTAssertFalse(deliveredNone,
            "deliverToPacketCallback must return false when no callback is set.")

        let sink = PayloadSink()
        await link.setPacketCallback { data, _ in
            await sink.record(data)
        }
        let hasCallbackAfterSet = await link.hasPacketCallback
        XCTAssertTrue(hasCallbackAfterSet,
            "hasPacketCallback must be true after registration.")

        let payload = Data([0x09, 0x09, 0x09])
        let delivered = await link.deliverToPacketCallback(data: payload, packet: packet)
        XCTAssertTrue(delivered,
            "deliverToPacketCallback must return true when a callback is set.")
        let recorded = await sink.last
        XCTAssertEqual(recorded, payload,
            "The callback must receive the exact plaintext passed to deliver.")
        let recordedCount = await sink.count
        XCTAssertEqual(recordedCount, 1, "The callback must fire exactly once.")

        await link.setPacketCallback(nil)
        let hasCallbackAfterClear = await link.hasPacketCallback
        XCTAssertFalse(hasCallbackAfterClear,
            "hasPacketCallback must be false after clearing.")
        let deliveredAfterClear = await link.deliverToPacketCallback(
            data: payload, packet: packet
        )
        XCTAssertFalse(deliveredAfterClear,
            "deliverToPacketCallback must return false again after the callback " +
            "is cleared.")
    }

    /// A fresh link has not been identified by its remote peer.
    func testRemoteIdentityDefaults() async throws {
        let link = makeInitiatorLink()
        let identified = await link.isRemoteIdentified
        XCTAssertFalse(identified,
            "A fresh link must report isRemoteIdentified == false.")
        let remote = await link.remoteIdentity
        XCTAssertNil(remote,
            "A fresh link must have a nil remoteIdentity.")
    }

    // MARK: - LinkState / TeardownReason pure predicates & descriptions

    /// `isEstablished` is true only for the can-transmit states (.active /
    /// .stale). Drives the production computed property across every case.
    func testLinkStateIsEstablishedMatrix() {
        XCTAssertTrue(LinkState.active.isEstablished, ".active must be established.")
        XCTAssertTrue(LinkState.stale.isEstablished, ".stale must be established.")
        XCTAssertFalse(LinkState.pending.isEstablished, ".pending is not established.")
        XCTAssertFalse(LinkState.handshake.isEstablished, ".handshake is not established.")
        XCTAssertFalse(LinkState.closed(reason: .timeout).isEstablished,
            ".closed is not established.")
    }

    /// `isTerminal` is true only for `.closed`.
    func testLinkStateIsTerminalMatrix() {
        XCTAssertTrue(LinkState.closed(reason: .initiatorClosed).isTerminal,
            ".closed must be terminal.")
        XCTAssertFalse(LinkState.pending.isTerminal, ".pending is not terminal.")
        XCTAssertFalse(LinkState.handshake.isTerminal, ".handshake is not terminal.")
        XCTAssertFalse(LinkState.active.isTerminal, ".active is not terminal.")
        XCTAssertFalse(LinkState.stale.isTerminal, ".stale is not terminal.")
    }

    /// LinkState.description for every case, including the reason embedded in
    /// `.closed`.
    func testLinkStateDescriptions() {
        XCTAssertEqual(LinkState.pending.description, "pending")
        XCTAssertEqual(LinkState.handshake.description, "handshake")
        XCTAssertEqual(LinkState.active.description, "active")
        XCTAssertEqual(LinkState.stale.description, "stale")
        XCTAssertEqual(LinkState.closed(reason: .timeout).description, "closed(timeout)",
            ".closed must embed its reason's description.")
    }

    /// TeardownReason.description maps each case to its RNS wire-style label.
    func testTeardownReasonDescriptions() {
        XCTAssertEqual(TeardownReason.timeout.description, "timeout")
        XCTAssertEqual(TeardownReason.initiatorClosed.description, "initiator_closed")
        XCTAssertEqual(TeardownReason.destinationClosed.description, "destination_closed")
        XCTAssertEqual(TeardownReason.proofInvalid.description, "proof_invalid")
        XCTAssertEqual(TeardownReason.cryptoError.description, "crypto_error")
        XCTAssertEqual(TeardownReason.transportError.description, "transport_error")
    }

    // MARK: - Keepalive-interval derivation

    /// `LinkConstants.keepaliveInterval(forRTT:)` clamps to [KEEPALIVE_MIN,
    /// KEEPALIVE_MAX] and scales linearly between. Exercises both clamp
    /// branches and the in-band multiply.
    func testKeepaliveIntervalDerivationClamps() {
        // Below the floor: a tiny RTT yields a sub-MIN raw value -> clamp up.
        XCTAssertEqual(
            LinkConstants.keepaliveInterval(forRTT: 0.0),
            LinkConstants.KEEPALIVE_MIN, accuracy: 1e-9,
            "rtt 0 must clamp up to KEEPALIVE_MIN.")
        XCTAssertEqual(
            LinkConstants.keepaliveInterval(forRTT: 0.001),
            LinkConstants.KEEPALIVE_MIN, accuracy: 1e-9,
            "A tiny rtt must clamp up to KEEPALIVE_MIN.")

        // In-band: rtt 1.0 -> 1.0 * (360 / 1.75) == 205.714285..., which lies
        // strictly between MIN and MAX.
        let mid = LinkConstants.keepaliveInterval(forRTT: 1.0)
        XCTAssertEqual(mid, 205.714285, accuracy: 1e-4,
            "rtt 1.0 must yield the un-clamped scaled value ~205.71s.")
        XCTAssertGreaterThan(mid, LinkConstants.KEEPALIVE_MIN,
            "The in-band value must exceed the floor.")
        XCTAssertLessThan(mid, LinkConstants.KEEPALIVE_MAX,
            "The in-band value must be below the ceiling.")

        // Above the ceiling: a large RTT clamps down to KEEPALIVE_MAX.
        XCTAssertEqual(
            LinkConstants.keepaliveInterval(forRTT: 100.0),
            LinkConstants.KEEPALIVE_MAX, accuracy: 1e-9,
            "A large rtt must clamp down to KEEPALIVE_MAX.")
    }
}
#endif
