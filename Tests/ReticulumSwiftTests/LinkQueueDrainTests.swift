// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  LinkQueueDrainTests.swift
//  ReticulumSwiftTests
//
//  Regression coverage for the outbound-resource one-at-a-time gate and the
//  event-driven drain of `pendingOutgoingQueue` (the swift equivalent of RNS
//  QUEUED, RNS/Resource.py:522-534; RNS/Link.py:1320-1330).
//
//  These drive REAL production code only:
//   - LinkState.canEmitTeardown (pure enum predicate, RNS/Link.py:704).
//   - Link.sendResource(...) -> advertise-now vs queue-behind the in-flight
//     outbound resource (RNS/Link.py:1328-1330 ready_for_new_resource gate).
//   - Link.cancelOutgoingResource(_:) -> frees the slot AND drains the queue
//     (the bf01893 fix; before it, the queue stalled permanently).
//   - Resource.cancel() -> link.cancelOutgoingResource path for a callback-less
//     transfer (the exact remote-cancel stall the fix addresses,
//     RNS/Resource.py:1089-1094).
//   - Link.resourceConcluded(_:) -> the normal-conclusion drain trigger.
//
//  The strongest observable each test pins: a resource that was QUEUED behind an
//  in-flight outbound resource becomes ADVERTISED (and a fresh advertisement
//  leaves the link) the instant the slot is freed. Before the fix the queued
//  resource stays QUEUED and outgoingResourceCount drops to 0.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class LinkQueueDrainTests: XCTestCase {

    // MARK: - Helpers

    /// Records every byte string handed to the Link's send callback so a test
    /// can assert that an advertisement actually left the wire (not merely that
    /// an in-memory state flag flipped). Nested so it never collides with a
    /// sibling test file's helpers.
    private actor SendLog {
        private(set) var packets: [Data] = []
        func record(_ d: Data) { packets.append(d) }
        var count: Int { packets.count }
    }

    /// Stand up a responder Link in `.active` state WITH a derived encryption
    /// token, so `sendResource` (which needs `state.isEstablished` AND a token)
    /// can run end to end. Mirrors LinkDataSendTests.makeActiveLink()'s
    /// IncomingLinkRequest construction, but additionally calls the real
    /// `deriveResponderKeys()` so the link can prepare/encrypt outbound
    /// resources — `_setStateForTesting(.active)` alone leaves `token == nil`.
    private func makeActiveLink() async throws -> Link {
        let identity = Identity()
        let dest = Destination(
            identity: identity, appName: "test", aspects: ["link-queue-drain"]
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
        // Derive the ECDH session token from the peer's (random but valid)
        // ephemeral key + our responder ephemeral key, then force ACTIVE. Both
        // are real production paths — only the LRRTT round-trip is skipped.
        try await link.deriveResponderKeys()
        await link._setStateForTesting(.active)
        return link
    }

    // MARK: - Test 1: LinkState.canEmitTeardown (pure enum, RNS/Link.py:704)

    /// `canEmitTeardown` is the can-send-a-LINKCLOSE predicate: true for any
    /// status that is not PENDING and not CLOSED — i.e. `.handshake`, `.active`,
    /// `.stale`. RNS emits the teardown packet from `.handshake` too (a responder
    /// sits there until the initiator's RTT packet) so the peer records
    /// DESTINATION_CLOSED rather than a watchdog TIMEOUT.
    func testCanEmitTeardownTrueForHandshakeActiveStale() {
        XCTAssertTrue(LinkState.handshake.canEmitTeardown,
            "canEmitTeardown must be true for .handshake (RNS/Link.py:704 — a " +
            "responder still in handshake must still emit the teardown).")
        XCTAssertTrue(LinkState.active.canEmitTeardown,
            "canEmitTeardown must be true for .active.")
        XCTAssertTrue(LinkState.stale.canEmitTeardown,
            "canEmitTeardown must be true for .stale.")
    }

    /// `.pending` and every `.closed(reason:)` must NOT emit a teardown: RNS
    /// guards `status != PENDING and status != CLOSED` (RNS/Link.py:704). A
    /// PENDING link never went on the wire; a CLOSED link already tore down.
    func testCanEmitTeardownFalseForPendingAndClosed() {
        XCTAssertFalse(LinkState.pending.canEmitTeardown,
            "canEmitTeardown must be false for .pending (never established).")
        // Exercise several TeardownReason associated values — the predicate must
        // ignore the reason and stay false for ALL .closed variants.
        for reason: TeardownReason in [.timeout, .initiatorClosed, .destinationClosed,
                                       .proofInvalid, .cryptoError, .transportError] {
            XCTAssertFalse(LinkState.closed(reason: reason).canEmitTeardown,
                "canEmitTeardown must be false for .closed(\(reason)).")
        }
    }

    /// canEmitTeardown is DISTINCT from isEstablished: `.handshake` can teardown
    /// but cannot carry app data. Pinning this divergence guards against a future
    /// refactor collapsing the two predicates (which would regress the
    /// DESTINATION_CLOSED-from-handshake behavior).
    func testCanEmitTeardownDistinctFromIsEstablished() {
        XCTAssertTrue(LinkState.handshake.canEmitTeardown,
            ".handshake can emit a teardown...")
        XCTAssertFalse(LinkState.handshake.isEstablished,
            "...but .handshake is NOT established (cannot carry app data). The " +
            "two predicates must not be conflated.")
    }

    // MARK: - Test 2: cancelOutgoingResource drains the pending queue

    /// The core regression (commit bf01893). Build an active link, sendResource A
    /// (advertised immediately — link was free), then sendResource B (queued
    /// behind A by the one-at-a-time gate, RNS/Link.py:1328-1330). Cancel A via
    /// the public `cancelOutgoingResource(_:)` and assert B is drained:
    /// QUEUED -> ADVERTISED, the slot stays full (count == 1), and a fresh
    /// advertisement leaves the link. Before the fix `cancelOutgoingResource`
    /// removed A but never drained, so B stayed QUEUED and the count fell to 0.
    func testCancelOutgoingResourceDrainsQueuedResource() async throws {
        let log = SendLog()
        let link = try await makeActiveLink()
        await link.setSendCallback { data in await log.record(data) }

        // Distinct payloads -> distinct resource hashes (outboundResources is
        // keyed by hash; identical data would collide the registry).
        let dataA = Data(repeating: 0x41, count: 300)
        let dataB = Data(repeating: 0x42, count: 300)

        // A: link is free -> advertised immediately and occupies the slot.
        let rA = try await link.sendResource(data: dataA)
        let stateA = await rA.state
        XCTAssertEqual(stateA, .advertised,
            "First resource must advertise immediately when the link is free.")
        let countAfterA = await link.outgoingResourceCount
        XCTAssertEqual(countAfterA, 1, "A must occupy the single outgoing slot.")
        let sentAfterA = await log.count
        XCTAssertGreaterThanOrEqual(sentAfterA, 1,
            "A's advertisement must have left the link.")

        // B: link is busy -> QUEUED, no packet, slot still A.
        let rB = try await link.sendResource(data: dataB)
        let stateBQueued = await rB.state
        XCTAssertEqual(stateBQueued, .queued,
            "Second resource must QUEUE behind the in-flight resource " +
            "(one-at-a-time gate, RNS/Link.py:1328-1330).")
        let countAfterB = await link.outgoingResourceCount
        XCTAssertEqual(countAfterB, 1,
            "Queued B must NOT enter the outgoing slot while A is in flight.")
        let readyWhileBusy = await link.readyForNewResource()
        XCTAssertFalse(readyWhileBusy, "Link must report busy while A is in flight.")
        let sentAfterB = await log.count
        XCTAssertEqual(sentAfterB, sentAfterA,
            "Queuing B must NOT advertise it — no new packet should leave yet.")

        // Cancel A directly through the Link API under test.
        await link.cancelOutgoingResource(rA)

        // B must now be drained into the freed slot.
        let stateBDrained = await rB.state
        XCTAssertEqual(stateBDrained, .advertised,
            "REGRESSION: queued B must advertise once A's slot is freed. Before " +
            "bf01893 cancelOutgoingResource skipped the drain and B stalled QUEUED.")
        let countAfterCancel = await link.outgoingResourceCount
        XCTAssertEqual(countAfterCancel, 1,
            "After cancelling A the freed slot must be refilled by B (count stays 1).")
        let sentAfterCancel = await log.count
        XCTAssertGreaterThan(sentAfterCancel, sentAfterB,
            "B's advertisement must actually leave the link during the drain.")
    }

    /// Same drain, reached through `Resource.cancel()` on a CALLBACK-LESS
    /// transfer — the exact stall the fix targets. `sendResource` installs no
    /// completion callback, so `Resource.cancel()` removes A via
    /// `link.cancelOutgoingResource` and then skips the callback-gated
    /// `resourceConcluded` (RNS/Resource.py:1099-1104). Before the fix the drain
    /// lived ONLY in resourceConcluded, so this path stalled B forever; now the
    /// drain inside cancelOutgoingResource itself releases B.
    func testResourceCancelDrainsQueuedResource() async throws {
        let log = SendLog()
        let link = try await makeActiveLink()
        await link.setSendCallback { data in await log.record(data) }

        let dataA = Data(repeating: 0x43, count: 300)
        let dataB = Data(repeating: 0x44, count: 300)

        let rA = try await link.sendResource(data: dataA)
        let rB = try await link.sendResource(data: dataB)
        let stateBQueued = await rB.state
        XCTAssertEqual(stateBQueued, .queued, "B must start QUEUED behind A.")
        let sentBeforeCancel = await log.count

        // Cancel A the way a remote EXHAUSTED/ICL flows in: Resource.cancel().
        await rA.cancel()

        let stateA = await rA.state
        XCTAssertEqual(stateA, .failed,
            "cancel() must move the in-flight resource to .failed " +
            "(RNS/Resource.py:1086-1087).")
        let stateBDrained = await rB.state
        XCTAssertEqual(stateBDrained, .advertised,
            "REGRESSION: B must advertise after A is cancelled via Resource.cancel() " +
            "on a callback-less transfer. Before bf01893 this path never drained.")
        let countAfterCancel = await link.outgoingResourceCount
        XCTAssertEqual(countAfterCancel, 1,
            "B must now hold the single outgoing slot (A removed, B promoted).")
        let sentAfterCancel = await log.count
        XCTAssertGreaterThan(sentAfterCancel, sentBeforeCancel,
            "At least B's advertisement (and A's ICL) must leave the link.")
    }

    // MARK: - Test 3: resourceConcluded drains the pending queue

    /// The normal-conclusion drain trigger (RNS/Link.py:1281-1290): when an
    /// in-flight outbound resource concludes, the next queued resource is
    /// advertised. Distinct trigger from cancel — exercises the
    /// `outboundResources[hash] != nil -> drainOutgoingQueue()` branch of the
    /// real `resourceConcluded`.
    func testResourceConcludedDrainsQueuedResource() async throws {
        let log = SendLog()
        let link = try await makeActiveLink()
        await link.setSendCallback { data in await log.record(data) }

        let dataA = Data(repeating: 0x45, count: 300)
        let dataB = Data(repeating: 0x46, count: 300)

        let rA = try await link.sendResource(data: dataA)
        let rB = try await link.sendResource(data: dataB)
        let stateBQueued = await rB.state
        XCTAssertEqual(stateBQueued, .queued, "B must start QUEUED behind A.")
        let sentBeforeConclude = await log.count

        // A concludes normally -> link bookkeeping must release B.
        await link.resourceConcluded(rA)

        let stateBDrained = await rB.state
        XCTAssertEqual(stateBDrained, .advertised,
            "resourceConcluded(A) must advertise the queued B " +
            "(RNS/Link.py:1281-1290 conclusion drain).")
        let countAfterConclude = await link.outgoingResourceCount
        XCTAssertEqual(countAfterConclude, 1,
            "B must occupy the single outgoing slot after A concludes.")
        let sentAfterConclude = await log.count
        XCTAssertGreaterThan(sentAfterConclude, sentBeforeConclude,
            "B's advertisement must leave the link when A concludes.")
    }

    /// Cancelling the ONLY in-flight resource (empty queue) frees the slot
    /// without advertising anything new: the drain is a guarded no-op when
    /// `pendingOutgoingQueue` is empty (`drainOutgoingQueue` guard,
    /// RNS/Link.py:1320-1322). Guards against an over-eager drain spuriously
    /// re-advertising or trapping on an empty queue.
    func testCancelWithEmptyQueueLeavesSlotEmpty() async throws {
        let log = SendLog()
        let link = try await makeActiveLink()
        await link.setSendCallback { data in await log.record(data) }

        let rA = try await link.sendResource(data: Data(repeating: 0x47, count: 300))
        let countBefore = await link.outgoingResourceCount
        XCTAssertEqual(countBefore, 1)
        let sentBefore = await log.count

        await link.cancelOutgoingResource(rA)

        let countAfter = await link.outgoingResourceCount
        XCTAssertEqual(countAfter, 0,
            "Cancelling the only resource with an empty queue must empty the slot.")
        let ready = await link.readyForNewResource()
        XCTAssertTrue(ready, "Link must be ready for a new resource after cancel.")
        let sentAfter = await log.count
        XCTAssertEqual(sentAfter, sentBefore,
            "An empty queue drain must not put any new advertisement on the wire.")
    }
}
