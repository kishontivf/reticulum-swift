// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  TransportCoverageTests.swift
//  ReticulumSwift
//
//  Breadth coverage for synchronous accessors and state-transition surface of
//  ReticulumTransport that the send/forwarding/interop/path suites don't touch:
//
//    - registerDestination + callback-manager wiring
//    - unregisterDestination / isLocalDestination / destinationCount
//    - registerProbeDestination (mgmt tracking + idempotency)
//    - registerRemoteManagementDestination (ACL validation + idempotency + throw)
//    - packetHashlistCount / packetHashlistContains observability accessors
//    - registerLink / getLink / unregisterLink / activeLinkCount / activeLinkList
//    - linksForDestination (responder filter fallback)
//    - detachInterfaces (active + pending teardown to terminal)
//    - registerDestinationLinkCallback / registeredLinkCallbackHashes
//    - setUseImplicitProof / shouldUseImplicitProof
//    - registerAnnounceHandler / deregisterAnnounceHandler / announceHandlerCount
//    - interface accessors (getInterface / interfaceCount / interfaceIds /
//      listInterfaceIds) + getPathTable / getCallbackManager / getAnnounceTable
//    - nextHopInterfaceHwMtu nil branch
//
//  All tests drive the REAL ReticulumTransport actor. MockInterface is REUSED
//  from TransportSendTests.swift (same test target) — not redefined here.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class TransportCoverageTests: XCTestCase {

    // MARK: - Private helpers (no global/top-level helpers — collide at integration)

    /// Stub external announce handler. `hasAspectFilter` is configurable so we can
    /// exercise the `register_announce_handler` registration guard
    /// (Transport.py:2476-2477) on both branches.
    private final class StubAnnounceHandler: AnnounceHandlerProtocol, @unchecked Sendable {
        let aspectFilter: String?
        let hasAspectFilter: Bool
        let receivePathResponses: Bool
        let callbackParameterCount: Int

        init(hasAspectFilter: Bool, aspectFilter: String? = nil) {
            self.hasAspectFilter = hasAspectFilter
            self.aspectFilter = aspectFilter
            self.receivePathResponses = false
            self.callbackParameterCount = 3
        }

        func receivedAnnounce(
            destinationHash: Data,
            announcedIdentity: Identity?,
            appData: Data?,
            announcePacketHash: Data?,
            isPathResponse: Bool?
        ) throws {
            // No-op: registration/observability tests don't drive dispatch.
        }
    }

    /// Build a fresh outbound link (state `.pending`) with a real, distinct
    /// 16-byte link_id derived from freshly generated ephemeral keys.
    private func makeOutboundLink(appName: String = "coverage", aspect: String) -> Link {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: appName, aspects: [aspect])
        return Link(destination: dest, identity: identity)
    }

    /// Build a responder (inbound) link in `.active` state for a given destination.
    /// `initiator == false`, so it is matched by `linksForDestination`'s filter branch.
    private func makeResponderLink(for dest: Destination) async throws -> Link {
        let identity = Identity()
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

    // MARK: - registerDestination / callback-manager wiring

    func testRegisterDestinationWiresCallbackManagerAndAccessors() async throws {
        let transport = ReticulumTransport()
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "cov", aspects: ["reg"])

        // Precondition: nothing registered.
        let before = await transport.destinationCount
        XCTAssertEqual(before, 0)
        let registeredBefore = await transport.isDestinationRegistered(dest.hash)
        XCTAssertFalse(registeredBefore)

        await transport.registerDestination(dest)

        // The destination's callback manager must now be the transport's manager —
        // registerDestination() calls destination.setCallbackManager(callbackManager).
        let cm = await transport.getCallbackManager()
        if let wired = dest.callbackManager {
            XCTAssertTrue(wired as AnyObject === cm as AnyObject,
                "registerDestination must wire the destination to the transport's callback manager")
        } else {
            XCTFail("registerDestination did not set destination.callbackManager")
        }

        // Accessors reflect the registration.
        let count = await transport.destinationCount
        XCTAssertEqual(count, 1)
        let isReg = await transport.isDestinationRegistered(dest.hash)
        XCTAssertTrue(isReg)
        let isLocal = await transport.isLocalDestination(dest.hash)
        XCTAssertTrue(isLocal)

        let hexes = await transport.registeredDestinationHashes()
        let expectedHex = dest.hash.map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(hexes.contains(expectedHex),
            "registeredDestinationHashes should contain the full-hex destination hash")
    }

    func testUnregisterDestinationRemovesIt() async throws {
        let transport = ReticulumTransport()
        let dest = Destination(identity: Identity(), appName: "cov", aspects: ["unreg"])

        await transport.registerDestination(dest)
        var isLocal = await transport.isLocalDestination(dest.hash)
        XCTAssertTrue(isLocal)

        await transport.unregisterDestination(hash: dest.hash)

        isLocal = await transport.isLocalDestination(dest.hash)
        XCTAssertFalse(isLocal, "unregisterDestination must remove the destination")
        let count = await transport.destinationCount
        XCTAssertEqual(count, 0)
        let isReg = await transport.isDestinationRegistered(dest.hash)
        XCTAssertFalse(isReg)
    }

    // MARK: - Probe destination

    func testRegisterProbeDestinationTracksMgmtAndIsIdempotent() async throws {
        let transport = ReticulumTransport()
        let identity = Identity()

        // Default off.
        let off = await transport.respondToProbes
        XCTAssertFalse(off)
        let probeNil = await transport.probeDestination
        XCTAssertNil(probeNil)

        await transport.registerProbeDestination(identity: identity)

        let probe = await transport.probeDestination
        XCTAssertNotNil(probe, "probeDestination should be set after registration")
        let respond = await transport.respondToProbes
        XCTAssertTrue(respond)

        // PROVE_ALL — probe destination always answers with proofs (Transport.py:399).
        XCTAssertEqual(probe?.proofStrategy, Destination.PROVE_ALL)

        // Probe is appended to mgmt_destinations but NOT mgmt_hashes (Transport.py:400).
        let mgmtDests = await transport.mgmtDestinations
        XCTAssertEqual(mgmtDests.count, 1)
        let mgmtHashes = await transport.mgmtHashes
        XCTAssertFalse(mgmtHashes.contains(probe!.hash),
            "probe destination must NOT be tracked in mgmtHashes")

        // It is also registered as a live routable destination.
        let routable = await transport.isDestinationRegistered(probe!.hash)
        XCTAssertTrue(routable)

        // Idempotent: a second call must not append a duplicate mgmt entry.
        await transport.registerProbeDestination(identity: identity)
        let mgmtDestsAfter = await transport.mgmtDestinations
        XCTAssertEqual(mgmtDestsAfter.count, 1,
            "registerProbeDestination must be idempotent (no duplicate mgmt entry)")
        let probeAfter = await transport.probeDestination
        XCTAssertEqual(probeAfter?.hash, probe?.hash,
            "probe destination hash must be stable across idempotent calls")
    }

    // MARK: - Remote-management destination

    func testRegisterRemoteManagementDestinationTracksAclAndMgmt() async throws {
        let transport = ReticulumTransport()
        let identity = Identity()
        let acl = [Data(repeating: 0x11, count: 16), Data(repeating: 0x22, count: 16)]

        let enabledBefore = await transport.remoteManagementEnabled
        XCTAssertFalse(enabledBefore)

        try await transport.registerRemoteManagementDestination(identity: identity, allowed: acl)

        let dest = await transport.remoteManagementDestination
        XCTAssertNotNil(dest)
        let enabled = await transport.remoteManagementEnabled
        XCTAssertTrue(enabled)
        let allowed = await transport.remoteManagementAllowed
        XCTAssertEqual(allowed, acl)

        // Tracked in BOTH mgmt_destinations AND mgmt_hashes (Transport.py:254-255).
        let mgmtHashes = await transport.mgmtHashes
        XCTAssertTrue(mgmtHashes.contains(dest!.hash),
            "remote-management destination must be in mgmtHashes")
        let mgmtDests = await transport.mgmtDestinations
        XCTAssertTrue(mgmtDests.contains { $0.hash == dest!.hash })
        let routable = await transport.isDestinationRegistered(dest!.hash)
        XCTAssertTrue(routable)

        // Idempotent on the destination side (guard returns before re-registering).
        try await transport.registerRemoteManagementDestination(identity: identity, allowed: acl)
        let mgmtHashesAfter = await transport.mgmtHashes
        XCTAssertEqual(mgmtHashesAfter.count, 1,
            "registerRemoteManagementDestination must not duplicate the mgmt hash")
    }

    func testRegisterRemoteManagementRejectsBadAclLength() async throws {
        let transport = ReticulumTransport()
        let identity = Identity()
        // 15-byte ACL entry — not TRUNCATED_HASH_LENGTH (16).
        let badAcl = [Data(repeating: 0x33, count: 15)]

        do {
            try await transport.registerRemoteManagementDestination(identity: identity, allowed: badAcl)
            XCTFail("Expected TransportError.invalidConfiguration for a non-16-byte ACL entry")
        } catch let error as TransportError {
            guard case .invalidConfiguration = error else {
                XCTFail("Expected .invalidConfiguration, got \(error)")
                return
            }
        }

        // The throw happens before any state mutation: nothing should be registered.
        let dest = await transport.remoteManagementDestination
        XCTAssertNil(dest, "no destination should be registered when ACL validation fails")
        let enabled = await transport.remoteManagementEnabled
        XCTAssertFalse(enabled, "remote management must stay disabled on validation failure")
    }

    // MARK: - Packet hashlist observability accessors

    func testPacketHashlistCountAndContains() async throws {
        let transport = ReticulumTransport()

        let emptyCount = await transport.packetHashlistCount()
        XCTAssertEqual(emptyCount, 0)

        let hash = Data(repeating: 0xA5, count: 32)
        let other = Data(repeating: 0x5A, count: 32)

        // Membership negative before recording.
        let containsBefore = await transport.packetHashlistContains(hash)
        XCTAssertFalse(containsBefore)

        await transport.packetHashlist.record(hash)

        let count = await transport.packetHashlistCount()
        XCTAssertEqual(count, 1, "packetHashlistCount must reflect a recorded hash")
        let contains = await transport.packetHashlistContains(hash)
        XCTAssertTrue(contains, "packetHashlistContains must be true for a recorded hash")
        let containsOther = await transport.packetHashlistContains(other)
        XCTAssertFalse(containsOther, "packetHashlistContains must be false for an unseen hash")
    }

    // MARK: - Link registry accessors

    func testRegisterGetUnregisterLink() async throws {
        let transport = ReticulumTransport()
        let link = makeOutboundLink(aspect: "registry")
        let linkId = await link.linkId
        XCTAssertEqual(linkId.count, 16, "outbound link should have a 16-byte link_id")

        // Before registration.
        let countBefore = await transport.activeLinkCount
        XCTAssertEqual(countBefore, 0)
        let missing = await transport.getLink(linkId: linkId)
        XCTAssertNil(missing)

        await transport.registerLink(link)

        let countAfter = await transport.activeLinkCount
        XCTAssertEqual(countAfter, 1)
        let found = await transport.getLink(linkId: linkId)
        XCTAssertNotNil(found, "getLink must return a registered active link")
        let foundId = await found?.linkId
        XCTAssertEqual(foundId, linkId)

        let list = await transport.activeLinkList()
        XCTAssertEqual(list.count, 1)
        let listIds = await withTaskGroup(of: Data.self) { group -> [Data] in
            for l in list { group.addTask { await l.linkId } }
            var ids: [Data] = []
            for await id in group { ids.append(id) }
            return ids
        }
        XCTAssertTrue(listIds.contains(linkId), "activeLinkList must include the registered link")

        await transport.unregisterLink(linkId: linkId)
        let countFinal = await transport.activeLinkCount
        XCTAssertEqual(countFinal, 0)
        let afterUnreg = await transport.getLink(linkId: linkId)
        XCTAssertNil(afterUnreg, "getLink must return nil after unregisterLink")
    }

    func testLinksForDestinationResponderFilterFallback() async throws {
        let transport = ReticulumTransport()
        let dest = Destination(identity: Identity(), appName: "cov", aspects: ["responder"])
        let link = try await makeResponderLink(for: dest)
        await transport.registerLink(link)

        // Destination is NOT in the `destinations` map, so linksForDestination falls
        // through to filtering active responder links by destination hash.
        let links = await transport.linksForDestination(dest.hash)
        XCTAssertEqual(links.count, 1, "responder link should be found via the filter fallback")

        // A different (unknown) destination hash yields no links.
        let none = await transport.linksForDestination(Data(repeating: 0xEE, count: 16))
        XCTAssertEqual(none.count, 0)
    }

    // MARK: - detachInterfaces

    func testDetachInterfacesClosesActiveAndPendingLinks() async throws {
        // Set up a transport with a connected interface and a path so initiateLink works.
        let identity = Identity()
        let dest = Destination(identity: Identity(), appName: "cov", aspects: ["detach"])

        let pathTable = PathTable()
        let entry = PathEntry(
            destinationHash: dest.hash,
            publicKeys: Data(),
            interfaceId: "mock-interface",
            hopCount: 1,
            randomBlob: Data(repeating: 0x22, count: 10),
            nextHop: nil
        )
        await pathTable.record(entry: entry)

        let transport = ReticulumTransport(pathTable: pathTable)
        let mock = MockInterface()
        try await transport.addInterface(mock)

        // Two active links registered directly.
        let active1 = makeOutboundLink(aspect: "detach-a1")
        let active2 = makeOutboundLink(aspect: "detach-a2")
        await transport.registerLink(active1)
        await transport.registerLink(active2)

        // One pending link via initiateLink (populates pendingLinks).
        let pending = try await transport.initiateLink(to: dest, identity: identity)

        let activeCount = await transport.activeLinkCount
        XCTAssertEqual(activeCount, 2)
        let pendingCount = await transport.pendingLinkCount
        XCTAssertEqual(pendingCount, 1, "initiateLink should register a pending link")

        // Precondition: links are not yet terminal.
        let a1Before = await active1.state
        XCTAssertFalse(a1Before.isTerminal)
        let pendingBefore = await pending.state
        XCTAssertFalse(pendingBefore.isTerminal)

        await transport.detachInterfaces()

        // All active AND pending links must be torn down to a terminal (.closed) state.
        let a1After = await active1.state
        XCTAssertTrue(a1After.isTerminal, "active link 1 must be closed after detachInterfaces")
        let a2After = await active2.state
        XCTAssertTrue(a2After.isTerminal, "active link 2 must be closed after detachInterfaces")
        let pendingAfter = await pending.state
        XCTAssertTrue(pendingAfter.isTerminal, "pending link must be closed after detachInterfaces")
    }

    // MARK: - Destination link callbacks

    func testRegisterDestinationLinkCallbackTracksHash() async throws {
        let transport = ReticulumTransport()
        let destHash = Data(repeating: 0xC3, count: 16)

        let before = await transport.registeredLinkCallbackHashes()
        XCTAssertTrue(before.isEmpty)

        await transport.registerDestinationLinkCallback(for: destHash) { _ in }

        let after = await transport.registeredLinkCallbackHashes()
        let expectedHex = destHash.map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(after.contains(expectedHex),
            "registeredLinkCallbackHashes must include the registered destination hash")
    }

    // MARK: - Implicit-proof policy

    func testUseImplicitProofTogglesPerTransport() async throws {
        let transport = ReticulumTransport()

        // RNS default is True (Reticulum.py:256).
        let initial = await transport.shouldUseImplicitProof()
        XCTAssertTrue(initial)

        await transport.setUseImplicitProof(false)
        let off = await transport.shouldUseImplicitProof()
        XCTAssertFalse(off, "setUseImplicitProof(false) must flip the policy")

        await transport.setUseImplicitProof(true)
        let on = await transport.shouldUseImplicitProof()
        XCTAssertTrue(on, "setUseImplicitProof(true) must restore implicit proofs")
    }

    // MARK: - External announce handler registration

    func testRegisterAnnounceHandlerGuardAndDeregister() async throws {
        let transport = ReticulumTransport()

        let countStart = await transport.announceHandlerCount
        XCTAssertEqual(countStart, 0)

        // Handler WITHOUT aspect filter is not registered (Transport.py:2476-2477).
        let noFilter = StubAnnounceHandler(hasAspectFilter: false)
        let registeredNoFilter = await transport.registerAnnounceHandler(noFilter)
        XCTAssertFalse(registeredNoFilter, "handler without aspect filter must NOT register")
        let countAfterNoFilter = await transport.announceHandlerCount
        XCTAssertEqual(countAfterNoFilter, 0)

        // Handler WITH aspect filter registers.
        let withFilter = StubAnnounceHandler(hasAspectFilter: true, aspectFilter: "lxmf.delivery")
        let registered = await transport.registerAnnounceHandler(withFilter)
        XCTAssertTrue(registered, "handler with aspect filter must register")
        let countAfter = await transport.announceHandlerCount
        XCTAssertEqual(countAfter, 1)

        // Deregister removes it by identity.
        await transport.deregisterAnnounceHandler(withFilter)
        let countFinal = await transport.announceHandlerCount
        XCTAssertEqual(countFinal, 0, "deregisterAnnounceHandler must remove the handler")
    }

    // MARK: - Interface + dependency accessors

    func testInterfaceAccessors() async throws {
        let transport = ReticulumTransport()
        let mock = MockInterface(id: "iface-accessors")

        let countBefore = await transport.interfaceCount
        XCTAssertEqual(countBefore, 0)

        try await transport.addInterface(mock)

        let count = await transport.interfaceCount
        XCTAssertEqual(count, 1)
        let ids = await transport.interfaceIds
        XCTAssertEqual(ids, ["iface-accessors"])
        let listed = await transport.listInterfaceIds()
        XCTAssertEqual(listed, ["iface-accessors"])

        let fetched = await transport.getInterface(id: "iface-accessors")
        XCTAssertNotNil(fetched)
        XCTAssertEqual(fetched?.id, "iface-accessors")
        let missing = await transport.getInterface(id: "does-not-exist")
        XCTAssertNil(missing)
    }

    func testDependencyAccessorsReturnInjectedInstances() async throws {
        let pathTable = PathTable()
        let entry = PathEntry(
            destinationHash: Data(repeating: 0x71, count: 16),
            publicKeys: Data(),
            interfaceId: "x",
            hopCount: 1,
            randomBlob: Data(repeating: 0x01, count: 10),
            nextHop: nil
        )
        await pathTable.record(entry: entry)

        let transport = ReticulumTransport(pathTable: pathTable)

        // getPathTable returns the SAME table we injected — the recorded entry is visible.
        let returnedTable = await transport.getPathTable()
        let hasPath = await returnedTable.hasPath(for: Data(repeating: 0x71, count: 16))
        XCTAssertTrue(hasPath, "getPathTable must return the injected path table")

        // getCallbackManager / getAnnounceHandler / getAnnounceTable are non-nil accessors.
        _ = await transport.getCallbackManager()
        _ = await transport.getAnnounceHandler()
        let announceTable = await transport.getAnnounceTable()
        let announceCount = await announceTable.count
        XCTAssertEqual(announceCount, 0, "a fresh announce table starts empty")
    }

    // MARK: - nextHopInterfaceHwMtu nil branch

    func testNextHopHwMtuNilWithoutPath() async throws {
        let transport = ReticulumTransport()
        let mtu = await transport.nextHopInterfaceHwMtu(for: Data(repeating: 0x44, count: 16))
        XCTAssertNil(mtu, "nextHopInterfaceHwMtu must be nil when there is no path")
    }

    func testNextHopHwMtuReturnsInterfaceMtu() async throws {
        let destHash = Data(repeating: 0x66, count: 16)
        let pathTable = PathTable()
        let entry = PathEntry(
            destinationHash: destHash,
            publicKeys: Data(),
            interfaceId: "mock-interface",
            hopCount: 1,
            randomBlob: Data(repeating: 0x01, count: 10),
            nextHop: nil
        )
        await pathTable.record(entry: entry)

        let transport = ReticulumTransport(pathTable: pathTable)
        let mock = MockInterface()
        try await transport.addInterface(mock)

        // MockInterface uses the NetworkInterface default hwMtu of 500.
        let mtu = await transport.nextHopInterfaceHwMtu(for: destHash)
        XCTAssertEqual(mtu, 500)

        // Path present but interface unknown → nil (interfaceId mismatch branch).
        let otherDest = Data(repeating: 0x77, count: 16)
        let otherEntry = PathEntry(
            destinationHash: otherDest,
            publicKeys: Data(),
            interfaceId: "unregistered-iface",
            hopCount: 1,
            randomBlob: Data(repeating: 0x02, count: 10),
            nextHop: nil
        )
        await pathTable.record(entry: otherEntry)
        let nilMtu = await transport.nextHopInterfaceHwMtu(for: otherDest)
        XCTAssertNil(nilMtu, "nextHopInterfaceHwMtu must be nil when the path interface is not registered")
    }
}
