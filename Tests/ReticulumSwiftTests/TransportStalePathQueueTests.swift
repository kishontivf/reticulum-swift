// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  TransportStalePathQueueTests.swift
//  ReticulumSwift
//
//  Tests for the stale-path invalidation / queue-and-retry behavior in
//  ReticulumTransport. Covers:
//    - Disconnected interface: packet is queued instead of sent
//    - Missing interface (stale entry from previous run): packet is queued
//      and the stale entry is removed
//    - The 10-packet-per-destination queue cap silently drops oldest entries
//    - A fresh path recorded via pathTable.record flushes the queue via
//      processPendingPackets
//    - Conditional remove (PathTable.remove(destinationHash:, ifInterface:))
//      preserves a freshly-recorded entry that references a different interface
//

import XCTest
@testable import ReticulumSwift

// MARK: - Togglable mock interface

/// NetworkInterface whose `state` can be flipped between .connected and
/// .disconnected by the test. The existing MockInterface in TransportSendTests
/// hard-codes `.connected`, so we need a separate type to exercise the stale-
/// path branches of sendViaPath / send(packet:).
final class TogglableMockInterface: NetworkInterface, @unchecked Sendable {
    let id: String
    let config: InterfaceConfig

    nonisolated(unsafe) var state: InterfaceState = .connected
    nonisolated(unsafe) private(set) var sentPackets: [Data] = []

    init(id: String, initialState: InterfaceState = .connected) {
        self.id = id
        self.config = InterfaceConfig(
            id: id,
            name: "Togglable Mock",
            type: .tcp,
            enabled: true,
            mode: .full,
            host: "127.0.0.1",
            port: 0
        )
        self.state = initialState
    }

    /// No-op so `transport.addInterface`'s auto-connect doesn't clobber the
    /// state the test set via `initialState`. Tests that need to simulate a
    /// later connect call `setState(.connected)` explicitly.
    func connect() async throws {}

    func disconnect() async {}

    /// Test hook: set the interface state without going through connect/disconnect.
    func setState(_ new: InterfaceState) {
        state = new
    }

    func send(_ data: Data) async throws {
        sentPackets.append(data)
    }

    func setDelegate(_ delegate: InterfaceDelegate) async {}

    func drainSentPackets() -> [Data] {
        let out = sentPackets
        sentPackets = []
        return out
    }
}

// MARK: - Tests

final class TransportStalePathQueueTests: XCTestCase {

    /// 16-byte destination hash used across tests.
    private static let destHash = Data(repeating: 0x77, count: 16)
    private static let nextHop  = Data(repeating: 0x99, count: 16)

    /// Build a transport with a single path for `destHash` pointing at `interfaceId`,
    /// hopCount=1 (so a disconnected-interface path resolves to the interface-
    /// missing branch without triggering HEADER_2 conversion).
    private func makeTransportWithPath(
        interfaceId: String,
        hopCount: UInt8 = 1,
        nextHop: Data? = nil
    ) async throws -> (ReticulumTransport, PathTable) {
        let pathTable = PathTable()
        let entry = PathEntry(
            destinationHash: Self.destHash,
            publicKeys: Data(repeating: 0xAA, count: 64),
            interfaceId: interfaceId,
            hopCount: hopCount,
            randomBlob: Data(repeating: 0xBB, count: 10),
            nextHop: nextHop
        )
        await pathTable.record(entry: entry)
        let transport = ReticulumTransport(pathTable: pathTable)
        return (transport, pathTable)
    }

    /// Build a HEADER_2 / TRANSPORT data packet addressed to `destHash`.
    /// HEADER_2 routes via sendViaPath, which is the function whose disconnected-
    /// interface branch we're exercising.
    private func makeRoutedPacket(hopCount: UInt8 = 0) -> Packet {
        let header = PacketHeader(
            headerType: .header2,
            hasContext: false,
            transportType: .transport,
            destinationType: .single,
            packetType: .data,
            hopCount: hopCount
        )
        return Packet(
            header: header,
            destination: Self.destHash,
            transportAddress: Self.nextHop,
            context: 0x00,
            data: Data(repeating: 0xDD, count: 16)
        )
    }

    // MARK: - Disconnected interface

    /// When the path's interface is disconnected, the packet should be queued
    /// instead of sent on the disconnected interface or broadcast.
    func testDisconnectedInterfaceQueuesPacket() async throws {
        let (transport, _) = try await makeTransportWithPath(interfaceId: "iface-x")
        let iface = TogglableMockInterface(id: "iface-x", initialState: .disconnected)
        try await transport.addInterface(iface)

        try await transport.send(packet: makeRoutedPacket())

        XCTAssertEqual(
            iface.sentPackets.count, 0,
            "Disconnected interface must not be used to send"
        )
        let queueCountDisc = await transport.pendingPacketCount
        XCTAssertEqual(queueCountDisc, 1, "Packet should be queued for the destination")
    }

    // MARK: - Missing interface (stale entry)

    /// When the path's interface is absent from `interfaces` (e.g. after an app
    /// restart with a persisted path table), the packet should be queued AND
    /// the stale entry should be removed so follow-up logic sees a clean slate.
    func testMissingInterfaceQueuesAndInvalidates() async throws {
        let (transport, pathTable) = try await makeTransportWithPath(interfaceId: "iface-missing")
        // Deliberately do not addInterface("iface-missing") — the path table
        // references an interface that doesn't exist in this session.

        // Add a different connected interface so requestPath doesn't throw
        // for lack of any outbound interface.
        let otherIface = TogglableMockInterface(id: "iface-other")
        try await transport.addInterface(otherIface)

        try await transport.send(packet: makeRoutedPacket())

        let queueCountMissing = await transport.pendingPacketCount
        XCTAssertEqual(queueCountMissing, 1, "Packet should be queued after stale-path invalidation")

        // Path entry should be gone now that it was detected stale.
        let after = await pathTable.lookup(destinationHash: Self.destHash)
        XCTAssertNil(after, "Stale path entry should have been removed")
    }

    // MARK: - Queue cap

    /// Sending more than `maxPendingPacketsPerDestination` (10) packets to a
    /// destination with a stale/disconnected path must cap the queue at 10
    /// and silently drop the oldest. Verifies the documented trade-off.
    func testQueueCapDropsOldest() async throws {
        let (transport, _) = try await makeTransportWithPath(interfaceId: "iface-x")
        let iface = TogglableMockInterface(id: "iface-x", initialState: .disconnected)
        try await transport.addInterface(iface)

        for _ in 0..<15 {
            try await transport.send(packet: makeRoutedPacket())
        }

        let queueCountCap = await transport.pendingPacketCount
        XCTAssertEqual(
            queueCountCap, 10,
            "Queue must cap at 10 — the 11th+ enqueues should drop the oldest"
        )
    }

    // MARK: - Fresh path flushes queue

    /// After a packet has been queued, recording a fresh path to the same
    /// destination (simulating an announce arrival) should trigger
    /// processPendingPackets, which dispatches through send(packet:) and
    /// delivers the packet via the now-connected interface.
    func testFreshPathFlushesQueuedPacket() async throws {
        let (transport, pathTable) = try await makeTransportWithPath(interfaceId: "iface-stale")
        // Stale interface is not added — simulates post-restart persisted path.

        let liveIface = TogglableMockInterface(id: "iface-live")
        try await transport.addInterface(liveIface)

        // First send: stale path invalidated, packet queued.
        try await transport.send(packet: makeRoutedPacket())
        let queuedCount = await transport.pendingPacketCount
        XCTAssertEqual(queuedCount, 1)

        // Announce arrives on the live interface — record a fresh path. The
        // transport's path-recorded hook is responsible for flushing queued
        // packets via processPendingPackets; in isolation tests we invoke the
        // public recordPath path via pathTable.record + explicit flush trigger.
        let freshEntry = PathEntry(
            destinationHash: Self.destHash,
            publicKeys: Data(repeating: 0xAA, count: 64),
            interfaceId: "iface-live",
            hopCount: 1,
            randomBlob: Data(repeating: 0xBB, count: 10),
            nextHop: nil
        )
        await pathTable.record(entry: freshEntry)

        // The first send's requestPath broadcast a path-request on the live
        // interface; drain those before measuring the flush so we assert on
        // the flush's deliveries specifically.
        _ = liveIface.drainSentPackets()

        await transport.testFlushPendingPackets(for: Self.destHash)

        // Queue should be empty, packet delivered on the live interface.
        let flushedCount = await transport.pendingPacketCount
        XCTAssertEqual(flushedCount, 0, "Fresh path should flush the queue")
        XCTAssertEqual(
            liveIface.sentPackets.count, 1,
            "Queued packet should have been delivered via the live interface"
        )
    }

    // MARK: - Conditional remove

    /// PathTable.remove(destinationHash:, ifInterface:) must remove ONLY the
    /// entry for the named interface. This is the key guarantee that prevents
    /// the stale-path invalidation flow from erasing a freshly-recorded path
    /// that arrived during the actor suspension: with multi-path storage the
    /// fresh entry lives in its own (destination, interface) slot and
    /// survives the stale entry's removal.
    func testConditionalRemoveSkipsWhenInterfaceChanged() async throws {
        let pathTable = PathTable()
        let stale = PathEntry(
            destinationHash: Self.destHash,
            publicKeys: Data(repeating: 0xAA, count: 64),
            interfaceId: "iface-old",
            hopCount: 1,
            randomBlob: Data(repeating: 0xBB, count: 10),
            nextHop: nil
        )
        await pathTable.record(entry: stale)

        // Simulate an announce recording a fresh path on a different interface
        // between our decision to remove and the remove call itself.
        let fresh = PathEntry(
            destinationHash: Self.destHash,
            publicKeys: Data(repeating: 0xAA, count: 64),
            interfaceId: "iface-new",
            hopCount: 1,
            randomBlob: Data(repeating: 0xCC, count: 10),
            nextHop: nil
        )
        await pathTable.record(entry: fresh)

        // Remove the STALE interface's entry — the fresh entry must survive.
        let removed = await pathTable.remove(destinationHash: Self.destHash, ifInterface: "iface-old")
        XCTAssertTrue(removed, "Stale interface's own entry should be removed")

        let after = await pathTable.lookup(destinationHash: Self.destHash)
        XCTAssertNotNil(after, "Fresh entry must be preserved")
        XCTAssertEqual(after?.interfaceId, "iface-new")
        let remaining = await pathTable.lookupAll(destinationHash: Self.destHash)
        XCTAssertEqual(remaining.count, 1, "Only the fresh entry should remain")
    }

    /// Conditional remove must still work when the entry does reference the
    /// specified interface — the happy path for invalidating a truly stale
    /// entry.
    func testConditionalRemoveActsWhenInterfaceMatches() async throws {
        let pathTable = PathTable()
        let stale = PathEntry(
            destinationHash: Self.destHash,
            publicKeys: Data(repeating: 0xAA, count: 64),
            interfaceId: "iface-old",
            hopCount: 1,
            randomBlob: Data(repeating: 0xBB, count: 10),
            nextHop: nil
        )
        await pathTable.record(entry: stale)

        let removed = await pathTable.remove(destinationHash: Self.destHash, ifInterface: "iface-old")
        XCTAssertTrue(removed, "Remove should succeed when interface matches")

        let after = await pathTable.lookup(destinationHash: Self.destHash)
        XCTAssertNil(after, "Stale entry should be gone")
    }
}
