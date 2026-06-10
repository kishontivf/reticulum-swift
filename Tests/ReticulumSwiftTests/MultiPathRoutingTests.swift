// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  MultiPathRoutingTests.swift
//  ReticulumSwiftTests
//
//  Tests for multi-path routing: per-interface path storage, per-interface
//  announce dedup with single rebroadcast, nearby-aware outbound selection,
//  and interface-loss failover (path invalidation + link teardown + events).
//

import XCTest
import SQLite3
@testable import ReticulumSwift

// MARK: - Mock interface with configurable type

/// NetworkInterface mock with a configurable InterfaceType so tests can mix
/// direct-class (.ble) and indirect-class (.tcp) interfaces.
final class ClassedMockInterface: NetworkInterface, @unchecked Sendable {
    let id: String
    let config: InterfaceConfig
    let hwMtu: Int

    nonisolated(unsafe) var state: InterfaceState = .connected
    nonisolated(unsafe) private(set) var sentPackets: [Data] = []

    init(id: String, type: InterfaceType, initialState: InterfaceState = .connected) {
        self.id = id
        self.config = InterfaceConfig(
            id: id,
            name: "Mock \(type.rawValue)",
            type: type,
            enabled: true,
            mode: .full,
            host: "127.0.0.1",
            port: 0
        )
        // Mirror the real interfaces' hardware MTUs so throughput-aware
        // selection sees realistic ranks (BLEPeerInterface 508,
        // MPCPeerInterface 1196, TCP effectively unbounded).
        switch type {
        case .ble: self.hwMtu = 508
        case .multipeerConnectivity: self.hwMtu = 1196
        default: self.hwMtu = 262144
        }
        self.state = initialState
    }

    func connect() async throws {}
    func disconnect() async {}
    func setState(_ new: InterfaceState) { state = new }

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

// MARK: - Event collector

/// Thread-safe collector for TransportEvents (emitted from detached Tasks).
final class TransportEventCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var _events: [ReticulumTransport.TransportEvent] = []

    func append(_ event: ReticulumTransport.TransportEvent) {
        lock.lock(); defer { lock.unlock() }
        _events.append(event)
    }

    var events: [ReticulumTransport.TransportEvent] {
        lock.lock(); defer { lock.unlock() }
        return _events
    }

    /// Poll until at least `count` events arrived or the timeout elapses.
    func waitForEvents(count: Int, timeout: TimeInterval = 2.0) async {
        let deadline = Date().addingTimeInterval(timeout)
        while events.count < count && Date() < deadline {
            try? await Task.sleep(for: .milliseconds(20))
        }
    }
}

// MARK: - Shared helpers

/// Create a random blob with a specific emission timestamp embedded at bytes[5:10].
private func makeBlob(timestamp: UInt64, prefix: UInt8 = 0x11) -> Data {
    var blob = Data(repeating: prefix, count: 5)
    for i in (0..<5).reversed() {
        blob.append(UInt8((timestamp >> (i * 8)) & 0xFF))
    }
    return blob
}

private func makeEntry(
    destHash: Data,
    interfaceId: String,
    hopCount: UInt8 = 1,
    blob: Data,
    nextHop: Data? = nil
) -> PathEntry {
    PathEntry(
        destinationHash: destHash,
        publicKeys: Data(repeating: 0xAA, count: 64),
        interfaceId: interfaceId,
        hopCount: hopCount,
        randomBlob: blob,
        nextHop: nextHop
    )
}

/// HEADER_1 broadcast DATA packet to a destination.
private func makeDataPacket(dest: Data) -> Packet {
    let header = PacketHeader(
        headerType: .header1,
        hasContext: false,
        transportType: .broadcast,
        destinationType: .single,
        packetType: .data,
        hopCount: 0
    )
    return Packet(
        header: header,
        destination: dest,
        transportAddress: nil,
        context: 0x00,
        data: Data(repeating: 0xDD, count: 16)
    )
}

// MARK: - PathTable multi-path tests

final class PathTableMultiPathTests: XCTestCase {

    private let destHash = Data(repeating: 0x42, count: 16)

    /// The same announce (same blob) heard on a second interface must record
    /// an additional path (rule 1b with ">=").
    func testSameAnnounceOnSecondInterfaceRecordsBothPaths() async throws {
        let table = PathTable()
        let blob = makeBlob(timestamp: 1000)

        let viaTcp = await table.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", hopCount: 3, blob: blob))
        XCTAssertTrue(viaTcp)
        let viaBle = await table.record(entry: makeEntry(destHash: destHash, interfaceId: "ble0", hopCount: 1, blob: blob))
        XCTAssertTrue(viaBle, "Same-blob announce on a second interface must be accepted (rule 1b, >=)")

        let all = await table.lookupAll(destinationHash: destHash)
        XCTAssertEqual(all.count, 2)
        XCTAssertEqual(Set(all.map(\.interfaceId)), ["tcp0", "ble0"])
    }

    /// A replayed OLD announce on a new interface must be rejected (rule 1b
    /// guards with the destination timebase).
    func testReplayedOldAnnounceOnNewInterfaceRejected() async throws {
        let table = PathTable()

        let fresh = await table.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", blob: makeBlob(timestamp: 2000)))
        XCTAssertTrue(fresh)
        let replayed = await table.record(entry: makeEntry(destHash: destHash, interfaceId: "ble0", blob: makeBlob(timestamp: 1000)))
        XCTAssertFalse(replayed, "Replayed old announce must not hijack the route via a new interface")

        let all = await table.lookupAll(destinationHash: destHash)
        XCTAssertEqual(all.map(\.interfaceId), ["tcp0"])
    }

    /// lookup() returns the best entry across interfaces (min hops).
    func testLookupReturnsBestAcrossInterfaces() async throws {
        let table = PathTable()
        let blob = makeBlob(timestamp: 1000)
        await table.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", hopCount: 4, blob: blob))
        await table.record(entry: makeEntry(destHash: destHash, interfaceId: "ble0", hopCount: 1, blob: blob))

        let best = await table.lookup(destinationHash: destHash)
        XCTAssertEqual(best?.interfaceId, "ble0")
        XCTAssertEqual(best?.hopCount, 1)
    }

    /// removeAll(forInterface:) drops that interface's entries everywhere,
    /// preserves sibling entries, and reports affected destinations.
    func testRemoveAllForInterfacePreservesSiblings() async throws {
        let table = PathTable()
        let otherDest = Data(repeating: 0x43, count: 16)
        let blob = makeBlob(timestamp: 1000)
        await table.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", hopCount: 3, blob: blob))
        await table.record(entry: makeEntry(destHash: destHash, interfaceId: "ble0", hopCount: 1, blob: blob))
        await table.record(entry: makeEntry(destHash: otherDest, interfaceId: "ble0", hopCount: 1, blob: blob))

        let affected = await table.removeAll(forInterface: "ble0")
        XCTAssertEqual(Set(affected), [destHash, otherDest])

        let survivors = await table.lookupAll(destinationHash: destHash)
        XCTAssertEqual(survivors.map(\.interfaceId), ["tcp0"], "TCP sibling must survive")
        let gone = await table.lookupAll(destinationHash: otherDest)
        XCTAssertTrue(gone.isEmpty, "Destination with only the removed interface should be gone")
        let hasPath = await table.hasPath(for: otherDest)
        XCTAssertFalse(hasPath)
    }

    /// Per-interface lookup.
    func testInterfaceScopedLookup() async throws {
        let table = PathTable()
        let blob = makeBlob(timestamp: 1000)
        await table.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", hopCount: 3, blob: blob))

        let hit = await table.lookup(destinationHash: destHash, interfaceId: "tcp0")
        XCTAssertNotNil(hit)
        let miss = await table.lookup(destinationHash: destHash, interfaceId: "ble0")
        XCTAssertNil(miss)
    }

    /// Python rules 2-5 still apply per (destination, interface) bucket:
    /// a duplicate blob on the SAME interface is rejected.
    func testDuplicateBlobSameInterfaceRejected() async throws {
        let table = PathTable()
        let blob = makeBlob(timestamp: 1000)
        await table.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", blob: blob))
        let duplicate = await table.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", blob: blob))
        XCTAssertFalse(duplicate, "Duplicate blob on the same interface must be rejected (Python rule 2)")
    }

    /// v1 → v2 SQLite migration: a database with the old single-PK schema is
    /// rebuilt with the composite PK and rows carry over.
    func testSQLiteMigrationFromV1Schema() async throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pathtable_migration_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }
        let dbPath = tmpDir.appendingPathComponent("paths.db").path

        // Build a v1 database by hand (single-column PRIMARY KEY, user_version 0).
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open(dbPath, &db), SQLITE_OK)
        let createV1 = """
            CREATE TABLE paths (
                destination_hash BLOB PRIMARY KEY,
                public_keys BLOB NOT NULL,
                interface_id TEXT NOT NULL,
                hop_count INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                expires REAL NOT NULL,
                random_blobs TEXT NOT NULL,
                ratchet BLOB,
                app_data BLOB,
                next_hop BLOB,
                announce_data BLOB
            )
            """
        XCTAssertEqual(sqlite3_exec(db, createV1, nil, nil, nil), SQLITE_OK)
        let now = Date().timeIntervalSince1970
        let insert = """
            INSERT INTO paths VALUES (
                X'\(String(repeating: "42", count: 16))',
                X'\(String(repeating: "aa", count: 64))',
                'tcp0', 2, \(now), \(now + 86400),
                '["11111111110000000010"]',
                NULL, NULL, NULL, NULL
            )
            """
        XCTAssertEqual(sqlite3_exec(db, insert, nil, nil, nil), SQLITE_OK)
        sqlite3_close(db)

        // Open through PathTable — migration + load run async in init.
        let table = try PathTable(databasePath: dbPath)
        let deadline = Date().addingTimeInterval(3)
        var loaded = 0
        while loaded == 0 && Date() < deadline {
            loaded = await table.totalCount
            if loaded == 0 { try? await Task.sleep(for: .milliseconds(30)) }
        }
        XCTAssertEqual(loaded, 1, "Migrated row should be loaded")

        let entry = await table.lookup(destinationHash: destHash)
        XCTAssertEqual(entry?.interfaceId, "tcp0")
        XCTAssertEqual(entry?.hopCount, 2)

        // user_version must be stamped to 2.
        var checkDb: OpaquePointer?
        XCTAssertEqual(sqlite3_open(dbPath, &checkDb), SQLITE_OK)
        var stmt: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(checkDb, "PRAGMA user_version", -1, &stmt, nil), SQLITE_OK)
        XCTAssertEqual(sqlite3_step(stmt), SQLITE_ROW)
        XCTAssertEqual(sqlite3_column_int(stmt, 0), 2)
        sqlite3_finalize(stmt)
        sqlite3_close(checkDb)
    }
}

// MARK: - Announce dedup tests

final class AnnounceDedupMultiInterfaceTests: XCTestCase {

    private func makeAnnouncePacket() throws -> (Packet, Data) {
        let identity = Identity()
        let destination = Destination(identity: identity, appName: "test", aspects: ["dedup"])
        let announce = Announce(destination: destination, randomHash: makeBlob(timestamp: 1234))
        return (try announce.buildPacket(), destination.hash)
    }

    /// First arrival on tcp0 records and rebroadcasts; second arrival of the
    /// SAME packet on ble0 records the additional path WITHOUT rebroadcast;
    /// third arrival on tcp0 again is ignored.
    func testSecondInterfaceRecordsWithoutRebroadcast() async throws {
        let pathTable = PathTable()
        let handler = AnnounceHandler(pathTable: pathTable)
        let (packet, destHash) = try makeAnnouncePacket()

        // 1. tcp0: global first sight → recorded and rebroadcast (mode .full)
        let first = await handler.process(packet: packet, from: "tcp0", interfaceMode: .full)
        guard case .recordedAndRebroadcast = first else {
            return XCTFail("First sight should be recordedAndRebroadcast, got \(first)")
        }

        // 2. ble0: same packet, new interface → recorded, NO rebroadcast
        let second = await handler.process(packet: packet, from: "ble0", interfaceMode: .full)
        guard case .recorded = second else {
            return XCTFail("Second interface should record without rebroadcast, got \(second)")
        }

        let all = await pathTable.lookupAll(destinationHash: destHash)
        XCTAssertEqual(Set(all.map(\.interfaceId)), ["tcp0", "ble0"], "Both interfaces should have paths")

        // 3. tcp0 again: true duplicate → ignored
        let third = await handler.process(packet: packet, from: "tcp0", interfaceMode: .full)
        XCTAssertEqual(third, .ignored(reason: .alreadySeen))
    }
}

// MARK: - Outbound selection tests

final class TransportSelectionTests: XCTestCase {

    private var destHash = Data(repeating: 0x55, count: 16)

    private func makeSetup() async throws -> (ReticulumTransport, PathTable, ClassedMockInterface, ClassedMockInterface) {
        let pathTable = PathTable()
        let transport = ReticulumTransport(pathTable: pathTable)
        let tcp = ClassedMockInterface(id: "tcp0", type: .tcp)
        let ble = ClassedMockInterface(id: "ble-mesh0-aabbccdd", type: .ble)
        try await transport.addInterface(tcp)
        try await transport.addInterface(ble)

        let blob = makeBlob(timestamp: 1000)
        await pathTable.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", hopCount: 1, blob: blob))
        await pathTable.record(entry: makeEntry(destHash: destHash, interfaceId: "ble-mesh0-aabbccdd", hopCount: 1, blob: blob))
        return (transport, pathTable, tcp, ble)
    }

    /// Not nearby → indirect (TCP) preferred even when a direct path exists.
    func testNotNearbyPrefersIndirect() async throws {
        let (transport, _, tcp, ble) = try await makeSetup()

        try await transport.send(packet: makeDataPacket(dest: destHash))

        XCTAssertEqual(tcp.sentPackets.count, 1, "Not-nearby traffic should use TCP")
        XCTAssertEqual(ble.sentPackets.count, 0)
    }

    /// Nearby + live direct path → direct (BLE) preferred.
    func testNearbyPrefersDirect() async throws {
        let (transport, _, tcp, ble) = try await makeSetup()
        await transport.setNearbyDestinations([destHash])

        try await transport.send(packet: makeDataPacket(dest: destHash))

        XCTAssertEqual(ble.sentPackets.count, 1, "Nearby traffic should use BLE")
        XCTAssertEqual(tcp.sentPackets.count, 0)
    }

    /// Nearby but the direct interface is down → falls back to TCP (no black hole).
    func testNearbyWithDeadDirectFallsBackToIndirect() async throws {
        let (transport, _, tcp, ble) = try await makeSetup()
        await transport.setNearbyDestinations([destHash])
        ble.setState(.disconnected)

        try await transport.send(packet: makeDataPacket(dest: destHash))

        XCTAssertEqual(tcp.sentPackets.count, 1, "Nearby with dead direct path must fall back to TCP")
        XCTAssertEqual(ble.sentPackets.count, 0)
    }

    /// Only the direct interface is live → use it even when not nearby.
    func testOnlyDirectLiveUsedEvenWhenNotNearby() async throws {
        let (transport, _, tcp, ble) = try await makeSetup()
        tcp.setState(.disconnected)

        try await transport.send(packet: makeDataPacket(dest: destHash))

        XCTAssertEqual(ble.sentPackets.count, 1, "Only-direct-live should still deliver")
        XCTAssertEqual(tcp.sentPackets.count, 0)
    }

    /// Nearby set changes re-route subsequent sends.
    func testNearbyToggleSwitchesRoute() async throws {
        let (transport, _, tcp, ble) = try await makeSetup()

        await transport.setNearbyDestinations([destHash])
        try await transport.send(packet: makeDataPacket(dest: destHash))
        await transport.setNearbyDestinations([])
        try await transport.send(packet: makeDataPacket(dest: destHash))

        XCTAssertEqual(ble.sentPackets.count, 1)
        XCTAssertEqual(tcp.sentPackets.count, 1)
    }

    /// Among live direct candidates with equal hops, the higher-throughput
    /// interface wins (MPC's WiFi over BLE's GATT) instead of an arbitrary
    /// announce-recency tiebreak.
    func testDirectCandidatesRankedByThroughput() async throws {
        let pathTable = PathTable()
        let transport = ReticulumTransport(pathTable: pathTable)
        let ble = ClassedMockInterface(id: "ble-mesh0-aabbccdd", type: .ble)        // hwMtu default low
        let mpc = ClassedMockInterface(id: "mpc-mpc0-peer", type: .multipeerConnectivity)
        try await transport.addInterface(ble)
        try await transport.addInterface(mpc)

        // BLE announce is NEWER — the old timestamp tiebreak would pick BLE.
        let blob = makeBlob(timestamp: 1000)
        await pathTable.record(entry: makeEntry(destHash: destHash, interfaceId: "mpc-mpc0-peer", hopCount: 1, blob: blob))
        try? await Task.sleep(for: .milliseconds(5))
        await pathTable.record(entry: makeEntry(destHash: destHash, interfaceId: "ble-mesh0-aabbccdd", hopCount: 1, blob: makeBlob(timestamp: 1001)))
        await transport.setNearbyDestinations([destHash])

        try await transport.send(packet: makeDataPacket(dest: destHash))

        XCTAssertEqual(mpc.sentPackets.count, 1,
            "Equal-hop direct tie must go to the higher-throughput interface (MPC)")
        XCTAssertEqual(ble.sentPackets.count, 0)
    }

    /// A .preferIndirect route hint on initiateLink pins the LINKREQUEST to
    /// TCP even when the destination is nearby with a live direct path —
    /// and the hint is cleared afterwards (subsequent sends go direct again).
    func testRouteHintPinsLinkToIndirect() async throws {
        let pathTable = PathTable()
        let transport = ReticulumTransport(pathTable: pathTable)
        let tcp = ClassedMockInterface(id: "tcp0", type: .tcp)
        let ble = ClassedMockInterface(id: "ble-mesh0-aabbccdd", type: .ble)
        try await transport.addInterface(tcp)
        try await transport.addInterface(ble)

        let peerIdentity = Identity()
        let destination = Destination(identity: peerIdentity, appName: "test", aspects: ["hint"])
        let blob = makeBlob(timestamp: 1000)
        await pathTable.record(entry: makeEntry(destHash: destination.hash, interfaceId: "tcp0", hopCount: 1, blob: blob))
        await pathTable.record(entry: makeEntry(destHash: destination.hash, interfaceId: "ble-mesh0-aabbccdd", hopCount: 1, blob: blob))
        await transport.setNearbyDestinations([destination.hash])

        _ = try await transport.initiateLink(to: destination, identity: Identity(), routeHint: .preferIndirect)

        XCTAssertEqual(tcp.sentPackets.count, 1,
            "preferIndirect hint must pin the LINKREQUEST to TCP despite nearby")
        XCTAssertEqual(ble.sentPackets.count, 0)

        // Hint must not leak: a plain data send afterwards goes direct again.
        try await transport.send(packet: makeDataPacket(dest: destination.hash))
        XCTAssertEqual(ble.sentPackets.count, 1, "Hint must be cleared after establishment")
    }

    /// The hint is preference-only: with no live indirect path, the link
    /// still establishes over the direct interface (offline case).
    func testRouteHintFallsBackToDirectWhenNoIndirect() async throws {
        let pathTable = PathTable()
        let transport = ReticulumTransport(pathTable: pathTable)
        let ble = ClassedMockInterface(id: "ble-mesh0-aabbccdd", type: .ble)
        try await transport.addInterface(ble)

        let peerIdentity = Identity()
        let destination = Destination(identity: peerIdentity, appName: "test", aspects: ["hint-offline"])
        await pathTable.record(entry: makeEntry(destHash: destination.hash, interfaceId: "ble-mesh0-aabbccdd", hopCount: 1, blob: makeBlob(timestamp: 1000)))

        _ = try await transport.initiateLink(to: destination, identity: Identity(), routeHint: .preferIndirect)

        XCTAssertEqual(ble.sentPackets.count, 1,
            "With no indirect path the hint must not block the direct route")
    }

    /// hasLivePath(for:linkClass:) reflects per-class liveness.
    func testHasLivePathByLinkClass() async throws {
        let pathTable = PathTable()
        let transport = ReticulumTransport(pathTable: pathTable)
        let tcp = ClassedMockInterface(id: "tcp0", type: .tcp)
        let ble = ClassedMockInterface(id: "ble-mesh0-aabbccdd", type: .ble)
        try await transport.addInterface(tcp)
        try await transport.addInterface(ble)
        let blob = makeBlob(timestamp: 1000)
        await pathTable.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", hopCount: 1, blob: blob))
        await pathTable.record(entry: makeEntry(destHash: destHash, interfaceId: "ble-mesh0-aabbccdd", hopCount: 1, blob: blob))

        let hasIndirect = await transport.hasLivePath(for: destHash, linkClass: .indirect)
        let hasDirect = await transport.hasLivePath(for: destHash, linkClass: .direct)
        XCTAssertTrue(hasIndirect)
        XCTAssertTrue(hasDirect)

        tcp.setState(.disconnected)
        let indirectAfterDrop = await transport.hasLivePath(for: destHash, linkClass: .indirect)
        XCTAssertFalse(indirectAfterDrop, "Disconnected TCP must not count as a live indirect path")
    }

    /// initiateLink emits exactly one LINKREQUEST, on the selected (direct)
    /// interface, so the whole link lives on the chosen wire.
    func testLinkRequestPinnedToSelectedInterface() async throws {
        let pathTable = PathTable()
        let transport = ReticulumTransport(pathTable: pathTable)
        let tcp = ClassedMockInterface(id: "tcp0", type: .tcp)
        let ble = ClassedMockInterface(id: "ble-mesh0-aabbccdd", type: .ble)
        try await transport.addInterface(tcp)
        try await transport.addInterface(ble)

        let peerIdentity = Identity()
        let destination = Destination(identity: peerIdentity, appName: "test", aspects: ["link"])
        let blob = makeBlob(timestamp: 1000)
        await pathTable.record(entry: makeEntry(destHash: destination.hash, interfaceId: "tcp0", hopCount: 1, blob: blob))
        await pathTable.record(entry: makeEntry(destHash: destination.hash, interfaceId: "ble-mesh0-aabbccdd", hopCount: 1, blob: blob))
        await transport.setNearbyDestinations([destination.hash])

        _ = try await transport.initiateLink(to: destination, identity: Identity())

        XCTAssertEqual(ble.sentPackets.count, 1, "LINKREQUEST should go out on the selected direct interface")
        XCTAssertEqual(tcp.sentPackets.count, 0, "LINKREQUEST must not leak onto other interfaces")
    }
}

// MARK: - Failover tests

final class TransportFailoverTests: XCTestCase {

    private let destHash = Data(repeating: 0x66, count: 16)

    /// The end-to-end failover: paths on BLE+TCP, link active on BLE, nearby.
    /// Removing the BLE child invalidates its paths, tears down the link with
    /// .attachedInterfaceClosed (no LINKCLOSE on the wire), emits events, and
    /// the next send lands on TCP with no path re-request needed.
    func testInterfaceRemovalFailsOverToTcp() async throws {
        let pathTable = PathTable()
        let transport = ReticulumTransport(pathTable: pathTable)
        let tcp = ClassedMockInterface(id: "tcp0", type: .tcp)
        let bleChildId = "ble-mesh0-aabbccdd"
        let ble = ClassedMockInterface(id: bleChildId, type: .ble)
        try await transport.addInterface(tcp)
        try await transport.addInterface(ble)

        let blob = makeBlob(timestamp: 1000)
        await pathTable.record(entry: makeEntry(destHash: destHash, interfaceId: "tcp0", hopCount: 2, blob: blob, nextHop: nil))
        await pathTable.record(entry: makeEntry(destHash: destHash, interfaceId: bleChildId, hopCount: 1, blob: blob))
        await transport.setNearbyDestinations([destHash])

        // Stand up a fake active link attached to the BLE child.
        let peerIdentity = Identity()
        let destination = Destination(identity: peerIdentity, appName: "test", aspects: ["failover"])
        let link = Link(destination: destination, identity: Identity(), hwMtu: nil)
        await link.setAttachedInterface(bleChildId)
        await link._setStateForTesting(.active)
        await transport.registerLink(link)

        // Collect events (the nearby-set change above already emitted one
        // preferredPathChanged; drain by collecting from here on).
        let collector = TransportEventCollector()
        await transport.setOnTransportEvent { event in
            collector.append(event)
        }

        // Drop the BLE child (what BLEInterface's onPeerRemoved does).
        await transport.removeInterface(id: bleChildId)

        // Path table: BLE entry gone, TCP entry intact.
        let survivors = await pathTable.lookupAll(destinationHash: destHash)
        XCTAssertEqual(survivors.map(\.interfaceId), ["tcp0"])

        // Link: terminal, with the no-LINKCLOSE reason, and nothing sent on BLE.
        let linkState = await link.state
        XCTAssertEqual(linkState, .closed(reason: .attachedInterfaceClosed))
        XCTAssertEqual(ble.sentPackets.count, 0, "Teardown must not emit LINKCLOSE on the dead medium")
        let activeCount = await transport.activeLinkCount
        XCTAssertEqual(activeCount, 0)

        // Events: pathsInvalidated + preferredPathChanged + linkClosed.
        await collector.waitForEvents(count: 3)
        var sawPathsInvalidated = false
        var sawPreferredChanged = false
        var sawLinkClosed = false
        for event in collector.events {
            switch event {
            case .pathsInvalidated(let dests, let ifaceId):
                sawPathsInvalidated = true
                XCTAssertEqual(dests, [destHash])
                XCTAssertEqual(ifaceId, bleChildId)
            case .preferredPathChanged(let dest):
                sawPreferredChanged = true
                XCTAssertEqual(dest, destHash)
            case .linkClosed(_, let dest, let reason):
                sawLinkClosed = true
                XCTAssertEqual(dest, destination.hash)
                XCTAssertEqual(reason, .attachedInterfaceClosed)
            }
        }
        XCTAssertTrue(sawPathsInvalidated)
        XCTAssertTrue(sawPreferredChanged)
        XCTAssertTrue(sawLinkClosed)

        // Next send fails over to TCP immediately — still nearby, no re-request.
        try await transport.send(packet: makeDataPacket(dest: destHash))
        XCTAssertEqual(tcp.sentPackets.count, 1, "Failover send must land on TCP")
        let pendingCount = await transport.pendingPacketCount
        XCTAssertEqual(pendingCount, 0, "No queueing — the TCP path was already known")
    }

    /// Announces from an interface that was already unregistered are dropped
    /// (race guard) and must not resurrect invalidated paths.
    func testAnnounceFromUnregisteredInterfaceDropped() async throws {
        let pathTable = PathTable()
        let transport = ReticulumTransport(pathTable: pathTable)
        let tcp = ClassedMockInterface(id: "tcp0", type: .tcp)
        try await transport.addInterface(tcp)

        let identity = Identity()
        let destination = Destination(identity: identity, appName: "test", aspects: ["race"])
        let announce = Announce(destination: destination, randomHash: makeBlob(timestamp: 99))
        let packet = try announce.buildPacket()

        // Deliver from an interface id that is NOT registered.
        await transport.receive(packet: packet, from: "ble-ghost")

        let hasPath = await pathTable.hasPath(for: destination.hash)
        XCTAssertFalse(hasPath, "Announce from unregistered interface must not record a path")
    }
}
