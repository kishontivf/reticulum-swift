// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  PathTableRecordDecisionTests.swift
//  ReticulumSwiftTests
//
//  PORT DEVIATION [TEMPORARY] — `PathTable.onRecordDecision` traces which rule of the 5-path tree
//  installed a route. Field sessions could measure that a peer sat on a 3-hop detour while a live
//  1-hop link was in the candidate set, but not which branch put it there. See port-deviations.md.
//

import XCTest
@testable import ReticulumSwift

final class PathTableRecordDecisionTests: XCTestCase {

    private let destination = Data(repeating: 0xD2, count: 16)

    private func entry(interfaceId: String, hopCount: UInt8, emitted: UInt64) -> PathEntry {
        var blob = Data((0..<5).map { _ in UInt8.random(in: 0...255) })
        for i in (0..<5).reversed() { blob.append(UInt8((emitted >> (i * 8)) & 0xFF)) }
        return PathEntry(destinationHash: destination,
                         publicKeys: Data(repeating: 0, count: 64),
                         interfaceId: interfaceId,
                         hopCount: hopCount,
                         expiration: PathEntry.standardExpiration,
                         randomBlob: blob)
    }

    /// Collects the trace for one block of work, and always restores the sink — it is process-wide
    /// static state, so leaking it would bleed lines into every later test in the same run.
    private func trace(_ body: () async throws -> Void) async rethrows -> [String] {
        let box = Box()
        PathTable.onRecordDecision = { line in box.append(line) }
        defer { PathTable.onRecordDecision = nil }
        try await body()
        return box.lines
    }

    private final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [String] = []
        func append(_ line: String) { lock.lock(); storage.append(line); lock.unlock() }
        var lines: [String] { lock.lock(); defer { lock.unlock() }; return storage }
    }

    /// The motivating case: a fresher announce arriving further away takes the route from a live,
    /// nearer one. Path 4 does this with no hop penalty and no grace window, and the trace has to
    /// name it — otherwise the outcome is visible in the path table but the cause is not.
    func testPathFourTakeoverIsNamedInTheTrace() async throws {
        let table = try PathTable()
        let lines = await trace {
            _ = await table.record(entry: entry(interfaceId: "icWebrtc0-direct", hopCount: 1, emitted: 1_000))
            _ = await table.record(entry: entry(interfaceId: "icWebrtc0-relay", hopCount: 3, emitted: 1_001))
        }

        XCTAssertEqual(lines.count, 2)
        XCTAssertTrue(lines[0].contains("ACCEPT"), lines[0])
        XCTAssertTrue(lines[0].contains("path 1 · unknown destination"), lines[0])

        let takeover = lines[1]
        XCTAssertTrue(takeover.contains("ACCEPT"), takeover)
        XCTAssertTrue(takeover.contains("path 4"), takeover)
        XCTAssertTrue(takeover.contains("WORSE HOPS"), takeover)
        // Both sides of the swap, so a reader never has to hold the previous line in their head.
        XCTAssertTrue(takeover.contains("icWebrtc0-relay/3h"), takeover)
        XCTAssertTrue(takeover.contains("vs icWebrtc0-direct/1h"), takeover)
        // The emission delta is the whole reason Path 4 fired, so it belongs on the line.
        XCTAssertTrue(takeover.contains("emitΔ=1"), takeover)

        let chosen = await table.lookup(destinationHash: destination)
        XCTAssertEqual(chosen?.interfaceId, "icWebrtc0-relay")
    }

    /// A strictly shorter copy is ALWAYS adopted, freshness be damned — Path 2b exists precisely so
    /// a relayed copy that won the arrival race cannot hold the route once the direct copy lands.
    /// Worth pinning down: it means a persistent multi-hop detour can never be explained by "the
    /// 1-hop copy arrived and was turned away", only by "it never arrived". The trace is what
    /// separates those two in the field.
    func testAStrictlyShorterCopyAlwaysWinsAndSaysSo() async throws {
        let table = try PathTable()
        let lines = await trace {
            _ = await table.record(entry: entry(interfaceId: "icWifi0-relay", hopCount: 2, emitted: 2_001))
            // Nearer but STALER — Path 2's freshness gate turns it away, and Path 2b takes it anyway.
            _ = await table.record(entry: entry(interfaceId: "icWifi0-direct", hopCount: 1, emitted: 2_000))
        }

        XCTAssertEqual(lines.count, 2)
        let reclaim = lines[1]
        XCTAssertTrue(reclaim.contains("ACCEPT"), reclaim)
        XCTAssertTrue(reclaim.contains("path 2b"), reclaim)
        XCTAssertTrue(reclaim.contains("icWifi0-direct/1h vs icWifi0-relay/2h"), reclaim)

        let chosen = await table.lookup(destinationHash: destination)
        XCTAssertEqual(chosen?.interfaceId, "icWifi0-direct")
    }

    /// A rejected candidate is as interesting as an accepted one. At EQUAL hops there is no Path 2b
    /// safety net, so the staler copy is simply dropped and the incumbent interface keeps the route
    /// — the case where two carriers to the same peer trade the route on arrival order alone.
    func testEqualHopRejectionsAreTracedWithTheirReason() async throws {
        let table = try PathTable()
        let lines = await trace {
            _ = await table.record(entry: entry(interfaceId: "icWifi0-a", hopCount: 1, emitted: 2_001))
            _ = await table.record(entry: entry(interfaceId: "icWebrtc0-a", hopCount: 1, emitted: 2_000))
        }

        XCTAssertEqual(lines.count, 2)
        let rejection = lines[1]
        XCTAssertTrue(rejection.contains("IGNORE"), rejection)
        XCTAssertTrue(rejection.contains("path 2"), rejection)
        XCTAssertTrue(rejection.contains("icWebrtc0-a/1h vs icWifi0-a/1h"), rejection)
        XCTAssertTrue(rejection.contains("emitΔ=-1"), rejection)

        let chosen = await table.lookup(destinationHash: destination)
        XCTAssertEqual(chosen?.interfaceId, "icWifi0-a", "arrival order decided it, not the carrier")
    }

    /// Volume control. `record` runs on every inbound announce and most of those are the incumbent
    /// interface refreshing itself, which says nothing about route selection. Tracing them would
    /// bury the handful of route-moving lines and roll the log generation in minutes.
    func testSameInterfaceRefreshesAreNotTraced() async throws {
        let table = try PathTable()
        let lines = await trace {
            _ = await table.record(entry: entry(interfaceId: "icBle0-peer", hopCount: 1, emitted: 3_000))
            for i in 1...20 {
                _ = await table.record(entry: entry(interfaceId: "icBle0-peer", hopCount: 1, emitted: 3_000 + UInt64(i)))
            }
        }

        XCTAssertEqual(lines.count, 1, "only the first arrival moved the route; the other 20 refreshed it")
        XCTAssertTrue(lines[0].contains("path 1"), lines[0])
    }

    /// The sink is opt-in. A fleet build that never sets it must not pay for string building, and
    /// must not be changed by its absence.
    func testNoSinkMeansNoWork() async throws {
        PathTable.onRecordDecision = nil
        let table = try PathTable()
        _ = await table.record(entry: entry(interfaceId: "icWifi0-a", hopCount: 1, emitted: 4_000))
        let accepted = await table.record(entry: entry(interfaceId: "icWifi0-b", hopCount: 3, emitted: 4_001))
        XCTAssertTrue(accepted, "routing behaviour must be identical with the trace off")
    }
}
