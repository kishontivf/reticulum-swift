// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  PathTableWorseHopSilenceTests.swift
//  ReticulumSwiftTests
//
//  Path 4 accepts a worse-hop route on a fresher announce. `path4IncumbentSilenceSeconds` requires
//  the incumbent's interface to have gone quiet first — a fresher announce down a longer road is not
//  evidence the short road closed. Session10 measured 21 takeovers that replaced a 1-hop route with
//  a 3-hop one on that reasoning alone.
//

import XCTest
@testable import ReticulumSwift

final class PathTableWorseHopSilenceTests: XCTestCase {

    private let destination = Data(repeating: 0xD4, count: 16)
    private let direct = "icWebrtc0-peer"
    private let detour = "icWifi0-relay"

    private func entry(_ interfaceId: String, _ hopCount: UInt8, emitted: UInt64) -> PathEntry {
        var blob = Data((0..<5).map { _ in UInt8.random(in: 0...255) })
        for i in (0..<5).reversed() { blob.append(UInt8((emitted >> (i * 8)) & 0xFF)) }
        return PathEntry(destinationHash: destination,
                         publicKeys: Data(repeating: 0, count: 64),
                         interfaceId: interfaceId,
                         hopCount: hopCount,
                         expiration: PathEntry.standardExpiration,
                         randomBlob: blob)
    }

    override func tearDown() {
        PathTable.path4IncumbentSilenceSeconds = 75
        super.tearDown()
    }

    /// The Session10 case: a 1-hop direct route, and a 3-hop copy of a newer announce arrives because
    /// the direct link had not relayed that particular announce yet. The direct link is still
    /// carrying announces, so it keeps the route.
    func testWorseHopTakeoverRefusedWhileIncumbentStillHeard() async throws {
        let table = try PathTable()
        _ = await table.record(entry: entry(direct, 1, emitted: 1_000))

        let took = await table.record(entry: entry(detour, 3, emitted: 1_021))
        XCTAssertFalse(took, "a fresher 3-hop copy must not displace a 1-hop link that is still live")
        let path = await table.lookup(destinationHash: destination)
        XCTAssertEqual(path?.interfaceId, direct)
        XCTAssertEqual(path?.hopCount, 1)
    }

    /// Once the incumbent has gone silent the peer really has moved, and path 4 follows it — the
    /// behaviour the rule exists for, preserved.
    func testWorseHopTakeoverProceedsOnceIncumbentIsSilent() async throws {
        let table = try PathTable()
        _ = await table.record(entry: entry(direct, 1, emitted: 1_000))
        let refused = await table.record(entry: entry(detour, 3, emitted: 1_021))
        XCTAssertFalse(refused)

        // No silence required == the incumbent counts as quiet.
        PathTable.path4IncumbentSilenceSeconds = 0
        let took = await table.record(entry: entry(detour, 3, emitted: 1_042))
        XCTAssertTrue(took, "with the incumbent quiet, the longer route is the only one left")
        let path = await table.lookup(destinationHash: destination)
        XCTAssertEqual(path?.interfaceId, detour)
    }

    /// A hop change on the incumbent's OWN interface is the plain "peer moved" case. The check must
    /// skip it — this arrival refreshed that interface's sighting itself, so it could never pass.
    func testSameInterfaceHopChangeIsNotBlocked() async throws {
        let table = try PathTable()
        _ = await table.record(entry: entry(direct, 1, emitted: 1_000))

        let took = await table.record(entry: entry(direct, 3, emitted: 1_021))
        XCTAssertTrue(took, "the peer moved further away on the same link — path 4 must still follow")
        let path = await table.lookup(destinationHash: destination)
        XCTAssertEqual(path?.hopCount, 3)
    }

    /// Zero restores Python's unbounded path 4, so the divergence can be switched off wholesale.
    func testZeroRestoresUnboundedPythonBehaviour() async throws {
        PathTable.path4IncumbentSilenceSeconds = 0
        let table = try PathTable()
        _ = await table.record(entry: entry(direct, 1, emitted: 1_000))

        let took = await table.record(entry: entry(detour, 3, emitted: 1_021))
        XCTAssertTrue(took, "with the requirement disabled, freshness alone wins as upstream")
    }

    /// Equal-or-better hops never reach path 4, so the requirement must not interfere with them.
    func testBetterHopsAreUnaffected() async throws {
        let table = try PathTable()
        _ = await table.record(entry: entry(detour, 3, emitted: 1_000))

        let took = await table.record(entry: entry(direct, 1, emitted: 1_021))
        XCTAssertTrue(took, "a shorter route is decided long before path 4")
        let path = await table.lookup(destinationHash: destination)
        XCTAssertEqual(path?.interfaceId, direct)
    }
}
