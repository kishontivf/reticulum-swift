// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  PathTableFallbackHopGuardTests.swift
//  ReticulumSwiftTests
//
//  The fallback rules resolve carrier-vs-normal by liveness and freshness, deliberately ignoring
//  hop count. `PathTable.fallbackMaxHopPenalty` bounds that: a normal path may cost a little more
//  than the carrier, but not arbitrarily more. Motivated by Session09, where a device discarded a
//  live 1-hop carrier route for a 3-hop normal one on the same announce and closed a forwarding
//  loop with its neighbour.
//

import XCTest
@testable import ReticulumSwift

final class PathTableFallbackHopGuardTests: XCTestCase {

    private let destination = Data(repeating: 0xE3, count: 16)
    private let carrier = "icBle0-peer"
    private let normal = "icWifi0-peer"

    /// Both copies of one announce share an emission timestamp and a random blob; only the
    /// interface and hop count differ. Matching the Session09 shape (`emitΔ=0`) matters — a
    /// generated-per-call blob would exercise the freshness branches instead of the guard.
    private func sameAnnounce(emitted: UInt64) -> (String, UInt8) -> PathEntry {
        var blob = Data((0..<5).map { _ in UInt8.random(in: 0...255) })
        for i in (0..<5).reversed() { blob.append(UInt8((emitted >> (i * 8)) & 0xFF)) }
        let destination = destination
        return { interfaceId, hopCount in
            PathEntry(destinationHash: destination,
                      publicKeys: Data(repeating: 0, count: 64),
                      interfaceId: interfaceId,
                      hopCount: hopCount,
                      expiration: PathEntry.standardExpiration,
                      randomBlob: blob)
        }
    }

    /// A table with the carrier registered as fallback and the normal interface *connected*, so the
    /// "normal still live" branch is armed — the branch that refused the 1-hop carrier in Session09.
    private func armedTable() throws -> PathTable {
        let table = try PathTable()
        return table
    }

    private func arm(_ table: PathTable) async {
        await table.setFallbackInterface(carrier, isFallback: true)
        await table.setConnectedInterfaces([normal])
    }

    override func tearDown() {
        PathTable.fallbackMaxHopPenalty = 1
        super.tearDown()
    }

    // MARK: - Carrier arriving against a live normal incumbent

    /// The Session09 case: Apone held a 3-hop normal route and refused a live 1-hop carrier because
    /// the normal interface was still connected. Liveness must not outrank a decisively shorter link.
    func testDecisivelyShorterCarrierTakesRouteFromLiveNormalPath() async throws {
        let table = try armedTable()
        await arm(table)
        let announce = sameAnnounce(emitted: 5_000)

        let seeded = await table.record(entry: announce(normal, 3))
        XCTAssertTrue(seeded)

        let took = await table.record(entry: announce(carrier, 1))
        XCTAssertTrue(took, "a 1-hop carrier must beat a 3-hop normal path even while it is connected")
        let path = await table.lookup(destinationHash: destination)
        XCTAssertEqual(path?.interfaceId, carrier)
        XCTAssertEqual(path?.hopCount, 1)
    }

    /// The guard must not swallow the reason a fallback set exists: one extra hop on the normal path
    /// is the ordinary case (relayed TCP vs adjacent BLE) and the normal path keeps the route.
    func testCarrierOneHopShorterDoesNotDisplaceLiveNormalPath() async throws {
        let table = try armedTable()
        await arm(table)
        let announce = sameAnnounce(emitted: 5_000)

        _ = await table.record(entry: announce(normal, 2))
        let took = await table.record(entry: announce(carrier, 1))
        XCTAssertFalse(took, "1h carrier vs 2h normal is within the penalty — the normal path holds")
        let path = await table.lookup(destinationHash: destination)
        XCTAssertEqual(path?.interfaceId, normal)
    }

    // MARK: - Normal arriving against a carrier incumbent

    /// The promote branch is otherwise unconditional. A detour must not reclaim the route — and must
    /// be refused outright, not fall through to Path 4, which would accept it on freshness alone.
    func testDetouringNormalPathCannotPromoteOverCarrier() async throws {
        let table = try armedTable()
        await arm(table)

        _ = await table.record(entry: sameAnnounce(emitted: 5_000)(carrier, 1))
        // A *later* announce, so Path 4 would accept it on freshness if the guard let it through.
        let promoted = await table.record(entry: sameAnnounce(emitted: 9_000)(normal, 3))
        XCTAssertFalse(promoted, "a 3-hop normal path is a detour around a 1-hop carrier")
        let path = await table.lookup(destinationHash: destination)
        XCTAssertEqual(path?.interfaceId, carrier)
        XCTAssertEqual(path?.hopCount, 1)
    }

    /// Within the penalty the promote stays unconditional, including on an equal emission — the
    /// behaviour the fallback design depends on to get back off the carrier promptly.
    func testNormalPathWithinPenaltyStillPromotesUnconditionally() async throws {
        let table = try armedTable()
        await arm(table)
        let announce = sameAnnounce(emitted: 5_000)

        _ = await table.record(entry: announce(carrier, 1))
        let promoted = await table.record(entry: announce(normal, 2))
        XCTAssertTrue(promoted, "2h normal over 1h carrier is the ordinary promote and must still fire")
        let path = await table.lookup(destinationHash: destination)
        XCTAssertEqual(path?.interfaceId, normal)
    }

    /// The penalty is a tunable, and tightening it to 0 makes any longer normal path lose.
    func testPenaltyIsTunable() async throws {
        PathTable.fallbackMaxHopPenalty = 0
        let table = try armedTable()
        await arm(table)
        let announce = sameAnnounce(emitted: 5_000)

        _ = await table.record(entry: announce(normal, 2))
        let took = await table.record(entry: announce(carrier, 1))
        XCTAssertTrue(took, "with no penalty allowed, the shorter carrier wins at 1h vs 2h")
        let path = await table.lookup(destinationHash: destination)
        XCTAssertEqual(path?.interfaceId, carrier)
    }
}
