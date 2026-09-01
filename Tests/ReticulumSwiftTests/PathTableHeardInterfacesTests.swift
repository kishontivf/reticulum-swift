// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  PathTableHeardInterfacesTests.swift
//  ReticulumSwiftTests
//
//  PORT DEVIATION — `lastHeardByInterface` carries the arrival hop count alongside the arrival
//  time, and `heardInterfaces(for:)` exposes it. `record()` is the only place every candidate route
//  is still visible before ranking discards the losers, so distance has to be captured on the way
//  past or it is unrecoverable. See port-deviations.md.
//

import XCTest
@testable import ReticulumSwift

final class PathTableHeardInterfacesTests: XCTestCase {

    private let destination = Data(repeating: 0xC1, count: 16)

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

    /// The point of the deviation: a losing candidate's interface AND its distance survive, so an
    /// embedder can tell "reachable directly over BLE" from "reachable via someone else over BLE".
    func testLosingCandidatesKeepTheirHopCount() async throws {
        let table = try PathTable()

        // A direct arrival, then a relayed one on another interface that ranking will reject for
        // being further away.
        _ = await table.record(entry: entry(interfaceId: "icWifi0", hopCount: 1, emitted: 1_000))
        _ = await table.record(entry: entry(interfaceId: "icBle0", hopCount: 3, emitted: 1_001))

        let heard = await table.heardInterfaces(for: destination)
        XCTAssertEqual(heard.count, 2, "both arrivals must be remembered, not just the winner")
        XCTAssertEqual(heard["icWifi0"]?.hopCount, 1)
        XCTAssertEqual(heard["icBle0"]?.hopCount, 3)
        XCTAssertEqual(heard["icWifi0"]?.isDirect, true)
        XCTAssertEqual(heard["icBle0"]?.isDirect, false, "3 hops came through a relay")

        // And note WHICH one Reticulum chose: the *relayed* one, because its announce was fresher.
        // That is the path table's Path-4 rule (a fresher announce is accepted even when worse),
        // and it is the motivating case for keeping the losers — the chosen route is three hops
        // away over Bluetooth while a direct LAN route was known a moment earlier. Without the hop
        // count on the loser there is no way to see that from outside.
        let chosen = await table.lookup(destinationHash: destination)
        XCTAssertEqual(chosen?.interfaceId, "icBle0")
        XCTAssertEqual(chosen?.hopCount, 3)
    }

    /// `1` is direct, not `0`: a peer's own announce is `hops = 0` on the wire but is recorded as
    /// `1`. Keying directness on `0` would classify every real path as relayed.
    func testOneHopIsDirectAndTwoIsNot() {
        XCTAssertTrue(PathTable.InterfaceSighting(at: Date(), hopCount: 0).isDirect)
        XCTAssertTrue(PathTable.InterfaceSighting(at: Date(), hopCount: 1).isDirect)
        XCTAssertFalse(PathTable.InterfaceSighting(at: Date(), hopCount: 2).isDirect)
    }

    /// A later arrival on the same interface replaces the earlier one — this is a "last heard"
    /// record, so a peer that moves from relayed to direct must read as direct.
    func testLaterArrivalOnAnInterfaceReplacesTheEarlierOne() async throws {
        let table = try PathTable()

        _ = await table.record(entry: entry(interfaceId: "icBle0", hopCount: 3, emitted: 2_000))
        let relayed = await table.heardInterfaces(for: destination)["icBle0"]?.hopCount
        XCTAssertEqual(relayed, 3)

        _ = await table.record(entry: entry(interfaceId: "icBle0", hopCount: 1, emitted: 2_001))
        let direct = await table.heardInterfaces(for: destination)["icBle0"]?.hopCount
        XCTAssertEqual(direct, 1)
    }

    /// A destination never heard from is an empty map, not a nil the caller has to unwrap.
    func testUnknownDestinationHasNoSightings() async throws {
        let table = try PathTable()
        let heard = await table.heardInterfaces(for: Data(repeating: 0xFF, count: 16))
        XCTAssertTrue(heard.isEmpty)
    }

    /// The existing time-window reader keeps working — it now reads the sighting's timestamp.
    func testWasHeardOnInterfaceStillAnswersTheWindow() async throws {
        let table = try PathTable()
        _ = await table.record(entry: entry(interfaceId: "icWifi0", hopCount: 1, emitted: 3_000))

        let heardOnWifi = await table.wasHeardOnInterface(destination, interfaceId: "icWifi0", within: 60)
        let heardOnBle = await table.wasHeardOnInterface(destination, interfaceId: "icBle0", within: 60)
        XCTAssertTrue(heardOnWifi)
        XCTAssertFalse(heardOnBle)
    }

    /// Sightings are pruned with the path, so a forgotten destination leaves nothing behind.
    func testRemovingADestinationDropsItsSightings() async throws {
        let table = try PathTable()
        _ = await table.record(entry: entry(interfaceId: "icWifi0", hopCount: 1, emitted: 4_000))

        await table.remove(destinationHash: destination)

        let remaining = await table.heardInterfaces(for: destination)
        XCTAssertTrue(remaining.isEmpty)
    }
}
