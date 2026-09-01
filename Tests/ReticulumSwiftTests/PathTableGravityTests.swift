// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  PathTableGravityTests.swift
//  ReticulumSwiftTests
//
//  Port of Python RNS `Interface.gravity` — per-interface pathing affinity, used as the tiebreak
//  when the SAME announce arrives on two interfaces. See port-deviations.md.
//

import XCTest
@testable import ReticulumSwift

final class PathTableGravityTests: XCTestCase {

    private let destination = Data(repeating: 0xE7, count: 16)

    /// Two arrivals of the *same* announce differ only by interface, so they must carry the same
    /// emission timestamp and the same random blob — that identity is what the gravity branch keys
    /// on, and generating a fresh blob per call would quietly test a different branch.
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

    private func entry(interfaceId: String, hopCount: UInt8, emitted: UInt64) -> PathEntry {
        sameAnnounce(emitted: emitted)(interfaceId, hopCount)
    }

    /// Unconfigured interfaces read as Python's default of 0, so a table nobody configured behaves
    /// exactly as it did before gravity existed.
    func testGravityDefaultsToZero() async throws {
        let table = try PathTable()
        let g = await table.gravity(of: "icWifi0-peer")
        XCTAssertEqual(g, PathTable.defaultGravity)
        XCTAssertEqual(g, 0)
    }

    /// The motivating case: two carriers reach the same peer at the same distance, and the same
    /// announce arrives on both. Without gravity the winner is whichever copy landed first.
    func testHigherGravityTakesTheRouteForTheSameAnnounce() async throws {
        let table = try PathTable()
        await table.setInterfaceGravity("icWifi0-peer", 20)
        await table.setInterfaceGravity("icWebrtc0-peer", 10)
        let announce = sameAnnounce(emitted: 9_000)

        // WebRTC's copy wins the arrival race...
        let webrtcWon = await table.record(entry: announce("icWebrtc0-peer", 1))
        XCTAssertTrue(webrtcWon)
        // ...and WiFi's copy of the SAME announce takes it back on affinity alone.
        let wifiReclaimed = await table.record(entry: announce("icWifi0-peer", 1))
        XCTAssertTrue(wifiReclaimed)

        let chosen = await table.lookup(destinationHash: destination)
        XCTAssertEqual(chosen?.interfaceId, "icWifi0-peer")
        XCTAssertEqual(chosen?.hopCount, 1)
    }

    /// Symmetry check — the lower-affinity copy arriving second must NOT displace the incumbent,
    /// or the route would simply flap on every announce instead of settling.
    func testLowerGravityDoesNotDisplaceTheIncumbent() async throws {
        let table = try PathTable()
        await table.setInterfaceGravity("icWifi0-peer", 20)
        await table.setInterfaceGravity("icBle0-peer", -10)
        let announce = sameAnnounce(emitted: 9_100)

        let wifiFirst = await table.record(entry: announce("icWifi0-peer", 1))
        XCTAssertTrue(wifiFirst)
        let bleRejected = await table.record(entry: announce("icBle0-peer", 1))
        XCTAssertFalse(bleRejected)

        let chosen = await table.lookup(destinationHash: destination)
        XCTAssertEqual(chosen?.interfaceId, "icWifi0-peer")
    }

    /// Gravity is a tiebreak, not an override. A staler announce loses however preferred its
    /// interface — Python gates the whole branch on `announce_emitted == path_timebase`, and
    /// without that gate a high-affinity carrier could pin an out-of-date route indefinitely.
    func testGravityCannotResurrectAStalerAnnounce() async throws {
        let table = try PathTable()
        await table.setInterfaceGravity("icWifi0-peer", 100)

        _ = await table.record(entry: entry(interfaceId: "icWebrtc0-peer", hopCount: 1, emitted: 9_201))
        let accepted = await table.record(entry: entry(interfaceId: "icWifi0-peer", hopCount: 1, emitted: 9_200))
        XCTAssertFalse(accepted, "a staler announce must lose regardless of affinity")

        let chosen = await table.lookup(destinationHash: destination)
        XCTAssertEqual(chosen?.interfaceId, "icWebrtc0-peer")
    }

    /// Distance still outranks affinity: a nearer route on a *less* preferred interface wins, via
    /// Path 2b. Getting this backwards would send traffic the long way round for a nicer carrier.
    func testShorterPathBeatsHigherGravity() async throws {
        let table = try PathTable()
        await table.setInterfaceGravity("icWifi0-relay", 100)
        await table.setInterfaceGravity("icBle0-direct", -10)
        let announce = sameAnnounce(emitted: 9_300)

        let relayFirst = await table.record(entry: announce("icWifi0-relay", 3))
        XCTAssertTrue(relayFirst)
        let directReclaimed = await table.record(entry: announce("icBle0-direct", 1))
        XCTAssertTrue(directReclaimed)

        let chosen = await table.lookup(destinationHash: destination)
        XCTAssertEqual(chosen?.interfaceId, "icBle0-direct")
        XCTAssertEqual(chosen?.hopCount, 1)
    }

    /// Equal affinity is the pre-gravity world: first arrival keeps the route.
    func testEqualGravityLeavesArrivalOrderInCharge() async throws {
        let table = try PathTable()
        let announce = sameAnnounce(emitted: 9_400)

        let firstArrival = await table.record(entry: announce("icWebrtc0-peer", 1))
        XCTAssertTrue(firstArrival)
        let secondArrival = await table.record(entry: announce("icWifi0-peer", 1))
        XCTAssertFalse(secondArrival, "equal affinity means no reason to move")

        let chosen = await table.lookup(destinationHash: destination)
        XCTAssertEqual(chosen?.interfaceId, "icWebrtc0-peer")
    }

    /// Setting an interface back to the default forgets it rather than storing a zero, so the map
    /// stays the size of the interfaces that actually differ from default.
    func testSettingDefaultGravityClearsTheEntry() async throws {
        let table = try PathTable()
        await table.setInterfaceGravity("icWifi0-peer", 20)
        let configured = await table.gravity(of: "icWifi0-peer")
        XCTAssertEqual(configured, 20)
        await table.setInterfaceGravity("icWifi0-peer", 0)
        let cleared = await table.gravity(of: "icWifi0-peer")
        XCTAssertEqual(cleared, 0)
    }
}
