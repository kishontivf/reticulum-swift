// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  TransportFallbackCopyTests.swift
//  ReticulumSwift
//
//  `sendFallbackCopy` duplicates a packet onto a nearby carrier only when the best route is a
//  relayed normal path — never on top of a direct one.
//

import XCTest
@testable import ReticulumSwift

final class TransportFallbackCopyTests: XCTestCase {

    private let destHash = Data(repeating: 0x07, count: 16)

    /// A transport whose best path to `destHash` is on `normal` at `normalHops`, with the peer
    /// also heard on the fallback `carrier` (the sighting is stamped even though the carrier
    /// loses the route).
    private func makeTransport(normalHops: UInt8) async throws -> (ReticulumTransport, MockInterface) {
        let pathTable = PathTable()
        await pathTable.setFallbackInterface("carrier")
        let blob = Data(repeating: 0xBB, count: 10)
        await pathTable.record(entry: PathEntry(destinationHash: destHash,
                                                publicKeys: Data(repeating: 0xAA, count: 64),
                                                interfaceId: "normal",
                                                hopCount: normalHops,
                                                randomBlob: blob,
                                                nextHop: normalHops > 1 ? Data(repeating: 0xD7, count: 16) : nil))
        await pathTable.record(entry: PathEntry(destinationHash: destHash,
                                                publicKeys: Data(repeating: 0xAA, count: 64),
                                                interfaceId: "carrier",
                                                hopCount: normalHops,
                                                randomBlob: blob,
                                                nextHop: nil))

        let transport = ReticulumTransport(pathTable: pathTable)
        try await transport.addInterface(MockInterface(id: "normal"))
        let carrier = MockInterface(id: "carrier")
        try await transport.addInterface(carrier)
        return (transport, carrier)
    }

    private func dataPacket() -> Packet {
        let header = PacketHeader(headerType: .header1,
                                  hasContext: false,
                                  transportType: .broadcast,
                                  destinationType: .single,
                                  packetType: .data,
                                  hopCount: 0)
        return Packet(header: header, destination: destHash, context: 0x00, data: Data(repeating: 0xDD, count: 50))
    }

    func testDirectNormalRouteGetsNoCarrierCopy() async throws {
        let (transport, carrier) = try await makeTransport(normalHops: 1)
        let bestPath = await transport.getPathTable().lookup(destinationHash: destHash)
        XCTAssertEqual(bestPath?.interfaceId, "normal")

        await transport.sendFallbackCopy(packet: dataPacket())

        let sent = await carrier.drainSentPackets()
        XCTAssertTrue(sent.isEmpty, "a direct route must not be duplicated onto the carrier")
    }

    func testRelayedNormalRouteGetsCarrierCopy() async throws {
        let (transport, carrier) = try await makeTransport(normalHops: 2)
        let bestPath = await transport.getPathTable().lookup(destinationHash: destHash)
        XCTAssertEqual(bestPath?.interfaceId, "normal")

        await transport.sendFallbackCopy(packet: dataPacket())

        let sent = await carrier.drainSentPackets()
        XCTAssertEqual(sent.count, 1, "a relayed route keeps its carrier copy")
    }
}
