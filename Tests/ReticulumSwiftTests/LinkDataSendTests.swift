// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  LinkDataSendTests.swift
//  ReticulumSwift
//
//  Tests for ReticulumTransport.sendLinkData(packet:) covering the
//  three observable behaviors:
//
//    1. No interfaces → throws TransportError.noInterfacesAvailable.
//    2. Link has an `attachedInterfaceId` → packet bytes land on
//       that specific interface, never on others.
//    3. Link is registered but has no attachedInterfaceId →
//       silent drop (mirrors python `Transport.outbound`
//       RNS/Transport.py:1124-1130 LINK destination guard, which
//       fails the `interface != attached_interface` test on every
//       interface when attached_interface is None and so transmits
//       on none of them).
//
//  Python reference: RNS/Transport.py:1063, 1118-1135.
//  See also `port-deviations.md` (the resolved deviation entry on
//  this method and its predecessor sendLinkData(packet:destinationHash:)).
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class LinkDataSendTests: XCTestCase {

    // MARK: - Helpers

    /// Build a Link in `.active` state with an established link_id, ready
    /// to be registered into a transport's `activeLinks` map. Mirrors the
    /// fixture pattern in LinkProveTests.swift but with no link-establish
    /// handshake — we just need the link to exist as a target and to
    /// optionally have an attachedInterfaceId.
    private func makeActiveLink() async throws -> Link {
        let identity = Identity()
        let dest = Destination(
            identity: identity, appName: "test", aspects: ["link-data-send"]
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
        await link._setStateForTesting(.active)
        return link
    }

    /// Build a HEADER_1 link DATA packet addressed to the given linkId.
    /// Caller-side encryption isn't required for the transport-level
    /// test (sendLinkData doesn't encrypt — that's the link's job).
    private func makeLinkDataPacket(linkId: Data) -> Packet {
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hopCount: 0
        )
        return Packet(
            header: header,
            destination: linkId,
            context: 0x00,
            data: Data("link-data-payload".utf8)
        )
    }

    // MARK: - Test 1: no interfaces → throws

    /// `sendLinkData` must throw `noInterfacesAvailable` when the
    /// transport has zero registered interfaces. Without this check,
    /// the function would silently no-op and outbound link DATA would
    /// disappear, leading to "state=SENT but recipient never receives"
    /// regressions.
    func testSendLinkDataThrowsWhenNoInterfaces() async throws {
        let transport = ReticulumTransport()
        // Note: we deliberately do NOT add an interface, do NOT register
        // a link. Both omissions are independently sufficient for the
        // check to fire — the no-interfaces guard runs FIRST, before
        // the activeLinks lookup, so a missing link doesn't matter here.

        let packet = makeLinkDataPacket(linkId: Data(repeating: 0xAB, count: 16))

        do {
            try await transport.sendLinkData(packet: packet)
            XCTFail("sendLinkData must throw when no interfaces are " +
                    "registered. A silent no-op here would mask outbound " +
                    "link DATA failures and cause downstream " +
                    "'state=SENT but never delivered' bugs.")
        } catch let error as TransportError {
            guard case .noInterfacesAvailable = error else {
                XCTFail("Expected TransportError.noInterfacesAvailable; " +
                        "got \(error). Other TransportError variants " +
                        "imply a different guard tripped first.")
                return
            }
        }
    }

    // MARK: - Test 2: attached interface → targeted send

    /// When the link has an `attachedInterfaceId` (set during the normal
    /// `handleLinkProof` / `handleLinkRequest` flow in production),
    /// `sendLinkData` must transmit the encoded packet bytes ONLY on
    /// that interface — never broadcast. This mirrors python
    /// Transport.outbound:1128-1130's LINK destination guard:
    ///     if interface != packet.destination.attached_interface:
    ///         should_transmit = False
    func testSendLinkDataRoutesToAttachedInterface() async throws {
        let attached = MockInterface(id: "attached-iface")
        let other = MockInterface(id: "other-iface")
        let transport = ReticulumTransport()
        try await transport.addInterface(attached)
        try await transport.addInterface(other)

        let link = try await makeActiveLink()
        let linkId = await link.linkId
        await link.setAttachedInterface(attached.id)
        await transport.registerLink(link)

        let packet = makeLinkDataPacket(linkId: linkId)
        try await transport.sendLinkData(packet: packet)

        let attachedSent = await attached.drainSentPackets()
        let otherSent = await other.drainSentPackets()

        XCTAssertEqual(attachedSent.count, 1,
            "Expected exactly one packet on the attached interface; " +
            "got \(attachedSent.count). Either sendLinkData routed to " +
            "the wrong interface or the attached_interface lookup " +
            "missed.")
        XCTAssertEqual(otherSent.count, 0,
            "Other interface received \(otherSent.count) packets — " +
            "sendLinkData broadcast instead of targeted-send. The " +
            "LINK-destination interface guard regressed.")

        // The bytes on the wire must be the packet's standard HEADER_1
        // encoding — NOT a HEADER_2-converted variant. Verifies the
        // 2026-05-10 fix (commits d19919a + 8253985) hasn't been
        // reintroduced.
        let expected = packet.encode()
        XCTAssertEqual(attachedSent[0], expected,
            "sendLinkData transmitted bytes that don't match " +
            "packet.encode() — possible HEADER_2 rewrite regression. " +
            "Per python Transport.outbound:1063, link DATA is never " +
            "HEADER_2-converted.")
    }

    // MARK: - Test 3: no attached interface → silent drop

    /// When a link is registered but has no `attachedInterfaceId`
    /// (e.g., a synthesized link in a test or a partial-establishment
    /// state), the packet is silently NOT transmitted on any
    /// interface. Mirrors python `Transport.outbound:1124-1130`:
    /// every interface fails the `interface != attached_interface`
    /// guard when `attached_interface` is `None`, so nothing is sent.
    /// Broadcasting in this case would spray link DATA across LoRa
    /// / BLE / other physical media that a stale-or-unestablished
    /// link should not be touching.
    func testSendLinkDataDropsWhenLinkHasNoAttachedInterface() async throws {
        let iface1 = MockInterface(id: "no-attached-iface-1")
        let iface2 = MockInterface(id: "no-attached-iface-2")
        let transport = ReticulumTransport()
        try await transport.addInterface(iface1)
        try await transport.addInterface(iface2)

        let link = try await makeActiveLink()
        let linkId = await link.linkId
        // Deliberately skip setAttachedInterface — that's the
        // condition under test.
        await transport.registerLink(link)

        let packet = makeLinkDataPacket(linkId: linkId)
        try await transport.sendLinkData(packet: packet)

        let sent1 = await iface1.drainSentPackets()
        let sent2 = await iface2.drainSentPackets()

        XCTAssertEqual(sent1.count, 0,
            "Link with no attached_interface must silently drop " +
            "(python Transport.py:1124-1130). iface1 got " +
            "\(sent1.count) packets — broadcast regression.")
        XCTAssertEqual(sent2.count, 0,
            "Link with no attached_interface must silently drop " +
            "(python Transport.py:1124-1130). iface2 got " +
            "\(sent2.count) packets — broadcast regression.")
    }

    // MARK: - Test 4: link not in activeLinks → silent drop

    /// When the packet's destination (linkId) doesn't match any
    /// registered link in `activeLinks`, the lookup returns nil.
    /// Same drop behavior as the no-attached-interface case: the
    /// guarded `else` branch logs a warning and returns without
    /// transmitting. Covers the `attachedId == nil` path via a
    /// different code shape (no Link instance at all vs Link without
    /// attached interface).
    func testSendLinkDataDropsWhenLinkIdUnknown() async throws {
        let iface = MockInterface(id: "unknown-link-iface")
        let transport = ReticulumTransport()
        try await transport.addInterface(iface)

        // No registerLink — `activeLinks` is empty.
        let unknownLinkId = Data(repeating: 0xCC, count: 16)
        let packet = makeLinkDataPacket(linkId: unknownLinkId)
        try await transport.sendLinkData(packet: packet)

        let sent = await iface.drainSentPackets()
        XCTAssertEqual(sent.count, 0,
            "Unknown linkId must silently drop (no Link → " +
            "attached_interface is effectively None → python " +
            "Transport.py:1124-1130 transmits on no interface). " +
            "Got \(sent.count) packets — broadcast regression.")
    }
}
