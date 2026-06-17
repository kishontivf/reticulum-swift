// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  AutoProofTests.swift
//  ReticulumSwiftTests
//
//  Regression coverage for the opportunistic-delivery auto-proof path in
//  ReticulumTransport.handleRegularData(). Two invariants pinned here:
//
//    1. The proof packet's wire-format destinationType MUST be SINGLE
//       (DestinationType.single = 0x00). Python RNS sets
//       ProofDestination.type = RNS.Destination.SINGLE, and remote peers
//       reject anything else as a malformed proof.
//
//    2. The proof bytes MUST be transmitted via sendToInterface, not the
//       raw interface.send. sendToInterface runs applyIFAC on the bytes;
//       sending raw skips IFAC entirely on IFAC-configured interfaces and
//       remote peers reject the resulting bare proof as
//       "IFAC validation failed".
//
//  Reference: Sources/ReticulumSwift/Transport/ReticulumTransport.swift
//  handleRegularData() ~lines 2280-2323 (auto-proof emission).
//

import XCTest
@testable import ReticulumSwift

final class AutoProofTests: XCTestCase {

    // MARK: - Setup

    /// Build a transport with one mock interface and one locally-registered
    /// SINGLE destination, with our identity's private keys present so the
    /// auto-proof handler will fire on inbound DATA.
    ///
    /// The destination opts into `PROVE_ALL`. RNS only emits an opportunistic
    /// SINGLE proof when the destination's `proof_strategy` calls for it
    /// (Transport.py:2156-2165) — the default `PROVE_NONE` proves nothing, so
    /// without this the auto-proof path (correctly) stays silent. These tests
    /// pin the proof *wire format* (SINGLE destination-type, IFAC routing), not
    /// the trigger policy, so they request proving explicitly here.
    ///
    /// Returns the transport, the interface, the destination, and the
    /// identity (caller needs the identity to encrypt a payload to it).
    private func makeAutoProofFixture(
        interface: any NetworkInterface
    ) async throws -> (
        transport: ReticulumTransport,
        destination: Destination,
        identity: Identity
    ) {
        let identity = Identity()
        let destination = Destination(
            identity: identity,
            appName: "test",
            aspects: ["autoproof"]
        )
        try destination.setProofStrategy(Destination.PROVE_ALL)

        let transport = ReticulumTransport()
        try await transport.addInterface(interface)
        await transport.registerDestination(destination)

        return (transport, destination, identity)
    }

    /// Build a SINGLE DATA packet addressed to `destination`, encrypting
    /// `plaintext` to the destination's identity. Mirrors the wire format
    /// produced by an opportunistic-delivery sender so handleRegularData()
    /// will accept and decrypt it.
    private func makeOpportunisticPacket(
        to destination: Destination,
        plaintext: Data
    ) throws -> Packet {
        // Encrypt plaintext to the destination's identity. The HKDF salt
        // is the *identity* hash, not the destination hash — see
        // Identity.encryptTo(_:identityHash:).
        let ciphertext = try destination.identity!.encryptTo(
            plaintext,
            identityHash: destination.identity!.hash
        )

        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            hasIFAC: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .data,
            hopCount: 0
        )
        return Packet(
            header: header,
            destination: destination.hash,
            transportAddress: nil,
            context: 0x00,
            data: ciphertext
        )
    }

    // MARK: - Test 1: SINGLE flag (regression for `.plain → .single` fix)

    /// Inbound DATA addressed to a local SINGLE destination must trigger
    /// an outbound proof whose wire-format destination-type bits decode
    /// to SINGLE (0b00), not PLAIN (0b10).
    ///
    /// Wire format (Packet.encode / PacketHeader.encode line 144):
    ///   flags = (hasIFAC<<7) | (headerType<<6) | (hasContext<<5) |
    ///           (transportType<<4) | (destinationType<<2) | packetType
    ///
    /// Bits 2-3 of the flags byte therefore encode destinationType:
    ///   SINGLE = 0x00 → bits 2-3 = 00
    ///   GROUP  = 0x01 → bits 2-3 = 01
    ///   PLAIN  = 0x02 → bits 2-3 = 10
    ///   LINK   = 0x03 → bits 2-3 = 11
    ///
    /// The bug this guards against: the auto-proof was constructed with
    /// destinationType: .plain, producing flag bits 2-3 = 10 on the wire,
    /// and Python/Android peers rejected it as a malformed proof against
    /// the original packet's truncated hash.
    func testAutoProofUsesSingleDestinationType() async throws {
        let mock = MockInterface(id: "auto-proof-iface")
        let (transport, destination, _) = try await makeAutoProofFixture(interface: mock)

        // Push a DATA packet through the transport as if it had just
        // arrived from the network.
        let packet = try makeOpportunisticPacket(
            to: destination,
            plaintext: Data("hello".utf8)
        )
        await transport.receive(packet: packet, from: "auto-proof-iface")

        // Drain everything sent on the interface. The auto-proof is the
        // only outbound on this fixture (no path table, no announces).
        let sent = await mock.drainSentPackets()
        XCTAssertEqual(sent.count, 1, "Expected exactly one outbound proof packet")

        let raw = try XCTUnwrap(sent.first)
        XCTAssertGreaterThanOrEqual(raw.count, 2, "Proof must have at least flags+hopCount")

        let flags = raw[0]
        let packetType    = flags & 0x03          // bits 0-1
        let destTypeBits  = (flags >> 2) & 0x03   // bits 2-3
        let transportType = (flags >> 4) & 0x01   // bit 4
        let headerType    = (flags >> 6) & 0x01   // bit 6
        let ifacFlag      = (flags >> 7) & 0x01   // bit 7

        XCTAssertEqual(packetType, 3,
            "Proof packets carry packetType=PROOF (3)")
        XCTAssertEqual(headerType, 0, "Proof must be HEADER_1")
        XCTAssertEqual(transportType, 0, "Proof must be BROADCAST")
        XCTAssertEqual(ifacFlag, 0,
            "No IFAC configured on this interface, so IFAC flag must be 0")

        XCTAssertEqual(destTypeBits, 0,
            """
            Auto-proof destinationType must encode as SINGLE (bits 2-3 = 00). \
            Got bits 2-3 = \(String(destTypeBits, radix: 2)). \
            If this is 10 (PLAIN) the .plain → .single fix has regressed; \
            see ReticulumTransport.swift handleRegularData ~line 2300 and \
            Python RNS Packet.py ProofDestination (type = SINGLE).
            """)

        // Decode through Packet for a typed sanity check on the same field.
        let decoded = try Packet(from: raw)
        XCTAssertEqual(decoded.header.packetType, .proof)
        XCTAssertEqual(decoded.header.destinationType, .single,
            "Decoded header.destinationType must be .single, not .plain")
    }

    // MARK: - Test 2: IFAC routing (regression for sendToInterface fix)

    /// When the receiving interface has IFAC configured, the auto-proof's
    /// outbound bytes must carry the IFAC flag (high bit of byte 0 = 1)
    /// and be ifacSize bytes longer than an unprotected encoding of the
    /// same proof. This is observable evidence that the proof went
    /// through `sendToInterface` (which calls `applyIFAC`) rather than
    /// straight to `interface.send` (which would emit the raw proof
    /// with no IFAC flag).
    ///
    /// Pre-fix behavior (raw `interface.send`): masked == raw,
    /// IFAC flag bit clear, length == proof body length. IFAC-configured
    /// peers reject as "IFAC validation failed".
    func testAutoProofGoesThroughIFACOnConfiguredInterface() async throws {
        // Use a stable IFAC key so failures are reproducible. 64 bytes:
        // first 32 are X25519, last 32 are the Ed25519 signing seed.
        let ifacKey = Data((0..<64).map { UInt8($0) })
        let ifacSize = 16
        let interfaceId = "auto-proof-ifac"

        let config = InterfaceConfig(
            id: interfaceId,
            name: "AutoProof IFAC",
            type: .tcp,
            enabled: true,
            mode: .full,
            host: "127.0.0.1",
            port: 0,
            ifac: nil,
            announceRateTarget: nil,
            announceRateGrace: 0,
            announceRatePenalty: 0,
            bitrate: 0,
            ifacSize: ifacSize,
            ifacKey: ifacKey
        )
        let mock = RecordingIFACInterface(config: config)
        let (transport, destination, _) = try await makeAutoProofFixture(interface: mock)

        let packet = try makeOpportunisticPacket(
            to: destination,
            plaintext: Data("ifac".utf8)
        )
        await transport.receive(packet: packet, from: interfaceId)

        let sent = await mock.drainSentPackets()
        XCTAssertEqual(sent.count, 1, "Expected exactly one outbound proof packet")
        let proofBytes = try XCTUnwrap(sent.first)

        // 1. IFAC flag must be set on the wire.
        XCTAssertEqual(proofBytes[0] & 0x80, 0x80,
            """
            IFAC flag (bit 7 of byte 0) must be set on the auto-proof, \
            proving the bytes went through sendToInterface → applyIFAC. \
            If it's clear, the proof is being emitted via raw \
            interface.send and IFAC-configured peers will drop it.
            """)

        // 2. Validate the wrapped proof round-trips through the IFAC
        //    layer back to a well-formed proof packet. This rules out the
        //    flag-only spoof (e.g. someone manually OR'ing 0x80 onto raw
        //    bytes without HKDF masking).
        let unwrapped = await transport.validateIFAC(raw: proofBytes, interfaceId: interfaceId)
        let unwrappedProof = try XCTUnwrap(unwrapped,
            "IFAC validation must succeed on a well-formed wrapped proof")
        XCTAssertEqual(unwrappedProof.count + ifacSize, proofBytes.count,
            "IFAC wrap should add exactly ifacSize bytes")

        // The unwrapped bytes are the original proof — confirm they
        // decode as a SINGLE PROOF packet (Test 1 invariant, but on the
        // post-IFAC-strip bytes, so we know the wrapping didn't corrupt
        // the underlying packet).
        let decoded = try Packet(from: unwrappedProof)
        XCTAssertEqual(decoded.header.packetType, .proof)
        XCTAssertEqual(decoded.header.destinationType, .single)
    }
}

// MARK: - Recording IFAC Mock Interface

/// Mock NetworkInterface that records sent bytes AND honors an IFAC config.
/// Combines TransportSendTests' MockInterface (drainSentPackets) with
/// IFACInteropTests' MockIFACInterface (config-driven IFAC keys).
actor RecordingIFACInterface: NetworkInterface {
    let id: String
    let config: InterfaceConfig
    nonisolated var state: InterfaceState { .connected }

    private(set) var sentPackets: [Data] = []

    init(config: InterfaceConfig) {
        self.id = config.id
        self.config = config
    }

    func connect() async throws {}
    func disconnect() async {}
    func send(_ data: Data) async throws {
        sentPackets.append(data)
    }
    func setDelegate(_ delegate: any InterfaceDelegate) async {}

    func drainSentPackets() -> [Data] {
        let packets = sentPackets
        sentPackets = []
        return packets
    }
}
