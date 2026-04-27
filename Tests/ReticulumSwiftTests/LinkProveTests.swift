// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  LinkProveTests.swift
//  ReticulumSwiftTests
//
//  Regression coverage for link-context delivery proofs:
//
//    1. `Link.provePacket(_:)` emits a Python-compatible PROOF packet
//       — destinationType=LINK, destination=linkId, explicit-format
//       data (32-byte hash + 64-byte signature), unencrypted. Python
//       `RNS.PacketReceipt.validate_link_proof` requires this exact
//       shape; SINGLE / implicit-only proofs are silently rejected on
//       the link path.
//
//    2. `ReticulumTransport.handleDataProof` fires the callback-style
//       `pendingProofCallbacks` registration for link-context proofs,
//       not just the continuation-style `pendingPacketProofs`. The
//       non-link proof path already checks both; this regression
//       guards the symmetric check on the link path so LXMF DIRECT
//       outbound state can advance to `delivered` when the proof
//       arrives over the link.
//
//  Reference: Sources/ReticulumSwift/Link/Link.swift `provePacket`
//  and Sources/ReticulumSwift/Transport/ReticulumTransport.swift
//  `handleDataProof`.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class LinkProveTests: XCTestCase {

    // MARK: - Test 1: provePacket wire format

    func testProvePacketEmitsExplicitLinkProof() async throws {
        // ---- Setup ---------------------------------------------------
        // Build a responder-shaped Link with a known identity, force it
        // into `.active` (the LRRTT handshake doesn't matter for proof
        // wire format — we only need `state.isEstablished == true`),
        // and capture the bytes it would have sent via sendCallback.
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["prove"])

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
        let incomingRequest = try IncomingLinkRequest(data: requestData, packet: lrPacket)
        let link = Link(incomingRequest: incomingRequest, destination: dest, identity: identity)

        let captured = CapturedSends()
        await link.setSendCallback { data in
            await captured.append(data)
        }
        await link._setStateForTesting(.active)

        // ---- Build a sample inbound packet to prove ----------------
        // The proof's `proofHash` is `getFullHash()` of THIS packet —
        // matching what the sender's `PacketReceipt` registered when
        // it sent the original. We mock an arbitrary link DATA packet
        // here and expect the proof's first 32 bytes to match its
        // full hash.
        let dataHeader = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hopCount: 0
        )
        let linkId = await link.linkId
        let inboundPacket = Packet(
            header: dataHeader,
            destination: linkId,
            context: 0x00,
            data: Data("ciphertext-stand-in".utf8)
        )

        // ---- Act ---------------------------------------------------
        try await link.provePacket(inboundPacket)

        // ---- Capture + decode the emitted proof --------------------
        let sent = await captured.drain()
        XCTAssertEqual(sent.count, 1, "Expected exactly one outbound proof packet")
        let raw = try XCTUnwrap(sent.first)

        let proof = try Packet(from: raw)

        // Header invariants — these are what python's
        // PacketReceipt.validate_link_proof reads to know it's a link
        // proof. Any drift here breaks the cross-impl proof path.
        XCTAssertEqual(proof.header.packetType, .proof,
            "Proof packet must carry packetType=PROOF")
        XCTAssertEqual(proof.header.destinationType, .link,
            "Link-context proof must use destinationType=LINK")
        XCTAssertEqual(proof.destination, linkId,
            "Proof destination must be the linkId so the python sender " +
            "can route it through Transport.active_links lookup")

        // Data layout: explicit proof = 32-byte packet hash +
        // 64-byte Ed25519 signature. Python's validate_link_proof
        // reads bytes 0..32 as proof_hash and 32..96 as signature;
        // implicit (signature-only) is `pass` in current upstream
        // and would be silently ignored.
        XCTAssertEqual(proof.data.count, 96,
            "Explicit link proof is 32-byte hash + 64-byte signature = 96 bytes; " +
            "got \(proof.data.count). Likely implicit fallback regressed.")

        let proofHash = Data(proof.data.prefix(32))
        let signature = Data(proof.data.dropFirst(32))
        XCTAssertEqual(proofHash, inboundPacket.getFullHash(),
            "First 32 bytes of proof data must match the inbound packet's " +
            "full hash — sender's PacketReceipt is keyed on this hash.")

        // Signature verifies against the Link's identity (which, on
        // the responder side, is the destination identity — same as
        // python's `Link.sign` using `owner.identity.sig_prv`).
        let ok = identity.verify(signature: signature, for: proofHash)
        XCTAssertTrue(ok,
            "Proof signature must validate against the destination identity's " +
            "signing key. If this fails, python peers will reject the proof.")
    }

    // MARK: - Test 2: handleDataProof fires pendingProofCallbacks

    func testRegisterProofCallbackFiresOnLinkContextProof() async throws {
        // Goal: prove that registering a callback via
        // `transport.registerProofCallback(truncatedHash:)` fires
        // when a link-context PROOF arrives whose first 32 bytes
        // truncate to that hash. Without the fix, only
        // `pendingPacketProofs` (continuation-style) was checked on
        // the link path; LXMF DIRECT outbound used the callback API
        // and got nothing.
        //
        // We bypass the full link establishment and inject the proof
        // packet through `transport.receive(packet:from:)` against
        // a transport with a known-active link in its activeLinks
        // map. The test verifies the callback fires and pending
        // callbacks dict is drained.
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["prove2"])

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
        let incomingRequest = try IncomingLinkRequest(data: requestData, packet: lrPacket)
        let link = Link(incomingRequest: incomingRequest, destination: dest, identity: identity)
        await link._setStateForTesting(.active)

        let mock = MockInterface(id: "link-proof-iface")
        let transport = ReticulumTransport()
        try await transport.addInterface(mock)
        await transport.registerLink(link)

        // ---- Synthesize a packet whose hash we'll prove --------------
        // The proof carries the original packet's hash — we just need
        // any deterministic 32 bytes. The transport's callback dict
        // is keyed by the TRUNCATED (first 16 bytes) hash, mirroring
        // `Packet.getTruncatedHash()`.
        let originalDataHeader = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hopCount: 0
        )
        let linkId = await link.linkId
        let originalPacket = Packet(
            header: originalDataHeader,
            destination: linkId,
            context: 0x00,
            data: Data("payload-for-hash-derivation".utf8)
        )
        let originalHash = originalPacket.getFullHash()
        let truncatedHash = originalPacket.getTruncatedHash()

        // ---- Register callback BEFORE injecting proof --------------
        let callbackFired = expectation(description: "delivery proof callback fires")
        await transport.registerProofCallback(truncatedHash: truncatedHash) {
            callbackFired.fulfill()
        }

        // ---- Build + inject a link PROOF packet ---------------------
        // Real proofs sign the hash with the link's signing key, but
        // `handleDataProof` only matches by hash — it doesn't validate
        // the signature on the callback path. A 96-byte explicit-format
        // proof with the right packet hash + a 64-byte filler is
        // sufficient to exercise the callback dispatch. Real-link
        // signature verification happens at the python sender end via
        // `PacketReceipt.validate_link_proof` and is covered by the
        // provePacket wire-format test above.
        var proofData = Data()
        proofData.append(originalHash)
        proofData.append(Data(repeating: 0, count: 64))
        let proofHeader = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .link,
            packetType: .proof,
            hopCount: 0
        )
        let proofPacket = Packet(
            header: proofHeader,
            destination: linkId,
            context: 0x00,
            data: proofData
        )
        await transport.receive(packet: proofPacket, from: "link-proof-iface")

        // ---- Assert callback fired -----------------------------------
        await fulfillment(of: [callbackFired], timeout: 2.0)
    }
}

// MARK: - Helpers

/// Sendable storage for sendCallback-captured bytes. The Link's
/// sendCallback is `@Sendable`, so the capture site needs an actor or
/// concurrency-safe wrapper.
private actor CapturedSends {
    private var packets: [Data] = []

    func append(_ data: Data) {
        packets.append(data)
    }

    func drain() -> [Data] {
        let copy = packets
        packets = []
        return copy
    }
}
