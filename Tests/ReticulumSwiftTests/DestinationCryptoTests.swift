// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  DestinationCryptoTests.swift
//  ReticulumSwiftTests
//
//  Coverage for Sources/ReticulumSwift/Crypto/Destination.swift. Drives the
//  REAL Destination code paths the conformance fix depends on:
//
//    1. Destination hash derivation — `Destination.hash`, the static
//       `Destination.hash(identity:appName:aspects:)`,
//       `Destination.hash(encryptionPublicKey:signingPublicKey:...)`,
//       `Destination.plainHash`, `nameHash`, `announceNameHash`, `fullName`,
//       `hexHash`, `publicKeys`. Same identity + appName + aspects yields a
//       deterministic 16-byte hash; different aspects / appName / identity
//       diverge — mirroring RNS Destination.hash semantics.
//
//    2. Drop-undecryptable invariant — feeding a foreign-key (undecryptable)
//       SINGLE DATA packet through `ReticulumTransport.receive` must NOT fire
//       the registered packet callback and must emit NO outbound proof; a
//       valid encrypt->receive round-trip DOES fire it (positive control).
//       Also exercised directly on `Destination.encrypt` / `Destination.decrypt`:
//       a valid round-trip returns the plaintext, a foreign-key ciphertext
//       returns nil.
//
//    3. Proof strategy + request handler + inbound link accessors —
//       `setProofStrategy` / `proofStrategy` / `setProofRequestedCallback` /
//       `proofRequestedCallback`, `registerRequestHandler` /
//       `deregisterRequestHandler` / `requestHandler(forPathHash:)`,
//       `appendLink` / `links`.
//
//  Reference: Sources/ReticulumSwift/Crypto/Destination.swift.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class DestinationCryptoTests: XCTestCase {

    // MARK: - Private Helpers

    /// Thread-safe recorder for the @Sendable packet callback. The
    /// callbackManager invokes callbacks off the test's actor, so the
    /// capture site needs concurrency-safe storage.
    private final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        private var _datas: [Data] = []
        func record(_ data: Data) { lock.withLock { _datas.append(data) } }
        var datas: [Data] { lock.withLock { _datas } }
        var count: Int { lock.withLock { _datas.count } }
    }

    /// Build a SINGLE DATA packet addressed to `destination`, encrypting
    /// `plaintext` to `identity`'s public key. When `identity` is the
    /// destination's own identity this is a valid opportunistic-delivery
    /// packet; when it is a foreign identity the destination cannot decrypt
    /// it (the drop-undecryptable case). The HKDF salt is always the
    /// DESTINATION identity's hash, matching what a real sender uses
    /// (Identity.get_salt()).
    private func makeSinglePacket(
        to destination: Destination,
        encryptedTo identity: Identity,
        plaintext: Data
    ) throws -> Packet {
        let ciphertext = try identity.encryptTo(
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

    /// Spin (bounded) until the callback manager reports a listener for
    /// `hash`. `Destination.registerCallback` routes to the manager's
    /// nonisolated `register`, which completes the registration in a
    /// spawned Task; this awaits that Task before we inject a packet so
    /// the negative test is meaningful.
    private func waitForListener(
        _ manager: DefaultCallbackManager,
        hash: Data
    ) async {
        for _ in 0..<400 {
            if await manager.hasListeners(for: hash) { return }
            try? await Task.sleep(nanoseconds: 5_000_000) // 5ms
        }
    }

    /// Build a responder (inbound) Link for `destination`, mirroring
    /// LinkProveTests' construction. No `_setStateForTesting` is used, so
    /// this stays outside any DEBUG guard.
    private func makeResponderLink(
        destination: Destination,
        identity: Identity
    ) throws -> Link {
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
            destination: destination.hash,
            context: 0x00,
            data: requestData
        )
        let incomingRequest = try IncomingLinkRequest(data: requestData, packet: lrPacket)
        return Link(incomingRequest: incomingRequest, destination: destination, identity: identity)
    }

    // MARK: - Hash Derivation

    func testHashIsDeterministicAndSixteenBytes() {
        let identity = Identity()
        let a = Destination(identity: identity, appName: "lxmf", aspects: ["delivery"])
        let b = Destination(identity: identity, appName: "lxmf", aspects: ["delivery"])

        XCTAssertEqual(a.hash.count, 16, "Destination hash must be 16 bytes")
        XCTAssertEqual(a.hash, b.hash,
            "Same identity + appName + aspects must produce an identical hash")
        // The instance hash must equal the static derivation RNS peers use.
        XCTAssertEqual(
            a.hash,
            Destination.hash(identity: identity, appName: "lxmf", aspects: ["delivery"]),
            "Instance .hash must match Destination.hash(identity:appName:aspects:)")
        XCTAssertEqual(a.hexHash, a.hash.map { String(format: "%02x", $0) }.joined(),
            "hexHash must be the lowercase hex of hash")
    }

    func testHashDiffersByAspects() {
        let identity = Identity()
        let delivery = Destination(identity: identity, appName: "lxmf", aspects: ["delivery"])
        let propagation = Destination(identity: identity, appName: "lxmf", aspects: ["propagation"])
        let noAspect = Destination(identity: identity, appName: "lxmf", aspects: [])

        XCTAssertNotEqual(delivery.hash, propagation.hash,
            "Different aspects must yield different destination hashes")
        XCTAssertNotEqual(delivery.hash, noAspect.hash,
            "Adding an aspect must change the destination hash")
    }

    func testHashDiffersByAppName() {
        let identity = Identity()
        let lxmf = Destination(identity: identity, appName: "lxmf", aspects: ["delivery"])
        let other = Destination(identity: identity, appName: "nomadnetwork", aspects: ["delivery"])
        XCTAssertNotEqual(lxmf.hash, other.hash,
            "Different appName must yield different destination hashes")
    }

    func testHashDiffersByIdentity() {
        let a = Destination(identity: Identity(), appName: "lxmf", aspects: ["delivery"])
        let b = Destination(identity: Identity(), appName: "lxmf", aspects: ["delivery"])
        XCTAssertNotEqual(a.hash, b.hash,
            "Different identities must yield different destination hashes")
    }

    func testStaticHashFromPublicKeysMatchesIdentityVariant() {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "lxmf", aspects: ["delivery"])

        let fromPubKeys = Destination.hash(
            encryptionPublicKey: identity.encryptionPublicKey.rawRepresentation,
            signingPublicKey: identity.signingPublicKey.rawRepresentation,
            appName: "lxmf",
            aspects: ["delivery"]
        )
        XCTAssertEqual(fromPubKeys, dest.hash,
            "Destination.hash(encryptionPublicKey:signingPublicKey:...) must match " +
            "the hash derived from the full Identity (same public keys -> same hash)")
        XCTAssertEqual(dest.publicKeys, identity.publicKeys,
            "publicKeys must surface the identity's 64-byte concatenated keys")
    }

    func testPlainDestinationHashIgnoresIdentity() {
        let plain = Destination(plainAppName: "broadcast", aspects: ["news"])

        XCTAssertNil(plain.publicKeys, "PLAIN destinations expose no public keys")
        XCTAssertEqual(plain.hash.count, 16, "PLAIN destination hash must be 16 bytes")
        XCTAssertEqual(
            plain.hash,
            Destination.plainHash(appName: "broadcast", aspects: ["news"]),
            "PLAIN destination .hash must match Destination.plainHash (name-only)")
        // The PLAIN hash is identity-independent: it equals plainHash regardless
        // of any identity, and changing aspects changes it.
        XCTAssertNotEqual(
            Destination.plainHash(appName: "broadcast", aspects: ["news"]),
            Destination.plainHash(appName: "broadcast", aspects: ["weather"]),
            "PLAIN hash must vary with aspects")
    }

    func testNameHashAnnounceNameHashFullNameAndPublicKeys() {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "lxmf", aspects: ["delivery", "v2"])

        // nameHash is the 10-byte (NAME_HASH_LENGTH) full-name hash.
        XCTAssertEqual(dest.nameHash.count, 10,
            "nameHash must be 10 bytes (NAME_HASH_LENGTH)")
        XCTAssertEqual(dest.nameHash,
            Hashing.destinationNameHash(appName: "lxmf", aspects: ["delivery", "v2"]),
            "nameHash must match Hashing.destinationNameHash")

        // announceNameHash concatenates 16 bytes per aspect (app name counts).
        XCTAssertEqual(dest.announceNameHash.count, 16 * 3,
            "announceNameHash must be 16 bytes * (1 appName + 2 aspects) = 48 bytes")

        XCTAssertEqual(dest.fullName, "lxmf.delivery.v2",
            "fullName must be the dot-joined appName + aspects")

        // An aspect-less destination's fullName is just the app name.
        let bare = Destination(identity: identity, appName: "lxmf")
        XCTAssertEqual(bare.fullName, "lxmf")
        XCTAssertEqual(bare.announceNameHash.count, 16,
            "An aspect-less announceNameHash is just the 16-byte appName hash")
    }

    // MARK: - encrypt / decrypt (Destination's own crypto)

    func testEncryptDecryptRoundTrip() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "lxmf", aspects: ["delivery"])
        let plaintext = Data("forward secrecy or static — round-trips either way".utf8)

        let ciphertext = try dest.encrypt(plaintext)
        XCTAssertNotEqual(ciphertext, plaintext,
            "SINGLE encrypt must transform the plaintext")
        XCTAssertGreaterThanOrEqual(ciphertext.count, 96,
            "Ciphertext carries a 32-byte ephemeral key + token")

        let recovered = await dest.decrypt(ciphertext)
        XCTAssertEqual(recovered, plaintext,
            "Destination.decrypt must recover the plaintext it encrypted")

        // No ratchets configured -> the static identity key was used, so the
        // ratchet-id receiver records nil (Destination.py:903-908 semantics).
        XCTAssertNil(dest.latestRatchetId,
            "With no ratchets the static key decrypts and latestRatchetId stays nil")
    }

    func testDecryptForeignKeyCiphertextReturnsNil() async throws {
        let dest = Destination(identity: Identity(), appName: "lxmf", aspects: ["delivery"])
        // Encrypt to a DIFFERENT identity's public key (with this destination's
        // salt) — the destination's private key can never reproduce the shared
        // secret, so decrypt must fail closed and return nil.
        let foreign = Identity()
        let foreignCiphertext = try foreign.encryptTo(
            Data("not for you".utf8),
            identityHash: dest.identity!.hash
        )

        let result = await dest.decrypt(foreignCiphertext)
        XCTAssertNil(result,
            "Destination.decrypt must return nil for an undecryptable foreign-key ciphertext")
    }

    func testPlainDestinationEncryptDecryptPassthrough() async throws {
        let plain = Destination(plainAppName: "broadcast", aspects: ["news"])
        let payload = Data("plain destinations are not encrypted".utf8)

        let enc = try plain.encrypt(payload)
        XCTAssertEqual(enc, payload, "PLAIN encrypt must pass plaintext through unchanged")

        let dec = await plain.decrypt(payload)
        XCTAssertEqual(dec, payload, "PLAIN decrypt must pass ciphertext through unchanged")
    }

    func testEncryptOnGroupDestinationThrowsIdentityRequired() throws {
        // GROUP encryption is out of scope for the SINGLE/PLAIN encrypt path,
        // so encrypt must reject it with .identityRequired (it is neither the
        // PLAIN passthrough nor a SINGLE/LINK type).
        let group = Destination(
            identity: Identity(),
            appName: "group",
            aspects: ["chat"],
            type: .group
        )
        XCTAssertThrowsError(try group.encrypt(Data("hi".utf8))) { error in
            XCTAssertEqual(error as? DestinationError, .identityRequired,
                "encrypt on a GROUP destination must throw .identityRequired")
        }
    }

    // MARK: - Drop-undecryptable invariant (through ReticulumTransport.receive)

    func testReceiveUndecryptablePacketFiresNoCallbackAndSendsNoProof() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["dropundec"])

        let mock = MockInterface(id: "destcrypto-drop-iface")
        let transport = ReticulumTransport()
        try await transport.addInterface(mock)
        await transport.registerDestination(dest)

        // Register a packet callback through the REAL Destination API; it
        // routes to the transport's callback manager keyed by dest.hash.
        let recorder = Recorder()
        try dest.registerCallback { data, _ in recorder.record(data) }
        await waitForListener(transport.getCallbackManager(), hash: dest.hash)

        // Foreign-key ciphertext addressed to dest.hash — undecryptable.
        let foreign = Identity()
        let packet = try makeSinglePacket(
            to: dest,
            encryptedTo: foreign,
            plaintext: Data("should be dropped".utf8)
        )
        await transport.receive(packet: packet, from: "destcrypto-drop-iface")

        // Give any (incorrectly-) dispatched callback time to land.
        try? await Task.sleep(nanoseconds: 200_000_000) // 200ms

        XCTAssertEqual(recorder.count, 0,
            "An undecryptable packet must NOT fire the destination packet callback")
        let sent = await mock.drainSentPackets()
        XCTAssertTrue(sent.isEmpty,
            "An undecryptable packet must emit no outbound proof — decrypt fails " +
            "before delivery and before the auto-proof step")
    }

    func testReceiveValidPacketFiresCallback() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["dropundec-ok"])

        let mock = MockInterface(id: "destcrypto-ok-iface")
        let transport = ReticulumTransport()
        try await transport.addInterface(mock)
        await transport.registerDestination(dest)

        let recorder = Recorder()
        let fired = expectation(description: "valid packet fires destination callback")
        let plaintext = Data("delivered for real".utf8)
        try dest.registerCallback { data, _ in
            recorder.record(data)
            fired.fulfill()
        }
        await waitForListener(transport.getCallbackManager(), hash: dest.hash)

        // Positive control: encrypt to the destination's OWN identity.
        let packet = try makeSinglePacket(
            to: dest,
            encryptedTo: identity,
            plaintext: plaintext
        )
        await transport.receive(packet: packet, from: "destcrypto-ok-iface")

        await fulfillment(of: [fired], timeout: 3.0)
        XCTAssertEqual(recorder.datas.first, plaintext,
            "A valid encrypt->receive round-trip must deliver the exact plaintext")
    }

    // MARK: - Proof Strategy Accessors

    func testProofStrategyDefaultSetInvalidAndCallback() throws {
        let dest = Destination(identity: Identity(), appName: "test", aspects: ["proof"])

        // Default is PROVE_NONE (Destination.py:160).
        XCTAssertEqual(dest.proofStrategy, Destination.PROVE_NONE,
            "Default proof strategy must be PROVE_NONE")

        try dest.setProofStrategy(Destination.PROVE_ALL)
        XCTAssertEqual(dest.proofStrategy, Destination.PROVE_ALL)
        try dest.setProofStrategy(Destination.PROVE_APP)
        XCTAssertEqual(dest.proofStrategy, Destination.PROVE_APP)

        // An out-of-set value must be rejected and leave the strategy unchanged.
        XCTAssertThrowsError(try dest.setProofStrategy(0x99)) { error in
            XCTAssertEqual(error as? DestinationError, .unsupportedProofStrategy)
        }
        XCTAssertEqual(dest.proofStrategy, Destination.PROVE_APP,
            "A rejected setProofStrategy must not mutate the stored strategy")

        // proof-requested callback round-trips through the accessor and is callable.
        XCTAssertNil(dest.proofRequestedCallback,
            "No proof-requested callback is set by default")
        dest.setProofRequestedCallback { _ in true }
        let cb = try XCTUnwrap(dest.proofRequestedCallback,
            "proofRequestedCallback must surface the registered callback")
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .data,
            hopCount: 0
        )
        let probe = Packet(header: header, destination: dest.hash, context: 0x00, data: Data([0x01]))
        XCTAssertTrue(cb(probe),
            "The registered proof-requested callback must run and return its value")

        dest.setProofRequestedCallback(nil)
        XCTAssertNil(dest.proofRequestedCallback,
            "Clearing the proof-requested callback must reset the accessor to nil")
    }

    // MARK: - Request Handler Accessors

    func testRegisterDeregisterRequestHandlerAndLookup() throws {
        let dest = Destination(identity: Identity(), appName: "test", aspects: ["req"])
        let path = "/status"
        let pathHash = Hashing.truncatedHash(Data(path.utf8))

        XCTAssertNil(dest.requestHandler(forPathHash: pathHash),
            "No handler is registered before registerRequestHandler is called")

        try dest.registerRequestHandler(
            path: path,
            responseGenerator: { _, _, _, _, _, _ in .none },
            allow: Destination.ALLOW_ALL
        )
        let handler = try XCTUnwrap(dest.requestHandler(forPathHash: pathHash),
            "registerRequestHandler must store a handler keyed by truncatedHash(path)")
        XCTAssertEqual(handler.path, path)
        XCTAssertEqual(handler.allow, Destination.ALLOW_ALL)

        // First deregister removes it (true), second finds nothing (false).
        XCTAssertTrue(dest.deregisterRequestHandler(path),
            "Deregistering an existing handler must return true")
        XCTAssertFalse(dest.deregisterRequestHandler(path),
            "Deregistering a missing handler must return false")
        XCTAssertNil(dest.requestHandler(forPathHash: pathHash),
            "Lookup must return nil after deregistration")

        // Validation: empty path and unknown policy are rejected.
        XCTAssertThrowsError(
            try dest.registerRequestHandler(path: "", responseGenerator: { _, _, _, _, _, _ in .none })
        ) { error in
            XCTAssertEqual(error as? DestinationError, .invalidPath)
        }
        XCTAssertThrowsError(
            try dest.registerRequestHandler(
                path: "/x",
                responseGenerator: { _, _, _, _, _, _ in .none },
                allow: 0x7F
            )
        ) { error in
            XCTAssertEqual(error as? DestinationError, .invalidRequestPolicy)
        }
    }

    // MARK: - Inbound Link Tracking

    func testAppendLinkTracksInboundLink() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["links"])

        XCTAssertTrue(dest.links.isEmpty, "A fresh destination tracks no inbound links")

        let link = try makeResponderLink(destination: dest, identity: identity)
        let linkId = await link.linkId

        dest.appendLink(link)

        XCTAssertEqual(dest.links.count, 1,
            "appendLink must add the accepted responder link to .links")
        let storedId = await dest.links.first?.linkId
        XCTAssertEqual(storedId, linkId,
            "The tracked link must be the one that was appended")
    }
}
