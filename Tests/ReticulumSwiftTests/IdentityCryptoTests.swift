// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  IdentityCryptoTests.swift
//  ReticulumSwift
//
//  Pure-Swift (no Python bridge) unit tests exercising the real Identity
//  crypto surface: Ed25519 sign/verify, X25519 encrypt/decrypt round-trips
//  and tamper rejection, identity-hash determinism, key import/export,
//  recall/remember known-destinations store, ratchet-id helpers, and the
//  ratchet-id-reporting decrypt overload.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class IdentityCryptoTests: XCTestCase {

    // MARK: - Helpers (private — no top-level collisions)

    private func randomBytes(_ count: Int) -> Data {
        var bytes = Data(count: count)
        _ = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        return bytes
    }

    /// Reference receiver for the ratchet-id-reporting decrypt overload.
    private final class CapturingReceiver: RatchetIdReceiver {
        var latestRatchetId: Data? = nil
    }

    // MARK: - Sign / Verify

    func testSignVerifyRoundTrip() throws {
        let identity = Identity()
        let message = "round-trip signing payload".data(using: .utf8)!

        let signature = try identity.sign(message)
        XCTAssertEqual(signature.count, 64, "Ed25519 signature is 64 bytes")
        XCTAssertTrue(identity.verify(signature: signature, for: message),
                      "Valid signature must verify against its identity")
    }

    func testVerifyRejectsTamperedMessage() throws {
        let identity = Identity()
        let message = "authentic message".data(using: .utf8)!
        let signature = try identity.sign(message)

        var tampered = message
        tampered[0] ^= 0xFF
        XCTAssertFalse(identity.verify(signature: signature, for: tampered),
                       "Signature must not verify against a modified message")
    }

    func testVerifyRejectsTamperedSignature() throws {
        let identity = Identity()
        let message = "authentic message".data(using: .utf8)!
        var signature = try identity.sign(message)

        signature[10] ^= 0xFF
        XCTAssertFalse(identity.verify(signature: signature, for: message),
                       "Corrupted signature bytes must be rejected")
    }

    func testSignThrowsOnPublicOnlyIdentity() throws {
        let full = Identity()
        let publicOnly = try Identity(publicKeyBytes: full.publicKeys)
        XCTAssertFalse(publicOnly.hasPrivateKeys)

        XCTAssertThrowsError(try publicOnly.sign(Data([1, 2, 3]))) { error in
            XCTAssertEqual(error as? IdentityError, .noPrivateKey)
        }
    }

    func testPublicOnlyIdentityCanVerify() throws {
        let signer = Identity()
        let verifier = try Identity(publicKeyBytes: signer.publicKeys)
        let message = "verify with public-only twin".data(using: .utf8)!

        let signature = try signer.sign(message)
        XCTAssertTrue(verifier.verify(signature: signature, for: message))
    }

    // MARK: - Static verify(signature:for:publicKey:)

    func testStaticVerifyAcceptsValidSignature() throws {
        let identity = Identity()
        let message = "static verify payload".data(using: .utf8)!
        let signature = try identity.sign(message)

        let signingPub = identity.signingPublicKey.rawRepresentation
        XCTAssertTrue(try Identity.verify(signature: signature, for: message, publicKey: signingPub))
    }

    func testStaticVerifyRejectsWrongSignatureLength() throws {
        let identity = Identity()
        let message = "x".data(using: .utf8)!
        let signingPub = identity.signingPublicKey.rawRepresentation

        // 63-byte signature (wrong length) returns false rather than throwing.
        let shortSig = Data(repeating: 0, count: 63)
        XCTAssertFalse(try Identity.verify(signature: shortSig, for: message, publicKey: signingPub))
    }

    func testStaticVerifyThrowsOnWrongPublicKeyLength() {
        let signature = Data(repeating: 0, count: 64)
        let message = "x".data(using: .utf8)!
        let badPub = Data(repeating: 0, count: 31)

        XCTAssertThrowsError(try Identity.verify(signature: signature, for: message, publicKey: badPub)) { error in
            guard case IdentityError.invalidKeyLength(let expected, let actual, _) = error else {
                return XCTFail("Expected invalidKeyLength, got \(error)")
            }
            XCTAssertEqual(expected, 32)
            XCTAssertEqual(actual, 31)
        }
    }

    // MARK: - Encrypt / Decrypt round-trips

    func testEncryptDecryptRoundTrip() throws {
        let identity = Identity()
        let plaintext = "secret payload for SINGLE destination".data(using: .utf8)!

        let ciphertext = try identity.encryptTo(plaintext, identityHash: identity.hash)
        XCTAssertGreaterThan(ciphertext.count, plaintext.count,
                             "Ciphertext carries ephemeral key + IV + HMAC overhead")

        let decrypted = try identity.decrypt(ciphertext, identityHash: identity.hash)
        XCTAssertEqual(decrypted, plaintext, "Decryption must recover the exact plaintext")
    }

    func testStaticEncryptToPublicKeyRoundTrip() throws {
        let identity = Identity()
        let plaintext = "static-encrypt to public key".data(using: .utf8)!

        let ciphertext = try Identity.encrypt(
            plaintext,
            to: identity.encryptionPublicKey,
            identityHash: identity.hash
        )
        // Output starts with the 32-byte ephemeral X25519 public key.
        XCTAssertGreaterThanOrEqual(ciphertext.count, 32 + 16 + 32)

        let decrypted = try identity.decrypt(ciphertext, identityHash: identity.hash)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptIsNonDeterministic() throws {
        // Ephemeral keypair per call -> two ciphertexts of the same plaintext differ.
        let identity = Identity()
        let plaintext = "same plaintext twice".data(using: .utf8)!

        let c1 = try identity.encryptTo(plaintext, identityHash: identity.hash)
        let c2 = try identity.encryptTo(plaintext, identityHash: identity.hash)
        XCTAssertNotEqual(c1, c2, "Ephemeral key randomization must vary ciphertext")

        XCTAssertEqual(try identity.decrypt(c1, identityHash: identity.hash), plaintext)
        XCTAssertEqual(try identity.decrypt(c2, identityHash: identity.hash), plaintext)
    }

    func testDecryptWithWrongIdentityFails() throws {
        let alice = Identity()
        let bob = Identity()
        let plaintext = "for alice only".data(using: .utf8)!

        let ciphertext = try alice.encryptTo(plaintext, identityHash: alice.hash)

        // Bob's private key yields a different ECDH secret -> HMAC mismatch.
        XCTAssertThrowsError(try bob.decrypt(ciphertext, identityHash: alice.hash)) { error in
            guard case IdentityError.decryptionFailed = error else {
                return XCTFail("Expected decryptionFailed, got \(error)")
            }
        }
    }

    func testDecryptCorruptedCiphertextFails() throws {
        let identity = Identity()
        let plaintext = "tamper-detect payload".data(using: .utf8)!
        var ciphertext = try identity.encryptTo(plaintext, identityHash: identity.hash)

        // Flip a byte in the HMAC tail to force token authentication failure.
        ciphertext[ciphertext.count - 1] ^= 0xFF
        XCTAssertThrowsError(try identity.decrypt(ciphertext, identityHash: identity.hash)) { error in
            guard case IdentityError.decryptionFailed = error else {
                return XCTFail("Expected decryptionFailed, got \(error)")
            }
        }
    }

    func testDecryptTooShortCiphertextThrows() throws {
        let identity = Identity()
        let tooShort = Data(repeating: 0, count: 50) // < 96-byte minimum
        XCTAssertThrowsError(try identity.decrypt(tooShort, identityHash: identity.hash)) { error in
            guard case IdentityError.decryptionFailed = error else {
                return XCTFail("Expected decryptionFailed, got \(error)")
            }
        }
    }

    func testDecryptOnPublicOnlyIdentityThrows() throws {
        let full = Identity()
        let plaintext = "data".data(using: .utf8)!
        let ciphertext = try full.encryptTo(plaintext, identityHash: full.hash)

        let publicOnly = try Identity(publicKeyBytes: full.publicKeys)
        XCTAssertThrowsError(try publicOnly.decrypt(ciphertext, identityHash: full.hash)) { error in
            XCTAssertEqual(error as? IdentityError, .noPrivateKey)
        }
    }

    // MARK: - Hash / publicKeys / hexHash

    func testHashLengthAndDeterminism() {
        let identity = Identity()
        XCTAssertEqual(identity.hash.count, 16, "Identity hash is truncated SHA-256 (16 bytes)")
        XCTAssertEqual(identity.hash, identity.hash, "Hash is deterministic across reads")
        XCTAssertEqual(identity.publicKeys.count, 64, "publicKeys = enc(32) || sig(32)")
    }

    func testHashMatchesHashingHelper() {
        let identity = Identity()
        let expected = Hashing.identityHash(
            encryptionPublicKey: identity.encryptionPublicKey.rawRepresentation,
            signingPublicKey: identity.signingPublicKey.rawRepresentation
        )
        XCTAssertEqual(identity.hash, expected,
                       "Identity.hash must equal Hashing.identityHash over its own public keys")
    }

    func testDistinctIdentitiesHaveDistinctHashes() {
        XCTAssertNotEqual(Identity().hash, Identity().hash)
    }

    func testHexHashFormat() {
        let identity = Identity()
        XCTAssertEqual(identity.hexHash.count, 32, "16-byte hash -> 32 hex chars")
        XCTAssertTrue(identity.hexHash.allSatisfy { $0.isHexDigit })
        XCTAssertEqual(identity.description, "Identity<\(identity.hexHash)>")
    }

    func testPublicOnlyIdentityHashMatchesFull() throws {
        let full = Identity()
        let publicOnly = try Identity(publicKeyBytes: full.publicKeys)
        XCTAssertEqual(full.hash, publicOnly.hash)
        XCTAssertEqual(full.publicKeys, publicOnly.publicKeys)
        XCTAssertFalse(publicOnly.hasPrivateKeys)
    }

    // MARK: - Key import / export

    func testExportPrivateKeysRoundTrip() throws {
        let identity = Identity()
        let exported = try identity.exportPrivateKeys()
        XCTAssertEqual(exported.count, 64, "Exported private keys = enc(32) || sig(32)")

        let restored = try Identity(privateKeyBytes: exported)
        XCTAssertEqual(restored.hash, identity.hash, "Restored identity has the same hash")

        // Restored identity reproduces real crypto behavior of the original.
        let message = "signed by original".data(using: .utf8)!
        let signature = try identity.sign(message)
        XCTAssertTrue(restored.verify(signature: signature, for: message))

        let ciphertext = try identity.encryptTo(message, identityHash: identity.hash)
        XCTAssertEqual(try restored.decrypt(ciphertext, identityHash: identity.hash), message)
    }

    func testExportPrivateKeysThrowsOnPublicOnly() throws {
        let publicOnly = try Identity(publicKeyBytes: Identity().publicKeys)
        XCTAssertThrowsError(try publicOnly.exportPrivateKeys()) { error in
            XCTAssertEqual(error as? IdentityError, .noPrivateKey)
        }
    }

    func testInitFromRawPrivateKeyBytesRoundTrip() throws {
        let original = Identity()
        let exported = try original.exportPrivateKeys()
        let encBytes = exported.prefix(32)
        let sigBytes = exported.suffix(32)

        let rebuilt = try Identity(
            encryptionPrivateKeyBytes: Data(encBytes),
            signingPrivateKeyBytes: Data(sigBytes)
        )
        XCTAssertEqual(rebuilt.hash, original.hash)
    }

    func testInitFromRawPrivateKeyBytesInvalidLengthThrows() {
        XCTAssertThrowsError(try Identity(
            encryptionPrivateKeyBytes: Data(repeating: 0, count: 31),
            signingPrivateKeyBytes: Data(repeating: 0, count: 32)
        )) { error in
            guard case IdentityError.invalidKeyLength(let expected, let actual, let keyType) = error else {
                return XCTFail("Expected invalidKeyLength, got \(error)")
            }
            XCTAssertEqual(expected, 32)
            XCTAssertEqual(actual, 31)
            XCTAssertEqual(keyType, "encryption")
        }
    }

    func testInitFromConcatenatedPrivateKeyInvalidLengthThrows() {
        XCTAssertThrowsError(try Identity(privateKeyBytes: Data(repeating: 0, count: 63))) { error in
            guard case IdentityError.invalidKeyLength(let expected, let actual, _) = error else {
                return XCTFail("Expected invalidKeyLength, got \(error)")
            }
            XCTAssertEqual(expected, 64)
            XCTAssertEqual(actual, 63)
        }
    }

    func testInitFromPublicKeyBytesInvalidLengthThrows() {
        XCTAssertThrowsError(try Identity(publicKeyBytes: Data(repeating: 0, count: 65))) { error in
            guard case IdentityError.invalidKeyLength(let expected, let actual, _) = error else {
                return XCTFail("Expected invalidKeyLength, got \(error)")
            }
            XCTAssertEqual(expected, 64)
            XCTAssertEqual(actual, 65)
        }
    }

    // MARK: - recall / remember (known_destinations store)

    func testRememberAndRecallRoundTrip() throws {
        let identity = Identity()
        let destinationHash = randomBytes(16)
        let packetHash = randomBytes(16)
        let appData = "last-heard app data".data(using: .utf8)!

        try Identity.remember(
            packetHash: packetHash,
            destinationHash: destinationHash,
            publicKey: identity.publicKeys,
            appData: appData
        )

        let recalled = try XCTUnwrap(Identity.recall(destinationHash),
                                     "remembered destination must be recallable")
        XCTAssertEqual(recalled.hash, identity.hash, "Recalled identity rebuilt from stored public keys")
        XCTAssertEqual(recalled.publicKeys, identity.publicKeys)
        XCTAssertEqual(recalled.appData, appData, "recall attaches the stored app_data")
        XCTAssertFalse(recalled.hasPrivateKeys, "Recalled identity is public-key-only")

        XCTAssertEqual(Identity.recallAppData(destinationHash), appData)
        XCTAssertEqual(Identity.knownDestinationEntryLength(destinationHash), 5,
                       "Stored entry is the canonical 5-element record")
    }

    func testRecallByIdentityHash() throws {
        let identity = Identity()
        let destinationHash = randomBytes(16)

        try Identity.remember(
            packetHash: randomBytes(16),
            destinationHash: destinationHash,
            publicKey: identity.publicKeys,
            appData: nil
        )

        // fromIdentityHash matches truncated_hash(public_key) == identity.hash.
        let recalled = try XCTUnwrap(Identity.recall(identity.hash, fromIdentityHash: true))
        XCTAssertEqual(recalled.publicKeys, identity.publicKeys)
    }

    func testRecallUnknownReturnsNil() {
        XCTAssertNil(Identity.recall(randomBytes(16)),
                     "Unknown destination hash has no recall result")
        XCTAssertNil(Identity.recallAppData(randomBytes(16)))
        XCTAssertNil(Identity.knownDestinationEntryLength(randomBytes(16)))
    }

    func testRememberRejectsWrongPublicKeyLength() {
        XCTAssertThrowsError(try Identity.remember(
            packetHash: randomBytes(16),
            destinationHash: randomBytes(16),
            publicKey: Data(repeating: 0, count: 32) // must be 64
        )) { error in
            guard case IdentityError.invalidKeyLength(let expected, let actual, _) = error else {
                return XCTFail("Expected invalidKeyLength, got \(error)")
            }
            XCTAssertEqual(expected, Identity.KEYSIZE_BYTES)
            XCTAssertEqual(actual, 32)
        }
    }

    func testRememberOverwritesAppDataInPlace() throws {
        let identity = Identity()
        let destinationHash = randomBytes(16)

        try Identity.remember(
            packetHash: randomBytes(16),
            destinationHash: destinationHash,
            publicKey: identity.publicKeys,
            appData: "first".data(using: .utf8)!
        )
        try Identity.remember(
            packetHash: randomBytes(16),
            destinationHash: destinationHash,
            publicKey: identity.publicKeys,
            appData: "second".data(using: .utf8)!
        )

        XCTAssertEqual(Identity.recallAppData(destinationHash), "second".data(using: .utf8)!,
                       "Re-remember refreshes app_data in place")
    }

    func testLocalDestinationRecallFallback() throws {
        let identity = Identity()
        let destinationHash = randomBytes(16)

        // Transport.destinations fallback path (Identity.py:151-159): recall by
        // local registration returns the identity with app_data == nil.
        Identity.registerLocalDestination(hash: destinationHash, publicKey: identity.publicKeys)
        defer { Identity.deregisterLocalDestination(destinationHash) }

        let recalled = try XCTUnwrap(Identity.recall(destinationHash))
        XCTAssertEqual(recalled.publicKeys, identity.publicKeys)
        XCTAssertNil(recalled.appData, "Local-fallback recall has nil app_data")

        Identity.deregisterLocalDestination(destinationHash)
        XCTAssertNil(Identity.recall(destinationHash), "Deregistered local destination no longer recalls")
    }

    // MARK: - announce app_data None-vs-empty distinction

    func testAnnounceAppDataNoneVsEmpty() {
        let raw = "present".data(using: .utf8)!
        XCTAssertEqual(Identity.announceAppData(rawAppData: raw, hasRatchet: false), raw)
        XCTAssertEqual(Identity.announceAppData(rawAppData: raw, hasRatchet: true), raw)
        XCTAssertEqual(Identity.announceAppData(rawAppData: nil, hasRatchet: true), Data(),
                       "No trailing field + ratchet present -> empty Data")
        XCTAssertNil(Identity.announceAppData(rawAppData: nil, hasRatchet: false),
                     "No trailing field + no ratchet -> nil")
    }

    // MARK: - Ratchet id helpers

    func testGetRatchetIdLengthAndConsistency() throws {
        let ratchetPriv = RatchetManager.generateRatchet()
        let ratchetPub = try RatchetManager.publicBytes(from: ratchetPriv)

        let id = Identity._getRatchetId(ratchetPub)
        XCTAssertEqual(id.count, Identity.NAME_HASH_LENGTH_BYTES, "Ratchet id is 10 bytes")
        XCTAssertEqual(id, Identity._getRatchetId(ratchetPub), "Ratchet id is deterministic")
        // Documented relation: _get_ratchet_id(pub) == full_hash(pub)[:10].
        XCTAssertEqual(id, Hashing.fullHash(ratchetPub).prefix(Identity.NAME_HASH_LENGTH_BYTES))
    }

    func testRatchetPublicBytesMatchesManager() throws {
        let ratchetPriv = RatchetManager.generateRatchet()
        let viaIdentity = try XCTUnwrap(Identity._ratchetPublicBytes(ratchetPriv))
        let viaManager = try RatchetManager.publicBytes(from: ratchetPriv)
        XCTAssertEqual(viaIdentity, viaManager)
    }

    func testRatchetPublicBytesNilForMalformedKey() {
        XCTAssertNil(Identity._ratchetPublicBytes(Data(repeating: 0, count: 16)),
                     "Malformed ratchet private key yields nil public bytes")
    }

    func testCurrentRatchetIdNilWhenUnknown() {
        // No storagePath / cache configured -> getRatchet returns nil -> id nil.
        XCTAssertNil(Identity.currentRatchetId(randomBytes(16)))
    }

    // MARK: - decrypt(...) ratchet-id-reporting overload

    func testDecryptReportsRatchetIdOnRatchetSuccess() throws {
        let identity = Identity()
        let ratchetPriv = RatchetManager.generateRatchet()
        let ratchetPub = try RatchetManager.publicBytes(from: ratchetPriv)
        let plaintext = "encrypted to a ratchet".data(using: .utf8)!

        let ciphertext = try Identity.encrypt(
            plaintext, toRatchetKey: ratchetPub, identityHash: identity.hash
        )

        let receiver = CapturingReceiver()
        let decrypted = identity.decrypt(
            ciphertext,
            identityHash: identity.hash,
            ratchets: [ratchetPriv],
            enforceRatchets: false,
            ratchetIdReceiver: receiver
        )
        XCTAssertEqual(decrypted, plaintext)
        XCTAssertEqual(receiver.latestRatchetId, Identity._getRatchetId(ratchetPub),
                       "Succeeding ratchet's id is reported to the receiver")
    }

    func testDecryptReportsNilIdOnStaticKeyFallback() throws {
        let identity = Identity()
        let plaintext = "encrypted to the base key".data(using: .utf8)!
        let ciphertext = try identity.encryptTo(plaintext, identityHash: identity.hash)

        let receiver = CapturingReceiver()
        receiver.latestRatchetId = Data([0xAA]) // ensure it gets cleared to nil
        let decrypted = identity.decrypt(
            ciphertext,
            identityHash: identity.hash,
            ratchets: nil,
            enforceRatchets: false,
            ratchetIdReceiver: receiver
        )
        XCTAssertEqual(decrypted, plaintext)
        XCTAssertNil(receiver.latestRatchetId, "Static-key decrypt reports nil ratchet id")
    }

    func testDecryptReturnsNilWhenEnforcedAndNoRatchetMatches() throws {
        let identity = Identity()
        let plaintext = "base-key message".data(using: .utf8)!
        let ciphertext = try identity.encryptTo(plaintext, identityHash: identity.hash)

        let nonMatching = RatchetManager.generateRatchet()
        let receiver = CapturingReceiver()
        let decrypted = identity.decrypt(
            ciphertext,
            identityHash: identity.hash,
            ratchets: [nonMatching],
            enforceRatchets: true,
            ratchetIdReceiver: receiver
        )
        XCTAssertNil(decrypted, "Enforcement rejects a non-ratcheted ciphertext")
        XCTAssertNil(receiver.latestRatchetId)
    }

    func testDecryptOverloadNilForPublicOnlyIdentity() throws {
        let publicOnly = try Identity(publicKeyBytes: Identity().publicKeys)
        let receiver = CapturingReceiver()
        let result = publicOnly.decrypt(
            randomBytes(100),
            identityHash: publicOnly.hash,
            ratchets: nil,
            enforceRatchets: false,
            ratchetIdReceiver: receiver
        )
        XCTAssertNil(result, "No private key -> nil (RNS surfaces nil for KeyError)")
    }
}
