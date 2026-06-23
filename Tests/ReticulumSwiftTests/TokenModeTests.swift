// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  TokenModeTests.swift
//  ReticulumSwift
//
//  Tests for Token AES mode selection by derived-key length:
//  32-byte key -> AES-128 (signing=key[:16], enc=key[16:32]),
//  64-byte key -> AES-256 (signing=key[:32], enc=key[32:64]),
//  any other length is rejected. Drives the real Token init/encrypt/decrypt.
//

import XCTest
@testable import ReticulumSwift

final class TokenModeTests: XCTestCase {

    // MARK: - Helpers

    /// Deterministic byte buffer of a given length (private to avoid
    /// collisions when integrated alongside sibling test files).
    private func bytes(_ count: Int) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 1) })
    }

    // MARK: - 32-byte key -> AES-128 mode

    func testInit32ByteKeySelectsAES128KeySplit() throws {
        let key = bytes(32)
        let token = try Token(derivedKey: key)

        // AES-128 mode: signing = key[:16], encryption = key[16:32].
        XCTAssertEqual(token.signingKey.count, 16, "32-byte key -> 16-byte signing key (AES-128)")
        XCTAssertEqual(token.encryptionKey.count, 16, "32-byte key -> 16-byte enc key (AES-128)")
        XCTAssertEqual(token.signingKey, Data(key.prefix(16)))
        XCTAssertEqual(token.encryptionKey, Data(key.dropFirst(16).prefix(16)))
    }

    func testAES128RoundTripWithRandomIV() throws {
        let token = try Token(derivedKey: bytes(32))
        let plaintext = "AES-128 round trip payload".data(using: .utf8)!

        let sealed = try token.encrypt(plaintext)
        // Format is [IV 16B][ciphertext][HMAC 32B]; ciphertext is non-empty.
        XCTAssertGreaterThanOrEqual(sealed.count, 64)
        XCTAssertNotEqual(sealed, plaintext)

        let recovered = try token.decrypt(sealed)
        XCTAssertEqual(recovered, plaintext, "AES-128 encrypt->decrypt must round-trip")
    }

    func testAES128RoundTripWithExplicitIV() throws {
        let token = try Token(derivedKey: bytes(32))
        let plaintext = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let iv = bytes(16)

        let sealed = try token.encrypt(plaintext, iv: iv)
        // First 16 bytes of the token are exactly the IV we supplied.
        XCTAssertEqual(Data(sealed.prefix(16)), iv)

        let recovered = try token.decrypt(sealed)
        XCTAssertEqual(recovered, plaintext)
    }

    // MARK: - 64-byte key -> AES-256 mode

    func testInit64ByteKeySelectsAES256KeySplit() throws {
        let key = bytes(64)
        let token = try Token(derivedKey: key)

        // AES-256 mode: signing = key[:32], encryption = key[32:64].
        XCTAssertEqual(token.signingKey.count, 32, "64-byte key -> 32-byte signing key (AES-256)")
        XCTAssertEqual(token.encryptionKey.count, 32, "64-byte key -> 32-byte enc key (AES-256)")
        XCTAssertEqual(token.signingKey, Data(key.prefix(32)))
        XCTAssertEqual(token.encryptionKey, Data(key.dropFirst(32).prefix(32)))
    }

    func testAES256RoundTripWithRandomIV() throws {
        let token = try Token(derivedKey: bytes(64))
        let plaintext = "AES-256 round trip payload, a bit longer".data(using: .utf8)!

        let sealed = try token.encrypt(plaintext)
        XCTAssertNotEqual(sealed, plaintext)

        let recovered = try token.decrypt(sealed)
        XCTAssertEqual(recovered, plaintext, "AES-256 encrypt->decrypt must round-trip")
    }

    // MARK: - Invalid key lengths are rejected

    func testInit16ByteKeyThrowsInvalidKeyLength() {
        XCTAssertThrowsError(try Token(derivedKey: bytes(16))) { error in
            XCTAssertEqual(error as? TokenError, .invalidKeyLength)
        }
    }

    func testInit48ByteKeyThrowsInvalidKeyLength() {
        XCTAssertThrowsError(try Token(derivedKey: bytes(48))) { error in
            XCTAssertEqual(error as? TokenError, .invalidKeyLength)
        }
    }

    func testInitEmptyKeyThrowsInvalidKeyLength() {
        XCTAssertThrowsError(try Token(derivedKey: Data())) { error in
            XCTAssertEqual(error as? TokenError, .invalidKeyLength)
        }
    }

    // MARK: - Mode isolation

    /// A ciphertext produced by a 32-byte-key (AES-128) Token must NOT decrypt
    /// under a 64-byte-key (AES-256) Token. The differing signing-key split
    /// makes HMAC verification fail before any AES work, which is the exact
    /// behavior that would regress if the length-based mode split were reverted.
    func testAES128CiphertextDoesNotDecryptUnderAES256Token() throws {
        let token128 = try Token(derivedKey: bytes(32))
        let token256 = try Token(derivedKey: bytes(64))

        let plaintext = "mode isolation".data(using: .utf8)!
        let sealed = try token128.encrypt(plaintext)

        // Sanity: it decrypts fine under its own (AES-128) token.
        XCTAssertEqual(try token128.decrypt(sealed), plaintext)

        // Cross-mode decryption is rejected (different signing key -> HMAC fail).
        XCTAssertThrowsError(try token256.decrypt(sealed)) { error in
            XCTAssertEqual(error as? TokenError, .hmacVerificationFailed)
        }
    }

    /// Symmetric direction: an AES-256 ciphertext must not decrypt under an
    /// AES-128 Token either.
    func testAES256CiphertextDoesNotDecryptUnderAES128Token() throws {
        let token128 = try Token(derivedKey: bytes(32))
        let token256 = try Token(derivedKey: bytes(64))

        let plaintext = "reverse isolation".data(using: .utf8)!
        let sealed = try token256.encrypt(plaintext)

        XCTAssertEqual(try token256.decrypt(sealed), plaintext)

        XCTAssertThrowsError(try token128.decrypt(sealed)) { error in
            XCTAssertEqual(error as? TokenError, .hmacVerificationFailed)
        }
    }
}
