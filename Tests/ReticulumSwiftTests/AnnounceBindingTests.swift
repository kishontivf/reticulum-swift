// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  AnnounceBindingTests.swift
//  ReticulumSwiftTests
//
//  Tests the announce destination-hash binding (AnnounceValidator.validateDestinationBinding).
//  A valid signature only proves ownership of the keys in the payload; the binding proves
//  those keys belong to the announced destination hash. Without it, any signature-valid
//  announce can hijack an arbitrary destination's path + cached key.
//

import XCTest
@testable import ReticulumSwift

final class AnnounceBindingTests: XCTestCase {

    /// Build the correctly-bound destination hash for a set of public keys + name hash,
    /// exactly as RNS does: truncated_hash(name_hash || truncated_hash(public_keys)).
    private func boundDestinationHash(publicKeys: Data, nameHash: Data) -> Data {
        let identityHash = Hashing.truncatedHash(publicKeys)
        var material = nameHash
        material.append(identityHash)
        return Hashing.truncatedHash(material)
    }

    private func makeParsed(publicKeys: Data?, nameHash: Data, destinationHash: Data) -> ParsedAnnounce {
        ParsedAnnounce(
            publicKeys: publicKeys,
            nameHash: nameHash,
            randomHash: Data(repeating: 0x01, count: 10),
            ratchet: nil,
            signature: publicKeys == nil ? nil : Data(repeating: 0x02, count: 64),
            appData: nil,
            destinationHash: destinationHash
        )
    }

    func testCorrectlyBoundAnnouncePasses() throws {
        let keys = Data(repeating: 0xAB, count: 64)
        let nameHash = Data(repeating: 0xCD, count: 10)
        let destHash = boundDestinationHash(publicKeys: keys, nameHash: nameHash)

        let parsed = makeParsed(publicKeys: keys, nameHash: nameHash, destinationHash: destHash)
        // Must not throw: the keys genuinely hash to this destination.
        XCTAssertNoThrow(try AnnounceValidator.validateDestinationBinding(parsed: parsed))
    }

    func testSpoofedAnnounceRejected() {
        // Attacker uses their OWN keys but claims a victim's destination hash.
        let attackerKeys = Data(repeating: 0x11, count: 64)
        let nameHash = Data(repeating: 0xCD, count: 10)
        let victimDestHash = Data(repeating: 0xEE, count: 16) // not derived from attackerKeys

        let parsed = makeParsed(publicKeys: attackerKeys, nameHash: nameHash, destinationHash: victimDestHash)

        XCTAssertThrowsError(try AnnounceValidator.validateDestinationBinding(parsed: parsed)) { error in
            guard case AnnounceValidationError.hashMismatch = error else {
                return XCTFail("Expected .hashMismatch, got \(error)")
            }
        }
    }

    func testWrongNameHashRejected() {
        // Correct keys, but a different name hash than the one the destination was built from.
        let keys = Data(repeating: 0xAB, count: 64)
        let realNameHash = Data(repeating: 0xCD, count: 10)
        let destHash = boundDestinationHash(publicKeys: keys, nameHash: realNameHash)

        let parsed = makeParsed(
            publicKeys: keys,
            nameHash: Data(repeating: 0x99, count: 10), // wrong name hash
            destinationHash: destHash
        )
        XCTAssertThrowsError(try AnnounceValidator.validateDestinationBinding(parsed: parsed))
    }

    func testPlainAnnounceSkipsBinding() throws {
        // PLAIN announces carry no keys — nothing to bind, must not throw.
        let parsed = makeParsed(
            publicKeys: nil,
            nameHash: Data(repeating: 0xCD, count: 10),
            destinationHash: Data(repeating: 0xEE, count: 16)
        )
        XCTAssertNoThrow(try AnnounceValidator.validateDestinationBinding(parsed: parsed))
    }
}
