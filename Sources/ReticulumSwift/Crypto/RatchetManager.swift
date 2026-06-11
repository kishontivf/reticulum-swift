// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  RatchetManager.swift
//  ReticulumSwift
//
//  Manages ratchet keypair lifecycle for forward secrecy.
//  Ratchets are ephemeral X25519 keypairs rotated periodically.
//  When a destination enables ratchets, its announces include the
//  current ratchet public key. Senders encrypt to the ratchet key
//  instead of the base identity key for forward secrecy.
//
//  Matches Python RNS Identity.py / Destination.py ratchet behavior.
//

import Foundation
import CryptoKit

/// Errors during ratchet operations
public enum RatchetError: Error, Sendable, Equatable {
    case persistenceFailed(String)
    case signatureInvalid
    case loadFailed(String)
    case noRatchetsAvailable
}

/// Actor managing ratchet keypair lifecycle per destination.
///
/// Generates, rotates, and persists ephemeral X25519 keypairs
/// for forward secrecy. Rotation happens before each announce
/// if the interval has elapsed.
///
/// Python reference:
/// - `Destination.enable_ratchets(path)` — load or create ratchet file
/// - `Destination.rotate_ratchets()` — generate new if interval elapsed
/// - Persistence: `msgpack({"signature": sign(packed), "ratchets": msgpack([prv1, prv2, ...])})`
public actor RatchetManager {

    // MARK: - Constants

    /// Maximum number of ratchet keys to retain
    public static let RATCHET_COUNT = 512

    /// Minimum interval between ratchet rotations (30 minutes)
    public static let RATCHET_INTERVAL: TimeInterval = 30 * 60

    /// Ratchet expiry time (30 days)
    public static let RATCHET_EXPIRY: TimeInterval = 60 * 60 * 24 * 30

    // MARK: - State

    /// Array of 32-byte X25519 private keys, newest first
    private var ratchets: [Data] = []

    /// Generation timestamp (epoch seconds) of each ratchet, parallel to
    /// `ratchets` (newest first). Used to enforce `RATCHET_EXPIRY` so stale
    /// private keys are dropped rather than retained indefinitely (forward
    /// secrecy). Persisted alongside the keys.
    private var ratchetTimes: [TimeInterval] = []

    /// Timestamp of most recent ratchet generation
    private var latestRatchetTime: TimeInterval = 0

    /// File path for persistent storage
    private let storagePath: String

    /// Identity used for signing persistence file
    private let identity: Identity

    // MARK: - Initialization

    /// Create a ratchet manager.
    ///
    /// - Parameters:
    ///   - storagePath: File path for persistent ratchet storage
    ///   - identity: Identity for signing the persistence file
    public init(storagePath: String, identity: Identity) {
        self.storagePath = storagePath
        self.identity = identity
    }

    // MARK: - Public API

    /// Load existing ratchets from disk, or generate initial ratchet.
    ///
    /// Call this once after creating the manager.
    public func loadOrCreate() throws {
        if FileManager.default.fileExists(atPath: storagePath) {
            do {
                let loaded = try load()
                self.ratchets = loaded.ratchets
                self.ratchetTimes = loaded.times
                self.latestRatchetTime = ratchetTimes.first ?? Date().timeIntervalSince1970
                // Drop any ratchets older than RATCHET_EXPIRY before use.
                expireOldRatchets()
            } catch {
                // Corrupted file — start fresh
                self.ratchets = []
                self.ratchetTimes = []
            }
        }

        if ratchets.isEmpty {
            let newKey = RatchetManager.generateRatchet()
            let now = Date().timeIntervalSince1970
            ratchets.insert(newKey, at: 0)
            ratchetTimes.insert(now, at: 0)
            latestRatchetTime = now
            try persist()
        }
    }

    /// Rotate ratchets if the interval has elapsed.
    ///
    /// Generates a new ratchet keypair, inserts at index 0, trims to
    /// RATCHET_COUNT, and persists to disk.
    ///
    /// - Returns: true if a new ratchet was generated
    @discardableResult
    public func rotateIfNeeded() -> Bool {
        let now = Date().timeIntervalSince1970
        guard now > latestRatchetTime + RatchetManager.RATCHET_INTERVAL else {
            return false
        }

        let newKey = RatchetManager.generateRatchet()
        ratchets.insert(newKey, at: 0)
        ratchetTimes.insert(now, at: 0)

        // Trim to max count (both arrays stay in lockstep)
        if ratchets.count > RatchetManager.RATCHET_COUNT {
            ratchets = Array(ratchets.prefix(RatchetManager.RATCHET_COUNT))
            ratchetTimes = Array(ratchetTimes.prefix(RatchetManager.RATCHET_COUNT))
        }

        // Drop ratchets past their expiry window.
        expireOldRatchets()

        latestRatchetTime = now

        do {
            try persist()
        } catch {
            // Log but don't fail — keys are in memory
        }

        return true
    }

    /// Remove ratchets older than `RATCHET_EXPIRY`, always retaining the newest.
    ///
    /// Retaining expired private keys weakens forward secrecy: a compromise of
    /// on-disk/in-memory state would expose keys far past their intended window.
    private func expireOldRatchets() {
        guard !ratchets.isEmpty else { return }
        let cutoff = Date().timeIntervalSince1970 - RatchetManager.RATCHET_EXPIRY
        var keptRatchets: [Data] = []
        var keptTimes: [TimeInterval] = []
        for (index, time) in ratchetTimes.enumerated() where index < ratchets.count {
            // Always keep the newest ratchet even if the clock looks skewed.
            if index == 0 || time >= cutoff {
                keptRatchets.append(ratchets[index])
                keptTimes.append(time)
            }
        }
        if keptRatchets.count != ratchets.count {
            ratchets = keptRatchets
            ratchetTimes = keptTimes
        }
    }

    /// Get the public key bytes of the current (newest) ratchet.
    ///
    /// - Returns: 32-byte X25519 public key, or nil if no ratchets
    public func currentRatchetPublicBytes() -> Data? {
        guard let newestPrivate = ratchets.first else { return nil }
        return try? RatchetManager.publicBytes(from: newestPrivate)
    }

    /// Get all ratchet private keys for decrypt fallback.
    ///
    /// Returns the full list of retained private keys. The decrypt
    /// path tries each one in order (newest first) until one succeeds.
    ///
    /// - Returns: Array of 32-byte X25519 private keys
    public func allRatchetPrivateKeys() -> [Data] {
        return ratchets
    }

    /// Compute a ratchet ID (truncated hash of current public key).
    ///
    /// Used for quick ratchet identification without exposing the full key.
    ///
    /// - Returns: First 10 bytes of SHA-256(currentRatchetPublicBytes), or nil
    public func ratchetId() -> Data? {
        guard let pubBytes = currentRatchetPublicBytes() else { return nil }
        let hash = SHA256.hash(data: pubBytes)
        return Data(hash.prefix(10))
    }

    /// Number of retained ratchets (for testing).
    public func count() -> Int {
        return ratchets.count
    }

    /// Force set the latest ratchet time (for testing rotation interval).
    public func _setLatestRatchetTime(_ time: TimeInterval) {
        self.latestRatchetTime = time
    }

    // MARK: - Key Generation

    /// Generate a new X25519 private key for ratcheting.
    ///
    /// - Returns: 32-byte raw private key representation
    public static func generateRatchet() -> Data {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        return privateKey.rawRepresentation
    }

    /// Derive public key bytes from a private key.
    ///
    /// - Parameter privateKey: 32-byte X25519 private key
    /// - Returns: 32-byte X25519 public key
    public static func publicBytes(from privateKey: Data) throws -> Data {
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        return key.publicKey.rawRepresentation
    }

    // MARK: - Persistence

    /// Persist ratchets to disk in signed msgpack format.
    ///
    /// Format matches Python:
    /// ```
    /// msgpack({"signature": sign(ratchetsPacked), "ratchets": msgpack([prv1, prv2, ...])})
    /// ```
    private func persist() throws {
        // Pack ratchets as msgpack array of binary values
        let ratchetValues = ratchets.map { MessagePackValue.binary($0) }
        let ratchetsPacked = packMsgPack(.array(ratchetValues))

        // Sign the packed ratchets
        let signature: Data
        do {
            signature = try identity.sign(ratchetsPacked)
        } catch {
            throw RatchetError.persistenceFailed("Signing failed: \(error)")
        }

        // Pack outer container. "ratchet_times" is an additive, unsigned field
        // (Python RNS ignores unknown keys, preserving interop); it only governs
        // local expiry timing, so it is not part of the signed key material.
        let timesValue = MessagePackValue.array(ratchetTimes.map { MessagePackValue.double($0) })
        let container: MessagePackValue = .map([
            .string("signature"): .binary(signature),
            .string("ratchets"): .binary(ratchetsPacked),
            .string("ratchet_times"): timesValue
        ])
        let packed = packMsgPack(container)

        // Write atomically
        do {
            try packed.write(to: URL(fileURLWithPath: storagePath), options: .atomic)
        } catch {
            throw RatchetError.persistenceFailed("Write failed: \(error)")
        }
    }

    /// Load ratchets from disk, verifying the signature.
    ///
    /// - Returns: The 32-byte private keys (newest first) and their parallel
    ///   generation timestamps. Timestamps are synthesized conservatively when
    ///   absent (e.g. a file written by Python RNS or an older build).
    private func load() throws -> (ratchets: [Data], times: [TimeInterval]) {
        let fileData: Data
        do {
            fileData = try Data(contentsOf: URL(fileURLWithPath: storagePath))
        } catch {
            throw RatchetError.loadFailed("Read failed: \(error)")
        }

        // Unpack outer container
        guard let container = try? unpackMsgPack(fileData),
              case .map(let dict) = container,
              case .binary(let signature)? = dict[.string("signature")],
              case .binary(let ratchetsPacked)? = dict[.string("ratchets")] else {
            throw RatchetError.loadFailed("Invalid format")
        }

        // Verify signature
        let isValid = identity.verify(signature: signature, for: ratchetsPacked)
        guard isValid else {
            throw RatchetError.signatureInvalid
        }

        // Unpack ratchets array
        guard let ratchetsValue = try? unpackMsgPack(ratchetsPacked),
              case .array(let ratchetArray) = ratchetsValue else {
            throw RatchetError.loadFailed("Invalid ratchets format")
        }

        let ratchets = ratchetArray.compactMap { value -> Data? in
            guard case .binary(let keyData) = value, keyData.count == 32 else { return nil }
            return keyData
        }

        // Parse parallel timestamps if present and consistent; otherwise
        // synthesize newest-first, spaced by the rotation interval. Synthesized
        // ages stay within RATCHET_EXPIRY for the retained count, so nothing is
        // wrongly expired on first load of a legacy/Python file.
        var times: [TimeInterval] = []
        if case .array(let timeArray)? = dict[.string("ratchet_times")],
           timeArray.count == ratchets.count {
            for value in timeArray {
                switch value {
                case .double(let d): times.append(d)
                case .float(let f): times.append(TimeInterval(f))
                case .uint(let u): times.append(TimeInterval(u))
                case .int(let i): times.append(TimeInterval(i))
                default: times.append(0)
                }
            }
        }
        if times.count != ratchets.count {
            let now = Date().timeIntervalSince1970
            times = ratchets.indices.map { now - Double($0) * RatchetManager.RATCHET_INTERVAL }
        }

        return (ratchets, times)
    }
}
