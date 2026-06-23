// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  RatchetAndConfigTests.swift
//  ReticulumSwift
//
//  Coverage for RatchetManager rotation/id/persistence accessors NOT exercised
//  by RatchetTests, the Interface MTU/bitrate/IFAC pure helpers (optimise_mtu,
//  effective bitrate floor, derive HW MTU, ifac_size bit->byte) plus the
//  InterfaceConfig + TCPInterface fixed/autoconfigure MTU invariants, and the
//  Destination ratchet-config surface (enable/enforce/interval/retained/rotate/
//  encrypt/decrypt). Every test drives REAL production code and asserts its real
//  observable behavior.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

final class RatchetAndConfigTests: XCTestCase {

    // MARK: - Private helpers (no top-level collisions)

    /// A unique temp path for ratchet storage. Caller is responsible for cleanup.
    private func tempPath(_ tag: String) -> String {
        NSTemporaryDirectory() + "rc_\(tag)_\(UUID().uuidString)"
    }

    private func makeManager(_ tag: String) -> (RatchetManager, String, Identity) {
        let identity = Identity()
        let path = tempPath(tag)
        return (RatchetManager(storagePath: path, identity: identity), path, identity)
    }

    private func tcpConfig(
        bitrate: Int = 0,
        fixedMtu: Int? = nil,
        autoconfigureMtu: Bool = true,
        type: InterfaceType = .tcp
    ) -> InterfaceConfig {
        InterfaceConfig(
            id: "cfg-\(UUID().uuidString)",
            name: "Test",
            type: type,
            enabled: true,
            mode: .full,
            host: "127.0.0.1",
            port: 4242,
            bitrate: bitrate,
            fixedMtu: fixedMtu,
            autoconfigureMtu: autoconfigureMtu
        )
    }

    // MARK: - RatchetManager: empty-state accessors (pre loadOrCreate)

    func testEmptyManagerAccessorsReturnNilAndZero() async throws {
        let (manager, path, _) = makeManager("empty")
        defer { try? FileManager.default.removeItem(atPath: path) }

        let count = await manager.count()
        XCTAssertEqual(count, 0, "Fresh manager holds no ratchets before loadOrCreate")
        let latest = await manager.latestTime()
        XCTAssertEqual(latest, 0, "latestTime is 0 until the first ratchet is created")
        let current = await manager.currentRatchetPublicBytes()
        XCTAssertNil(current, "No current ratchet public key when empty")
        let prev = await manager.previousRatchetPublicBytes()
        XCTAssertNil(prev, "No previous ratchet public key when empty")
        let id = await manager.ratchetId()
        XCTAssertNil(id, "No ratchet id when empty")
    }

    // MARK: - RatchetManager: ratchetId

    func testRatchetIdIsTenByteSha256OfCurrentPublic() async throws {
        let (manager, path, _) = makeManager("rid")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await manager.loadOrCreate()

        let idOpt = await manager.ratchetId()
        let id = try XCTUnwrap(idOpt)
        XCTAssertEqual(id.count, 10, "Ratchet id is the 10-byte SHA-256 prefix")

        let pubOpt = await manager.currentRatchetPublicBytes()
        let pub = try XCTUnwrap(pubOpt)
        let expected = Data(SHA256.hash(data: pub).prefix(10))
        XCTAssertEqual(id, expected, "ratchetId() == SHA256(currentPublic)[:10]")

        // Deterministic for an unchanged current ratchet.
        let again = await manager.ratchetId()
        XCTAssertEqual(id, again)
    }

    // MARK: - RatchetManager: latestTime / loadOrCreate

    func testLatestTimeSetAfterLoadOrCreate() async throws {
        let (manager, path, _) = makeManager("ltime")
        defer { try? FileManager.default.removeItem(atPath: path) }

        let before = Date().timeIntervalSince1970
        try await manager.loadOrCreate()
        let latest = await manager.latestTime()
        XCTAssertGreaterThanOrEqual(latest, before,
            "latestTime is stamped at/after creation time")
        let count = await manager.count()
        XCTAssertEqual(count, 1, "loadOrCreate seeds exactly one ratchet")
    }

    // MARK: - RatchetManager: rotate(interval:retained:)

    func testRotateRespectsIntervalGateClosed() async throws {
        let (manager, path, _) = makeManager("rot_closed")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await manager.loadOrCreate()

        // latestTime is ~now; a long interval keeps the gate closed.
        let rotated = await manager.rotate(interval: 10_000, retained: 512)
        XCTAssertFalse(rotated, "rotate must not fire before interval elapses")
        let count = await manager.count()
        XCTAssertEqual(count, 1, "No new ratchet inserted when gate is closed")
    }

    func testRotateHonorsPerDestinationInterval() async throws {
        let (manager, path, _) = makeManager("rot_open")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await manager.loadOrCreate()

        let firstPubOpt = await manager.currentRatchetPublicBytes()
        let firstPub = try XCTUnwrap(firstPubOpt)

        // Push latest 2s into the past so a 1s per-destination interval opens the
        // gate even though the static 30-minute RATCHET_INTERVAL would not.
        await manager._setLatestRatchetTime(Date().timeIntervalSince1970 - 2)
        let rotated = await manager.rotate(interval: 1.0, retained: 512)
        XCTAssertTrue(rotated, "rotate fires once now > latestTime + interval")

        let count = await manager.count()
        XCTAssertEqual(count, 2, "Rotation inserts a new newest ratchet")

        // The prior current becomes the previous (RNS rotate_ratchets).
        let prev = await manager.previousRatchetPublicBytes()
        XCTAssertEqual(prev, firstPub, "Prior current ratchet is now the previous one")
        let newPub = await manager.currentRatchetPublicBytes()
        XCTAssertNotEqual(newPub, firstPub, "New current ratchet differs from the old")
    }

    func testPreviousRatchetNilWithSingleRatchet() async throws {
        let (manager, path, _) = makeManager("prev_single")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await manager.loadOrCreate()

        let prev = await manager.previousRatchetPublicBytes()
        XCTAssertNil(prev, "No previous ratchet exists with only one retained key")
    }

    // MARK: - RatchetManager: cleanRatchets (RNS truncation quirk)

    func testCleanRatchetsTruncatesToRatchetCountQuirk() async throws {
        let (manager, path, _) = makeManager("clean_quirk")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await manager.loadOrCreate()

        // Inflate past the retained cap, then clean: the gate compares against
        // `retained` but truncation is to the static RATCHET_COUNT (512).
        await manager._padRatchets(to: 600)
        let padded = await manager.count()
        XCTAssertEqual(padded, 600)

        await manager.cleanRatchets(retained: 10)
        let cleaned = await manager.count()
        XCTAssertEqual(cleaned, RatchetManager.RATCHET_COUNT,
            "cleanRatchets truncates to RATCHET_COUNT (512), not the retained cap")
    }

    func testCleanRatchetsNoOpUnderRetainedCap() async throws {
        let (manager, path, _) = makeManager("clean_noop")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await manager.loadOrCreate()

        await manager._padRatchets(to: 100)
        await manager.cleanRatchets(retained: 512)
        let count = await manager.count()
        XCTAssertEqual(count, 100, "No truncation while count <= retained cap")
    }

    func testPadRatchetsGrowsThenIsNoOp() async throws {
        let (manager, path, _) = makeManager("pad")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await manager.loadOrCreate()

        await manager._padRatchets(to: 5)
        let grown = await manager.count()
        XCTAssertEqual(grown, 5, "_padRatchets grows the list to the target")

        await manager._padRatchets(to: 3)
        let still = await manager.count()
        XCTAssertEqual(still, 5, "_padRatchets is a no-op when already at/above target")
    }

    // MARK: - RatchetManager: public persist / reload

    func testPersistAndReloadRoundTrip() async throws {
        let (manager, path, _) = makeManager("persist_rt")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await manager.loadOrCreate()

        // Grow to two keys via a forced rotation, then persist + reload.
        await manager._setLatestRatchetTime(0)
        let rotated = await manager.rotateIfNeeded()
        XCTAssertTrue(rotated)
        let before = await manager.allRatchetPrivateKeys()
        XCTAssertEqual(before.count, 2)

        try await manager.persistRatchets()
        let loadedCount = try await manager.reloadRatchets()
        XCTAssertEqual(loadedCount, 2, "reloadRatchets returns the persisted key count")

        let after = await manager.allRatchetPrivateKeys()
        XCTAssertEqual(before, after, "Reloaded keys match the persisted keys byte-for-byte")
    }

    func testReloadThrowsOnMissingFile() async throws {
        // Path that was never written.
        let (manager, path, _) = makeManager("reload_missing")
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))

        do {
            _ = try await manager.reloadRatchets()
            XCTFail("reloadRatchets should throw when the store is absent")
        } catch let error as RatchetError {
            guard case .loadFailed = error else {
                return XCTFail("Expected .loadFailed, got \(error)")
            }
        }
    }

    func testReloadThrowsOnCorruptFile() async throws {
        let (manager, path, _) = makeManager("reload_corrupt")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await manager.loadOrCreate()
        try await manager.persistRatchets()

        // Overwrite the signed store with non-msgpack garbage.
        try Data([0xFF, 0xFE, 0xFD, 0xFC]).write(to: URL(fileURLWithPath: path))

        do {
            _ = try await manager.reloadRatchets()
            XCTFail("reloadRatchets should throw on a malformed store")
        } catch is RatchetError {
            // expected
        }
    }

    func testReloadRejectsTamperedSignature() async throws {
        let identity = Identity()
        let path = tempPath("reload_tamper")
        defer { try? FileManager.default.removeItem(atPath: path) }

        let writer = RatchetManager(storagePath: path, identity: identity)
        try await writer.loadOrCreate()
        try await writer.persistRatchets()

        // A DIFFERENT identity cannot verify the signature over the same blob.
        let imposter = RatchetManager(storagePath: path, identity: Identity())
        do {
            _ = try await imposter.reloadRatchets()
            XCTFail("Signature check must reject a foreign-identity reload")
        } catch let error as RatchetError {
            // Wrong-signer either fails the signature check or the format parse;
            // both surface as RatchetError.
            XCTAssertTrue(error == .signatureInvalid || {
                if case .loadFailed = error { return true } else { return false }
            }(), "Expected a signature/format failure, got \(error)")
        }
    }

    // MARK: - Interface.optimiseMtu tier table

    func testOptimiseMtuTierTable() {
        // RNS-standard 10 Mbps TCP link lands on 8192 (not > 10M, but > 5M).
        XCTAssertEqual(Interface.optimiseMtu(bitrate: 10_000_000), 8192)
        // Just above 10 Mbps crosses into the next tier.
        XCTAssertEqual(Interface.optimiseMtu(bitrate: 10_000_001), 16384)
        // Exactly 5 Mbps is NOT > 5M, so it falls to the 4096 tier.
        XCTAssertEqual(Interface.optimiseMtu(bitrate: 5_000_000), 4096)
        XCTAssertEqual(Interface.optimiseMtu(bitrate: 5_000_001), 8192)
        // Top tier uses >= (1 Gbps -> 524288).
        XCTAssertEqual(Interface.optimiseMtu(bitrate: 1_000_000_000), 524288)
        XCTAssertEqual(Interface.optimiseMtu(bitrate: 999_999_999), 262144)
        XCTAssertEqual(Interface.optimiseMtu(bitrate: 750_000_000), 131072)
        // Bottom boundary: 62_500 is not > 62_500 -> nil; 62_501 -> 1024.
        XCTAssertNil(Interface.optimiseMtu(bitrate: 62_500))
        XCTAssertEqual(Interface.optimiseMtu(bitrate: 62_501), 1024)
        XCTAssertNil(Interface.optimiseMtu(bitrate: 0))
    }

    // MARK: - Interface.effectiveBitrate floor

    func testEffectiveBitrateFloor() {
        let guess = Interface.tcpBitrateGuess
        // 0 (unset sentinel) and sub-minimum keep the guess.
        XCTAssertEqual(Interface.effectiveBitrate(configured: 0, guess: guess), guess)
        XCTAssertEqual(
            Interface.effectiveBitrate(configured: Interface.MINIMUM_BITRATE - 1, guess: guess),
            guess)
        // At/above MINIMUM_BITRATE the configured value is honored.
        XCTAssertEqual(
            Interface.effectiveBitrate(configured: Interface.MINIMUM_BITRATE, guess: guess),
            Interface.MINIMUM_BITRATE)
        XCTAssertEqual(Interface.effectiveBitrate(configured: 50_000_000, guess: guess), 50_000_000)
    }

    // MARK: - Interface.deriveHwMtu

    func testDeriveHwMtuFixedWins() {
        let mtu = Interface.deriveHwMtu(
            fixedMtu: 1000,
            autoconfigureMtu: true,            // ignored when fixedMtu is set
            bitrate: 1_000_000_000,            // ignored
            bitrateGuess: Interface.tcpBitrateGuess,
            classHwMtu: Interface.tcpClassHwMtu)
        XCTAssertEqual(mtu, 1000, "A configured fixed_mtu wins outright")
    }

    func testDeriveHwMtuAutoconfiguredTcpIs8192() {
        // The headline RNS-standard value: a default autoconfigured 10 Mbps TCP
        // link negotiates 8192, NOT the 262144 class ceiling.
        let mtu = Interface.deriveHwMtu(
            fixedMtu: nil,
            autoconfigureMtu: true,
            bitrate: 0,                        // unset -> guess (10 Mbps)
            bitrateGuess: Interface.tcpBitrateGuess,
            classHwMtu: Interface.tcpClassHwMtu)
        XCTAssertEqual(mtu, 8192)
    }

    func testDeriveHwMtuAutoconfigureLowBitrateFallsToBaselineMtu() {
        // effectiveBitrate honors configured 5 (>= MINIMUM_BITRATE); optimiseMtu(5)
        // is nil, so deriveHwMtu surfaces the baseline Reticulum.MTU (500).
        let mtu = Interface.deriveHwMtu(
            fixedMtu: nil,
            autoconfigureMtu: true,
            bitrate: Interface.MINIMUM_BITRATE,
            bitrateGuess: Interface.tcpBitrateGuess,
            classHwMtu: Interface.tcpClassHwMtu)
        XCTAssertEqual(mtu, MTU, "nil optimise_mtu result surfaces as Reticulum.MTU (500)")
        XCTAssertEqual(mtu, 500)
    }

    func testDeriveHwMtuNoAutoconfigureKeepsClassCeiling() {
        let mtu = Interface.deriveHwMtu(
            fixedMtu: nil,
            autoconfigureMtu: false,
            bitrate: 0,
            bitrateGuess: Interface.tcpBitrateGuess,
            classHwMtu: Interface.tcpClassHwMtu)
        XCTAssertEqual(mtu, Interface.tcpClassHwMtu, "Without autoconfigure the class ceiling is kept")
        XCTAssertEqual(mtu, 262144)
    }

    // MARK: - Interface.resolveIfacSize bit->byte

    func testResolveIfacSizeBitToByte() {
        // Unset -> DEFAULT_IFAC_SIZE.
        XCTAssertEqual(Interface.resolveIfacSize(bits: nil), TransportConstants.DEFAULT_IFAC_SIZE)
        // >= IFAC_MIN_SIZE*8 (== 8) divides by 8.
        XCTAssertEqual(Interface.resolveIfacSize(bits: 8), 1)
        XCTAssertEqual(Interface.resolveIfacSize(bits: 16), 2)
        XCTAssertEqual(Interface.resolveIfacSize(bits: 128), 16)
        // Sub-minimum falls back to the default, never passing through 0.
        XCTAssertEqual(Interface.resolveIfacSize(bits: 7), TransportConstants.DEFAULT_IFAC_SIZE)
        XCTAssertEqual(Interface.resolveIfacSize(bits: 0), TransportConstants.DEFAULT_IFAC_SIZE)
    }

    // MARK: - Interface base-class constants

    func testInterfaceBaseConstants() {
        XCTAssertFalse(Interface.AUTOCONFIGURE_MTU_DEFAULT, "Base AUTOCONFIGURE_MTU default is false")
        XCTAssertFalse(Interface.FIXED_MTU_DEFAULT, "Base FIXED_MTU default is false")
        XCTAssertEqual(Interface.tcpClassHwMtu, 262144)
        XCTAssertEqual(Interface.tcpBitrateGuess, 10_000_000)
        XCTAssertEqual(Interface.MINIMUM_BITRATE, 5)
    }

    // MARK: - InterfaceConfig fixed/autoconfigure MTU invariant

    func testConfigFixedMtuForcesAutoconfigureFalse() {
        let config = tcpConfig(fixedMtu: 8192, autoconfigureMtu: true)
        XCTAssertEqual(config.fixedMtu, 8192)
        XCTAssertFalse(config.autoconfigureMtu,
            "A configured fixed_mtu forces AUTOCONFIGURE_MTU false regardless of the request")
    }

    func testConfigDefaultsAutoconfigureTrueNoFixed() {
        let config = tcpConfig()
        XCTAssertNil(config.fixedMtu)
        XCTAssertTrue(config.autoconfigureMtu, "TCP default AUTOCONFIGURE_MTU is true")
    }

    func testConfigAutoconfigureFalseRespectedWithoutFixed() {
        let config = tcpConfig(autoconfigureMtu: false)
        XCTAssertNil(config.fixedMtu)
        XCTAssertFalse(config.autoconfigureMtu, "Explicit autoconfigure=false is kept when no fixed_mtu")
    }

    func testConfigMtuFieldsPropertyListRoundTrip() throws {
        let config = tcpConfig(bitrate: 50_000_000, fixedMtu: 4096)
        let data = try PropertyListEncoder().encode(config)
        let decoded = try PropertyListDecoder().decode(InterfaceConfig.self, from: data)
        XCTAssertEqual(decoded, config)
        XCTAssertEqual(decoded.fixedMtu, 4096)
        XCTAssertFalse(decoded.autoconfigureMtu, "Decoded fixed_mtu re-applies the invariant")
        XCTAssertEqual(decoded.bitrate, 50_000_000)
    }

    func testConfigDecodeLegacyPlistDefaultsMtuFields() throws {
        // An old plist predating the MTU keys: decodeIfPresent must default
        // fixedMtu=nil / autoconfigureMtu=true (the TCP class default).
        let legacy: [String: Any] = [
            "id": "legacy1",
            "name": "Legacy",
            "type": "tcp",
            "enabled": true,
            "mode": "full",
            "host": "10.0.0.1",
            "port": 4242,
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: legacy, format: .xml, options: 0)
        let decoded = try PropertyListDecoder().decode(InterfaceConfig.self, from: data)
        XCTAssertNil(decoded.fixedMtu, "Legacy plist has no fixed_mtu")
        XCTAssertTrue(decoded.autoconfigureMtu, "Legacy plist defaults autoconfigure to true")
        XCTAssertEqual(decoded.bitrate, 0, "Legacy plist defaults bitrate to 0")
        XCTAssertEqual(decoded.announceRateGrace, 0)
    }

    // MARK: - TCPInterface MTU posture

    func testTCPInterfaceDefaultHwMtuIs8192() async throws {
        let iface = try TCPInterface(config: tcpConfig())
        let hwMtu = await iface.hwMtu
        XCTAssertEqual(hwMtu, 8192, "Default autoconfigured TCP link negotiates 8192")
        let classHwMtu = await iface.classHwMtu
        XCTAssertEqual(classHwMtu, 262144, "classHwMtu exposes the pre-autoconfigure ceiling")
        let autoconfigure = await iface.autoconfigureMtu
        XCTAssertTrue(autoconfigure)
        let fixed = await iface.fixedMtu
        XCTAssertNil(fixed)
    }

    func testTCPInterfaceFixedMtuBecomesHwMtu() async throws {
        let iface = try TCPInterface(config: tcpConfig(fixedMtu: 4096))
        let hwMtu = await iface.hwMtu
        XCTAssertEqual(hwMtu, 4096, "A configured fixed_mtu becomes the live HW MTU")
        let autoconfigure = await iface.autoconfigureMtu
        XCTAssertFalse(autoconfigure)
        let fixed = await iface.fixedMtu
        XCTAssertEqual(fixed, 4096)
    }

    func testTCPInterfaceBitrateAutoconfiguresHwMtu() async throws {
        // 50 Mbps -> optimise_mtu -> 16384 (it is > 10M).
        let iface = try TCPInterface(config: tcpConfig(bitrate: 50_000_000))
        let hwMtu = await iface.hwMtu
        XCTAssertEqual(hwMtu, 16384)
    }

    func testTCPInterfaceRejectsTooSmallFixedMtu() {
        // fixed_mtu below Reticulum.MTU (500) is rejected at construction.
        XCTAssertThrowsError(try TCPInterface(config: tcpConfig(fixedMtu: 100))) { error in
            guard case InterfaceError.invalidConfig = error else {
                return XCTFail("Expected invalidConfig for sub-MTU fixed_mtu, got \(error)")
            }
        }
    }

    func testTCPInterfaceRejectsWrongConfigType() {
        XCTAssertThrowsError(try TCPInterface(config: tcpConfig(type: .udp))) { error in
            guard case InterfaceError.invalidConfig = error else {
                return XCTFail("Expected invalidConfig for non-TCP type, got \(error)")
            }
        }
    }

    // MARK: - Destination ratchet configuration

    func testEnableRatchetsSeedsCurrentRatchet() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "rc", aspects: ["enable"])
        let path = tempPath("dest_enable")
        defer { try? FileManager.default.removeItem(atPath: path) }

        XCTAssertFalse(dest.ratchetsEnabled)
        try await dest.enableRatchets(storagePath: path)
        XCTAssertTrue(dest.ratchetsEnabled)
        XCTAssertNotNil(dest.ratchetManager)

        let count = await dest.ratchetManager?.count()
        XCTAssertEqual(count, 1, "enableRatchets seeds a current ratchet")
        // The current ratchet is remembered for self so encrypt() can select it.
        let current = await dest.ratchetManager?.currentRatchetPublicBytes()
        XCTAssertEqual(Identity.getRatchet(dest.hash), current,
            "Current ratchet is cached against the destination hash")
    }

    func testEnforceRatchetsRequiresEnabled() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "rc", aspects: ["enforce"])
        let path = tempPath("dest_enforce")
        defer { try? FileManager.default.removeItem(atPath: path) }

        // No-op before ratchets are enabled.
        dest.enforceRatchets()
        XCTAssertFalse(dest.ratchetsEnforced, "enforceRatchets is a no-op until ratchets are enabled")

        try await dest.enableRatchets(storagePath: path)
        dest.enforceRatchets()
        XCTAssertTrue(dest.ratchetsEnforced)
    }

    func testSetRatchetIntervalRejectsNonPositive() {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "rc", aspects: ["interval"])

        let defaultInterval = dest.ratchetInterval
        XCTAssertEqual(defaultInterval, Int(RatchetManager.RATCHET_INTERVAL))

        XCTAssertFalse(dest.setRatchetInterval(0), "Zero interval is rejected")
        XCTAssertFalse(dest.setRatchetInterval(-30), "Negative interval is rejected")
        XCTAssertEqual(dest.ratchetInterval, defaultInterval, "Rejected values leave the interval unchanged")

        XCTAssertTrue(dest.setRatchetInterval(60))
        XCTAssertEqual(dest.ratchetInterval, 60)
    }

    func testSetRetainedRatchetsRejectsNonPositive() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "rc", aspects: ["retained"])

        XCTAssertEqual(dest.retainedRatchets, RatchetManager.RATCHET_COUNT)

        let rejectedZero = await dest.setRetainedRatchets(0)
        XCTAssertFalse(rejectedZero)
        let rejectedNeg = await dest.setRetainedRatchets(-1)
        XCTAssertFalse(rejectedNeg)
        XCTAssertEqual(dest.retainedRatchets, RatchetManager.RATCHET_COUNT,
            "Rejected retained cap leaves the value unchanged")

        let accepted = await dest.setRetainedRatchets(8)
        XCTAssertTrue(accepted)
        XCTAssertEqual(dest.retainedRatchets, 8)
    }

    func testRotateRatchetsFalseWithoutManager() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "rc", aspects: ["norotate"])
        let rotated = await dest.rotateRatchets()
        XCTAssertFalse(rotated, "rotateRatchets is a no-op when ratchets were never enabled")
    }

    func testRotateRatchetsInsertsNewCurrent() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "rc", aspects: ["rotate"])
        let path = tempPath("dest_rotate")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await dest.enableRatchets(storagePath: path)

        // Open the gate by pushing the manager's latest time into the past.
        await dest.ratchetManager?._setLatestRatchetTime(0)
        let rotated = await dest.rotateRatchets()
        XCTAssertTrue(rotated)
        let count = await dest.ratchetManager?.count()
        XCTAssertEqual(count, 2, "Rotation inserts a new newest ratchet")
    }

    // MARK: - Destination encrypt/decrypt ratchet selection

    func testEncryptDecryptUsesRatchetWhenEnabled() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "rc", aspects: ["encdec"])
        let path = tempPath("dest_encdec")
        defer { try? FileManager.default.removeItem(atPath: path) }
        try await dest.enableRatchets(storagePath: path)

        let currentPubOpt = await dest.ratchetManager?.currentRatchetPublicBytes()
        let currentPub = try XCTUnwrap(currentPubOpt)
        let expectedId = Identity._getRatchetId(currentPub)

        let plaintext = "ratcheted payload".data(using: .utf8)!
        let ciphertext = try dest.encrypt(plaintext)
        XCTAssertGreaterThan(ciphertext.count, plaintext.count)
        XCTAssertEqual(dest.latestRatchetId, expectedId,
            "encrypt records the selected ratchet id")

        let decrypted = await dest.decrypt(ciphertext)
        XCTAssertEqual(decrypted, plaintext, "Ratcheted ciphertext round-trips")
        XCTAssertEqual(dest.latestRatchetId, expectedId,
            "decrypt reports the same ratchet id that decrypted")
    }

    func testEncryptDecryptUsesBaseKeyWithoutRatchet() async throws {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "rc", aspects: ["basekey"])

        XCTAssertNil(Identity.getRatchet(dest.hash), "Fresh destination has no cached ratchet")

        let plaintext = "plain identity payload".data(using: .utf8)!
        let ciphertext = try dest.encrypt(plaintext)
        XCTAssertGreaterThan(ciphertext.count, plaintext.count)

        let decrypted = await dest.decrypt(ciphertext)
        XCTAssertEqual(decrypted, plaintext, "Base-key ciphertext round-trips")
        XCTAssertNil(dest.latestRatchetId, "Static-key decrypt reports a nil ratchet id")
    }
}
