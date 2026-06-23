// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  DiscoveryLogicTests.swift
//  ReticulumSwiftTests
//
//  Deterministic, network-free coverage for the interface-discovery subsystem
//  (Sources/ReticulumSwift/Discovery/*): the LXStamper proof-of-work primitives
//  (DiscoveryStamp), the address/name validation grammar (DiscoveryAddress), the
//  announce SENDER (InterfaceAnnouncer), the announce RECEIVER
//  (InterfaceAnnounceHandler), the resolver/store (InterfaceDiscovery), the record
//  value-type (DiscoveredInterface / DiscoveryValue) and the wire constants
//  (DiscoveryConstants / DiscoveryFeatureDefaults). Every test drives real
//  production code and asserts its real observable behavior. Stamp costs are kept
//  low so PoW generation is fast.
//

import XCTest
@testable import ReticulumSwift

final class DiscoveryLogicTests: XCTestCase {

    // Keep PoW cheap: a cost-6 stamp clears in ~64 attempts on average.
    private let lowCost = 6

    // MARK: - helpers (PRIVATE; no top-level collisions)

    /// Build a discoverable record directly via the public initializer.
    private func makeRecord(
        type: String = "TCPServerInterface",
        name: String = "Iface",
        received: TimeInterval,
        value: Int = 10,
        transport: Bool = true,
        reachableOn: String? = nil,
        discoveryHash: Data
    ) -> DiscoveredInterface {
        var rec = DiscoveredInterface(
            type: type,
            transport: transport,
            name: name,
            received: received,
            stamp: Data(repeating: 0, count: DiscoveryConstants.STAMP_SIZE),
            value: value,
            transportId: "00112233445566778899aabbccddeeff",
            networkId: "ffeeddccbbaa99887766554433221100",
            hops: 0,
            latitude: nil,
            longitude: nil,
            height: nil,
            discoveryHash: discoveryHash
        )
        rec.reachableOn = reachableOn
        return rec
    }

    /// Build a genuine TCPServer announce + the announced identity that signed it.
    private func makeGenuineAnnounce(
        name: String? = "MyIface",
        reachableOn: String = "192.168.1.10",
        port: Int = 4242,
        cost: Int = 6
    ) -> (announce: DiscoveryAnnounce, transportIdentity: Identity, announced: Identity) {
        let transportIdentity = Identity()
        let announced = Identity()
        let announce = InterfaceAnnouncer.buildAnnounceAppData(
            interfaceType: "TCPServerInterface",
            fields: DiscoveryFields(name: name, reachableOn: reachableOn, port: port),
            stampValue: cost,
            encrypt: false,
            transportEnabled: true,
            transportIdentity: transportIdentity,
            networkIdentity: nil
        )!
        return (announce, transportIdentity, announced)
    }

    // MARK: - DiscoveryStamp: work-block

    func testWorkblockLengthIsRoundsTimes256() {
        let m = Data("material".utf8)
        XCTAssertEqual(DiscoveryStamp.workblock(m, rounds: 1).count, 256)
        XCTAssertEqual(DiscoveryStamp.workblock(m, rounds: 3).count, 768)
    }

    func testWorkblockIsDeterministic() {
        let m = Data("repeatable".utf8)
        XCTAssertEqual(DiscoveryStamp.workblock(m, rounds: 4),
                       DiscoveryStamp.workblock(m, rounds: 4))
    }

    func testWorkblockDiffersByMaterial() {
        XCTAssertNotEqual(DiscoveryStamp.workblock(Data("a".utf8), rounds: 2),
                          DiscoveryStamp.workblock(Data("b".utf8), rounds: 2))
    }

    func testStampSizeConstant() {
        XCTAssertEqual(DiscoveryStamp.stampSize, 32)
    }

    // MARK: - DiscoveryStamp: value + valid relationship

    func testValueIsInBitRange() {
        let wb = DiscoveryStamp.workblock(Data("vrange".utf8), rounds: 2)
        let v = DiscoveryStamp.value(workblock: wb, stamp: Data(repeating: 0x5A, count: 32))
        XCTAssertGreaterThanOrEqual(v, 0)
        XCTAssertLessThanOrEqual(v, 256)
    }

    func testStampValidAtItsOwnValueAndAtZeroCost() {
        // A stamp's leading-zero-bit `value` is, by construction, the highest cost
        // at which `valid` is still guaranteed true; cost 0 and negative always pass.
        let wb = DiscoveryStamp.workblock(Data("relation".utf8), rounds: 2)
        let stamp = Data(repeating: 0x11, count: 32)
        let v = DiscoveryStamp.value(workblock: wb, stamp: stamp)
        XCTAssertTrue(DiscoveryStamp.valid(stamp, cost: v, workblock: wb))
        XCTAssertTrue(DiscoveryStamp.valid(stamp, cost: 0, workblock: wb))
        XCTAssertTrue(DiscoveryStamp.valid(stamp, cost: -5, workblock: wb))
    }

    func testValidRejectsImpossibleCosts() {
        let wb = DiscoveryStamp.workblock(Data("impossible".utf8), rounds: 2)
        let stamp = Data(repeating: 0x22, count: 32)
        // cost == 256 -> target is 1; a real hash exceeds it.
        XCTAssertFalse(DiscoveryStamp.valid(stamp, cost: 256, workblock: wb))
        // cost > 256 -> only an all-zero hash could pass.
        XCTAssertFalse(DiscoveryStamp.valid(stamp, cost: 300, workblock: wb))
    }

    func testGenerateProducesValidStampClearingCost() {
        let material = Hashing.fullHash(Data("genmat".utf8))
        let (stampOpt, value) = DiscoveryStamp.generate(material, cost: lowCost, rounds: 4)
        let stamp = try! XCTUnwrap(stampOpt)
        XCTAssertEqual(stamp.count, DiscoveryConstants.STAMP_SIZE)
        XCTAssertGreaterThanOrEqual(value, lowCost)
        let wb = DiscoveryStamp.workblock(material, rounds: 4)
        XCTAssertTrue(DiscoveryStamp.valid(stamp, cost: lowCost, workblock: wb))
        XCTAssertEqual(DiscoveryStamp.value(workblock: wb, stamp: stamp), value)
    }

    // MARK: - DiscoveryAddress: IP detection

    func testIsIPAddressV4AndV6() {
        XCTAssertTrue(DiscoveryAddress.isIPAddress("192.168.1.1"))
        XCTAssertTrue(DiscoveryAddress.isIPAddress("::1"))
        XCTAssertTrue(DiscoveryAddress.isIPAddress("2001:db8::1"))
    }

    func testIsIPAddressRejectsNonIP() {
        XCTAssertFalse(DiscoveryAddress.isIPAddress("256.1.1.1"))
        XCTAssertFalse(DiscoveryAddress.isIPAddress("example.com"))
        XCTAssertFalse(DiscoveryAddress.isIPAddress(""))
    }

    func testIsYggIPv6() {
        // 0x0200 -> first byte 0x02, masked by 0xFE == 0x02 (200::/7).
        XCTAssertTrue(DiscoveryAddress.isYggIPv6("200::1"))
        XCTAssertFalse(DiscoveryAddress.isYggIPv6("::1"))
        XCTAssertFalse(DiscoveryAddress.isYggIPv6("192.168.1.1"))
    }

    // MARK: - DiscoveryAddress: hostname grammar

    func testIsHostnameAcceptsValid() {
        XCTAssertTrue(DiscoveryAddress.isHostname("example.com"))
        XCTAssertTrue(DiscoveryAddress.isHostname("a.b.c.org"))
        // One trailing dot is stripped.
        XCTAssertTrue(DiscoveryAddress.isHostname("example.com."))
    }

    func testIsHostnameRejectsEmpty() {
        XCTAssertFalse(DiscoveryAddress.isHostname(""))
    }

    func testIsHostnameRejectsLeadingTrailingHyphenLabels() {
        XCTAssertFalse(DiscoveryAddress.isHostname("-bad.com"))
        XCTAssertFalse(DiscoveryAddress.isHostname("bad-.com"))
    }

    func testIsHostnameRejectsNumericTLD() {
        XCTAssertFalse(DiscoveryAddress.isHostname("host.123"))
    }

    func testIsHostnameRejectsOverlongLabel() {
        let label = String(repeating: "a", count: 64)
        XCTAssertFalse(DiscoveryAddress.isHostname("\(label).com"))
    }

    func testIsHostnameRejectsOverlongName() {
        // Four 63-char labels = 252 + 3 dots = 255 octets > 253.
        let label = String(repeating: "a", count: 63)
        let host = [label, label, label, label].joined(separator: ".")
        XCTAssertFalse(DiscoveryAddress.isHostname(host))
    }

    func testIsSanChar() {
        XCTAssertTrue(DiscoveryAddress.isSanChar("a"))
        XCTAssertTrue(DiscoveryAddress.isSanChar("Z"))
        XCTAssertTrue(DiscoveryAddress.isSanChar("5"))
        XCTAssertFalse(DiscoveryAddress.isSanChar("-"))
        XCTAssertFalse(DiscoveryAddress.isSanChar(" "))
        XCTAssertFalse(DiscoveryAddress.isSanChar(")"))
    }

    func testAddressSanitizeStripsCRLFAndTrims() {
        XCTAssertNil(DiscoveryAddress.sanitize(nil))
        XCTAssertEqual(DiscoveryAddress.sanitize("  hi\nthe\rre  "), "hithere")
        XCTAssertEqual(DiscoveryAddress.sanitize("plain"), "plain")
    }

    // MARK: - InterfaceAnnounceHandler.sanitizeName

    func testSanitizeNameNilForNilOrEmpty() {
        XCTAssertNil(InterfaceAnnounceHandler.sanitizeName(nil))
        XCTAssertNil(InterfaceAnnounceHandler.sanitizeName(""))
    }

    func testSanitizeNameDropsNonASCII() {
        // 'é' (non-ASCII) is dropped by the ascii-ignore coercion.
        XCTAssertEqual(InterfaceAnnounceHandler.sanitizeName("h\u{00e9}llo"), "hllo")
    }

    func testSanitizeNameStripsLeadingTrailingNonSan() {
        XCTAssertEqual(InterfaceAnnounceHandler.sanitizeName("##abc!!"), "abc")
    }

    func testSanitizeNameKeepsTrailingParen() {
        // ')' (0x29) is explicitly allowed as a trailing char.
        XCTAssertEqual(InterfaceAnnounceHandler.sanitizeName("abc)"), "abc)")
    }

    func testSanitizeNameCollapsesSpaceRuns() {
        XCTAssertEqual(InterfaceAnnounceHandler.sanitizeName("a     b"), "a b")
    }

    // MARK: - InterfaceAnnounceHandler defaults

    func testHandlerAspectFilterAndRequiredValue() {
        let h = InterfaceAnnounceHandler()
        XCTAssertEqual(h.aspectFilter, "rnstransport.discovery.interface")
        XCTAssertEqual(h.requiredValue, DiscoveryConstants.DEFAULT_STAMP_VALUE)
    }

    // MARK: - receivedAnnounce: accept + record composition

    func testReceiveAcceptsGenuineTCPServerAnnounce() {
        let (announce, transportIdentity, announced) = makeGenuineAnnounce(name: "MyIface")

        var callbackArg: DiscoveredInterface??
        let handler = InterfaceAnnounceHandler(requiredValue: lowCost)
        handler.callback = { callbackArg = .some($0) }

        let outcome = handler.receivedAnnounce(
            destinationHash: announced.hash,
            announcedIdentity: announced,
            appData: announce.appData)

        guard case .accepted(let record) = outcome else {
            return XCTFail("expected .accepted, got \(outcome)")
        }
        XCTAssertEqual(record.type, "TCPServerInterface")
        XCTAssertTrue(record.transport)
        XCTAssertEqual(record.name, "MyIface")
        XCTAssertEqual(record.reachableOn, "192.168.1.10")
        XCTAssertEqual(record.port, 4242)
        XCTAssertGreaterThanOrEqual(record.value, lowCost)
        XCTAssertEqual(record.transportId, discoveryHexrep(transportIdentity.hash))
        XCTAssertEqual(record.networkId, discoveryHexrep(announced.hash))
        // TCPServer composes a BackboneInterface config entry.
        XCTAssertNotNil(record.configEntry)
        XCTAssertTrue(record.configEntry!.contains("type = BackboneInterface"))
        XCTAssertTrue(record.configEntry!.contains("remote = 192.168.1.10"))
        // discovery_hash = full_hash((transport_id_hex || name).utf8).
        let expectedHash = Hashing.fullHash(Data((record.transportId + "MyIface").utf8))
        XCTAssertEqual(record.discoveryHash, expectedHash)
        // Callback fired with the same record.
        XCTAssertEqual(callbackArg ?? nil, record)
    }

    func testReceiveNameFallbackWhenAbsent() {
        // No name -> "Discovered <type>" fallback.
        let (announce, _, announced) = makeGenuineAnnounce(name: nil)
        let handler = InterfaceAnnounceHandler(requiredValue: lowCost)
        let outcome = handler.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: announce.appData)
        guard case .accepted(let record) = outcome else {
            return XCTFail("expected .accepted")
        }
        XCTAssertEqual(record.name, "Discovered TCPServerInterface")
    }

    func testReceiveDropsTooShortAppData() {
        let handler = InterfaceAnnounceHandler(requiredValue: lowCost)
        // STAMP_SIZE + 1 == 33; not strictly greater -> dropped.
        let outcome = handler.receivedAnnounce(
            destinationHash: Data(), announcedIdentity: Identity(),
            appData: Data(count: DiscoveryConstants.STAMP_SIZE + 1))
        XCTAssertEqual(outcome, .dropped)
    }

    func testReceiveDropsWhenSourceNotAllowlisted() {
        let (announce, _, announced) = makeGenuineAnnounce()
        // Allowlist contains a different identity -> source gate drops.
        let handler = InterfaceAnnounceHandler(requiredValue: lowCost, sources: [Identity().hash])
        let outcome = handler.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: announce.appData)
        XCTAssertEqual(outcome, .dropped)
    }

    func testReceiveAcceptsWhenSourceAllowlisted() {
        let (announce, _, announced) = makeGenuineAnnounce()
        let handler = InterfaceAnnounceHandler(requiredValue: lowCost, sources: [announced.hash])
        let outcome = handler.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: announce.appData)
        guard case .accepted = outcome else { return XCTFail("expected .accepted") }
    }

    func testReceiveDropsWhenStampValueBelowRequired() {
        // Stamp generated at cost 1; receiver demands 25 -> invalid / under-value drop.
        let (announce, _, announced) = makeGenuineAnnounce(cost: 1)
        let handler = InterfaceAnnounceHandler(requiredValue: 25)
        let outcome = handler.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: announce.appData)
        XCTAssertEqual(outcome, .dropped)
    }

    // MARK: - receivedAnnounce via craftAnnounce mutations

    func testReceiveCallbackNilWhenInterfaceTypeDropped() {
        let (announce, _, announced) = makeGenuineAnnounce()
        let crafted = InterfaceAnnouncer.craftAnnounce(
            base: announce,
            dropField: DiscoveryConstants.INTERFACE_TYPE,
            setInterfaceType: nil, setFields: [], stampValue: lowCost)!

        var sawNil = false
        let handler = InterfaceAnnounceHandler(requiredValue: lowCost)
        handler.callback = { if $0 == nil { sawNil = true } }
        let outcome = handler.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: crafted.appData)
        XCTAssertEqual(outcome, .callbackNil)
        XCTAssertTrue(sawNil)
    }

    func testReceiveDropsWhenTransportNotBool() {
        let (announce, _, announced) = makeGenuineAnnounce()
        // Overwrite TRANSPORT with a non-bool -> buildRecord throws -> drop, no callback.
        let crafted = InterfaceAnnouncer.craftAnnounce(
            base: announce, dropField: nil, setInterfaceType: nil,
            setFields: [DiscoveryFieldMutation(key: DiscoveryConstants.TRANSPORT, value: .uint(1))],
            stampValue: lowCost)!

        var callbackFired = false
        let handler = InterfaceAnnounceHandler(requiredValue: lowCost)
        handler.callback = { _ in callbackFired = true }
        let outcome = handler.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: crafted.appData)
        XCTAssertEqual(outcome, .dropped)
        XCTAssertFalse(callbackFired)
    }

    func testReceiveDropsNonWhitelistedInterfaceType() {
        let (announce, _, announced) = makeGenuineAnnounce()
        let crafted = InterfaceAnnouncer.craftAnnounce(
            base: announce, dropField: nil,
            setInterfaceType: "FooInterface", setFields: [], stampValue: lowCost)!
        let handler = InterfaceAnnounceHandler(requiredValue: lowCost)
        let outcome = handler.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: crafted.appData)
        XCTAssertEqual(outcome, .dropped)
    }

    // MARK: - Encrypted announce round trip (FLAG_ENCRYPTED branch)

    func testEncryptedAnnounceRoundTrip() {
        let transportIdentity = Identity()
        let announced = Identity()
        let networkIdentity = Identity()
        let announce = InterfaceAnnouncer.buildAnnounceAppData(
            interfaceType: "TCPServerInterface",
            fields: DiscoveryFields(name: "Enc", reachableOn: "10.0.0.5", port: 5000),
            stampValue: lowCost, encrypt: true, transportEnabled: false,
            transportIdentity: transportIdentity, networkIdentity: networkIdentity)!
        XCTAssertEqual(announce.flags, Int(DiscoveryConstants.FLAG_ENCRYPTED))

        // With the matching network identity -> decrypts and accepts.
        let good = InterfaceAnnounceHandler(requiredValue: lowCost, networkIdentity: networkIdentity)
        guard case .accepted(let rec) = good.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: announce.appData)
        else { return XCTFail("expected .accepted for encrypted announce") }
        XCTAssertEqual(rec.type, "TCPServerInterface")
        XCTAssertFalse(rec.transport)

        // Without a network identity -> cannot decrypt -> dropped.
        let bad = InterfaceAnnounceHandler(requiredValue: lowCost, networkIdentity: nil)
        XCTAssertEqual(bad.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: announce.appData),
            .dropped)
    }

    // MARK: - InterfaceAnnouncer pure helpers

    func testDefaultStampValueFallback() {
        XCTAssertEqual(InterfaceAnnouncer.defaultStampValue(nil), DiscoveryConstants.DEFAULT_STAMP_VALUE)
        XCTAssertEqual(InterfaceAnnouncer.defaultStampValue(0), DiscoveryConstants.DEFAULT_STAMP_VALUE)
        XCTAssertEqual(InterfaceAnnouncer.defaultStampValue(9), 9)
    }

    func testAnnouncerSanitizeDelegates() {
        XCTAssertEqual(InterfaceAnnouncer.sanitize("a\nb"), "ab")
        XCTAssertNil(InterfaceAnnouncer.sanitize(nil))
    }

    func testBuildAnnounceRejectsNonWhitelistedType() {
        XCTAssertNil(InterfaceAnnouncer.buildAnnounceAppData(
            interfaceType: "FooInterface", fields: DiscoveryFields(),
            stampValue: lowCost, encrypt: false, transportEnabled: true,
            transportIdentity: Identity(), networkIdentity: nil))
    }

    func testBuildAnnounceRejectsTCPClientWithoutKissFraming() {
        XCTAssertNil(InterfaceAnnouncer.buildAnnounceAppData(
            interfaceType: "TCPClientInterface",
            fields: DiscoveryFields(kissFraming: false),
            stampValue: lowCost, encrypt: false, transportEnabled: true,
            transportIdentity: Identity(), networkIdentity: nil))
    }

    func testBuildAnnounceRejectsInvalidBackboneReachable() {
        // reachableOn nil -> sanitize "" -> not ip/hostname -> abort.
        XCTAssertNil(InterfaceAnnouncer.buildAnnounceAppData(
            interfaceType: "BackboneInterface",
            fields: DiscoveryFields(name: "BB", reachableOn: nil),
            stampValue: lowCost, encrypt: false, transportEnabled: true,
            transportIdentity: Identity(), networkIdentity: nil))
    }

    func testBuildAnnounceRejectsEncryptWithoutNetworkIdentity() {
        XCTAssertNil(InterfaceAnnouncer.buildAnnounceAppData(
            interfaceType: "TCPServerInterface",
            fields: DiscoveryFields(reachableOn: "1.2.3.4", port: 1),
            stampValue: lowCost, encrypt: true, transportEnabled: true,
            transportIdentity: Identity(), networkIdentity: nil))
    }

    func testBuildAnnounceShapeForValidTCPServer() {
        let (announce, transportIdentity, _) = makeGenuineAnnounce(name: "Shape", reachableOn: "8.8.8.8")
        XCTAssertEqual(announce.flags, 0)
        XCTAssertEqual(announce.appData.first, 0x00)
        XCTAssertEqual(announce.stamp.count, DiscoveryConstants.STAMP_SIZE)
        XCTAssertFalse(announce.packedInfo.isEmpty)
        XCTAssertGreaterThanOrEqual(announce.stampGeneratedValue, lowCost)
        XCTAssertEqual(announce.transportIdHash, transportIdentity.hash)
        XCTAssertEqual(announce.infoMap[.uint(DiscoveryConstants.INTERFACE_TYPE)],
                       .string("TCPServerInterface"))
    }

    func testAnnounceIdentitySelection() {
        let net = Identity()
        let dev = Identity()
        // hasNetworkIdentity -> chooses network identity.
        let a = InterfaceAnnouncer.announceIdentity(
            hasNetworkIdentity: true, networkIdentity: net, identity: dev)!
        XCTAssertEqual(a.chosenIdentityHash, net.hash)
        XCTAssertEqual(a.destinationHash.count, 16)
        // !hasNetworkIdentity -> chooses device identity.
        let b = InterfaceAnnouncer.announceIdentity(
            hasNetworkIdentity: false, networkIdentity: net, identity: dev)!
        XCTAssertEqual(b.chosenIdentityHash, dev.hash)
        // No usable identity -> nil.
        XCTAssertNil(InterfaceAnnouncer.announceIdentity(
            hasNetworkIdentity: false, networkIdentity: net, identity: nil))
        XCTAssertNil(InterfaceAnnouncer.announceIdentity(
            hasNetworkIdentity: true, networkIdentity: nil, identity: dev))
    }

    // MARK: - InterfaceDiscovery store / dedup

    func testStoreWhitelistExcludesTCPClient() {
        XCTAssertEqual(InterfaceDiscovery.DISCOVERABLE_TYPES.count, 6)
        XCTAssertFalse(InterfaceDiscovery.DISCOVERABLE_TYPES.contains("TCPClientInterface"))
        XCTAssertTrue(InterfaceDiscovery.DISCOVERABLE_TYPES.contains("KISSInterface"))
    }

    func testInterfaceDiscoveredFirstSightingBookkeeping() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        let rec = makeRecord(received: now - 3600, discoveryHash: Data([1, 2, 3, 4]))
        XCTAssertFalse(disco.isStored(rec.discoveryHash))
        disco.interfaceDiscovered(rec)
        XCTAssertTrue(disco.isStored(rec.discoveryHash))
        let listed = disco.listDiscoveredInterfaces()
        XCTAssertEqual(listed.count, 1)
        XCTAssertEqual(listed[0].heardCount, 0)
        XCTAssertEqual(listed[0].discovered, rec.received)
    }

    func testInterfaceDiscoveredRepeatIncrementsHeardCount() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        let rec = makeRecord(received: now - 1800, discoveryHash: Data([9, 9, 9, 9]))
        disco.interfaceDiscovered(rec)
        disco.interfaceDiscovered(rec)
        disco.interfaceDiscovered(rec)
        let listed = disco.listDiscoveredInterfaces()
        XCTAssertEqual(listed.count, 1, "same discovery_hash dedups to one record")
        XCTAssertEqual(listed[0].heardCount, 2, "3 sightings -> heard_count 2")
    }

    func testInterfaceDiscoveredDropsNonDiscoverableType() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        let rec = makeRecord(type: "TCPClientInterface", received: now - 60,
                             discoveryHash: Data([7, 7]))
        disco.interfaceDiscovered(rec)
        XCTAssertFalse(disco.isStored(rec.discoveryHash))
        XCTAssertTrue(disco.listDiscoveredInterfaces().isEmpty)
    }

    func testClearEmptiesStore() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        disco.interfaceDiscovered(makeRecord(received: now, discoveryHash: Data([1])))
        XCTAssertTrue(disco.isStored(Data([1])))
        disco.clear()
        XCTAssertFalse(disco.isStored(Data([1])))
    }

    // MARK: - InterfaceDiscovery list: status, purge, sort, filters

    func testListAssignsStatusAndSortsByStatusCode() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        // available (<24h), unknown (>24h,<72h), stale (>72h,<168h).
        disco.interfaceDiscovered(makeRecord(name: "avail", received: now - 2 * 3600,
                                             discoveryHash: Data([1])))
        disco.interfaceDiscovered(makeRecord(name: "unk", received: now - 30 * 3600,
                                             discoveryHash: Data([2])))
        disco.interfaceDiscovered(makeRecord(name: "stale", received: now - 100 * 3600,
                                             discoveryHash: Data([3])))
        let listed = disco.listDiscoveredInterfaces()
        XCTAssertEqual(listed.count, 3)
        XCTAssertEqual(listed.map { $0.status }, ["available", "unknown", "stale"])
        XCTAssertEqual(listed.map { $0.statusCode },
                       [DiscoveryConstants.STATUS_AVAILABLE,
                        DiscoveryConstants.STATUS_UNKNOWN,
                        DiscoveryConstants.STATUS_STALE])
    }

    func testListSortsByValueWithinSameStatus() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        disco.interfaceDiscovered(makeRecord(name: "lo", received: now - 100, value: 5,
                                             discoveryHash: Data([10])))
        disco.interfaceDiscovered(makeRecord(name: "hi", received: now - 100, value: 9,
                                             discoveryHash: Data([20])))
        let listed = disco.listDiscoveredInterfaces()
        XCTAssertEqual(listed.count, 2)
        XCTAssertEqual(listed[0].value, 9, "higher stamp value sorts first")
        XCTAssertEqual(listed[1].value, 5)
    }

    func testListPurgesRecordsBeyondRemoveThreshold() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        let old = makeRecord(received: now - 200 * 3600, discoveryHash: Data([42]))
        disco.interfaceDiscovered(old)
        XCTAssertTrue(disco.isStored(old.discoveryHash))
        let listed = disco.listDiscoveredInterfaces()
        XCTAssertTrue(listed.isEmpty)
        XCTAssertFalse(disco.isStored(old.discoveryHash), "purge removes from the backing store")
    }

    func testListPurgesInvalidReachableOn() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        let rec = makeRecord(received: now - 60, reachableOn: "not a valid host!!",
                             discoveryHash: Data([55]))
        disco.interfaceDiscovered(rec)
        XCTAssertTrue(disco.listDiscoveredInterfaces().isEmpty)
        XCTAssertFalse(disco.isStored(rec.discoveryHash))
    }

    func testListReSanitizesName() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        let rec = makeRecord(name: "##weird!!", received: now - 60, discoveryHash: Data([77]))
        disco.interfaceDiscovered(rec)
        let listed = disco.listDiscoveredInterfaces()
        XCTAssertEqual(listed.first?.name, "weird")
    }

    func testListOnlyAvailableFilter() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        disco.interfaceDiscovered(makeRecord(name: "a", received: now - 100,
                                             discoveryHash: Data([1])))
        disco.interfaceDiscovered(makeRecord(name: "u", received: now - 30 * 3600,
                                             discoveryHash: Data([2])))
        let listed = disco.listDiscoveredInterfaces(onlyAvailable: true)
        XCTAssertEqual(listed.count, 1)
        XCTAssertEqual(listed.first?.status, "available")
    }

    func testListOnlyTransportFilter() {
        let disco = InterfaceDiscovery(requiredValue: lowCost)
        let now = Date().timeIntervalSince1970
        disco.interfaceDiscovered(makeRecord(name: "t", received: now - 100, transport: true,
                                             discoveryHash: Data([1])))
        disco.interfaceDiscovered(makeRecord(name: "n", received: now - 100, transport: false,
                                             discoveryHash: Data([2])))
        let listed = disco.listDiscoveredInterfaces(onlyTransport: true)
        XCTAssertEqual(listed.count, 1)
        XCTAssertTrue(listed.first?.transport ?? false)
    }

    func testListPurgesWhenSourcesConfiguredAndNotAllowlisted() {
        // Sources configured but the record's network_id is not in the allowlist.
        let disco = InterfaceDiscovery(requiredValue: lowCost, discoverySources: [Data(repeating: 0xAB, count: 16)])
        let now = Date().timeIntervalSince1970
        disco.interfaceDiscovered(makeRecord(received: now - 60, discoveryHash: Data([1])))
        XCTAssertTrue(disco.listDiscoveredInterfaces().isEmpty)
    }

    // MARK: - InterfaceDiscovery.injectRecords (full build->receive->store->list)

    func testInjectRecordsEndToEndSortsByValue() {
        let disco = InterfaceDiscovery(requiredValue: 6)
        let result = disco.injectRecords([
            DiscoveryInjectSpec(name: "alpha", ageSeconds: 120, stampValue: 6, valueOverride: 5),
            DiscoveryInjectSpec(name: "bravo", ageSeconds: 120, stampValue: 6, valueOverride: 9),
            DiscoveryInjectSpec(name: "charlie", ageSeconds: 120, stampValue: 6, valueOverride: 7),
        ])
        XCTAssertEqual(result.requested.count, 3)
        XCTAssertEqual(result.listed.count, 3)
        // All recent -> available -> sorted by value descending.
        XCTAssertEqual(result.listed.map { $0.value }, [9, 7, 5])
        XCTAssertEqual(result.listed.map { $0.name }, ["bravo", "charlie", "alpha"])
    }

    // MARK: - DiscoveredInterface value type / toDictionary

    func testToDictionaryAlwaysHasCoreKeys() {
        let now = Date().timeIntervalSince1970
        let rec = makeRecord(received: now, discoveryHash: Data([1, 2]))
        let d = rec.toDictionary()
        for key in ["type", "transport", "name", "received", "stamp", "value",
                    "transport_id", "network_id", "hops", "latitude", "longitude",
                    "height", "discovery_hash"] {
            XCTAssertNotNil(d[key], "core key \(key) must always be present")
        }
        XCTAssertEqual(d["type"], .string("TCPServerInterface"))
        XCTAssertEqual(d["transport"], .bool(true))
        XCTAssertEqual(d["hops"], .int(0))
    }

    func testToDictionaryNilCoordinatesProjectToNull() {
        let now = Date().timeIntervalSince1970
        let rec = makeRecord(received: now, discoveryHash: Data([1]))
        let d = rec.toDictionary()
        XCTAssertEqual(d["latitude"], .null)
        XCTAssertEqual(d["longitude"], .null)
        XCTAssertEqual(d["height"], .null)
    }

    func testToDictionaryPresentCoordinateProjectsToDouble() {
        let now = Date().timeIntervalSince1970
        var rec = makeRecord(received: now, discoveryHash: Data([1]))
        rec.latitude = 51.5
        let d = rec.toDictionary()
        XCTAssertEqual(d["latitude"], .double(51.5))
    }

    func testToDictionaryOmitsNilOptionalKeys() {
        let now = Date().timeIntervalSince1970
        let rec = makeRecord(received: now, discoveryHash: Data([1]))
        let d = rec.toDictionary()
        // A bare record carries no per-type optionals.
        XCTAssertNil(d["sf"])
        XCTAssertNil(d["port"])
        XCTAssertNil(d["channel"])
        XCTAssertNil(d["config_entry"])
        XCTAssertNil(d["status"])
    }

    func testToDictionaryIncludesSetOptionalKeys() {
        let now = Date().timeIntervalSince1970
        var rec = makeRecord(received: now, discoveryHash: Data([1]))
        rec.port = 4242
        rec.sf = 7
        rec.modulation = "LoRa"
        rec.configEntry = "[[X]]"
        rec.status = "available"
        rec.statusCode = DiscoveryConstants.STATUS_AVAILABLE
        let d = rec.toDictionary()
        XCTAssertEqual(d["port"], .int(4242))
        XCTAssertEqual(d["sf"], .int(7))
        XCTAssertEqual(d["modulation"], .string("LoRa"))
        XCTAssertEqual(d["config_entry"], .string("[[X]]"))
        XCTAssertEqual(d["status"], .string("available"))
        XCTAssertEqual(d["status_code"], .int(DiscoveryConstants.STATUS_AVAILABLE))
    }

    func testDiscoveredInterfaceEquatable() {
        let now = Date().timeIntervalSince1970
        let a = makeRecord(received: now, discoveryHash: Data([1]))
        let b = makeRecord(received: now, discoveryHash: Data([1]))
        XCTAssertEqual(a, b)
        var c = a
        c.name = "different"
        XCTAssertNotEqual(a, c)
    }

    func testDiscoveryValueEquatable() {
        XCTAssertEqual(DiscoveryValue.int(5), .int(5))
        XCTAssertNotEqual(DiscoveryValue.int(5), .int(6))
        XCTAssertNotEqual(DiscoveryValue.string("a"), .null)
        XCTAssertEqual(DiscoveryValue.bytes(Data([1, 2])), .bytes(Data([1, 2])))
        XCTAssertEqual(DiscoveryValue.null, .null)
    }

    func testDiscoveryHexrep() {
        XCTAssertEqual(discoveryHexrep(Data([0x00, 0x0f, 0xff, 0xab])), "000fffab")
        XCTAssertEqual(discoveryHexrep(Data()), "")
    }

    // MARK: - DiscoveryConstants / DiscoveryFeatureDefaults

    func testConstantFieldKeys() {
        XCTAssertEqual(DiscoveryConstants.NAME, 0xFF)
        XCTAssertEqual(DiscoveryConstants.TRANSPORT_ID, 0xFE)
        XCTAssertEqual(DiscoveryConstants.INTERFACE_TYPE, 0x00)
        XCTAssertEqual(DiscoveryConstants.TRANSPORT, 0x01)
        XCTAssertEqual(DiscoveryConstants.REACHABLE_ON, 0x02)
        XCTAssertEqual(DiscoveryConstants.CHANNEL, 0x0E)
        XCTAssertEqual(DiscoveryConstants.APP_NAME, "rnstransport")
    }

    func testConstantProtocolLiterals() {
        XCTAssertEqual(DiscoveryConstants.FLAG_SIGNED, 0b00000001)
        XCTAssertEqual(DiscoveryConstants.FLAG_ENCRYPTED, 0b00000010)
        XCTAssertEqual(DiscoveryConstants.DEFAULT_STAMP_VALUE, 14)
        XCTAssertEqual(DiscoveryConstants.WORKBLOCK_EXPAND_ROUNDS, 20)
        XCTAssertEqual(DiscoveryConstants.STAMP_SIZE, 32)
        XCTAssertEqual(DiscoveryConstants.TRANSPORT_ID_LENGTH, 16)
    }

    func testConstantThresholdsAndStatusMap() {
        XCTAssertEqual(DiscoveryConstants.THRESHOLD_UNKNOWN, 86400)
        XCTAssertEqual(DiscoveryConstants.THRESHOLD_STALE, 259200)
        XCTAssertEqual(DiscoveryConstants.THRESHOLD_REMOVE, 604800)
        XCTAssertEqual(DiscoveryConstants.STATUS_CODE_MAP["available"], DiscoveryConstants.STATUS_AVAILABLE)
        XCTAssertEqual(DiscoveryConstants.STATUS_CODE_MAP["unknown"], DiscoveryConstants.STATUS_UNKNOWN)
        XCTAssertEqual(DiscoveryConstants.STATUS_CODE_MAP["stale"], DiscoveryConstants.STATUS_STALE)
    }

    func testHandlerWhitelistIncludesTCPClientButStoreDoesNot() {
        XCTAssertEqual(DiscoveryConstants.DISCOVERABLE_INTERFACE_TYPES.count, 7)
        XCTAssertTrue(DiscoveryConstants.DISCOVERABLE_INTERFACE_TYPES.contains("TCPClientInterface"))
        // The store whitelist is the strict 6-type subset (no TCPClientInterface).
        XCTAssertFalse(InterfaceDiscovery.DISCOVERABLE_TYPES.contains("TCPClientInterface"))
        for t in InterfaceDiscovery.DISCOVERABLE_TYPES {
            XCTAssertTrue(DiscoveryConstants.DISCOVERABLE_INTERFACE_TYPES.contains(t))
        }
    }

    func testFeatureDefaultsAllOff() {
        XCTAssertFalse(DiscoveryFeatureDefaults.interfaceDiscoverable)
        XCTAssertFalse(DiscoveryFeatureDefaults.interfaceSupportsDiscovery)
        XCTAssertFalse(DiscoveryFeatureDefaults.discoverInterfaces)
        XCTAssertFalse(DiscoveryFeatureDefaults.shouldAutoconnectDiscoveredInterfaces)
        XCTAssertFalse(DiscoveryFeatureDefaults.maxAutoconnectedInterfaces)
    }
}
