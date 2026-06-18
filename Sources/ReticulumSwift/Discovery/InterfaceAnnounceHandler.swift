// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  InterfaceAnnounceHandler.swift
//  ReticulumSwift
//
//  Interface-discovery announce RECEIVER — a 1:1 port of
//  `RNS.Discovery.InterfaceAnnounceHandler` (Discovery.py:188-362):
//  `sanitize_name` (Discovery.py:205-212), `aspect_filter`, `required_value`,
//  and `received_announce` (Discovery.py:214-362) with every receive gate
//  reproduced IN ORDER. The result is reported as a `ReceiveOutcome` AND the
//  stored callback is invoked exactly as RNS does, so a consumer can observe the
//  callback-invoked / callback-with-None distinction the mandatory-fields test
//  keys on.
//

import Foundation

/// The disposition of an inbound discovery announce.
///
/// `.dropped` and `.callbackNil` are LOAD-BEARING distinct (Discovery.py:247 +
/// the KeyError path): an INTERFACE_TYPE-absent announce leaves `info` nil and
/// invokes `callback(nil)` (`.callbackNil`), whereas any OTHER missing/wrong
/// mandatory field raises before the callback is reached (`.dropped`, no callback).
public enum ReceiveOutcome: Equatable, Sendable {
    case dropped
    case callbackNil
    case accepted(DiscoveredInterface)
}

private enum DiscoveryReceiveError: Error { case invalid }

/// The interface-discovery announce receiver (Discovery.py InterfaceAnnounceHandler).
public final class InterfaceAnnounceHandler {
    /// `aspect_filter` (Discovery.py:200) — the dotted name Transport's
    /// announce-handler dispatch matches against the discovery destination so this
    /// handler receives real discovery announces. A wrong value silently never fires.
    public let aspectFilter = "rnstransport.discovery.interface"

    /// Required stamp value (Discovery.py:201). Defaults to DEFAULT_STAMP_VALUE=14.
    public let requiredValue: Int

    /// Receive-time source allowlist (`interface_discovery_sources()`,
    /// Discovery.py:216). Empty == no allowlist configured.
    public var sources: [Data]

    /// Network identity used to decrypt FLAG_ENCRYPTED announces
    /// (`RNS.Transport.network_identity`, Discovery.py:228-229). nil == none.
    public var networkIdentity: Identity?

    /// Hops to the announce source. DEVIATION: RNS reads `Transport.hops_to`
    /// (Discovery.py:271); the conformance/library context has no live Transport
    /// path table, so this is an injectable constant (default 0). Documented in
    /// port-deviations.md. The receive path still emits an int, as RNS does.
    public var hops: Int

    /// Discovery callback (Discovery.py:202,359). Invoked with the built record on
    /// acceptance, or with nil for the INTERFACE_TYPE-absent branch.
    public var callback: ((DiscoveredInterface?) -> Void)?

    public init(
        requiredValue: Int = DiscoveryConstants.DEFAULT_STAMP_VALUE,
        sources: [Data] = [],
        networkIdentity: Identity? = nil,
        hops: Int = 0,
        callback: ((DiscoveredInterface?) -> Void)? = nil
    ) {
        self.requiredValue = requiredValue
        self.sources = sources
        self.networkIdentity = networkIdentity
        self.hops = hops
        self.callback = callback
    }

    /// `sanitize_name` (Discovery.py:205-212): nil/empty -> nil; ASCII-coerce
    /// (drop non-ASCII scalars), trim, collapse 5/3/2-space runs to one, strip
    /// leading chars not in `san_map` and trailing chars not in `san_map+")"`.
    public static func sanitizeName(_ name: String?) -> String? {
        guard let name = name, !name.isEmpty else { return nil }
        // encode("ascii","ignore").decode("ascii") drops non-ASCII scalars.
        var s = String()
        for sc in name.unicodeScalars where sc.isASCII { s.unicodeScalars.append(sc) }
        s = s.trimmingCharacters(in: .whitespacesAndNewlines)
        for i in [5, 3, 2] {
            s = s.replacingOccurrences(of: String(repeating: " ", count: i), with: " ")
        }
        while let f = s.unicodeScalars.first, !DiscoveryAddress.isSanChar(f) { s.removeFirst() }
        // Trailing chars must be in san_map OR ")" (Discovery.py:211); ')' == 0x29.
        while let l = s.unicodeScalars.last, !(DiscoveryAddress.isSanChar(l) || l.value == 0x29) { s.removeLast() }
        return s
    }

    /// `received_announce` (Discovery.py:214-362). Runs every receive gate in RNS
    /// order: source allowlist, len > STAMP_SIZE+1, flag split (only FLAG_ENCRYPTED
    /// acts; FLAG_SIGNED / unknown high bits are computed-but-ignored),
    /// FLAG_ENCRYPTED -> network_identity.decrypt-or-drop, stamp valid AND
    /// value >= required, msgpack decode, the INTERFACE_TYPE-absent -> callback(nil)
    /// branch vs any-other-missing-mandatory -> drop-no-callback branch, per-field
    /// type/length validation, then per-type info + config_entry composition and
    /// discovery_hash derivation. The whole body is wrapped so any thrown error
    /// drops the announce (matching RNS's broad try/except, Discovery.py:215,361).
    public func receivedAnnounce(
        destinationHash: Data,
        announcedIdentity: Identity,
        appData: Data,
        hops: Int? = nil
    ) -> ReceiveOutcome {
        let C = DiscoveryConstants.self

        // 1. source allowlist (Discovery.py:216-219).
        if !sources.isEmpty && !sources.contains(announcedIdentity.hash) {
            return .dropped
        }

        // 2. minimum-length gate (Discovery.py:221).
        guard appData.count > C.STAMP_SIZE + 1 else { return .dropped }

        // 3. flag split (Discovery.py:222-225). Only FLAG_ENCRYPTED acts; signed
        // and unknown bits are computed-but-ignored.
        let flags = appData[appData.startIndex]
        var body = Data(appData.dropFirst())
        let encrypted = (flags & C.FLAG_ENCRYPTED) != 0

        // 4. encrypted -> decrypt with the network identity's OWN hash as salt,
        // or drop (Discovery.py:227-230).
        if encrypted {
            guard let netId = networkIdentity else { return .dropped }
            guard let decrypted = try? netId.decrypt(body, identityHash: netId.hash) else { return .dropped }
            body = decrypted
        }

        guard body.count >= C.STAMP_SIZE else { return .dropped }

        // 5. split stamp / packed; re-derive infohash, work-block, value, validity
        // (Discovery.py:232-237).
        let stamp = Data(body.suffix(C.STAMP_SIZE))
        let packed = Data(body.prefix(body.count - C.STAMP_SIZE))
        let infohash = Hashing.fullHash(packed)
        let workblock = DiscoveryStamp.workblock(infohash)
        let value = DiscoveryStamp.value(workblock: workblock, stamp: stamp)
        let valid = DiscoveryStamp.valid(stamp, cost: requiredValue, workblock: workblock)

        // 6. stamp gates (Discovery.py:239-243).
        if !valid { return .dropped }
        if value < requiredValue { return .dropped }

        // 7. decode + branch (Discovery.py:245-359).
        let unpacked: MessagePackValue
        do { unpacked = try unpackMsgPack(packed) } catch { return .dropped }
        guard case .map(let m) = unpacked else { return .dropped }

        // INTERFACE_TYPE absent -> info stays nil -> callback(nil) (Discovery.py:247,359).
        guard m[.uint(C.INTERFACE_TYPE)] != nil else {
            callback?(nil)
            return .callbackNil
        }

        // INTERFACE_TYPE present -> build the record; any thrown error drops with
        // NO callback (the KeyError / ValueError path, Discovery.py:251-357,361).
        do {
            let record = try buildRecord(
                m: m, stamp: stamp, value: value,
                announcedIdentity: announcedIdentity, hops: hops ?? self.hops)
            callback?(record)
            return .accepted(record)
        } catch {
            return .dropped
        }
    }

    // MARK: - record construction (Discovery.py:248-357)

    private func buildRecord(
        m: [MessagePackValue: MessagePackValue],
        stamp: Data,
        value: Int,
        announcedIdentity: Identity,
        hops: Int
    ) throws -> DiscoveredInterface {
        let C = DiscoveryConstants.self

        guard case .string(let interfaceType)? = m[.uint(C.INTERFACE_TYPE)] else {
            throw DiscoveryReceiveError.invalid
        }

        // NAME mandatory deref (Discovery.py:249); sanitize + fallback.
        guard let nameVal = m[.uint(C.NAME)] else { throw DiscoveryReceiveError.invalid }
        let sanitizedName = Self.sanitizeName(messagePackString(nameVal))

        // TRANSPORT must be bool (Discovery.py:251).
        guard let transportVal = m[.uint(C.TRANSPORT)] else { throw DiscoveryReceiveError.invalid }
        guard case .bool(let transport) = transportVal else { throw DiscoveryReceiveError.invalid }

        // LATITUDE/LONGITUDE/HEIGHT must be None-or-float (Discovery.py:252-254).
        let latitude = try coordinate(m[.uint(C.LATITUDE)])
        let longitude = try coordinate(m[.uint(C.LONGITUDE)])
        let height = try coordinate(m[.uint(C.HEIGHT)])

        // TRANSPORT_ID must be exactly 16 bytes (Discovery.py:255).
        guard let tidVal = m[.uint(C.TRANSPORT_ID)] else { throw DiscoveryReceiveError.invalid }
        guard case .binary(let tidBytes) = tidVal, tidBytes.count == C.TRANSPORT_ID_LENGTH else {
            throw DiscoveryReceiveError.invalid
        }

        // Receiver-side type whitelist (Discovery.py:256-257).
        guard C.DISCOVERABLE_INTERFACE_TYPES.contains(interfaceType) else {
            throw DiscoveryReceiveError.invalid
        }

        // REACHABLE_ON, if present, must be ip or hostname (Discovery.py:259-261).
        if let reachVal = m[.uint(C.REACHABLE_ON)] {
            guard case .string(let r) = reachVal,
                  DiscoveryAddress.isIPAddress(r) || DiscoveryAddress.isHostname(r) else {
                throw DiscoveryReceiveError.invalid
            }
        }

        let transportIdHex = discoveryHexrep(tidBytes)
        // name fallback "Discovered <type>" (Discovery.py:265): `name or f"..."`.
        let resolvedName: String
        if let n = sanitizedName, !n.isEmpty { resolvedName = n }
        else { resolvedName = "Discovered \(interfaceType)" }

        var info = DiscoveredInterface(
            type: interfaceType,
            transport: transport,
            name: resolvedName,
            received: Date().timeIntervalSince1970,
            stamp: stamp,
            value: value,
            transportId: transportIdHex,
            networkId: discoveryHexrep(announcedIdentity.hash),
            hops: hops,
            latitude: latitude,
            longitude: longitude,
            height: height,
            discoveryHash: Data()   // set below
        )

        // IFAC credentials (Discovery.py:276-277).
        if let v = m[.uint(C.IFAC_NETNAME)] { info.ifacNetname = pythonStr(v) }
        if let v = m[.uint(C.IFAC_NETKEY)]  { info.ifacNetkey  = pythonStr(v) }

        let netnameStr = info.ifacNetname.flatMap { $0.isEmpty ? nil : "\n  network_name = \($0)" } ?? ""
        let netkeyStr  = info.ifacNetkey.flatMap  { $0.isEmpty ? nil : "\n  passphrase = \($0)" } ?? ""
        let identityStr = "\n  transport_identity = \(transportIdHex)"

        // Per-type info + config_entry (Discovery.py:279-354). We never run on
        // Windows, so backbone_support is always True (connection_interface =
        // BackboneInterface, remote_str = remote).
        switch interfaceType {
        case "BackboneInterface", "TCPServerInterface":
            guard let reachVal = m[.uint(C.REACHABLE_ON)], case .string(let reachable) = reachVal else {
                throw DiscoveryReceiveError.invalid
            }
            let port = try derefInt(m, C.PORT)
            info.reachableOn = reachable
            info.port = port
            info.configEntry =
                "[[\(resolvedName)]]\n  type = BackboneInterface\n  enabled = yes\n  remote = \(reachable)" +
                "\n  target_port = \(cfgNum(port))\(identityStr)\(netnameStr)\(netkeyStr)"

        case "I2PInterface":
            guard let reachVal = m[.uint(C.REACHABLE_ON)], case .string(let reachable) = reachVal else {
                throw DiscoveryReceiveError.invalid
            }
            info.reachableOn = reachable
            info.configEntry =
                "[[\(resolvedName)]]\n  type = I2PInterface\n  enabled = yes\n  peers = \(reachable)" +
                "\(identityStr)\(netnameStr)\(netkeyStr)"

        case "RNodeInterface":
            let frequency = try derefInt(m, C.FREQUENCY)
            let bandwidth = try derefInt(m, C.BANDWIDTH)
            let sf = try derefInt(m, C.SPREADINGFACTOR)
            let cr = try derefInt(m, C.CODINGRATE)
            info.frequency = frequency
            info.bandwidth = bandwidth
            info.sf = sf
            info.cr = cr
            // NOTE: RNode config carries no transport_identity line (Discovery.py:324).
            info.configEntry =
                "[[\(resolvedName)]]\n  type = RNodeInterface\n  enabled = yes\n  port = " +
                "\n  frequency = \(cfgNum(frequency))\n  bandwidth = \(cfgNum(bandwidth))" +
                "\n  spreadingfactor = \(cfgNum(sf))\n  codingrate = \(cfgNum(cr))\n  txpower = \(netnameStr)\(netkeyStr)"

        case "WeaveInterface":
            let frequency = try derefInt(m, C.FREQUENCY)
            let bandwidth = try derefInt(m, C.BANDWIDTH)
            let channel = try derefInt(m, C.CHANNEL)
            let modulation = try derefStringOpt(m, C.MODULATION)
            info.frequency = frequency
            info.bandwidth = bandwidth
            info.channel = channel
            info.modulation = modulation
            // NOTE: Weave config carries no transport_identity line (Discovery.py:338).
            info.configEntry =
                "[[\(resolvedName)]]\n  type = WeaveInterface\n  enabled = yes\n  port = \(netnameStr)\(netkeyStr)"

        case "KISSInterface":
            let frequency = try derefInt(m, C.FREQUENCY)
            let bandwidth = try derefInt(m, C.BANDWIDTH)
            let modulation = try derefStringOpt(m, C.MODULATION)
            info.frequency = frequency
            info.bandwidth = bandwidth
            info.modulation = modulation
            info.configEntry =
                "[[\(resolvedName)]]\n  type = KISSInterface\n  enabled = yes\n  port = " +
                "\n  # Frequency: \(cfgNum(frequency))\n  # Bandwidth: \(cfgNum(bandwidth))" +
                "\n  # Modulation: \(modulation ?? "None")\(identityStr)\(netnameStr)\(netkeyStr)"

        default:
            // No per-type composition (e.g. TCPClientInterface) — the record is
            // surfaced without per-type fields / config_entry.
            break
        }

        // discovery_hash = full_hash((transport_id_hex || name).utf8) (Discovery.py:356-357).
        let material = Data((transportIdHex + resolvedName).utf8)
        info.discoveryHash = Hashing.fullHash(material)
        return info
    }

    // MARK: - field extraction helpers

    /// None-or-float coordinate (Discovery.py:252-254). Throws for a missing key
    /// (mandatory deref / KeyError) or a non-None-non-float type (ValueError).
    private func coordinate(_ v: MessagePackValue?) throws -> Double? {
        guard let v = v else { throw DiscoveryReceiveError.invalid }
        switch v {
        case .null:          return nil
        case .double(let d): return d
        case .float(let f):  return Double(f)
        default:             throw DiscoveryReceiveError.invalid
        }
    }

    /// Mandatory int deref — throws (KeyError) if the key is absent; coerces null
    /// or a non-int value to nil (RNS stores the raw value verbatim).
    private func derefInt(_ m: [MessagePackValue: MessagePackValue], _ key: UInt64) throws -> Int? {
        guard let v = m[.uint(key)] else { throw DiscoveryReceiveError.invalid }
        switch v {
        case .uint(let u): return Int(u)
        case .int(let i):  return Int(i)
        default:           return nil
        }
    }

    /// Mandatory string deref — throws (KeyError) if absent; null -> nil.
    private func derefStringOpt(_ m: [MessagePackValue: MessagePackValue], _ key: UInt64) throws -> String? {
        guard let v = m[.uint(key)] else { throw DiscoveryReceiveError.invalid }
        if case .string(let s) = v { return s }
        return nil
    }

    private func messagePackString(_ v: MessagePackValue) -> String? {
        if case .string(let s) = v { return s }
        return nil
    }

    /// Python `str(x)` of a msgpack value for IFAC credential surfacing.
    private func pythonStr(_ v: MessagePackValue) -> String {
        switch v {
        case .string(let s): return s
        case .null:          return "None"
        case .int(let i):    return String(i)
        case .uint(let u):   return String(u)
        case .bool(let b):   return b ? "True" : "False"
        default:             return ""
        }
    }

    /// Python f-string render of an Int? (None when nil).
    private func cfgNum(_ i: Int?) -> String { i.map(String.init) ?? "None" }
}
