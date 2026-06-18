// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  InterfaceAnnouncer.swift
//  ReticulumSwift
//
//  Interface-discovery announce SENDER — a 1:1 port of
//  `RNS.Discovery.InterfaceAnnouncer.get_interface_announce_data`
//  (Discovery.py:96-186) plus the `__init__` discovery-Destination identity
//  selection (Discovery.py:54-58). Assembles the fixed-key msgpack info map per
//  interface type, stamps it with the LXStamper PoW, and emits
//  `[flags] || (packed||stamp | network_identity.encrypt(packed||stamp))`.
//
//  The autoconnect/monitor/teardown/BlackholeUpdater halves of Discovery.py
//  (Transport interface lifecycle) are OUT OF SCOPE for this port.
//

import Foundation

/// A coordinate / loosely-typed field value supplied to the announce builder.
/// LATITUDE/LONGITUDE/HEIGHT are embedded verbatim (Discovery.py:107-109) so a
/// wrong-typed value (e.g. a string) can be carried to exercise the receiver's
/// None-or-float gate; `.none` is embedded as msgpack null.
public enum DiscoveryScalar: Equatable, Sendable {
    case none
    case double(Double)
    case int(Int)
    case string(String)
    case bool(Bool)

    var messagePackValue: MessagePackValue {
        switch self {
        case .none:          return .null
        case .double(let d): return .double(d)
        case .int(let i):    return i >= 0 ? .uint(UInt64(i)) : .int(Int64(i))
        case .string(let s): return .string(s)
        case .bool(let b):   return .bool(b)
        }
    }
}

/// Per-interface discovery parameters the announce builder reads (the
/// `interface.discovery_*` attributes RNS keys on, Discovery.py:96-166).
public struct DiscoveryFields: Sendable {
    public var name: String?
    public var reachableOn: String?
    public var port: Int?
    public var latitude: DiscoveryScalar
    public var longitude: DiscoveryScalar
    public var height: DiscoveryScalar
    public var publishIfac: Bool
    public var ifacNetname: String?
    public var ifacNetkey: String?
    public var kissFraming: Bool
    public var connectable: Bool
    public var b32: String?
    public var frequency: Int?
    public var bandwidth: Int?
    public var sf: Int?
    public var cr: Int?
    public var channel: Int?
    public var modulation: String?

    public init(
        name: String? = nil,
        reachableOn: String? = nil,
        port: Int? = nil,
        latitude: DiscoveryScalar = .none,
        longitude: DiscoveryScalar = .none,
        height: DiscoveryScalar = .none,
        publishIfac: Bool = false,
        ifacNetname: String? = nil,
        ifacNetkey: String? = nil,
        kissFraming: Bool = false,
        connectable: Bool = false,
        b32: String? = nil,
        frequency: Int? = nil,
        bandwidth: Int? = nil,
        sf: Int? = nil,
        cr: Int? = nil,
        channel: Int? = nil,
        modulation: String? = nil
    ) {
        self.name = name
        self.reachableOn = reachableOn
        self.port = port
        self.latitude = latitude
        self.longitude = longitude
        self.height = height
        self.publishIfac = publishIfac
        self.ifacNetname = ifacNetname
        self.ifacNetkey = ifacNetkey
        self.kissFraming = kissFraming
        self.connectable = connectable
        self.b32 = b32
        self.frequency = frequency
        self.bandwidth = bandwidth
        self.sf = sf
        self.cr = cr
        self.channel = channel
        self.modulation = modulation
    }
}

/// A single msgpack-key mutation applied by `craftAnnounce` to a decoded info map.
public struct DiscoveryFieldMutation: Sendable {
    public let key: UInt64
    public let value: MessagePackValue
    public init(key: UInt64, value: MessagePackValue) {
        self.key = key
        self.value = value
    }
}

/// The result of a successful announce build/craft — the assembled `app_data`
/// plus the split parts (Discovery.py:168-186). For an ENCRYPTED announce
/// `packedInfo`/`stamp`/`infohash` are the ciphertext fragments produced by
/// re-splitting the assembled buffer at the flag byte + STAMP_SIZE, exactly as
/// RNS reports them.
public struct DiscoveryAnnounce: Sendable {
    public var appData: Data
    public var flags: Int
    public var packedInfo: Data
    public var stamp: Data
    public var infohash: Data
    public var transportIdHash: Data
    public var transportEnabled: Bool
    /// The decoded info map (for `craftAnnounce` to mutate + re-stamp).
    public var infoMap: [MessagePackValue: MessagePackValue]
    /// The leading-zero-bit value of the generated stamp (used by craft output).
    public var stampGeneratedValue: Int
}

/// The interface-discovery announce SENDER (Discovery.py InterfaceAnnouncer).
public enum InterfaceAnnouncer {
    /// `DEFAULT_STAMP_VALUE` fallback (Discovery.py:34,98): the per-interface
    /// stamp cost, falling back to 14 when unset/None/0.
    public static func defaultStampValue(_ stampValue: Int?) -> Int {
        let v = stampValue ?? 0
        return v != 0 ? v : DiscoveryConstants.DEFAULT_STAMP_VALUE
    }

    /// `InterfaceAnnouncer.sanitize` (Discovery.py:89-94).
    public static func sanitize(_ value: String?) -> String? {
        return DiscoveryAddress.sanitize(value)
    }

    /// `get_interface_announce_data` (Discovery.py:96-186). Returns nil (aborted)
    /// for: a non-whitelisted type (`:100`), a TCPClientInterface without
    /// kiss_framing (`:111-113`), an invalid Backbone/TCPServer reachable_on
    /// (`:135-138`), a failed stamp (`:173`), or encrypt-requested with no network
    /// identity (`:178-180`). Otherwise builds the fixed integer-keyed msgpack info
    /// map, stamps SHA-256(packed) at `stampValue` (None/0 -> DEFAULT_STAMP_VALUE),
    /// and emits `[flags] || payload`.
    public static func buildAnnounceAppData(
        interfaceType: String,
        fields: DiscoveryFields,
        stampValue: Int?,
        encrypt: Bool,
        transportEnabled: Bool,
        transportIdentity: Identity,
        networkIdentity: Identity?
    ) -> DiscoveryAnnounce? {
        let cost = defaultStampValue(stampValue)

        // Sender-side type whitelist (Discovery.py:100).
        guard DiscoveryConstants.DISCOVERABLE_INTERFACE_TYPES.contains(interfaceType) else {
            return nil
        }

        let C = DiscoveryConstants.self
        var info: [MessagePackValue: MessagePackValue] = [:]
        // Mandatory fields (Discovery.py:103-109).
        info[.uint(C.INTERFACE_TYPE)] = .string(interfaceType)
        info[.uint(C.TRANSPORT)]      = .bool(transportEnabled)
        info[.uint(C.TRANSPORT_ID)]   = .binary(transportIdentity.hash)
        info[.uint(C.NAME)]           = strOrNull(sanitize(fields.name))
        info[.uint(C.LATITUDE)]       = fields.latitude.messagePackValue
        info[.uint(C.LONGITUDE)]      = fields.longitude.messagePackValue
        info[.uint(C.HEIGHT)]         = fields.height.messagePackValue

        // TCPClientInterface requires kiss_framing (Discovery.py:111-113).
        if interfaceType == "TCPClientInterface" && !fields.kissFraming {
            return nil
        }

        // Backbone / TCPServer: REACHABLE_ON (validated) + PORT (Discovery.py:115-141).
        if interfaceType == "BackboneInterface" || interfaceType == "TCPServerInterface" {
            let reachable = sanitize(fields.reachableOn) ?? ""
            if !(DiscoveryAddress.isIPAddress(reachable) || DiscoveryAddress.isHostname(reachable)) {
                return nil
            }
            info[.uint(C.REACHABLE_ON)] = .string(reachable)
            info[.uint(C.PORT)]         = intOrNull(fields.port)
        }

        // I2P: REACHABLE_ON = b32 only when connectable && b32 (Discovery.py:143-144).
        if interfaceType == "I2PInterface", fields.connectable, let b32 = fields.b32 {
            info[.uint(C.REACHABLE_ON)] = .string(b32)
        }

        // RNode radio params (Discovery.py:146-150).
        if interfaceType == "RNodeInterface" {
            info[.uint(C.FREQUENCY)]       = intOrNull(fields.frequency)
            info[.uint(C.BANDWIDTH)]       = intOrNull(fields.bandwidth)
            info[.uint(C.SPREADINGFACTOR)] = intOrNull(fields.sf)
            info[.uint(C.CODINGRATE)]      = intOrNull(fields.cr)
        }

        // Weave radio params (Discovery.py:152-156). MODULATION raw.
        if interfaceType == "WeaveInterface" {
            info[.uint(C.FREQUENCY)]  = intOrNull(fields.frequency)
            info[.uint(C.BANDWIDTH)]  = intOrNull(fields.bandwidth)
            info[.uint(C.CHANNEL)]    = intOrNull(fields.channel)
            info[.uint(C.MODULATION)] = strOrNull(fields.modulation)
        }

        // KISS (or TCPClient+kiss_framing): rewrite INTERFACE_TYPE to KISSInterface
        // and carry FREQUENCY/BANDWIDTH/sanitized-MODULATION (Discovery.py:158-162).
        if interfaceType == "KISSInterface" || (interfaceType == "TCPClientInterface" && fields.kissFraming) {
            info[.uint(C.INTERFACE_TYPE)] = .string("KISSInterface")
            info[.uint(C.FREQUENCY)]      = intOrNull(fields.frequency)
            info[.uint(C.BANDWIDTH)]      = intOrNull(fields.bandwidth)
            info[.uint(C.MODULATION)]     = strOrNull(sanitize(fields.modulation))
        }

        // IFAC credentials only when explicitly published (Discovery.py:164-166).
        if fields.publishIfac {
            info[.uint(C.IFAC_NETNAME)] = strOrNull(sanitize(fields.ifacNetname))
            info[.uint(C.IFAC_NETKEY)]  = strOrNull(sanitize(fields.ifacNetkey))
        }

        // Stamp over SHA-256(packed) (Discovery.py:168-173).
        let packed = packMsgPack(.map(info))
        let stampMaterial = Hashing.fullHash(packed)
        let (stampOpt, stampVal) = DiscoveryStamp.generate(stampMaterial, cost: cost)
        guard let stamp = stampOpt else { return nil }

        // flags + payload (Discovery.py:176-186).
        var flags: UInt8 = 0x00
        let payload: Data
        if encrypt {
            flags |= DiscoveryConstants.FLAG_ENCRYPTED
            guard let netIdentity = networkIdentity else { return nil }
            guard let enc = try? netIdentity.encryptTo(packed + stamp, identityHash: netIdentity.hash) else {
                return nil
            }
            payload = enc
        } else {
            payload = packed + stamp
        }

        var appData = Data([flags])
        appData.append(payload)

        return assemble(
            appData: appData, infoMap: info, transportIdHash: transportIdentity.hash,
            transportEnabled: transportEnabled, stampGeneratedValue: stampVal)
    }

    /// Adversarial crafter (Discovery.py:247-261 receive-path branches; bridge
    /// cmd_discovery_craft_announce): take a GENUINE announce's decoded info map,
    /// apply ONE mutation (drop a key / overwrite INTERFACE_TYPE / wrong-type a
    /// field), re-pack with the SAME serializer, re-stamp the new SHA-256(packed)
    /// PoW, and re-emit `[0x00] || packed || stamp` for replay through
    /// `receivedAnnounce`. Only the stamp/serialization is dropped — never the
    /// protocol logic — so each receiver rejection is attributable to the mutation.
    public static func craftAnnounce(
        base: DiscoveryAnnounce,
        dropField: UInt64?,
        setInterfaceType: String?,
        setFields: [DiscoveryFieldMutation],
        stampValue: Int
    ) -> DiscoveryAnnounce? {
        var info = base.infoMap
        if let drop = dropField {
            info.removeValue(forKey: .uint(drop))
        }
        if let setType = setInterfaceType {
            info[.uint(DiscoveryConstants.INTERFACE_TYPE)] = .string(setType)
        }
        for mut in setFields {
            info[.uint(mut.key)] = mut.value
        }

        let newPacked = packMsgPack(.map(info))
        let infohash = Hashing.fullHash(newPacked)
        let (stampOpt, stampVal) = DiscoveryStamp.generate(infohash, cost: stampValue)
        guard let stamp = stampOpt else { return nil }

        var appData = Data([0x00])
        appData.append(newPacked)
        appData.append(stamp)

        return assemble(
            appData: appData, infoMap: info, transportIdHash: base.transportIdHash,
            transportEnabled: base.transportEnabled, stampGeneratedValue: stampVal)
    }

    /// `InterfaceAnnouncer.__init__` discovery-Destination identity selection
    /// (Discovery.py:54-58): the discovery Destination is built under the network
    /// identity when has_network_identity() else the transport identity; the
    /// SINGLE/IN `rnstransport.discovery.interface` destination hash is
    /// truncated_hash(name_hash || chosen.hash).
    public static func announceIdentity(
        hasNetworkIdentity: Bool,
        networkIdentity: Identity?,
        identity: Identity?
    ) -> (destinationHash: Data, chosenIdentityHash: Data)? {
        guard let chosen = hasNetworkIdentity ? networkIdentity : identity else { return nil }
        let nameHash = Hashing.destinationNameHash(
            appName: DiscoveryConstants.APP_NAME, aspects: ["discovery", "interface"])
        var combined = Data()
        combined.append(nameHash)
        combined.append(chosen.hash)
        return (Hashing.truncatedHash(combined), chosen.hash)
    }

    // MARK: - helpers

    /// Re-split an assembled `app_data` at the flag byte + STAMP_SIZE and report
    /// the parts (Discovery.py:88-92 of the bridge split; matches the receiver's
    /// own re-derivation). For an encrypted announce these are ciphertext fragments.
    private static func assemble(
        appData: Data, infoMap: [MessagePackValue: MessagePackValue],
        transportIdHash: Data, transportEnabled: Bool, stampGeneratedValue: Int
    ) -> DiscoveryAnnounce {
        let flagByte = Int(appData[appData.startIndex])
        let body = Data(appData.dropFirst())
        let stampSize = DiscoveryConstants.STAMP_SIZE
        let packedPart = Data(body.prefix(body.count - stampSize))
        let stampPart = Data(body.suffix(stampSize))
        let infohash = Hashing.fullHash(packedPart)
        return DiscoveryAnnounce(
            appData: appData, flags: flagByte, packedInfo: packedPart, stamp: stampPart,
            infohash: infohash, transportIdHash: transportIdHash,
            transportEnabled: transportEnabled, infoMap: infoMap,
            stampGeneratedValue: stampGeneratedValue)
    }

    private static func strOrNull(_ s: String?) -> MessagePackValue {
        return s.map { MessagePackValue.string($0) } ?? .null
    }

    private static func intOrNull(_ i: Int?) -> MessagePackValue {
        guard let i = i else { return .null }
        return i >= 0 ? .uint(UInt64(i)) : .int(Int64(i))
    }
}
