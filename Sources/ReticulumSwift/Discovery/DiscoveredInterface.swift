// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  DiscoveredInterface.swift
//  ReticulumSwift
//
//  The receiver/store record for a discovered interface — the typed Swift
//  encapsulation of the dynamic `info` dict RNS builds in
//  `InterfaceAnnounceHandler.received_announce` (Discovery.py:263-357) and reads
//  back in `InterfaceDiscovery.list_discovered_interfaces` (Discovery.py:402-448).
//
//  DEVIATION (category a — Swift encapsulation vs Python's dynamic dict): RNS
//  models the record as a plain dict whose key set varies by interface type; the
//  Swift port uses a struct with typed core fields plus per-type optionals, and a
//  `toDictionary()` projection that OMITS nil keys so a consumer's JSON view
//  naturally satisfies the per-type negative assertions ("sf" not present for a
//  Weave record, "channel" not present for KISS, radio keys not present for
//  Backbone). Documented in port-deviations.md.
//

import Foundation

/// A scalar value in a `DiscoveredInterface.toDictionary()` projection. Mirrors
/// the heterogeneous value types RNS stores in its `info` dict (str/int/float/
/// bool/bytes/None).
public enum DiscoveryValue: Equatable, Sendable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case bytes(Data)
    case null
}

/// A discovered-interface record (Discovery.py:263-357 `info` dict).
public struct DiscoveredInterface: Equatable, Sendable {
    // MARK: - core fields (always present; Discovery.py:263-274)
    public var type: String
    public var transport: Bool
    public var name: String
    public var received: TimeInterval
    public var stamp: Data
    public var value: Int
    /// Undelimited lowercase hex of the 16-byte transport identity hash.
    public var transportId: String
    /// Undelimited lowercase hex of the 16-byte announcing identity hash.
    public var networkId: String
    public var hops: Int
    /// None-or-float coordinates (Discovery.py:272-274); nil == announced None.
    public var latitude: Double?
    public var longitude: Double?
    public var height: Double?
    /// full_hash((transport_id_hex || name).utf8) (Discovery.py:356-357).
    public var discoveryHash: Data

    // MARK: - optional IFAC credentials (Discovery.py:276-277)
    public var ifacNetname: String?
    public var ifacNetkey: String?

    // MARK: - per-type optional fields (Discovery.py:279-354)
    public var reachableOn: String?
    public var port: Int?
    public var frequency: Int?
    public var bandwidth: Int?
    public var sf: Int?
    public var cr: Int?
    public var channel: Int?
    public var modulation: String?
    /// The rnstatus -D config entry composed per type (Discovery.py:294-354).
    public var configEntry: String?

    // MARK: - resolver-store bookkeeping (Discovery.py:466-494)
    public var discovered: TimeInterval?
    public var lastHeard: TimeInterval?
    public var heardCount: Int?

    // MARK: - list-time status (Discovery.py:428-432)
    public var status: String?
    public var statusCode: Int?

    public init(
        type: String,
        transport: Bool,
        name: String,
        received: TimeInterval,
        stamp: Data,
        value: Int,
        transportId: String,
        networkId: String,
        hops: Int,
        latitude: Double?,
        longitude: Double?,
        height: Double?,
        discoveryHash: Data
    ) {
        self.type = type
        self.transport = transport
        self.name = name
        self.received = received
        self.stamp = stamp
        self.value = value
        self.transportId = transportId
        self.networkId = networkId
        self.hops = hops
        self.latitude = latitude
        self.longitude = longitude
        self.height = height
        self.discoveryHash = discoveryHash
    }

    /// Project the record to a JSON-friendly dictionary, OMITTING nil-valued
    /// optional keys so the projection mirrors RNS's per-type-varying `info` dict
    /// (a Weave record carries no "sf"/"cr", a Backbone record no radio keys).
    /// The mandatory core fields — including the None-or-float coordinates — are
    /// always present (Discovery.py:263-274 always populate them).
    public func toDictionary() -> [String: DiscoveryValue] {
        var d: [String: DiscoveryValue] = [
            "type":         .string(type),
            "transport":    .bool(transport),
            "name":         .string(name),
            "received":     .double(received),
            "stamp":        .bytes(stamp),
            "value":        .int(value),
            "transport_id": .string(transportId),
            "network_id":   .string(networkId),
            "hops":         .int(hops),
            "latitude":     latitude.map { .double($0) } ?? .null,
            "longitude":    longitude.map { .double($0) } ?? .null,
            "height":       height.map { .double($0) } ?? .null,
            "discovery_hash": .bytes(discoveryHash),
        ]
        if let v = ifacNetname { d["ifac_netname"] = .string(v) }
        if let v = ifacNetkey  { d["ifac_netkey"]  = .string(v) }
        if let v = reachableOn { d["reachable_on"] = .string(v) }
        if let v = port        { d["port"]         = .int(v) }
        if let v = frequency   { d["frequency"]    = .int(v) }
        if let v = bandwidth   { d["bandwidth"]    = .int(v) }
        if let v = sf          { d["sf"]           = .int(v) }
        if let v = cr          { d["cr"]           = .int(v) }
        if let v = channel     { d["channel"]      = .int(v) }
        if let v = modulation  { d["modulation"]   = .string(v) }
        if let v = configEntry { d["config_entry"] = .string(v) }
        if let v = discovered  { d["discovered"]   = .double(v) }
        if let v = lastHeard   { d["last_heard"]   = .double(v) }
        if let v = heardCount  { d["heard_count"]  = .int(v) }
        if let v = status      { d["status"]       = .string(v) }
        if let v = statusCode  { d["status_code"]  = .int(v) }
        return d
    }
}

/// Undelimited lowercase hex of `data` — RNS `hexrep(..., delimit=False)`
/// (Discovery.py:269-270,356).
func discoveryHexrep(_ data: Data) -> String {
    var s = ""
    s.reserveCapacity(data.count * 2)
    for b in data { s += String(format: "%02x", b) }
    return s
}
