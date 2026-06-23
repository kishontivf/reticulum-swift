// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  InterfaceDiscovery.swift
//  ReticulumSwift
//
//  Interface-discovery RESOLVER / STORE — a 1:1 port of the record-store half of
//  `RNS.Discovery.InterfaceDiscovery`: `interface_discovered` (Discovery.py:
//  450-505, store/dedup) and `list_discovered_interfaces` (Discovery.py:402-448,
//  re-sanitize / purge / status assignment / sort), plus an `injectRecords` test
//  affordance.
//
//  BACKING-STORE DEVIATION (category a): RNS persists one msgpack file per
//  discovery_hash under `storagepath`; this port uses an injectable in-memory
//  store defaulting to `[Data: DiscoveredInterface]` keyed by discovery_hash —
//  identical one-record-per-hash dedup / purge semantics without iOS-sandbox
//  filesystem coupling. Cross-launch persistence is deferred (not needed for
//  conformance). Documented in port-deviations.md.
//
//  The autoconnect / monitor / teardown / BlackholeUpdater halves of
//  Discovery.py (Transport interface lifecycle, BackboneClientInterface) are OUT
//  OF SCOPE per the skip list and are not ported.
//

import Foundation

/// A record specification for `injectRecords` (the staleness/sort test affordance).
public struct DiscoveryInjectSpec: Sendable {
    public let name: String
    public let ageSeconds: Double
    public let stampValue: Int
    public let valueOverride: Int?
    public init(name: String, ageSeconds: Double, stampValue: Int = 6, valueOverride: Int? = nil) {
        self.name = name
        self.ageSeconds = ageSeconds
        self.stampValue = stampValue
        self.valueOverride = valueOverride
    }
}

/// The result of an `injectRecords` run.
public struct DiscoveryInjectResult: Sendable {
    public let requested: [(name: String, discoveryHash: Data)]
    public let listed: [DiscoveredInterface]
}

/// The interface-discovery resolver/store (Discovery.py InterfaceDiscovery).
public final class InterfaceDiscovery {
    /// Resolver STORE whitelist (Discovery.py:377) — SIX types, EXCLUDING
    /// TCPClientInterface. DISTINCT from the handler/announcer 7-type
    /// `DiscoveryConstants.DISCOVERABLE_INTERFACE_TYPES`: a TCPClientInterface
    /// announce is accepted by the receiver but never stored/listed here.
    public static let DISCOVERABLE_TYPES = [
        "BackboneInterface", "TCPServerInterface", "I2PInterface",
        "RNodeInterface", "WeaveInterface", "KISSInterface",
    ]

    /// Required stamp value for the internal receiver (Discovery.py:381-382).
    public let requiredValue: Int

    /// List-time source allowlist (`interface_discovery_sources()`,
    /// Discovery.py:405). Empty == no allowlist (no trust-revocation purge).
    public var discoverySources: [Data]

    /// In-memory record store keyed by discovery_hash (deviation; see file header).
    private var store: [Data: DiscoveredInterface] = [:]

    public init(
        requiredValue: Int = DiscoveryConstants.DEFAULT_STAMP_VALUE,
        discoverySources: [Data] = []
    ) {
        self.requiredValue = requiredValue
        self.discoverySources = discoverySources
    }

    /// True when a record for `discoveryHash` is persisted in the store (the
    /// filesystem-existence check RNS performs, Discovery.py:463/650 of bridge).
    public func isStored(_ discoveryHash: Data) -> Bool {
        return store[discoveryHash] != nil
    }

    /// Clear the store (one-record-per-hash store must be reset per
    /// inject/store invocation to avoid cross-test state leak).
    public func clear() {
        store.removeAll()
    }

    /// `interface_discovered` (Discovery.py:450-505). Drops the record if its type
    /// is not in `DISCOVERABLE_TYPES` (excludes TCPClientInterface). Otherwise keys
    /// storage by discovery_hash: first sighting writes discovered=received,
    /// last_heard=received, heard_count=0; a repeat (same transport_id+name => same
    /// discovery_hash) preserves discovered, sets last_heard=received and increments
    /// heard_count. N stores -> one record, heard_count N-1.
    public func interfaceDiscovered(_ info: DiscoveredInterface) {
        guard Self.DISCOVERABLE_TYPES.contains(info.type) else { return }
        let key = info.discoveryHash

        if store[key] == nil {
            var rec = info
            rec.discovered = info.received
            rec.lastHeard = info.received
            rec.heardCount = 0
            store[key] = rec
        } else {
            let last = store[key]!
            let discovered = last.discovered ?? info.received
            let heardCount = last.heardCount ?? 0
            var rec = info
            rec.discovered = discovered
            rec.lastHeard = info.received
            rec.heardCount = heardCount + 1
            store[key] = rec
        }
    }

    /// `list_discovered_interfaces` (Discovery.py:402-448). For each stored record:
    /// re-sanitize name; PURGE if heard_delta>THRESHOLD_REMOVE(168h), or sources
    /// configured and network_id missing/not-allowlisted (trust revocation), or
    /// type missing/not in DISCOVERABLE_TYPES, or reachable_on present-and-invalid.
    /// Else assign status (>72h stale / >24h unknown / else available), set
    /// status_code, apply only_available/only_transport filters, then sort by
    /// (status_code, value, last_heard) DESCENDING.
    public func listDiscoveredInterfaces(onlyAvailable: Bool = false, onlyTransport: Bool = false) -> [DiscoveredInterface] {
        let now = Date().timeIntervalSince1970
        let C = DiscoveryConstants.self
        let sources = discoverySources
        var result: [DiscoveredInterface] = []
        var toRemove: [Data] = []

        for (key, stored) in store {
            var info = stored
            let lastHeard = info.lastHeard ?? info.received
            let heardDelta = now - lastHeard
            // Re-sanitize the name at list time (Discovery.py:414).
            info.name = InterfaceAnnounceHandler.sanitizeName(info.name) ?? info.name

            var shouldRemove = false
            if heardDelta > C.THRESHOLD_REMOVE {
                shouldRemove = true
            } else if !sources.isEmpty && !sourcesContains(sources, hexNetworkId: info.networkId) {
                // network_id always present in our records; not-in-allowlist purges
                // (trust revocation at list time, Discovery.py:417-418).
                shouldRemove = true
            } else if !Self.DISCOVERABLE_TYPES.contains(info.type) {
                shouldRemove = true
            } else if let reachable = info.reachableOn,
                      !(DiscoveryAddress.isIPAddress(reachable) || DiscoveryAddress.isHostname(reachable)) {
                shouldRemove = true
            }

            if shouldRemove {
                toRemove.append(key)
                continue
            }

            // Status by heard-delta (Discovery.py:428-430).
            let status: String
            if heardDelta > C.THRESHOLD_STALE { status = "stale" }
            else if heardDelta > C.THRESHOLD_UNKNOWN { status = "unknown" }
            else { status = "available" }
            info.status = status
            info.statusCode = C.STATUS_CODE_MAP[status]

            // Filters (Discovery.py:433-440).
            if onlyAvailable || onlyTransport {
                var shouldAppend = true
                if onlyAvailable && status != "available" { shouldAppend = false }
                if onlyTransport && !info.transport { shouldAppend = false }
                if shouldAppend { result.append(info) }
            } else {
                result.append(info)
            }
        }

        // Persist the purges (RNS os.unlink, Discovery.py:424).
        for key in toRemove { store.removeValue(forKey: key) }

        // Sort by (status_code, value, last_heard) DESCENDING (Discovery.py:447).
        result.sort { a, b in
            let ac = a.statusCode ?? 0, bc = b.statusCode ?? 0
            if ac != bc { return ac > bc }
            if a.value != b.value { return a.value > b.value }
            let al = a.lastHeard ?? a.received, bl = b.lastHeard ?? b.received
            return al > bl
        }
        return result
    }

    private func sourcesContains(_ sources: [Data], hexNetworkId: String) -> Bool {
        guard let bytes = hexToData(hexNetworkId) else { return false }
        return sources.contains(bytes)
    }

    /// `injectRecords` (category-a instrumentation; bridge cmd_discovery_inject_records,
    /// :3477). For each spec builds a GENUINE TCPServer announce, receives it to a
    /// real info record, back-dates received/last_heard by age_seconds (and
    /// optionally overrides the stamp value for the sort key), stores via
    /// `interfaceDiscovered`, then returns `listDiscoveredInterfaces` output.
    /// Clears the store first so each invocation is deterministic.
    public func injectRecords(_ specs: [DiscoveryInjectSpec]) -> DiscoveryInjectResult {
        clear()
        let now = Date().timeIntervalSince1970
        var requested: [(name: String, discoveryHash: Data)] = []

        for spec in specs {
            let transportIdentity = Identity()
            let announced = Identity()
            guard let announce = InterfaceAnnouncer.buildAnnounceAppData(
                interfaceType: "TCPServerInterface",
                fields: DiscoveryFields(name: spec.name, reachableOn: "example.com", port: 4242),
                stampValue: spec.stampValue,
                encrypt: false,
                transportEnabled: true,
                transportIdentity: transportIdentity,
                networkIdentity: nil
            ) else { continue }

            let handler = InterfaceAnnounceHandler(requiredValue: spec.stampValue, hops: 0)
            let outcome = handler.receivedAnnounce(
                destinationHash: announced.hash, announcedIdentity: announced, appData: announce.appData)
            guard case .accepted(var record) = outcome else { continue }

            record.received = now - spec.ageSeconds
            if let v = spec.valueOverride { record.value = v }
            interfaceDiscovered(record)
            requested.append((spec.name, record.discoveryHash))
        }

        return DiscoveryInjectResult(requested: requested, listed: listDiscoveredInterfaces())
    }
}

/// Parse undelimited hex into Data (for network_id allowlist comparison).
private func hexToData(_ hex: String) -> Data? {
    let chars = Array(hex)
    guard chars.count % 2 == 0 else { return nil }
    var data = Data(capacity: chars.count / 2)
    var i = 0
    while i < chars.count {
        guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else { return nil }
        data.append(UInt8(hi << 4 | lo))
        i += 2
    }
    return data
}
