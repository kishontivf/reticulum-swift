// Ext+Discovery.swift — conformance bridge extension cluster: M-DISCOVERY
//   discovery_sanitize_name        — sender/receiver interface-name sanitizers
//   discovery_validate_address     — is_ip_address / is_ygg_ipv6 / is_hostname
//   discovery_stamp                — LXMF LXStamper proof-of-work primitives
//   discovery_announce_identity    — discovery Destination identity selection
//   discovery_feature_defaults     — opt-in discovery feature default gates
//   discovery_build_announce_appdata — InterfaceAnnouncer.buildAnnounceAppData
//   discovery_craft_announce       — adversarial mutate+restamp of a genuine announce
//   discovery_receive_announce     — InterfaceAnnounceHandler.receivedAnnounce
//   discovery_inject_records       — InterfaceDiscovery resolver staleness/sort
//   discovery_store_record         — InterfaceDiscovery store whitelist/dedup
//
// Ports from reticulum-conformance reference/bridge_server.py
// (cmd_discovery_* at :3016/:3125/:3215/:3271/:3289/:3305/:3392/:3444/:3477/:3574).
//
// EVERY command here is now thin delegation to the REAL RNS.Discovery port that
// lives in the library (Sources/ReticulumSwift/Discovery/): InterfaceAnnouncer
// (sender), InterfaceAnnounceHandler (receiver), InterfaceDiscovery
// (resolver/store), DiscoveryStamp (LXStamper PoW), DiscoveryAddress (address +
// name grammar) and DiscoveredInterface (the record). The bridge only marshals
// JSON params into the library's typed inputs and projects the library's outputs
// back to JSON — it assembles no protocol bytes. The two formerly-throwing
// LIBRARY-GAP commands (discovery_inject_records / discovery_store_record) and
// the net-new discovery_receive_announce now drive the real
// receiver + stateful resolver/store the library gained.
import Foundation
import ReticulumSwift

func handleDiscoveryExtCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // -------------------------------------------------------------------------
    // Interface-name sanitization: receiver-side InterfaceAnnounceHandler
    // .sanitizeName (Discovery.py:205-212) and the sender-side
    // InterfaceAnnouncer.sanitize / DiscoveryAddress.sanitize (Discovery.py:89-94).
    case "discovery_sanitize_name":
        let name = getStringOptional(p, "name")
        return [
            "sanitize_name": InterfaceAnnounceHandler.sanitizeName(name).map { str($0) } ?? .null,
            "sanitize": DiscoveryAddress.sanitize(name).map { str($0) } ?? .null,
        ]

    // -------------------------------------------------------------------------
    // Address validation grammar: DiscoveryAddress.isIPAddress / isYggIPv6 /
    // isHostname (Discovery.py:769-785). isHostname already reports false for any
    // raising input (e.g. ""), matching the cmd's try/except.
    case "discovery_validate_address":
        let address = try getString(p, "address")
        return [
            "is_ip_address": boolean(DiscoveryAddress.isIPAddress(address)),
            "is_ygg_ipv6": boolean(DiscoveryAddress.isYggIPv6(address)),
            "is_hostname": boolean(DiscoveryAddress.isHostname(address)),
        ]

    // -------------------------------------------------------------------------
    // LXStamper proof-of-work primitives (DiscoveryStamp; Discovery.py:172,235-237).
    case "discovery_stamp":
        let op = try getString(p, "op")
        switch op {
        case "workblock":
            let material = try getHex(p, "material")
            let rounds = getIntOptional(p, "expand_rounds") ?? DiscoveryConstants.WORKBLOCK_EXPAND_ROUNDS
            let wb = DiscoveryStamp.workblock(material, rounds: rounds)
            return ["workblock": hex(wb), "length": num(wb.count)]
        case "value":
            let wb = try getHex(p, "workblock")
            let stamp = try getHex(p, "stamp")
            return ["value": num(DiscoveryStamp.value(workblock: wb, stamp: stamp))]
        case "valid":
            let wb = try getHex(p, "workblock")
            let stamp = try getHex(p, "stamp")
            let cost = try getInt(p, "cost")
            return ["valid": boolean(DiscoveryStamp.valid(stamp, cost: cost, workblock: wb))]
        case "generate":
            let material = try getHex(p, "material")
            let cost = try getInt(p, "cost")
            let rounds = getIntOptional(p, "expand_rounds") ?? DiscoveryConstants.WORKBLOCK_EXPAND_ROUNDS
            let (stamp, value) = DiscoveryStamp.generate(material, cost: cost, rounds: rounds)
            return [
                "stamp": stamp.map { hex($0) } ?? .null,
                "value": num(value),
                "stamp_size": num(DiscoveryConstants.STAMP_SIZE),
            ]
        case "default_cost":
            // InterfaceAnnouncer DEFAULT_STAMP_VALUE (Discovery.py:34) and the
            // receiver default required_value (Discovery.py:192) — both literal 14.
            return [
                "default_stamp_value": num(DiscoveryConstants.DEFAULT_STAMP_VALUE),
                "handler_default_required_value": num(DiscoveryConstants.DEFAULT_STAMP_VALUE),
            ]
        default:
            throw BridgeError.invalidData("unknown discovery_stamp op: \(op)")
        }

    // -------------------------------------------------------------------------
    // InterfaceAnnouncer.announceIdentity (Discovery.py:54-58): the discovery
    // Destination is built under the network identity when has_network_identity()
    // else the transport identity; its hash is truncated_hash(name_hash || chosen).
    case "discovery_announce_identity":
        let hasNet = getBoolOptional(p, "has_network_identity") ?? false
        let netIdentity = try getHexOptional(p, "network_identity_priv").map { try Identity(privateKeyBytes: $0) }
        let baseIdentity = try getHexOptional(p, "identity_priv").map { try Identity(privateKeyBytes: $0) }
        guard let result = InterfaceAnnouncer.announceIdentity(
            hasNetworkIdentity: hasNet, networkIdentity: netIdentity, identity: baseIdentity) else {
            throw BridgeError.invalidData("no identity available for discovery announce")
        }
        return [
            "discovery_destination_hash": hex(result.destinationHash),
            "chosen_identity_hash": hex(result.chosenIdentityHash),
            "network_identity_hash": netIdentity.map { hex($0.hash) } ?? .null,
            "identity_hash": baseIdentity.map { hex($0.hash) } ?? .null,
            "app_name": str(DiscoveryConstants.APP_NAME),
        ]

    // -------------------------------------------------------------------------
    // Opt-in discovery feature default gates (DiscoveryFeatureDefaults). FORCED
    // DEVIATION: reticulum-swift models no Reticulum config / Interface discovery
    // flags, so these are the RNS spec-literal opt-in defaults — all OFF.
    case "discovery_feature_defaults":
        return [
            "interface_discoverable": boolean(DiscoveryFeatureDefaults.interfaceDiscoverable),
            "interface_supports_discovery": boolean(DiscoveryFeatureDefaults.interfaceSupportsDiscovery),
            "discover_interfaces": boolean(DiscoveryFeatureDefaults.discoverInterfaces),
            "should_autoconnect_discovered_interfaces":
                boolean(DiscoveryFeatureDefaults.shouldAutoconnectDiscoveredInterfaces),
            "max_autoconnected_interfaces": boolean(DiscoveryFeatureDefaults.maxAutoconnectedInterfaces),
        ]

    // -------------------------------------------------------------------------
    // InterfaceAnnouncer.buildAnnounceAppData (Discovery.py:96-186): app_data =
    // [flags] || msgpack(info) || stamp (or network_identity.encrypt of the same).
    case "discovery_build_announce_appdata":
        guard let a = try discoveryBuildAnnounce(p) else {
            return ["aborted": boolean(true), "app_data": .null]
        }
        return [
            "aborted": boolean(false),
            "app_data": hex(a.appData),
            "flags": num(a.flags),
            "packed_info": hex(a.packedInfo),
            "stamp": hex(a.stamp),
            "infohash": hex(a.infohash),
            "stamp_size": num(DiscoveryConstants.STAMP_SIZE),
            "transport_id": hex(a.transportIdHash),
            "transport_enabled": boolean(a.transportEnabled),
            "default_stamp_value": num(DiscoveryConstants.DEFAULT_STAMP_VALUE),
        ]

    // -------------------------------------------------------------------------
    // Adversarial crafter (Discovery.py:247-261): InterfaceAnnouncer.craftAnnounce
    // — build a genuine announce, mutate ONE decoded field, re-pack + re-stamp,
    // re-emit [0x00] || packed || stamp for replay through receivedAnnounce.
    case "discovery_craft_announce":
        guard let base = try discoveryBuildAnnounce(p) else {
            return ["aborted": boolean(true), "app_data": .null]
        }
        let dropField = p["drop_field"].flatMap(discoveryInt).map { UInt64($0) }
        let setType = getStringOptional(p, "set_interface_type")
        var muts: [DiscoveryFieldMutation] = []
        if let specs = p["set_fields"]?.arrayValue {
            for spec in specs {
                guard case .dict(let sd) = spec,
                      let keyJ = sd["key"], let key = discoveryInt(keyJ) else { continue }
                let kind = sd["kind"]?.stringValue ?? "str"
                let valJ = sd["value"]
                let mv: MessagePackValue
                switch kind {
                case "bytes": mv = .binary(hexToBytes(valJ?.stringValue ?? "") ?? Data())
                case "int":   mv = .int(Int64(valJ.flatMap(discoveryInt) ?? 0))
                case "float": mv = .double(valJ?.doubleValue ?? 0)
                case "bool":  mv = .bool(discoveryBool(valJ))
                default:      mv = .string(valJ?.stringValue ?? "")
                }
                muts.append(DiscoveryFieldMutation(key: UInt64(key), value: mv))
            }
        }
        let cost = getIntOptional(p, "stamp_value") ?? DiscoveryConstants.DEFAULT_STAMP_VALUE
        guard let crafted = InterfaceAnnouncer.craftAnnounce(
            base: base, dropField: dropField, setInterfaceType: setType,
            setFields: muts, stampValue: cost) else {
            return ["aborted": boolean(true), "app_data": .null]
        }
        return [
            "aborted": boolean(false),
            "app_data": hex(crafted.appData),
            "stamp_value": num(crafted.stampGeneratedValue),
            "stamp_size": num(DiscoveryConstants.STAMP_SIZE),
        ]

    // -------------------------------------------------------------------------
    // InterfaceAnnounceHandler.receivedAnnounce (Discovery.py:214-362). Construct
    // the real handler with a capturing callback, feed the app_data, and report
    // the ReceiveOutcome mapped to callback_invoked / callback_info_none /
    // accepted + the surfaced info record.
    case "discovery_receive_announce":
        let appData = try getHex(p, "app_data")
        let requiredValueParam = getIntOptional(p, "required_value") ?? DiscoveryConstants.DEFAULT_STAMP_VALUE
        let useDefault = getBoolOptional(p, "default_required_value") ?? false
        let requiredValue = useDefault ? DiscoveryConstants.DEFAULT_STAMP_VALUE : requiredValueParam

        let netIdentity = try getHexOptional(p, "network_identity_priv").map { try Identity(privateKeyBytes: $0) }
        let sources: [Data] = (p["discovery_sources"]?.arrayValue ?? [])
            .compactMap { hexToBytes($0.stringValue ?? "") }

        let announced: Identity
        if let priv = getHexOptional(p, "announce_identity_priv") {
            announced = try Identity(privateKeyBytes: priv)
        } else {
            announced = Identity()
        }
        let destHash = getHexOptional(p, "destination_hash") ?? announced.hash

        let cap = DiscoveryReceiveCapture()
        let handler = InterfaceAnnounceHandler(
            requiredValue: requiredValue, sources: sources,
            networkIdentity: netIdentity, hops: 0
        ) { rec in
            cap.invocations += 1
            if let r = rec { cap.info = r } else { cap.infoNone = true }
        }
        _ = handler.receivedAnnounce(
            destinationHash: destHash, announcedIdentity: announced, appData: appData)

        var out: Result = [
            "callback_invoked": boolean(cap.invocations > 0),
            "callback_info_none": boolean(cap.infoNone),
            "info_present": boolean(cap.info != nil),
            "accepted": boolean(cap.info != nil),
            "announce_identity_hash": hex(announced.hash),
            "aspect_filter": str(handler.aspectFilter),
            "required_value": num(handler.requiredValue),
            "default_stamp_value": num(DiscoveryConstants.DEFAULT_STAMP_VALUE),
        ]
        if let rec = cap.info {
            out["info"] = discoveryInfoJSON(rec)
        }
        return out

    // -------------------------------------------------------------------------
    // InterfaceDiscovery.injectRecords (Discovery.py:402-448 list + 450-505 store):
    // build genuine records with controlled ages, store, then read back the real
    // status assignment / staleness removal / sort order.
    case "discovery_inject_records":
        let records = p["records"]?.arrayValue ?? []
        var specs: [DiscoveryInjectSpec] = []
        for r in records {
            guard case .dict(let rd) = r else { continue }
            let name = rd["name"]?.stringValue ?? ""
            let age = rd["age_seconds"]?.doubleValue ?? 0
            let sv = rd["stamp_value"]?.intValue ?? 6
            let valueOverride = rd["value"]?.intValue
            specs.append(DiscoveryInjectSpec(
                name: name, ageSeconds: age, stampValue: sv, valueOverride: valueOverride))
        }
        let disc = InterfaceDiscovery(requiredValue: DiscoveryConstants.DEFAULT_STAMP_VALUE)
        let result = disc.injectRecords(specs)
        let requested = JSONValue.array(result.requested.map {
            JSONValue.dict(["name": str($0.name), "discovery_hash": hex($0.discoveryHash)])
        })
        let listed = JSONValue.array(result.listed.map { rec in
            JSONValue.dict([
                "name": str(rec.name),
                "status": rec.status.map { str($0) } ?? .null,
                "status_code": rec.statusCode.map { num($0) } ?? .null,
                "value": num(rec.value),
                "last_heard": rec.lastHeard.map { num($0) } ?? .null,
                "discovery_hash": hex(rec.discoveryHash),
            ])
        })
        return [
            "requested": requested,
            "listed": listed,
            "threshold_unknown": num(Int(DiscoveryConstants.THRESHOLD_UNKNOWN)),
            "threshold_stale": num(Int(DiscoveryConstants.THRESHOLD_STALE)),
            "threshold_remove": num(Int(DiscoveryConstants.THRESHOLD_REMOVE)),
            "status_available": num(DiscoveryConstants.STATUS_AVAILABLE),
            "status_unknown": num(DiscoveryConstants.STATUS_UNKNOWN),
            "status_stale": num(DiscoveryConstants.STATUS_STALE),
        ]

    // -------------------------------------------------------------------------
    // InterfaceDiscovery store whitelist / dedup / list-time purge: receive a
    // genuine (or type-forced) record `repeat` times through the real receiver,
    // store via interfaceDiscovered, then read back stored/heard_count/listing.
    case "discovery_store_record":
        return try discoveryStoreRecord(p)

    default:
        return nil
    }
}

// MARK: - receive callback capture

/// Mirrors the python bridge's `invoked`/`captured` dicts so the bridge can
/// observe the handler's callback exactly as RNS fires it (cmd_discovery_receive_
/// announce, bridge_server.py:158-166).
private final class DiscoveryReceiveCapture {
    var invocations = 0
    var infoNone = false
    var info: DiscoveredInterface?
}

// MARK: - announce build marshalling

/// Parse the JSON `fields` map + identities into the library's typed inputs and
/// drive InterfaceAnnouncer.buildAnnounceAppData.
private func discoveryBuildAnnounce(_ p: [String: JSONValue]) throws -> DiscoveryAnnounce? {
    let interfaceType = try getString(p, "interface_type")
    // stamp_value: nil/absent (or null) -> library applies DEFAULT_STAMP_VALUE.
    let stampValue = getIntOptional(p, "stamp_value")
    let transportEnabled = getBoolOptional(p, "transport_enabled") ?? false
    let encrypt = getBoolOptional(p, "encrypt") ?? false

    let transportIdentity: Identity
    if let priv = getHexOptional(p, "transport_identity_priv") {
        transportIdentity = try Identity(privateKeyBytes: priv)
    } else {
        transportIdentity = Identity()
    }
    let networkIdentity = try getHexOptional(p, "network_identity_priv").map { try Identity(privateKeyBytes: $0) }

    return InterfaceAnnouncer.buildAnnounceAppData(
        interfaceType: interfaceType,
        fields: discoveryFieldsFromJSON(p),
        stampValue: stampValue,
        encrypt: encrypt,
        transportEnabled: transportEnabled,
        transportIdentity: transportIdentity,
        networkIdentity: networkIdentity)
}

private func discoveryFieldsFromJSON(_ p: [String: JSONValue]) -> DiscoveryFields {
    let f: [String: JSONValue]
    if case .dict(let d)? = p["fields"] { f = d } else { f = [:] }
    return DiscoveryFields(
        name: getStringOptional(f, "name"),
        reachableOn: getStringOptional(f, "reachable_on"),
        port: getIntOptional(f, "port"),
        latitude: discoveryCoordScalar(f, "latitude"),
        longitude: discoveryCoordScalar(f, "longitude"),
        height: discoveryCoordScalar(f, "height"),
        publishIfac: getBoolOptional(f, "publish_ifac") ?? false,
        ifacNetname: getStringOptional(f, "ifac_netname"),
        ifacNetkey: getStringOptional(f, "ifac_netkey"),
        kissFraming: getBoolOptional(f, "kiss_framing") ?? false,
        connectable: getBoolOptional(f, "connectable") ?? false,
        b32: getStringOptional(f, "b32"),
        frequency: getIntOptional(f, "frequency"),
        bandwidth: getIntOptional(f, "bandwidth"),
        sf: getIntOptional(f, "sf"),
        cr: getIntOptional(f, "cr"),
        channel: getIntOptional(f, "channel"),
        modulation: getStringOptional(f, "modulation"))
}

/// A raw coordinate value carries through with its JSON type (numeric -> float,
/// string -> string for the receiver's None-or-float negative test, absent/null
/// -> none) so the sender embeds exactly what RNS would.
private func discoveryCoordScalar(_ f: [String: JSONValue], _ key: String) -> DiscoveryScalar {
    guard let v = f[key] else { return .none }
    switch v {
    case .double(let d): return .double(d)
    case .int(let i): return .double(Double(i))
    case .string(let s): return .string(s)
    case .bool(let b): return .bool(b)
    case .null: return .none
    default: return .none
    }
}

// MARK: - store_record

private func discoveryStoreRecord(_ p: [String: JSONValue]) throws -> Result {
    let setType = getStringOptional(p, "set_interface_type")
    let repeatCount = getIntOptional(p, "repeat") ?? 1
    let stampValue = getIntOptional(p, "stamp_value") ?? 6

    let fields: DiscoveryFields
    if case .dict? = p["fields"] {
        fields = discoveryFieldsFromJSON(p)
    } else {
        let nm = getStringOptional(p, "name") ?? "Node"
        fields = DiscoveryFields(name: nm, reachableOn: "example.com", port: 4242)
    }

    let announced: Identity
    if let priv = getHexOptional(p, "announce_identity_priv") {
        announced = try Identity(privateKeyBytes: priv)
    } else {
        announced = Identity()
    }
    let recvSources: [Data] = (p["recv_sources"]?.arrayValue ?? [])
        .compactMap { hexToBytes($0.stringValue ?? "") }

    let transportIdentity = Identity()
    guard let base = InterfaceAnnouncer.buildAnnounceAppData(
        interfaceType: "TCPServerInterface", fields: fields, stampValue: stampValue,
        encrypt: false, transportEnabled: true,
        transportIdentity: transportIdentity, networkIdentity: nil) else {
        return discoveryStoreEmptyResult(announced: announced)
    }

    // Force a non-default interface type through the real craft path when asked
    // (proves the resolver-store DISCOVERABLE_TYPES whitelist excludes TCPClient).
    let appData: Data
    if let st = setType {
        guard let crafted = InterfaceAnnouncer.craftAnnounce(
            base: base, dropField: nil, setInterfaceType: st,
            setFields: [], stampValue: stampValue) else {
            return discoveryStoreEmptyResult(announced: announced)
        }
        appData = crafted.appData
    } else {
        appData = base.appData
    }

    let disc = InterfaceDiscovery(requiredValue: stampValue)
    var recordType: String?
    var discoveryHash: Data?
    var receivedOk = false
    for _ in 0..<max(0, repeatCount) {
        let handler = InterfaceAnnounceHandler(requiredValue: stampValue, sources: recvSources, hops: 0)
        let outcome = handler.receivedAnnounce(
            destinationHash: announced.hash, announcedIdentity: announced, appData: appData)
        guard case .accepted(let rec) = outcome else { break }
        receivedOk = true
        recordType = rec.type
        discoveryHash = rec.discoveryHash
        disc.interfaceDiscovered(rec)
    }

    // Filesystem-existence check is BEFORE the list-time purge (Discovery.py order).
    let stored = discoveryHash.map { disc.isStored($0) } ?? false

    // Optional trust-revocation purge: apply a (possibly different) allowlist at
    // LIST time (Discovery.py:417-418).
    if let lsJ = p["list_sources"] {
        disc.discoverySources = (lsJ.arrayValue ?? []).compactMap { hexToBytes($0.stringValue ?? "") }
    }
    let listed = disc.listDiscoveredInterfaces()
    let listedNames = listed.map { $0.name }

    var heardCount: JSONValue = .null
    if let dh = discoveryHash, let rec = listed.first(where: { $0.discoveryHash == dh }) {
        heardCount = rec.heardCount.map { num($0) } ?? .null
    }

    return [
        "received": boolean(receivedOk),
        "record_type": recordType.map { str($0) } ?? .null,
        "stored": boolean(stored),
        "heard_count": heardCount,
        "discovery_hash": discoveryHash.map { hex($0) } ?? .null,
        "listed_names": .array(listedNames.map { str($0) }),
        "announce_identity_hash": hex(announced.hash),
        "discoverable_types": .array(InterfaceDiscovery.DISCOVERABLE_TYPES.map { str($0) }),
        "discoverable_interface_types":
            .array(DiscoveryConstants.DISCOVERABLE_INTERFACE_TYPES.map { str($0) }),
    ]
}

private func discoveryStoreEmptyResult(announced: Identity) -> Result {
    return [
        "received": boolean(false),
        "record_type": .null,
        "stored": boolean(false),
        "heard_count": .null,
        "discovery_hash": .null,
        "listed_names": .array([]),
        "announce_identity_hash": hex(announced.hash),
        "discoverable_types": .array(InterfaceDiscovery.DISCOVERABLE_TYPES.map { str($0) }),
        "discoverable_interface_types":
            .array(DiscoveryConstants.DISCOVERABLE_INTERFACE_TYPES.map { str($0) }),
    ]
}

// MARK: - info-record projection

/// Project a DiscoveredInterface to the JSON `info` dict (bytes -> hex), mirroring
/// the python bridge's `safe = {k: bytes_to_hex(v) if isinstance(v, bytes) ...}`.
private func discoveryInfoJSON(_ rec: DiscoveredInterface) -> JSONValue {
    var out: [String: JSONValue] = [:]
    for (k, v) in rec.toDictionary() {
        out[k] = discoveryValueToJSON(v)
    }
    return .dict(out)
}

private func discoveryValueToJSON(_ v: DiscoveryValue) -> JSONValue {
    switch v {
    case .string(let s): return .string(s)
    case .int(let i):    return .int(i)
    case .double(let d): return .double(d)
    case .bool(let b):   return .bool(b)
    case .bytes(let d):  return .string(bytesToHex(d))
    case .null:          return .null
    }
}

// MARK: - JSON value coercions for craft mutations

private func discoveryInt(_ v: JSONValue) -> Int? {
    switch v {
    case .int(let i): return i
    case .double(let d): return Int(d)
    case .string(let s): return Int(s)
    default: return nil
    }
}

private func discoveryBool(_ v: JSONValue?) -> Bool {
    switch v {
    case .some(.bool(let b)): return b
    case .some(.int(let i)): return i != 0
    case .some(.double(let d)): return d != 0
    case .some(.string(let s)): return !s.isEmpty
    default: return false
    }
}
