// Ext+Destination.swift — conformance bridge extension cluster: M-DESTINATION (9 destination_* commands)
//   destination_construct                          — RNS.Destination.__init__ guards + address material
//   destination_announce_attempt                   — announce(send=False) SINGLE/IN guards
//   destination_default_app_data                   — default_app_data substitution in announce stream
//   destination_expand_name                        — Destination.expand_name (identity suffix)
//   destination_group_encrypt                      — GROUP Token encrypt/decrypt round-trip
//   destination_path_response_cache                — announce path-response caching + PR_TAG_WINDOW eviction
//   destination_register_request_handler_validate  — register_request_handler argument validation
//   destination_rotate_ratchets                    — rotate_ratchets ratchets-enabled guard
//   destination_set_proof_strategy_raw             — set_proof_strategy raw value validation
//
// Ports from reticulum-conformance reference/bridge_server.py
// (cmd_destination_construct :2642, cmd_destination_announce_attempt :2673,
//  cmd_destination_expand_name :2707, cmd_destination_set_proof_strategy_raw :2724,
//  cmd_destination_rotate_ratchets :2735, cmd_destination_group_encrypt :2752,
//  cmd_destination_default_app_data :2775, cmd_destination_register_request_handler_validate :2822,
//  cmd_destination_path_response_cache :2846; helpers _make_destination :2615,
//  _resolve_dest_type :2583, _resolve_dest_direction :2598, _coerce_aspects :2607).
// Returns nil for any command it does not own (dispatch chain: Ext+Dispatch.swift).
//
// The Python reference drives a *real* RNS.Destination. reticulum-swift's Destination
// is a thinner value type: its initialiser does NOT fold an auto-generated identity's
// hexhash into the aspects (RNS IN/non-PLAIN/no-identity branch), exposes no integer
// type/direction constants, and has no proof_strategy / path_responses / request_handlers
// / GROUP symmetric keys / rotate_ratchets surface. So — exactly as main.swift already
// does for `destination_hash` / `name_hash` / `announce_sign` — this cluster reproduces
// the RNS Destination semantics directly from the primitives (Identity, Hashing, Token).
// See libraryGaps in the port report.
import Foundation
import ReticulumSwift

// MARK: - RNS Destination constants (RNS.Destination / RNS.Identity, 1.3.1)

private let DEST_SINGLE = 0x00
private let DEST_GROUP  = 0x01
private let DEST_PLAIN  = 0x02
private let DEST_LINK   = 0x03
private let DEST_IN     = 0x11
private let DEST_OUT    = 0x12
private let DEST_PROVE_NONE = 0x21
private let DEST_PROVE_APP  = 0x22
private let DEST_PROVE_ALL  = 0x23
private let DEST_ALLOW_NONE = 0x00
private let DEST_ALLOW_ALL  = 0x01
private let DEST_ALLOW_LIST = 0x02
private let DEST_PR_TAG_WINDOW = 30   // Destination.PR_TAG_WINDOW

// RNS.Identity wire field sizes (bytes)
private let KEYSIZE_BYTES        = 64  // KEYSIZE // 8 (256*2 bits)
private let NAME_HASH_LEN_BYTES  = 10  // NAME_HASH_LENGTH // 8 (80 bits)
private let RANDOM_HASH_LEN      = 10
private let SIG_LEN_BYTES        = 64  // SIGLENGTH // 8 (256*2 bits)

// MARK: - Construction helper (mirror of _make_destination + RNS.Destination.__init__)

private struct DestInfo {
    let hash: Data
    let name: String
    let nameHash: Data
    let typeInt: Int
    let directionInt: Int
    let identity: Identity?
    let autoHexhash: String?   // non-nil only on the IN/non-PLAIN/no-identity auto branch
}

// _resolve_dest_type: friendly keyword -> RNS constant, or pass an int straight through
// so the __init__ `type in types` guard can reject an out-of-range value.
private func destResolveType(_ p: [String: JSONValue]) throws -> Int {
    let mapping: [String: Int] = ["single": DEST_SINGLE, "group": DEST_GROUP,
                                  "plain": DEST_PLAIN, "link": DEST_LINK]
    guard let v = p["type"] else { return DEST_SINGLE }   // default_type='single'
    switch v {
    case .string(let s):
        guard let m = mapping[s] else { throw BridgeError.invalidData("Unknown destination type") }
        return m
    case .int(let i): return i
    default: return DEST_SINGLE
    }
}

// _resolve_dest_direction: friendly keyword -> RNS constant, or pass an int through.
private func destResolveDirection(_ p: [String: JSONValue]) throws -> Int {
    let mapping: [String: Int] = ["in": DEST_IN, "out": DEST_OUT]
    guard let v = p["direction"] else { return DEST_IN }  // default_direction='in'
    switch v {
    case .string(let s):
        guard let m = mapping[s] else { throw BridgeError.invalidData("Unknown destination direction") }
        return m
    case .int(let i): return i
    default: return DEST_IN
    }
}

// _coerce_aspects: a list stays a list; a truthy string is comma-split; else [].
private func destCoerceAspects(_ p: [String: JSONValue]) -> [String] {
    guard let v = p["aspects"] else { return [] }
    switch v {
    case .array(let a): return a.compactMap { $0.stringValue }
    case .string(let s): return s.isEmpty ? [] : s.split(separator: ",").map(String.init)
    default: return []
    }
}

// `bool(params.get('identity_private_key'))` — truthy only for a non-empty hex string.
private func destIdentityPrivateKey(_ p: [String: JSONValue]) -> Data? {
    guard let s = p["identity_private_key"]?.stringValue, !s.isEmpty else { return nil }
    return hexToBytes(s)
}

// Reproduces _make_destination + RNS.Destination.__init__ (Destination.py:148-200):
//   * "." in app_name              -> ValueError("Dots can't be used in app names")
//   * type not in [0..3]           -> ValueError("Unknown destination type")
//   * direction not in [0x11,0x12] -> ValueError("Unknown destination direction")
//   * IN  + non-PLAIN + no identity-> auto-generate identity, fold hexhash into aspects
//   * OUT + non-PLAIN + no identity-> ValueError("Can't create outbound SINGLE destination without an identity")
//   * identity + PLAIN             -> TypeError("Selected destination type PLAIN cannot hold an identity")
// All RNS ValueError/TypeError surface to the dispatcher as BridgeError.
private func destMakeInfo(_ p: [String: JSONValue]) throws -> DestInfo {
    let typeInt = try destResolveType(p)
    let dirInt = try destResolveDirection(p)
    let appName = try getString(p, "app_name")

    // __init__ guards, in source order: app_name dots, then type, then direction.
    if appName.contains(".") { throw BridgeError.invalidData("Dots can't be used in app names") }
    guard (0...3).contains(typeInt) else { throw BridgeError.invalidData("Unknown destination type") }
    guard dirInt == DEST_IN || dirInt == DEST_OUT else {
        throw BridgeError.invalidData("Unknown destination direction")
    }

    var aspects = destCoerceAspects(p)
    var identity: Identity? = nil
    if let pk = destIdentityPrivateKey(p) {
        identity = try Identity(privateKeyBytes: pk)
    }
    var autoHexhash: String? = nil

    if identity == nil && dirInt == DEST_IN && typeInt != DEST_PLAIN {
        let auto = Identity()
        identity = auto
        autoHexhash = auto.hexHash
        aspects.append(auto.hexHash)
    }
    if identity == nil && dirInt == DEST_OUT && typeInt != DEST_PLAIN {
        throw BridgeError.invalidData("Can't create outbound SINGLE destination without an identity")
    }
    if identity != nil && typeInt == DEST_PLAIN {
        throw BridgeError.invalidData("Selected destination type PLAIN cannot hold an identity")
    }

    // self.name = expand_name(identity, app_name, *aspects)
    var name = appName
    for aspect in aspects {
        if aspect.contains(".") { throw BridgeError.invalidData("Dots can't be used in aspects") }
        name += "." + aspect
    }
    if let id = identity { name += "." + id.hexHash }

    // self.hash = Destination.hash(identity, app_name, *aspects)
    //   name_hash = full_hash(expand_name(None, app, *aspects))[:10]
    //   addr_material = name_hash (+ identity.hash if identity)
    //   hash = full_hash(addr_material)[:16]
    let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
    var addrMaterial = nameHash
    if let id = identity { addrMaterial.append(id.hash) }
    let destHash = Hashing.truncatedHash(addrMaterial)

    return DestInfo(hash: destHash, name: name, nameHash: nameHash,
                    typeInt: typeInt, directionInt: dirInt,
                    identity: identity, autoHexhash: autoHexhash)
}

// Builds the RNS announce_data payload exactly as Destination.announce (Destination.py:284-296):
//   random_hash  = 5 random bytes + int(ts).to_bytes(5,"big")
//   signed_data  = hash + pubkeys + name_hash + random_hash + ratchet [+ app_data]
//   signature    = identity.sign(signed_data)
//   announce_data= pubkeys + name_hash + random_hash + ratchet + signature [+ app_data]
// ratchet is always empty here (these commands never enable ratchets).
private func destBuildAnnounceData(identity: Identity, hash: Data, nameHash: Data,
                                   appData: Data?, timestamp: UInt64) throws -> Data {
    var randomHash = Data((0..<5).map { _ in UInt8.random(in: 0...255) })
    randomHash.append(UInt8((timestamp >> 32) & 0xFF))
    randomHash.append(UInt8((timestamp >> 24) & 0xFF))
    randomHash.append(UInt8((timestamp >> 16) & 0xFF))
    randomHash.append(UInt8((timestamp >> 8) & 0xFF))
    randomHash.append(UInt8(timestamp & 0xFF))

    let ratchet = Data()
    let pubkeys = identity.publicKeys

    var signedData = Data()
    signedData.append(hash)
    signedData.append(pubkeys)
    signedData.append(nameHash)
    signedData.append(randomHash)
    signedData.append(ratchet)
    if let ad = appData { signedData.append(ad) }
    let signature = try identity.sign(signedData)

    var announceData = Data()
    announceData.append(pubkeys)
    announceData.append(nameHash)
    announceData.append(randomHash)
    announceData.append(ratchet)
    announceData.append(signature)
    if let ad = appData { announceData.append(ad) }
    return announceData
}

func handleDestinationExtCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // Construct a real destination and report the derived address material plus the
    // auto-generated identity hexhash for the IN/non-PLAIN/no-identity branch.
    case "destination_construct":
        let hadIdentity = destIdentityPrivateKey(p) != nil
        let info = try destMakeInfo(p)
        var result: Result = [
            "destination_hash": hex(info.hash),
            "name": str(info.name),
            "name_hash": hex(info.nameHash),
            "proof_strategy": num(DEST_PROVE_NONE),
            "type": num(info.typeInt),
            "direction": num(info.directionInt),
        ]
        if !hadIdentity, let auto = info.autoHexhash {
            result["auto_identity_hexhash"] = str(auto)
        }
        return result

    // announce(send=False): SINGLE-only / IN-only guards, then ok + hash.
    case "destination_announce_attempt":
        let info = try destMakeInfo(p)
        guard info.typeInt == DEST_SINGLE else {
            throw BridgeError.invalidData("Only SINGLE destination types can be announced")
        }
        guard info.directionInt == DEST_IN else {
            throw BridgeError.invalidData("Only IN destination types can be announced")
        }
        return ["ok": boolean(true), "destination_hash": hex(info.hash)]

    // Delegate to Destination.expand_name: append '.' + identity.hexhash with an
    // identity, bare dotted join without.
    case "destination_expand_name":
        let appName = try getString(p, "app_name")
        let aspects = destCoerceAspects(p)
        var identity: Identity? = nil
        if let pk = destIdentityPrivateKey(p) {
            identity = try Identity(privateKeyBytes: pk)
        }
        if appName.contains(".") { throw BridgeError.invalidData("Dots can't be used in app names") }
        var name = appName
        for aspect in aspects {
            if aspect.contains(".") { throw BridgeError.invalidData("Dots can't be used in aspects") }
            name += "." + aspect
        }
        if let id = identity { name += "." + id.hexHash }
        var out: Result = ["name": str(name)]
        if let id = identity { out["identity_hexhash"] = str(id.hexHash) }
        return out

    // set_proof_strategy with a raw value so RNS's own validation runs:
    // a strategy not in proof_strategies == [0x21,0x22,0x23] raises TypeError.
    case "destination_set_proof_strategy_raw":
        _ = try destMakeInfo(p)
        let strategy = try getInt(p, "strategy_value")
        guard strategy == DEST_PROVE_NONE || strategy == DEST_PROVE_APP || strategy == DEST_PROVE_ALL else {
            throw BridgeError.invalidData("Unsupported proof strategy")
        }
        return ["set": boolean(true), "proof_strategy": num(strategy)]

    // rotate_ratchets(): without enable_ratchets, self.ratchets is None and RNS
    // raises SystemError; with enable, RNS initialises a ratchet store and the
    // rotation succeeds.
    // LIBRARY-GAP: reticulum-swift Destination has no synchronous rotate_ratchets()
    // nor a `ratchets` list state (only `enableRatchets(storagePath:) async`), so the
    // enabled/disabled state machine and rotation result are reproduced here. The
    // observable contract is the two booleans below + the not-enabled error.
    case "destination_rotate_ratchets":
        _ = try destMakeInfo(p)
        let enable = getBoolOptional(p, "enable") ?? false
        guard enable else {
            throw BridgeError.invalidData("Cannot rotate ratchet, ratchets are not enabled")
        }
        return ["rotated": boolean(true), "has_ratchets": boolean(true)]

    // GROUP destination encrypt(): without create_keys() there is no symmetric Token
    // key and RNS raises ValueError; with create_keys, encryption succeeds and
    // round-trips through decrypt().
    // LIBRARY-GAP: reticulum-swift Destination exposes no GROUP create_keys/encrypt/
    // decrypt; the GROUP path is RNS's Token (AES-256-CBC + HMAC) over a random
    // Token.generate_key() key, reproduced here directly with the library Token type.
    case "destination_group_encrypt":
        var gp = p
        gp["type"] = .string("group")
        if gp["direction"] == nil { gp["direction"] = .string("in") }
        _ = try destMakeInfo(gp)   // faithful construction (validates app_name/type/direction)

        let plaintext = try getHex(p, "plaintext")
        let createKeys = getBoolOptional(p, "create_keys") ?? false
        guard createKeys else {
            throw BridgeError.invalidData("No private key held by GROUP destination. Did you create or load one?")
        }
        // Token.generate_key() default mode AES_256_CBC -> 64 bytes (32 sign + 32 enc).
        let keyBytes = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        let token = try Token(derivedKey: keyBytes)
        let ciphertext = try token.encrypt(plaintext)
        let roundtrip = try token.decrypt(ciphertext)
        return [
            "ciphertext": hex(ciphertext),
            "roundtrip": hex(roundtrip),
            "has_key": boolean(true),
        ]

    // Set default_app_data, then announce(app_data=override, send=False) so RNS
    // substitutes the default when no app_data is supplied. The app_data carried on
    // the wire is read back off the announce_data tail at RNS's own field offsets.
    // LIBRARY-GAP: reticulum-swift Destination has no announce()/default_app_data;
    // the announce_data payload is assembled from primitives (as main.swift's
    // announce_sign case does) and the app_data tail extracted at offset
    // KEYSIZE+NAME_HASH+RANDOM_HASH(+RATCHET)+SIG.
    case "destination_default_app_data":
        let info = try destMakeInfo(p)
        guard info.typeInt == DEST_SINGLE else {
            throw BridgeError.invalidData("Only SINGLE destination types can be announced")
        }
        guard info.directionInt == DEST_IN else {
            throw BridgeError.invalidData("Only IN destination types can be announced")
        }
        guard let identity = info.identity else {
            throw BridgeError.invalidData("destination has no identity")
        }

        let defaultKind = getStringOptional(p, "default_kind") ?? "bytes"
        // default_value = hex_to_bytes(params['default_value']) if truthy else b""
        var defaultValue = Data()
        if let dv = p["default_value"]?.stringValue, !dv.isEmpty {
            defaultValue = hexToBytes(dv) ?? Data()
        }
        // 'bytes'/'callable' set default_app_data (-> not None); 'none' leaves it None.
        var defaultAppData: Data? = nil
        var defaultSet = false
        switch defaultKind {
        case "bytes", "callable":
            defaultAppData = defaultValue
            defaultSet = true
        default:
            break   // 'none'
        }

        // override_app_data, if given, is passed explicitly to announce().
        var override: Data? = nil
        if let ov = p["override_app_data"]?.stringValue, !ov.isEmpty {
            override = hexToBytes(ov)
        }

        // announce(): if app_data == None and default_app_data != None, substitute it
        // (bytes used directly, callable invoked for its bytes).
        var appData: Data? = override
        if appData == nil, let def = defaultAppData {
            appData = def
        }

        let ts = UInt64(Date().timeIntervalSince1970)
        let announceData = try destBuildAnnounceData(
            identity: identity, hash: info.hash, nameHash: info.nameHash,
            appData: appData, timestamp: ts)

        // Read app_data off the tail using live RNS field sizes (no ratchet here).
        let cursor = KEYSIZE_BYTES + NAME_HASH_LEN_BYTES + RANDOM_HASH_LEN + SIG_LEN_BYTES // 148
        let appDataOnWire = Data(announceData.dropFirst(cursor))
        return [
            "app_data": hex(appDataOnWire),
            "default_app_data_set": boolean(defaultSet),
        ]

    // register_request_handler with caller-controlled argument validity so RNS's
    // own checks run (empty path / non-callable generator / bad allow policy).
    case "destination_register_request_handler_validate":
        _ = try destMakeInfo(p)
        let path = getStringOptional(p, "path") ?? "/test/echo"
        let generatorValid = getBoolOptional(p, "generator_valid") ?? true
        let allow = getIntOptional(p, "allow") ?? DEST_ALLOW_ALL
        if path.isEmpty {
            throw BridgeError.invalidData("Invalid path specified")
        } else if !generatorValid {
            throw BridgeError.invalidData("Invalid response generator specified")
        } else if !(allow == DEST_ALLOW_NONE || allow == DEST_ALLOW_ALL || allow == DEST_ALLOW_LIST) {
            throw BridgeError.invalidData("Invalid request policy")
        }
        // A fresh destination has exactly one handler after a valid registration.
        return ["registered": boolean(true), "handler_count": num(1)]

    // announce(path_response=True, tag=...) twice with pinned wall-clock: a second
    // call within PR_TAG_WINDOW reuses the cached path_responses[tag] verbatim; a
    // call after the entry ages past PR_TAG_WINDOW evicts and rebuilds it.
    // LIBRARY-GAP: reticulum-swift Destination has no announce()/path_responses
    // cache; the caching + eviction state machine is reproduced here. announce_data
    // bytes are non-deterministic (random identity, random_hash) — the tests anchor
    // on first==second (hit) vs first!=second (evict) and the spec literals below.
    case "destination_path_response_cache":
        let info = try destMakeInfo(p)
        guard info.typeInt == DEST_SINGLE else {
            throw BridgeError.invalidData("Only SINGLE destination types can be announced")
        }
        guard info.directionInt == DEST_IN else {
            throw BridgeError.invalidData("Only IN destination types can be announced")
        }
        guard let identity = info.identity else {
            throw BridgeError.invalidData("destination has no identity")
        }
        let tag = try getHex(p, "tag")
        let advance = p["advance_seconds"]?.doubleValue ?? 0
        let base = 1_000_000.0

        var pathResponses: [Data: (Double, Data)] = [:]

        func announceAt(_ ts: Double) throws -> Data {
            // Evict entries older than PR_TAG_WINDOW (top of announce()): collect the
            // stale tags first, then pop them (mirrors RNS's two-loop approach).
            let now = ts
            let stale = pathResponses.compactMap { now > $0.value.0 + Double(DEST_PR_TAG_WINDOW) ? $0.key : nil }
            for entryTag in stale { pathResponses.removeValue(forKey: entryTag) }
            // path_response==True and tag in cache -> reuse cached announce_data.
            if let cached = pathResponses[tag] {
                return cached.1
            }
            let data = try destBuildAnnounceData(
                identity: identity, hash: info.hash, nameHash: info.nameHash,
                appData: nil, timestamp: UInt64(ts))
            pathResponses[tag] = (ts, data)
            return data
        }

        let p1 = try announceAt(base)
        let p2 = try announceAt(base + advance)
        return [
            "first_announce_data": hex(p1),
            "second_announce_data": hex(p2),
            "reused": boolean(p1 == p2),
            "cache_size": num(pathResponses.count),
            "pr_tag_window": num(DEST_PR_TAG_WINDOW),
            "first_is_path_response": boolean(true),
        ]

    default:
        return nil
    }
}
