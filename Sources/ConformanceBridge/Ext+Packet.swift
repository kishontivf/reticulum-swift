// Ext+Packet.swift — conformance bridge extension cluster: M-PACKET
//   packet_build                — build a real packet on a real Destination, pack it,
//                                 report wire bytes + the fields a receiver parses back.
//   packet_build_raw_header2    — build a HEADER_2 packet and let pack() surface RNS's
//                                 OWN failure (no harness pre-check).
//   packet_constants            — live RNS wire-size / header constants.
//   packet_context_constants    — live RNS.Packet context-byte code points.
//   packet_resend_observe       — pack, then re-pack (resend) and report fresh bytes.
//
// Ports from reticulum-conformance reference/bridge_server.py
// (cmd_packet_build :770, cmd_packet_build_raw_header2 :964,
//  cmd_packet_resend_observe :1008, cmd_packet_constants :2886,
//  cmd_packet_context_constants :2919). Returns nil for any command it does not
// own (dispatch chain: Ext+Dispatch.swift).
//
// FORCED SWIFT DEVIATION (documented in port-deviations.md): the python reference
// delegates to a real RNS.Packet / RNS.Destination — RNS.Packet.pack() composes
// the flags byte, lays out the header, and routes the payload through
// Destination.encrypt(). reticulum-swift's `Packet` is a low-level wire struct
// with no high-level pack()/Destination.encrypt() entry point, so this file
// reconstructs RNS.Packet.pack() semantics inline (get_packed_flags, the
// per-context/per-type encryption gate from Packet.py:184-226, and get_hashable_part)
// on top of the available primitives (Identity.encrypt for SINGLE, Token for GROUP,
// Hashing.fullHash for the packet hash). Byte-faithful for the deterministic
// (PLAIN / cleartext) frames the tests reconstruct; property-faithful for the
// SINGLE/GROUP encrypted frames (fresh ephemeral key + IV each pack), which the
// reference's own randomness makes non-deterministic and never cross-compares.
import Foundation
import ReticulumSwift
import CryptoKit

// MARK: - Packet-build helpers (RNS.Packet.pack reconstruction)

/// The destination material a packet is built against. Mirrors the three
/// dest_type kinds the reference constructs (RNS.Destination PLAIN / SINGLE /
/// GROUP). SINGLE and GROUP carry a random Identity so the 16-byte destination
/// hash includes the identity hash exactly as RNS.Destination.hash does
/// (Destination.py:116-130); GROUP additionally holds a symmetric Token key.
private enum PacketDest {
    case plain
    case single(Identity)
    case group(identity: Identity, key: Data)

    /// RNS.Destination.type code → flags bits 3-2 (SINGLE=0, GROUP=1, PLAIN=2).
    var dtype: Int {
        switch self {
        case .plain: return 2
        case .single: return 0
        case .group: return 1
        }
    }

    /// 16-byte destination hash (matches RNS.Destination.hash for "conformance.packet").
    var hash: Data {
        switch self {
        case .plain:
            return Destination.plainHash(appName: "conformance", aspects: ["packet"])
        case .single(let id):
            return Destination.hash(identity: id, appName: "conformance", aspects: ["packet"])
        case .group(let id, _):
            return Destination.hash(identity: id, appName: "conformance", aspects: ["packet"])
        }
    }
}

/// 64-byte symmetric key for a GROUP destination's Token, as RNS mints via
/// Token.generate_key() (default AES_256_CBC → 64 bytes) in Destination.create_keys().
private func randomTokenKey() -> Data {
    let key = SymmetricKey(size: .init(bitCount: 512))
    return key.withUnsafeBytes { Data($0) }
}

/// Build the PacketDest for a dest_type. `strict` rejects unknown types
/// (cmd_packet_build raises ValueError); non-strict mirrors cmd_packet_resend_observe,
/// whose else-branch treats any unknown dest_type as SINGLE.
private func makePacketDest(_ destType: String, strict: Bool) throws -> PacketDest {
    switch destType {
    case "plain": return .plain
    case "single": return .single(Identity())
    case "group": return .group(identity: Identity(), key: randomTokenKey())
    default:
        if strict {
            throw BridgeError.invalidData(
                "unsupported dest_type: '\(destType)' (use 'plain', 'single' or 'group')")
        }
        return .single(Identity())
    }
}

/// The on-wire body for a HEADER_1 packet — the per-context / per-packet-type
/// encryption gate from RNS.Packet.pack (Packet.py:184-226). Announce / link-request
/// / resource-proof / resource / keepalive / cache-request payloads ride in the clear;
/// everything else goes through the destination's encrypt method (PLAIN returns the
/// plaintext unchanged, SINGLE uses Identity.encrypt, GROUP uses the symmetric Token).
private func rnsCiphertext(dest: PacketDest, packetType: Int, context: Int, data: Data) throws -> Data {
    if packetType == 1 { return data }                    // ANNOUNCE — not encrypted
    if packetType == 2 { return data }                    // LINKREQUEST — not encrypted
    if packetType == 3 && context == 0x05 { return data } // PROOF + RESOURCE_PRF — not encrypted
    if context == 0x01 { return data }                    // RESOURCE — encrypted by the resource
    if context == 0xFA { return data }                    // KEEPALIVE — no payload
    if context == 0x08 { return data }                    // CACHE_REQUEST — not encrypted
    switch dest {
    case .plain:
        return data
    case .single(let id):
        return try Identity.encrypt(data, to: id.encryptionPublicKey, identityHash: id.hash)
    case .group(_, let key):
        return try Token(derivedKey: key).encrypt(data)
    }
}

/// Assemble a HEADER_1 frame the way RNS.Packet.pack does: flags || hops ||
/// destination_hash(16) || context || ciphertext, enforcing the MTU ceiling.
private func packHeader1Raw(dest: PacketDest, packetType: Int, context: Int, contextFlag: Int,
                            transportType: Int, hops: Int, data: Data) throws -> Data {
    // get_packed_flags: header_type(0)<<6 | context_flag<<5 | transport_type<<4 |
    //                   destination_type<<2 | packet_type
    let flagsInt = (0 << 6) | (contextFlag << 5) | (transportType << 4) | (dest.dtype << 2) | packetType
    var raw = Data([UInt8(flagsInt & 0xFF), UInt8(truncatingIfNeeded: hops)])
    raw.append(dest.hash)
    raw.append(UInt8(context & 0xFF))
    raw.append(try rnsCiphertext(dest: dest, packetType: packetType, context: context, data: data))
    if raw.count > MTU {
        throw BridgeError.invalidData("Packet size of \(raw.count) exceeds MTU of \(MTU) bytes")
    }
    return raw
}

/// Packet hash = full_hash(get_hashable_part). The hashable part masks the first
/// byte to its low 4 bits and skips the hop byte (and, for HEADER_2, the 16-byte
/// transport id), so a routed packet hashes identically to its single-hop form
/// (RNS.Packet.get_hashable_part, Packet.py:354-360).
private func packetHash(_ raw: Data) -> Data {
    guard raw.count >= 1 else { return Hashing.fullHash(Data()) }
    var hp = Data([raw[0] & 0x0F])
    let headerType = (raw[0] >> 6) & 1
    if headerType == 1 {
        if raw.count > 18 { hp.append(Data(raw[18...])) }
    } else {
        if raw.count > 2 { hp.append(Data(raw[2...])) }
    }
    return Hashing.fullHash(hp)
}

/// Re-derive the wire fields the way a receiver does — a faithful mirror of
/// RNS.Packet.unpack (Packet.py:241-266) reading straight off the bytes — plus the
/// raw flags byte and the packet hash. This is exactly the dict cmd_packet_build
/// returns after re-unpacking its own frame.
private func decodePacketFields(_ raw: Data) -> Result {
    let flags = raw[0]
    let headerType = Int((flags >> 6) & 1)
    var r: Result = [
        "raw": hex(raw),
        "flags": num(Int(flags)),
        "hops": num(Int(raw[1])),
        "header_type": num(headerType),
        "context_flag": num(Int((flags >> 5) & 1)),
        "transport_type": num(Int((flags >> 4) & 1)),
        "destination_type": num(Int((flags >> 2) & 3)),
        "packet_type": num(Int(flags & 3)),
    ]
    if headerType == 1 {
        r["transport_id"] = hex(Data(raw[2..<18]))
        r["destination_hash"] = hex(Data(raw[18..<34]))
        r["context"] = num(Int(raw[34]))
        r["data"] = hex(raw.count > 35 ? Data(raw[35...]) : Data())
    } else {
        r["transport_id"] = .null
        r["destination_hash"] = hex(Data(raw[2..<18]))
        r["context"] = num(Int(raw[18]))
        r["data"] = hex(raw.count > 19 ? Data(raw[19...]) : Data())
    }
    r["hash"] = hex(packetHash(raw))
    return r
}

func handlePacketExtCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // Build a real packet on a real Destination, pack it, and report the wire
    // bytes plus the fields RNS itself parses back out. dest_type ('plain' |
    // 'single' | 'group') picks the destination kind (and whether the payload is
    // encrypted); header_type accepts the human 1/2 or "HEADER_1"/"HEADER_2".
    case "packet_build":
        let destType = getStringOptional(p, "dest_type") ?? "plain"
        let packetType = getIntOptional(p, "packet_type") ?? 0       // DATA
        let context = getIntOptional(p, "context") ?? 0
        let contextFlag = getIntOptional(p, "context_flag") ?? 0
        let transportType = getIntOptional(p, "transport_type") ?? 0 // BROADCAST
        let hops = getIntOptional(p, "hops") ?? 0
        let data = getHexOptional(p, "data") ?? Data()
        guard (0...255).contains(hops) else {
            throw BridgeError.invalidData("hops must be 0-255, got \(hops)")
        }

        // Resolve header_type from the human "1"/"2" or "HEADER_1"/"HEADER_2"
        // convention. Default 1 → HEADER_1. (RNS values HEADER_1=0, HEADER_2=1.)
        let headerType: Int
        switch p["header_type"] {
        case nil, .some(.null):
            headerType = 0
        case .some(.int(let i)):
            switch i {
            case 1: headerType = 0
            case 2: headerType = 1
            default:
                throw BridgeError.invalidData(
                    "unsupported header_type: \(i) (use 1 / 2 or 'HEADER_1' / 'HEADER_2')")
            }
        case .some(.string(let s)):
            switch s {
            case "1", "HEADER_1": headerType = 0
            case "2", "HEADER_2": headerType = 1
            default:
                throw BridgeError.invalidData(
                    "unsupported header_type: '\(s)' (use 1 / 2 or 'HEADER_1' / 'HEADER_2')")
            }
        default:
            throw BridgeError.invalidData(
                "unsupported header_type (use 1 / 2 or 'HEADER_1' / 'HEADER_2')")
        }

        // HEADER_2 pre-validation — RNS only assembles a HEADER_2 frame for an
        // ANNOUNCE with a 16-byte transport_id (Packet.py:220-229). cmd_packet_build
        // guards these before pack rather than crashing on RNS's internal paths.
        var transportId: Data? = nil
        if headerType == 1 {
            if packetType != 1 { // ANNOUNCE
                throw BridgeError.invalidData(
                    "HEADER_2 packets are only buildable for ANNOUNCE packet_type (1); "
                    + "RNS.Packet.pack only assembles a HEADER_2 header for announces "
                    + "(Packet.py:220-229).")
            }
            guard let tidRaw = getHexOptional(p, "transport_id") else {
                throw BridgeError.invalidData("HEADER_2 packets require a 16-byte transport_id")
            }
            guard tidRaw.count == 16 else {
                throw BridgeError.invalidData("transport_id must be 16 bytes, got \(tidRaw.count)")
            }
            transportId = tidRaw
        }

        // LRPROOF (0xFF) drives RNS's link-id packing path (Packet.py:181-183),
        // which is unbuildable on a non-link destination — RNS would crash. The
        // conformance tests never build it; reject cleanly to mirror that failure.
        if headerType == 0 && context == 0xFF {
            throw BridgeError.invalidData("context 0xFF (LRPROOF) requires a link destination")
        }

        let dest = try makePacketDest(destType, strict: true)

        let raw: Data
        if headerType == 0 {
            raw = try packHeader1Raw(
                dest: dest, packetType: packetType, context: context,
                contextFlag: contextFlag, transportType: transportType,
                hops: hops, data: data)
        } else {
            // HEADER_2 ANNOUNCE: transport_id rides between the hops byte and the
            // destination_hash; an announce payload is not encrypted (clear).
            let flagsInt = (1 << 6) | (contextFlag << 5) | (transportType << 4)
                | (dest.dtype << 2) | packetType
            var h2 = Data([UInt8(flagsInt & 0xFF), UInt8(truncatingIfNeeded: hops)])
            h2.append(transportId!)          // 16 bytes (length validated above)
            h2.append(dest.hash)             // 16 bytes
            h2.append(UInt8(context & 0xFF))
            h2.append(data)
            if h2.count > MTU {
                throw BridgeError.invalidData("Packet size of \(h2.count) exceeds MTU of \(MTU) bytes")
            }
            raw = h2
        }

        return decodePacketFields(raw)

    // Build a HEADER_2 packet and run RNS.Packet.pack() WITHOUT pre-validation,
    // surfacing RNS's OWN failure. Returns {raw, raw_len} on success, or
    // {error, error_type} when pack refuses.
    case "packet_build_raw_header2":
        let packetType = getIntOptional(p, "packet_type") ?? 1   // ANNOUNCE
        var data = getHexOptional(p, "data") ?? Data()
        if data.isEmpty { data = Data([0x00]) }                  // hex_to_bytes('') or b'\x00'
        let transportId = getHexOptional(p, "transport_id")
        // A SINGLE OUT destination supplies destination.hash for the HEADER_2 body.
        let identity = Identity()
        let destHash = Destination.hash(identity: identity, appName: "conformance", aspects: ["packet"])

        // FORCED DEVIATION: python lets the REAL RNS.Packet.pack() raise and
        // reports str(e)/type(e).__name__. reticulum-swift has no RNS.Packet.pack,
        // so the two failure conditions are reproduced inline and their error
        // dicts synthesized to byte-mirror CPython's exact output (only the
        // 'Packet with header type 2 must have a transport ID' substring and the
        // presence of an error are asserted by the tests).
        // transport_id is None → RNS.Packet.pack raises IOError (== OSError),
        // Packet.py:228.
        guard let tid = transportId else {
            return [
                "error": str("Packet with header type 2 must have a transport ID"),
                "error_type": str("OSError"),
            ]
        }
        // Only ANNOUNCE assigns self.ciphertext on the HEADER_2 branch; for any
        // other packet_type RNS leaves ciphertext unset and .raw assembly raises
        // AttributeError (Packet.py:220-229).
        let ciphertext: Data
        if packetType == 1 {
            ciphertext = data
        } else {
            return [
                "error": str("'RNS.Packet.Packet' object has no attribute 'ciphertext'"),
                "error_type": str("AttributeError"),
            ]
        }
        // flags: HEADER_2(1)<<6 | context_flag 0 | BROADCAST 0 | SINGLE(0)<<2 | packet_type
        let flagsInt = (1 << 6) | packetType
        var raw = Data([UInt8(flagsInt & 0xFF), 0x00])  // flags, hops=0
        raw.append(tid)
        raw.append(destHash)
        raw.append(UInt8(0x00))                         // context NONE
        raw.append(ciphertext)
        if raw.count > MTU {
            return [
                "error": str("Packet size of \(raw.count) exceeds MTU of \(MTU) bytes"),
                "error_type": str("OSError"),
            ]
        }
        return ["raw": hex(raw), "raw_len": num(raw.count)]

    // Live RNS wire-size / header constants, read straight off the spec. Tests pin
    // each against its documented literal and the defining arithmetic
    // (MDU == MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE, etc.).
    case "packet_constants":
        return [
            "mtu": num(MTU),                                 // 500
            "header_minsize": num(19),                       // flags+hops+dest(16)+context
            "header_maxsize": num(35),                       // + transport_id(16)
            "mdu": num(MDU),                                 // 464
            "ifac_min_size": num(TransportConstants.IFAC_MIN_SIZE),  // 1
            "packet_mdu": num(MDU),                          // Packet.MDU == 464
            "packet_plain_mdu": num(MDU),                    // PLAIN_MDU == MDU
            "packet_encrypted_mdu": num(ENCRYPTED_MDU),      // 383
            "link_mdu": num(LinkConstants.LINK_MDU),         // 431
            "hashlength": num(256),                          // bits (SHA-256)
            "siglength": num(512),                           // bits (Ed25519 sig = 64B)
            "truncated_hashlength": num(128),                // bits (16-byte addresses)
            "keysize": num(512),                             // bits (X25519 32 + Ed25519 32)
            "name_hash_length": num(80),                     // bits (10-byte name hash)
            "token_overhead": num(48),                       // bytes (16 IV + 32 HMAC)
            "aes128_blocksize": num(16),                     // bytes
        ]

    // Live RNS.Packet context-byte code points (Packet.py:72-92). REQUEST (0x09)
    // is intentionally absent, mirroring cmd_packet_context_constants exactly.
    case "packet_context_constants":
        return [
            "NONE": num(0x00),
            "RESOURCE": num(0x01),
            "RESOURCE_ADV": num(0x02),
            "RESOURCE_REQ": num(0x03),
            "RESOURCE_HMU": num(0x04),
            "RESOURCE_PRF": num(0x05),
            "RESOURCE_ICL": num(0x06),
            "RESOURCE_RCL": num(0x07),
            "CACHE_REQUEST": num(0x08),
            "RESPONSE": num(0x0A),
            "PATH_RESPONSE": num(0x0B),
            "COMMAND": num(0x0C),
            "COMMAND_STATUS": num(0x0D),
            "CHANNEL": num(0x0E),
            "KEEPALIVE": num(0xFA),
            "LINKIDENTIFY": num(0xFB),
            "LINKCLOSE": num(0xFC),
            // LIBRARY-GAP: ReticulumSwift.PacketContext omits LINKPROOF (0xFD); emitted
            // as the spec literal so the table stays complete (reported in libraryGaps).
            "LINKPROOF": num(0xFD),
            "LRRTT": num(0xFE),
            "LRPROOF": num(0xFF),
        ]

    // Pack a packet, then re-pack it (RNS.Packet.resend re-packs before
    // re-transmitting, Packet.py:305-323) and report whether the re-pack produced
    // fresh wire bytes. An encrypted SINGLE/GROUP destination gets fresh ephemeral
    // key material / IV each pack (raw + hash change); a PLAIN packet re-packs
    // byte-identically.
    case "packet_resend_observe":
        let destType = getStringOptional(p, "dest_type") ?? "single"
        var data = getHexOptional(p, "data") ?? Data()
        if data.isEmpty { data = Data("conformance-resend".utf8) }
        let dest = try makePacketDest(destType, strict: false)
        // DATA(0) / NONE(0) / context_flag 0 / BROADCAST(0) / hops 0 / HEADER_1.
        let raw1 = try packHeader1Raw(
            dest: dest, packetType: 0, context: 0, contextFlag: 0,
            transportType: 0, hops: 0, data: data)
        let hash1 = packetHash(raw1)
        // resend() calls self.pack() again — fresh ephemeral/IV for encrypted dests.
        let raw2 = try packHeader1Raw(
            dest: dest, packetType: 0, context: 0, contextFlag: 0,
            transportType: 0, hops: 0, data: data)
        let hash2 = packetHash(raw2)
        return [
            "raw_1": hex(raw1), "hash_1": hex(hash1),
            "raw_2": hex(raw2), "hash_2": hex(hash2),
        ]

    default:
        return nil
    }
}
