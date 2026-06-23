// Ext+Announce.swift — conformance bridge extension cluster: M-ANNOUNCE
//   announce_build            — real RNS.Destination.announce(send=False) wire bytes + parsed fields
//   announce_validate         — real RNS.Identity.validate_announce verdict + extracted fields
//   announce_queue_constants  — RNS.Reticulum announce-bandwidth / egress-queue constants
//
// Ports from reticulum-conformance reference/bridge_server.py
// (cmd_announce_build :1056, cmd_announce_validate :1177,
//  cmd_announce_queue_constants :2958). Returns nil for any command it does
// not own (dispatch chain: Ext+Dispatch.swift).
//
// FORCED SWIFT DEVIATION (announce_queue_constants — documented in
// port-deviations.md): python returns int(RNS.Reticulum.ANNOUNCE_CAP), where
// RNS stores the cap as the integer percent literal 2. reticulum-swift's
// TransportConstants.ANNOUNCE_CAP instead stores the same cap as the FRACTION
// 0.02 (it is consumed as `txTime / ANNOUNCE_CAP`). To match python's emitted
// value byte-for-byte we recover the percent by *100, rather than reading the
// raw library constant (which would emit 0). max_queued_announces /
// queued_announce_life are read straight off the library constants.
import Foundation
import ReticulumSwift
import CryptoKit

func handleAnnounceExtCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // Build a real RNS announce packet WITHOUT putting it on the wire — mirrors
    // RNS.Destination.announce(send=False).pack(). Constructs an IN/SINGLE
    // destination from the identity, optionally enables a fresh X25519 ratchet,
    // emits the wire bytes, and re-parses the field layout RNS itself wrote.
    // (Unlike python there is no global Transport.destinations registry to
    // collide with, so each build constructs a fresh destination — output bytes
    // are unaffected.)
    case "announce_build":
        let privateKey = try getHex(p, "private_key")
        let appName = try getString(p, "app_name")

        // aspects: python accepts either a list OR a comma-separated string.
        let aspects: [String]
        if let arr = p["aspects"]?.arrayValue {
            aspects = arr.compactMap { $0.stringValue }
        } else if let s = p["aspects"]?.stringValue, !s.isEmpty {
            aspects = s.split(separator: ",").map(String.init)
        } else {
            aspects = []
        }

        // app_data: python treats a missing OR empty value as None (not signed,
        // not appended). hex_to_bytes("") -> b"" which is falsy -> None.
        let appDataParam = getHexOptional(p, "app_data")
        let appData: Data? = (appDataParam?.isEmpty == false) ? appDataParam : nil

        let enableRatchets = getBoolOptional(p, "enable_ratchets") ?? false
        let emissionTs = getIntOptional(p, "emission_ts")

        let identity = try Identity(privateKeyBytes: privateKey)
        let destination = Destination(
            identity: identity, appName: appName, aspects: aspects,
            type: .single, direction: .in
        )

        // enable_ratchets: RNS generates a fresh X25519 ratchet internally on the
        // first rotate inside announce(). Mirror that by generating a fresh
        // X25519 keypair and embedding its 32-byte public key.
        var ratchet: Data? = nil
        if enableRatchets {
            let ratchetPriv = Curve25519.KeyAgreement.PrivateKey()
            ratchet = ratchetPriv.publicKey.rawRepresentation
        }

        // emission_ts: RNS embeds int(time.time()).to_bytes(5,"big") as the last
        // 5 bytes of the 10-byte random_hash (first 5 are random). When a caller
        // pins emission_ts, build that random_hash explicitly; otherwise let the
        // library generate it (it already does 5 random + 5 timestamp bytes,
        // matching RNS Destination.py:282).
        var randomHash: Data? = nil
        if let ts = emissionTs {
            var rh = Data()
            for _ in 0..<5 { rh.append(UInt8.random(in: 0...255)) }
            let t = UInt64(ts)
            rh.append(UInt8((t >> 32) & 0xFF))
            rh.append(UInt8((t >> 24) & 0xFF))
            rh.append(UInt8((t >> 16) & 0xFF))
            rh.append(UInt8((t >> 8) & 0xFF))
            rh.append(UInt8(t & 0xFF))
            randomHash = rh
        }

        let announce = Announce(
            destination: destination,
            appData: appData,
            randomHash: randomHash,
            ratchet: ratchet
        )
        let packet = try announce.buildPacket()
        let raw = packet.encode()

        // Parse the fields RNS itself wrote — the field layout straight off the
        // produced packet.data (mirrors cmd_announce_build's slice arithmetic).
        let keysize = 64
        let nameHashLen = 10
        let randomHashLen = 10
        let ratchetSize = 32
        let sigLen = 64
        let hasRatchet = packet.header.hasContext
        let data = packet.data
        let pubkey = Data(data[0..<keysize])
        let nameHash = Data(data[keysize..<keysize + nameHashLen])
        let randomHashOff = keysize + nameHashLen
        let randomHashOut = Data(data[randomHashOff..<randomHashOff + randomHashLen])
        var cursor = randomHashOff + randomHashLen
        var ratchetOut = Data()
        if hasRatchet {
            ratchetOut = Data(data[cursor..<cursor + ratchetSize])
            cursor += ratchetSize
        }
        let signature = Data(data[cursor..<cursor + sigLen])
        cursor += sigLen
        let appDataOut = cursor < data.count ? Data(data[cursor...]) : Data()

        return [
            "raw": hex(raw),
            "destination_hash": hex(destination.hash),
            "announce_data": hex(data),
            "public_key": hex(pubkey),
            "name_hash": hex(nameHash),
            "random_hash": hex(randomHashOut),
            // python: bytes_to_hex(ratchet) if ratchet else "" (empty -> "")
            "ratchet": ratchetOut.isEmpty ? str("") : hex(ratchetOut),
            "signature": hex(signature),
            "app_data": hex(appDataOut),
            "has_ratchet": boolean(hasRatchet),
        ]

    // Validate a real RNS announce packet — mirrors RNS.Identity.validate_announce,
    // which (1) verifies the Ed25519 signature over
    //   destination_hash || public_key || name_hash || random_hash [|| ratchet] [|| app_data]
    // against the ANNOUNCED signing key, AND (2) recomputes
    //   expected_hash = truncated_hash(name_hash || identity_hash)
    // and rejects a destination_hash mismatch even when the signature verifies
    // (the forged + re-signed dest-hash branch). Never crashes on malformed
    // input: an unpackable packet -> {valid:false, error:"unpack_failed"};
    // a truncated/corrupt body -> {valid:false} with the parsed header fields.
    case "announce_validate":
        let raw = try getHex(p, "raw")

        let packet: Packet
        do {
            packet = try Packet(from: raw)
        } catch {
            return ["valid": boolean(false), "error": str("unpack_failed")]
        }
        if packet.header.packetType != .announce {
            return ["valid": boolean(false), "error": str("not_an_announce")]
        }

        let hasRatchet = packet.header.hasContext
        let data = packet.data
        let destHash = packet.destination

        // Compute the validation verdict without throwing — any structural
        // shortfall (truncated body, undecodable signing key) yields false,
        // matching validate_announce's swallow-and-return-false contract.
        var valid = false
        let keysize = 64
        let nameHashLen = 10
        let randomHashLen = 10
        let ratchetSize = hasRatchet ? 32 : 0
        let sigLen = 64
        let minLen = keysize + nameHashLen + randomHashLen + ratchetSize + sigLen
        if data.count >= minLen {
            let pubkey = Data(data[0..<keysize])
            let nameHash = Data(data[keysize..<keysize + nameHashLen])
            let randomHashOff = keysize + nameHashLen
            let randomHash = Data(data[randomHashOff..<randomHashOff + randomHashLen])
            var cursor = randomHashOff + randomHashLen
            var ratchet = Data()
            if hasRatchet {
                ratchet = Data(data[cursor..<cursor + ratchetSize])
                cursor += ratchetSize
            }
            let signature = Data(data[cursor..<cursor + sigLen])
            cursor += sigLen
            let appData = cursor < data.count ? Data(data[cursor...]) : Data()

            // signed_data layout mirrors RNS.Identity.validate_announce.
            var signedData = Data()
            signedData.append(destHash)
            signedData.append(pubkey)
            signedData.append(nameHash)
            signedData.append(randomHash)
            if !ratchet.isEmpty { signedData.append(ratchet) }
            if !appData.isEmpty { signedData.append(appData) }

            // (1) Ed25519 signature check against the ANNOUNCED signing key.
            var sigValid = false
            let sigPub = Data(pubkey.suffix(32))
            if let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: sigPub) {
                sigValid = pubKey.isValidSignature(signature, for: signedData)
            }
            // (2) destination_hash recompute: full_hash(name_hash || identity_hash)[:16].
            let identityHash = Hashing.truncatedHash(pubkey)
            var hashMaterial = Data()
            hashMaterial.append(nameHash)
            hashMaterial.append(identityHash)
            let expectedDestHash = Hashing.truncatedHash(hashMaterial)
            let destValid = (destHash == expectedDestHash)

            valid = sigValid && destValid
        }

        var result: Result = [
            "valid": boolean(valid),
            "destination_hash": hex(destHash),
            "has_ratchet": boolean(hasRatchet),
        ]
        if hasRatchet {
            // RNS reads the ratchet off packet.data at the offsets it parses to.
            let ratchetOff = keysize + nameHashLen + randomHashLen
            if data.count >= ratchetOff + 32 {
                result["ratchet"] = hex(Data(data[ratchetOff..<ratchetOff + 32]))
            } else {
                result["ratchet"] = str("")
            }
        }
        return result

    // Live RNS.Reticulum announce-bandwidth / egress-queue constants pinned
    // against their documented literals (16384, 86400 == 24h, 2). See the
    // FORCED SWIFT DEVIATION header re: ANNOUNCE_CAP percent vs fraction.
    case "announce_queue_constants":
        return [
            "announce_cap": num(Int((TransportConstants.ANNOUNCE_CAP * 100).rounded())),
            "max_queued_announces": num(TransportConstants.MAX_QUEUED_ANNOUNCES),
            "queued_announce_life": num(Int(TransportConstants.QUEUED_ANNOUNCE_LIFE)),
        ]

    default:
        return nil
    }
}
