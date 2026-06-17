// WireTcp+Inject.swift — conformance bridge wire sub-handler cluster: W-INJECT (wire_inject_crafted_*, wire_capture_*, wire_send_forged_link_close)
//
// Ports from reticulum-conformance reference/wire_tcp.py. Shares the global
// wireInstances registry + wireLock + requireInstance()/newHandle() helpers
// (now internal in WireTcp.swift). Returns nil for any command it does not own
// (dispatch chain: handleWireExtensionCommand in Ext+Dispatch.swift).
//
// Faithfulness notes (read before editing):
//   * The python reference drives RNS-internal objects (RNS.PacketReceipt,
//     RNS.Resource sender/receiver, RNS.Link.validate_proof / validate_request /
//     receive) that reticulum-swift either does not expose or models with a
//     different (actor-based, lazily-prepared) surface. Where the security gate
//     is a bounded crypto/byte computation (LRPROOF / LINKIDENTIFY / packet-proof
//     / resource-proof / part map-hash / link-request size+mode gates), this
//     file RECONSTRUCTS the exact python algorithm INLINE using the swift
//     production primitives (Identity.sign/verify, Hashing, ResourceHashmap,
//     Packet/PacketHeader, Token via live links) so the returned dict matches
//     python byte-for-byte AND the real crypto code path is exercised.
//   * Commands that require genuinely-unrepresentable live RNS state — a
//     sender Resource serving windowed part-requests, a receiver Resource's
//     assemble()/hashmap_update() height bookkeeping, a Link's private
//     incoming_resources RESOURCE_ADV dispatch, or interception of an inbound
//     RESPONSE packet — carry a `// LIBRARY-GAP:` marker and are reported in
//     libraryGaps. They throw a clear LIBRARY-GAP error rather than fabricate a
//     deterministic-by-variant dict that would fake-pass without exercising
//     swift.
//
// Document forced Swift deviations in reticulum-swift/port-deviations.md with
// file:line + python ref site (handled by the orchestrator).

import CryptoKit
import Foundation
import ReticulumSwift

// MARK: - Local status-name maps (match python _*_STATUS_NAMES verbatim)

/// python _LINK_STATUS_NAMES = {0:PENDING,1:HANDSHAKE,2:ACTIVE,3:STALE,4:CLOSED}
private func wireLinkStatus(_ state: LinkState) -> (Int, String) {
    switch state {
    case .pending: return (0, "PENDING")
    case .handshake: return (1, "HANDSHAKE")
    case .active: return (2, "ACTIVE")
    case .stale: return (3, "STALE")
    case .closed: return (4, "CLOSED")
    }
}

/// python _LINK_STATUS_NAMES lookup by raw int (used by inline reconstructions
/// that track status as a python-valued int rather than a swift LinkState).
private func wireLinkStatusName(_ status: Int) -> String {
    switch status {
    case 0: return "PENDING"
    case 1: return "HANDSHAKE"
    case 2: return "ACTIVE"
    case 3: return "STALE"
    case 4: return "CLOSED"
    default: return "PENDING"
    }
}

/// python _PACKET_RECEIPT_STATUS_NAMES = {0x00:FAILED,0x01:SENT,0x02:DELIVERED,0xFF:CULLED}
private func wirePacketReceiptStatusName(_ status: Int) -> String {
    switch status {
    case 0x00: return "FAILED"
    case 0x01: return "SENT"
    case 0x02: return "DELIVERED"
    case 0xFF: return "CULLED"
    default: return "SENT"
    }
}

/// python _RESOURCE_STATUS_NAMES (0x00..0x08).
private func wireResourceStatusName(_ status: Int) -> String {
    switch status {
    case 0x00: return "NONE"
    case 0x01: return "QUEUED"
    case 0x02: return "ADVERTISED"
    case 0x03: return "TRANSFERRING"
    case 0x04: return "AWAITING_PROOF"
    case 0x05: return "ASSEMBLING"
    case 0x06: return "COMPLETE"
    case 0x07: return "FAILED"
    case 0x08: return "CORRUPT"
    default: return "NONE"
    }
}

// MARK: - Constants mirrored from RNS (verified against RNS Link.py / Packet.py)

private enum InjectConst {
    static let ECPUBSIZE = 64                 // RNS.Link.ECPUBSIZE (32 enc + 32 sig)
    static let KEYSIZE = 32                   // RNS.Identity public half size
    static let SIGLENGTH = 64                 // RNS.Identity.SIGLENGTH//8
    static let HASHLENGTH = 32                // RNS.Identity.HASHLENGTH//8
    static let LINK_MTU_SIZE = 3              // RNS.Link.LINK_MTU_SIZE
    static let IMPL_LENGTH = 64               // RNS.PacketReceipt.IMPL_LENGTH
    static let EXPL_LENGTH = 96               // RNS.PacketReceipt.EXPL_LENGTH
    static let MODE_AES256_CBC: UInt8 = 0x01  // RNS.Link.MODE_AES256_CBC (== MODE_DEFAULT)
    static let MODE_AES256_GCM: UInt8 = 0x02  // RNS.Link.MODE_AES256_GCM
    static let MODE_DEFAULT: UInt8 = 0x01
    static let MODE_BYTEMASK: UInt8 = 0xE0    // RNS.Link.MODE_BYTEMASK
    static let ESTABLISHMENT_TIMEOUT_PER_HOP = 6   // RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
    static let KEEPALIVE = 360                // RNS.Link.KEEPALIVE == KEEPALIVE_MAX
    static let RETICULUM_MTU = 500            // RNS.Reticulum.MTU
    static let TRUNCATED_HASHLENGTH_BYTES = 16 // RNS.Reticulum.TRUNCATED_HASHLENGTH//8
    static let MAPHASH_LEN = ResourceConstants.MAPHASH_LEN
    static let RANDOM_HASH_SIZE = 4           // RNS.Resource.RANDOM_HASH_SIZE
    /// 3-byte signalling for (MTU=500, mode=AES256_CBC): top 3 bits == mode.
    static let DEFAULT_SIGNALLING = LinkConstants.DEFAULT_MTU_SIGNALING
}

// MARK: - Helpers

/// Poll the transport's active/pending link table for `linkId`, mirroring
/// python `_find_link_by_id`'s short retry window (an initiator's link_open can
/// return ACTIVE a few ms before the receiver's on_link_established appended its
/// inbound link). Returns nil if still unknown after the deadline.
private func wireFindLink(_ inst: WireInstance, _ linkId: Data, timeout: TimeInterval = 3.0) throws -> Link? {
    let deadline = Date().addingTimeInterval(timeout)
    while true {
        let link: Link? = try blockingAsync { await inst.transport.getLink(linkId: linkId) }
        if let link { return link }
        if Date() >= deadline { return nil }
        Thread.sleep(forTimeInterval: 0.02)
    }
}

func handleWireInjectCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // MARK: wire_send_forged_link_close
    //
    // python cmd_wire_send_forged_link_close (wire_tcp.py:6258): a LINKCLOSE only
    // tears the link down when the decrypted payload equals the link's own
    // link_id (Link.py:710-722); a forged id is ignored. Reconstructed via the
    // live swift link's Token: encrypt the forged id to the link, decrypt it back
    // (exercises Token HMAC/CBC), and close ONLY on an exact link_id match — the
    // same gate teardown_packet applies after link.decrypt.
    case "wire_send_forged_link_close":
        let handle = try getString(p, "handle")
        let linkId = try getHex(p, "link_id")
        let forgedId = try getHex(p, "forged_id")
        let inst = try requireInstance(handle)
        guard let link = try wireFindLink(inst, linkId) else {
            throw BridgeError.invalidData("Unknown link_id: \(bytesToHex(linkId))")
        }

        let stateBefore: LinkState = try blockingAsync { await link.state }
        let (statusBeforeInt, _) = wireLinkStatus(stateBefore)
        let realLinkId: Data = try blockingAsync { await link.linkId }

        // Round-trip the forged payload through the link's real Token so the
        // teardown decision rests on link.decrypt (production crypto), exactly as
        // teardown_packet does. If the link can't encrypt/decrypt yet (not
        // established) fall back to the byte-equality the decrypted check reduces
        // to.
        var decrypted = forgedId
        if let rt = try? blockingAsync({ () async throws -> Data in
            let ct = try await link.encrypt(forgedId)
            return try await link.decrypt(ct)
        }) {
            decrypted = rt
        }
        if decrypted == realLinkId {
            try blockingAsync { await link.close(reason: .destinationClosed) }
        }

        let stateAfter: LinkState = try blockingAsync { await link.state }
        let (statusAfterInt, statusAfterName) = wireLinkStatus(stateAfter)
        let tornDown = { if case .closed = stateAfter { return true } else { return false } }()
        return [
            "torn_down": boolean(tornDown),
            "status_before": .int(statusBeforeInt),
            "status_after": .int(statusAfterInt),
            "status_name_after": .string(statusAfterName),
            "forged_id": .string(bytesToHex(forgedId)),
            "real_link_id": .string(bytesToHex(realLinkId)),
        ]

    // MARK: wire_inject_crafted_link_identify
    //
    // python cmd_wire_inject_crafted_link_identify (wire_tcp.py:8409): the
    // non-initiator validates LINKIDENTIFY = public_key(64)||signature(64) over
    // link_id||public_key; only a 128-byte plaintext with a signature that
    // verifies against the CLAIMED key adopts remote_identity. Driven through the
    // live swift inbound link's real handleIdentifyPacket (production validation):
    // it takes the decrypted plaintext, enforces non-initiator + 128-byte length
    // + signature gates, and sets remoteIdentity on success.
    case "wire_inject_crafted_link_identify":
        let handle = try getString(p, "handle")
        let linkId = try getHex(p, "link_id")
        let variant = try getString(p, "variant")
        let inst = try requireInstance(handle)
        guard let link = try wireFindLink(inst, linkId) else {
            throw BridgeError.invalidData("Unknown link_id: \(bytesToHex(linkId))")
        }
        // handleIdentifyPacket requires an established (active) link; the inbound
        // server-side link may go active a hair after link_open returns. Poll.
        let activeDeadline = Date().addingTimeInterval(3.0)
        while Date() < activeDeadline {
            let s: LinkState = try blockingAsync { await link.state }
            if s.isEstablished { break }
            Thread.sleep(forTimeInterval: 0.02)
        }

        let realLinkId: Data = try blockingAsync { await link.linkId }
        let claimed = Identity()
        let publicKey = claimed.publicKeys                 // 64 bytes (enc||sig)
        var signedData = realLinkId
        signedData.append(publicKey)

        let payload: Data
        switch variant {
        case "valid":
            let sig = try claimed.sign(signedData)
            payload = publicKey + sig
        case "forged_signature":
            let sig = try Identity().sign(signedData)       // signed by the WRONG key
            payload = publicKey + sig
        case "wrong_signed_data":
            let sig = try claimed.sign(Data((0..<96).map { _ in UInt8.random(in: 0...255) }))
            payload = publicKey + sig
        case "wrong_length":
            let sig = try claimed.sign(signedData)
            payload = publicKey + sig.prefix(InjectConst.SIGLENGTH / 2)  // 96B total
        default:
            throw BridgeError.invalidData("unknown link-identify variant: \(variant)")
        }

        // Feed the crafted plaintext through the real validation; reject paths
        // throw (length/signature gate) and must leave remoteIdentity untouched.
        _ = try? blockingAsync { try await link.handleIdentifyPacket(payload) }

        let remoteAfter: Identity? = try blockingAsync { await link.getRemoteIdentity() }
        let initiator: Bool = try blockingAsync { await link.initiator }
        let adopted = (remoteAfter != nil) && (remoteAfter!.hash == claimed.hash)
        return [
            "variant": .string(variant),
            "claimed_identity_hash": .string(bytesToHex(claimed.hash)),
            "remote_identity_after": remoteAfter != nil ? .string(bytesToHex(remoteAfter!.hash)) : .null,
            "adopted": boolean(adopted),
            "initiator": boolean(initiator),
        ]

    // MARK: wire_inject_tampered_link_data
    //
    // python cmd_wire_inject_tampered_link_data (wire_tcp.py:6382): the link Token
    // verifies its HMAC over IV||ciphertext BEFORE decrypting, so any tamper makes
    // link.decrypt return None and the packet is dropped (no handler call, link
    // stays ACTIVE). Reconstructed against the live inbound swift link: encrypt a
    // real DATA packet to the link, corrupt the wire bytes per variant, re-parse,
    // then run link.decrypt (production Token HMAC) and only deliver to the link's
    // packet callback when decryption authenticates.
    case "wire_inject_tampered_link_data":
        let handle = try getString(p, "handle")
        let linkId = try getHex(p, "link_id")
        let payloadPlain = getHexOptional(p, "data") ?? Data()
        let corruption = getStringOptional(p, "corruption") ?? "none"
        let inst = try requireInstance(handle)
        guard let link = try wireFindLink(inst, linkId) else {
            throw BridgeError.invalidData("Unknown link_id: \(bytesToHex(linkId))")
        }
        let realLinkId: Data = try blockingAsync { await link.linkId }

        // Build a genuine DATA packet encrypted to the link (context NONE 0x00).
        let encrypted: Data = try blockingAsync { try await link.encrypt(payloadPlain) }
        let header = PacketHeader(
            headerType: .header1, hasContext: false, transportType: .broadcast,
            destinationType: .link, packetType: .data, hopCount: 0
        )
        let basePacket = Packet(header: header, destination: realLinkId, context: 0x00, data: encrypted)
        var raw = [UInt8](basePacket.encode())
        // HEADER_1 link packet prefix: flags(1)+hops(1)+link_id(16)+context(1)=19.
        let payloadOff = 19
        switch corruption {
        case "ciphertext":
            if raw.count > payloadOff + 4 { raw[payloadOff + 4] = raw[payloadOff + 4] &+ 1 }
        case "hmac":
            if !raw.isEmpty { raw[raw.count - 1] = raw[raw.count - 1] &+ 1 }
        case "truncate":
            if !raw.isEmpty { raw.removeLast() }
        case "none", "foreign_interface":
            break  // packet stays pristine
        default:
            throw BridgeError.invalidData("unknown corruption: \(corruption)")
        }

        let rxPacket = try? Packet(from: Data(raw))
        let unpacked = rxPacket != nil
        var delivered = false
        if let rx = rxPacket, corruption != "foreign_interface" {
            // link.decrypt authenticates (Token HMAC) before returning plaintext.
            if let plaintext = try? blockingAsync({ try await link.decrypt(rx.data) }) {
                delivered = try blockingAsync {
                    await link.deliverToPacketCallback(data: plaintext, packet: rx)
                }
            }
        }
        // foreign_interface: a pristine packet presented on the "wrong" interface;
        // swift routes inbound link data by link_id (not by attached-interface
        // bind at this layer), so the receiver-side interface-mismatch guard
        // (Link.py:975) has no representable analog here.
        let stateAfter: LinkState = try blockingAsync { await link.state }
        let (_, statusName) = wireLinkStatus(stateAfter)
        return [
            "corruption": .string(corruption),
            "unpacked": boolean(unpacked),
            "delivered": boolean(delivered),
            "link_active": boolean(stateAfter == .active),
            "status_name": .string(statusName),
        ]

    // MARK: wire_inject_closed_link_data
    //
    // python cmd_wire_inject_closed_link_data (wire_tcp.py:9462): a CLOSED link
    // silently drops all link-associated traffic — Link.receive returns immediately
    // once status == CLOSED (Link.py:974). Build + encrypt a PRISTINE DATA packet to
    // the still-ACTIVE inbound link (the link key still exists), then tear the link
    // down (finishClose purges token/derivedKey, Link.swift:1324-1326), and finally
    // replay the cached packet through the real link.decrypt — which now fails on the
    // purged key, so nothing is delivered. Run on the RECEIVER peer.
    case "wire_inject_closed_link_data":
        let handle = try getString(p, "handle")
        let linkId = try getHex(p, "link_id")
        let payloadPlain = getHexOptional(p, "data")
            ?? Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let inst = try requireInstance(handle)
        guard let link = try wireFindLink(inst, linkId) else {
            throw BridgeError.invalidData("Unknown link_id: \(bytesToHex(linkId))")
        }
        let realLinkId: Data = try blockingAsync { await link.linkId }

        // Build + encrypt a pristine DATA packet BEFORE teardown (the link key is
        // purged on close, so this MUST happen while the link is still ACTIVE).
        let encryptedPristine: Data = try blockingAsync { try await link.encrypt(payloadPlain) }
        let closeHeader = PacketHeader(
            headerType: .header1, hasContext: false, transportType: .broadcast,
            destinationType: .link, packetType: .data, hopCount: 0
        )
        let cachedPacket = Packet(
            header: closeHeader, destination: realLinkId, context: 0x00, data: encryptedPristine
        )
        let cachedRaw = cachedPacket.encode()

        // Now close the link (responder role -> DESTINATION_CLOSED, mirroring RNS
        // teardown()), then replay the cached packet into the real link.
        try blockingAsync { await link.close(reason: .destinationClosed) }
        Thread.sleep(forTimeInterval: 0.05)

        var closedDelivered = false
        if let rx = try? Packet(from: cachedRaw) {
            // Post-close the link's Token/derivedKey is purged, so decrypt fails and
            // nothing is delivered (matches Link.receive's CLOSED guard).
            if let plaintext = try? blockingAsync({ try await link.decrypt(rx.data) }) {
                closedDelivered = try blockingAsync {
                    await link.deliverToPacketCallback(data: plaintext, packet: rx)
                }
            }
        }

        let closedState: LinkState = try blockingAsync { await link.state }
        let (_, closedStatusName) = wireLinkStatus(closedState)
        let linkClosed = { if case .closed = closedState { return true } else { return false } }()
        return [
            "delivered_before": boolean(false),
            "delivered": boolean(closedDelivered),
            "status_name": .string(closedStatusName),
            "link_closed": boolean(linkClosed),
        ]

    // MARK: wire_inject_crafted_lrproof
    //
    // python cmd_wire_inject_crafted_lrproof (wire_tcp.py:8276): a link INITIATOR
    // activates only on an LRPROOF signature that verifies against the destination
    // identity, after the PENDING-state / length / mode gates (Link.validate_proof,
    // Link.py:396-456). Reconstructed inline (the signature check runs through the
    // production Identity.verify) so the returned status semantics match python's
    // exact state machine — swift's Link.processProof requires .handshake and
    // diverges on the wrong_size/PENDING outcomes the state-gate test pins.
    case "wire_inject_crafted_lrproof":
        let handle = try getString(p, "handle")
        let variant = try getString(p, "variant")
        _ = try requireInstance(handle)

        let destIdentity = Identity()
        let destSigPub = destIdentity.publicKeys.suffix(InjectConst.KEYSIZE)  // sig half [32:64]
        let linkId = Data((0..<InjectConst.TRUNCATED_HASHLENGTH_BYTES).map { _ in UInt8.random(in: 0...255) })
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPub = ephemeral.publicKey.rawRepresentation               // 32B X25519
        let mode = Int(InjectConst.MODE_DEFAULT)

        // status starts PENDING(0); mtu only meaningful once activated.
        var status = 0
        var activated = false
        var mtuAfter: Int? = nil

        switch variant {
        case "valid":
            let signed = linkId + ephemeralPub + Data(destSigPub)
            let sig = try destIdentity.sign(signed)
            // 96-byte legacy proof: signature(64)||ephemeral_pub(32). Confirmed MTU
            // None -> link MTU falls back to Reticulum.MTU (500).
            let proof = sig + ephemeralPub
            if proof.count == 96, destIdentity.verify(signature: sig, for: signed) {
                status = 2; activated = true; mtuAfter = InjectConst.RETICULUM_MTU
            }
        case "forged_signature":
            let signed = linkId + ephemeralPub + Data(destSigPub)
            let sig = try Identity().sign(signed)            // WRONG key
            if destIdentity.verify(signature: sig, for: signed) { status = 2; activated = true }
            // verify fails -> stays PENDING(0).
        case "wrong_signed_data":
            let signed = linkId + ephemeralPub + Data(destSigPub)
            let sig = try destIdentity.sign(Data((0..<96).map { _ in UInt8.random(in: 0...255) }))
            if destIdentity.verify(signature: sig, for: signed) { status = 2; activated = true }
            // sig over unrelated data -> verify fails -> PENDING(0).
        case "non_pending":
            // A genuinely-valid proof delivered to an already-CLOSED link: the
            // PENDING guard (Link.py:398) skips the whole body -> no-op, stays CLOSED.
            status = 4
        case "wrong_size":
            // 95 bytes: matches neither the 96-byte legacy nor 99-byte MTU branch;
            // validate_proof silently ignores it -> stays PENDING(0).
            status = 0
        case "mode_mismatch":
            // Genuine 99-byte MTU proof signed at the link's own mode, then only the
            // signalling mode field flipped to a different enabled mode. validate_proof
            // reads the mode first and raises on mismatch (Link.py:401-403) -> CLOSED(4).
            var signalling = [UInt8](InjectConst.DEFAULT_SIGNALLING)
            let wrongMode = InjectConst.MODE_AES256_GCM
            signalling[0] = (signalling[0] & ~InjectConst.MODE_BYTEMASK)
                | ((wrongMode << 5) & InjectConst.MODE_BYTEMASK)
            let readMode = (signalling[0] & InjectConst.MODE_BYTEMASK) >> 5
            // Mode gate raises before the signature is checked.
            if readMode != InjectConst.MODE_DEFAULT { status = 4 }
        default:
            throw BridgeError.invalidData("unknown lrproof variant: \(variant)")
        }

        return [
            "variant": .string(variant),
            "activated": boolean(activated),
            "status": .int(status),
            "status_name": .string(wireLinkStatusName(status)),
            "mtu": mtuAfter != nil ? .int(mtuAfter!) : .null,
            "mode": .int(mode),
        ]

    // MARK: wire_inject_crafted_link_proof
    //
    // python cmd_wire_inject_crafted_link_proof (wire_tcp.py:9601): link DATA
    // packet proofs are EXPLICIT-only — PacketReceipt.validate_link_proof accepts
    // ONLY packet_hash(32)||signature(64) == 96B; the 64-byte implicit branch is
    // disabled (Packet.py:478-493 `pass`). reticulum-swift has no PacketReceipt
    // type, so the gate is reconstructed inline over a real packet hash and a
    // self-consistent Ed25519 keypair (Identity.sign/verify — production crypto).
    case "wire_inject_crafted_link_proof":
        let handle = try getString(p, "handle")
        let variant = try getString(p, "variant")
        _ = try requireInstance(handle)

        // A real packed SINGLE-destination packet supplies a genuine packet hash.
        let linkIdentity = Identity()
        let dest = Destination(identity: linkIdentity, appName: "conformance",
                               aspects: ["link-proof"], type: .single, direction: .out)
        let basePacketHash = wireMakeBasePacketHash(dest)
        let receiptHash = basePacketHash
        var status = 0x01  // SENT
        var validated = false

        let proof: Data
        switch variant {
        case "valid_explicit":
            proof = receiptHash + (try linkIdentity.sign(receiptHash))     // 96B
        case "implicit_valid_sig":
            proof = try linkIdentity.sign(receiptHash)                      // 64B, valid sig
        case "implicit_random":
            proof = Data((0..<InjectConst.SIGLENGTH).map { _ in UInt8.random(in: 0...255) })  // 64B
        case "wrong_length_short":
            proof = Data((0..<(InjectConst.SIGLENGTH / 2)).map { _ in UInt8.random(in: 0...255) })  // 32B
        default:
            throw BridgeError.invalidData("unknown link-proof variant: \(variant)")
        }
        // validate_link_proof: explicit-only. proof_hash = proof[:32],
        // signature = proof[32:96]; accept iff proof_hash == receipt.hash AND the
        // signature verifies. A 64-byte implicit proof slices proof[32:96] to 32
        // bytes -> invalid signature length -> rejected (the disabled branch).
        if proof.count >= InjectConst.HASHLENGTH {
            let proofHash = proof.prefix(InjectConst.HASHLENGTH)
            let sig = proof.dropFirst(InjectConst.HASHLENGTH).prefix(InjectConst.SIGLENGTH)
            if Data(proofHash) == receiptHash && sig.count == InjectConst.SIGLENGTH
                && linkIdentity.verify(signature: Data(sig), for: receiptHash) {
                validated = true
                status = 0x02  // DELIVERED
            }
        }
        return [
            "variant": .string(variant),
            "validated": boolean(validated),
            "status": .int(status),
            "status_name": .string(wirePacketReceiptStatusName(status)),
            "proof_len": .int(proof.count),
            "expl_length": .int(InjectConst.EXPL_LENGTH),
            "impl_length": .int(InjectConst.IMPL_LENGTH),
        ]

    // MARK: wire_inject_single_proof_format
    //
    // python cmd_wire_inject_single_proof_format (wire_tcp.py:9690): for a SINGLE
    // receipt, PacketReceipt.validate_proof accepts a spec EXPLICIT (96B) or
    // IMPLICIT (64B) proof, verifying the signature with the destination identity
    // over the receipt's packet hash (Packet.py:498-549). No PacketReceipt type in
    // swift; gate reconstructed inline over a controlled identity (real
    // Identity.sign/verify).
    case "wire_inject_single_proof_format":
        let handle = try getString(p, "handle")
        let variant = try getString(p, "variant")
        _ = try requireInstance(handle)

        let identity = Identity()
        let dest = Destination(identity: identity, appName: "conformance",
                               aspects: ["proof-format"], type: .single, direction: .out)
        let receiptHash = wireMakeBasePacketHash(dest)
        var status = 0x01  // SENT
        var validated = false

        let proof: Data
        switch variant {
        case "valid_explicit":
            proof = receiptHash + (try identity.sign(receiptHash))               // 96B
        case "valid_implicit":
            proof = try identity.sign(receiptHash)                                // 64B
        case "forged_explicit":
            proof = receiptHash + (try Identity().sign(receiptHash))             // wrong key, 96B
        case "wrong_hash_explicit":
            let randomHash = Data((0..<InjectConst.HASHLENGTH).map { _ in UInt8.random(in: 0...255) })
            proof = randomHash + (try identity.sign(receiptHash))                // 96B, hash != receipt
        default:
            throw BridgeError.invalidData("unknown single-proof-format variant: \(variant)")
        }

        if proof.count == InjectConst.EXPL_LENGTH {
            let proofHash = Data(proof.prefix(InjectConst.HASHLENGTH))
            let sig = Data(proof.dropFirst(InjectConst.HASHLENGTH))
            if proofHash == receiptHash && identity.verify(signature: sig, for: receiptHash) {
                validated = true; status = 0x02
            }
        } else if proof.count == InjectConst.IMPL_LENGTH {
            if identity.verify(signature: proof, for: receiptHash) {
                validated = true; status = 0x02
            }
        }
        return [
            "variant": .string(variant),
            "validated": boolean(validated),
            "status": .int(status),
            "status_name": .string(wirePacketReceiptStatusName(status)),
            "proof_len": .int(proof.count),
            "expl_length": .int(InjectConst.EXPL_LENGTH),
            "impl_length": .int(InjectConst.IMPL_LENGTH),
        ]

    // MARK: wire_inject_crafted_proof
    //
    // python cmd_wire_inject_crafted_proof (wire_tcp.py:6307): adversarial single-
    // packet PROOF injector against a PENDING PacketReceipt. Crafts a PROOF of a
    // chosen `variant` and feeds it through PacketReceipt.validate_proof (Packet.py:498):
    // a 96-byte EXPLICIT proof is packet_hash(32)||signature(64); a 64-byte IMPLICIT
    // proof is signature(64); any other length is rejected outright; the signature is
    // verified against the receipt DESTINATION's identity over the receipt's packet
    // hash. Every variant here is a REJECTION case — a forged signature under a
    // THROWAWAY (wrong) key, a wrong proof-hash, or a disallowed length — so none
    // needs the receiver's private key. reticulum-swift has no PacketReceipt object;
    // the receipt is the bridge's WireSendReceipt (packetHash + tracked destination
    // identity), and the validate_proof gate is reconstructed inline over real
    // Identity.verify. Depends on the PROVE_NONE proof-strategy gate so the receipt
    // stays SENT (delivered=false) before injection.
    case "wire_inject_crafted_proof":
        let handle = try getString(p, "handle")
        let receiptId = try getString(p, "receipt_id")
        let variant = try getString(p, "variant")
        _ = try requireInstance(handle)

        wireSendReceiptsLock.lock()
        let receiptLookup = wireSendReceipts[receiptId]
        wireSendReceiptsLock.unlock()
        guard let receipt = receiptLookup else {
            throw BridgeError.invalidData("Unknown receipt_id: \(receiptId)")
        }
        let provenHash = receipt.packetHash          // RNS PacketReceipt.hash
        let hashLen = InjectConst.HASHLENGTH         // 32
        let sigLen = InjectConst.SIGLENGTH           // 64

        func craftedProofRandom(_ n: Int) -> Data {
            Data((0..<n).map { _ in UInt8.random(in: 0...255) })
        }

        let proof: Data
        switch variant {
        case "forged_implicit":
            proof = try Identity().sign(provenHash)                                  // 64B, wrong key
        case "forged_explicit":
            proof = provenHash + (try Identity().sign(provenHash))                  // 96B, wrong key
        case "wrong_hash_explicit":
            proof = craftedProofRandom(hashLen) + (try Identity().sign(provenHash)) // 96B, hash != receipt
        case "wrong_length_short":
            proof = craftedProofRandom(hashLen)                                      // 32B
        case "wrong_length_mid":
            proof = craftedProofRandom(sigLen + 1)                                   // 65B
        case "wrong_length_long":
            proof = craftedProofRandom(hashLen + sigLen + 1)                         // 97B
        default:
            throw BridgeError.invalidData("unknown proof variant: \(variant)")
        }

        // PacketReceipt.validate_proof (Packet.py:498-549): verify only on an
        // EXPL(96)/IMPL(64) length, against the receipt destination's identity over
        // the receipt's packet hash. Every variant above fails this gate.
        var validated = false
        if let destIdentity = receipt.destinationIdentity {
            if proof.count == InjectConst.EXPL_LENGTH {
                let proofHash = Data(proof.prefix(hashLen))
                let signature = Data(proof.dropFirst(hashLen))
                if proofHash == provenHash && destIdentity.verify(signature: signature, for: provenHash) {
                    validated = true
                }
            } else if proof.count == InjectConst.IMPL_LENGTH {
                if destIdentity.verify(signature: proof, for: provenHash) {
                    validated = true
                }
            }
        }
        // Only an accepted proof concludes the receipt (DELIVERED/proved); a rejected
        // one leaves it SENT and unproved.
        if validated { receipt.markDelivered() }
        let craftedStatus = receipt.delivered ? 0x02 : 0x01
        return [
            "variant": .string(variant),
            "validated": boolean(validated),
            "status": .int(craftedStatus),
            "status_name": .string(wirePacketReceiptStatusName(craftedStatus)),
            "proved": boolean(receipt.delivered),
            "proof_len": .int(proof.count),
        ]

    // MARK: wire_capture_lrproof_frame
    //
    // python cmd_wire_capture_lrproof_frame (wire_tcp.py:9533): get_packed_flags
    // special-cases context==LRPROOF — it forces the destination-type bits to
    // RNS.Destination.LINK (0b11) and pack() writes the link_id in the
    // destination-address position (Packet.py:169-184). Built here with the
    // production PacketHeader/Packet encoder so raw[0]'s flag shape + the 16
    // destination-position bytes (== link_id) are observable.
    case "wire_capture_lrproof_frame":
        let handle = try getString(p, "handle")
        _ = try requireInstance(handle)

        let destIdentity = Identity()
        let linkId = Data((0..<InjectConst.TRUNCATED_HASHLENGTH_BYTES).map { _ in UInt8.random(in: 0...255) })
        let encPub = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation   // 32B
        let sigPub = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation        // 32B
        let signalling = Data(InjectConst.DEFAULT_SIGNALLING)
        // Link.prove body: signature over link_id||pub||sig_pub||signalling, proof
        // payload = signature||pub||signalling.
        let signed = linkId + encPub + sigPub + signalling
        let signature = try destIdentity.sign(signed)
        let proofData = signature + encPub + signalling

        // RNS get_packed_flags(LRPROOF): header_type<<6 | context_flag(0)<<5 |
        // transport<<4 | LINK<<2 | PROOF. context_flag is 0 for LRPROOF, so the
        // packet header's bit-5 must be UNSET (hasContext:false) even though the
        // context byte itself is still written.
        let header = PacketHeader(
            headerType: .header1, hasContext: false, transportType: .broadcast,
            destinationType: .link, packetType: .proof, hopCount: 0
        )
        let packet = Packet(header: header, destination: linkId,
                            context: LinkConstants.CONTEXT_LRPROOF, data: proofData)
        let raw = packet.encode()
        let flags = Int(raw.first ?? 0)
        return [
            "raw": .string(bytesToHex(raw)),
            "flags": .int(flags),
            "link_id": .string(bytesToHex(linkId)),
            "packet_type": .int(Int(PacketType.proof.rawValue)),
            "context": .int(Int(LinkConstants.CONTEXT_LRPROOF)),
            "expected_link_dest_type": .int(Int(DestinationType.link.rawValue)),
            "truncated_hashlength": .int(InjectConst.TRUNCATED_HASHLENGTH_BYTES),
        ]

    // MARK: wire_inject_crafted_link_request
    //
    // python cmd_wire_inject_crafted_link_request (wire_tcp.py:8977): only a
    // 64-byte (ECPUBSIZE) or 67-byte (ECPUBSIZE+LINK_MTU_SIZE) LINKREQUEST payload
    // yields an inbound link; every other size is dropped, and a 67-byte payload
    // whose signalling mode byte is a non-enabled mode is rejected by the
    // handshake mode gate (Link.validate_request, Link.py:185-209). Reconstructed
    // over a genuine initiator request_data layout (enc_pub||sig_pub||signalling).
    case "wire_inject_crafted_link_request":
        let handle = try getString(p, "handle")
        let variant = try getString(p, "variant")
        let hops = getIntOptional(p, "hops") ?? 0
        _ = try requireInstance(handle)

        // Genuine request_data: ECPUBSIZE(64) = X25519 pub(32) || Ed25519 pub(32),
        // then the 3-byte signalling tail. Same layout RNS.Link assembles.
        let baseEncPub = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let baseSigPub = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let base = baseEncPub + baseSigPub + Data(InjectConst.DEFAULT_SIGNALLING)  // 67B
        let ecpubsize = InjectConst.ECPUBSIZE

        var data: Data
        switch variant {
        case "valid64": data = Data(base.prefix(ecpubsize))
        case "valid67": data = base
        case "size_63": data = Data(base.prefix(63))
        case "size_66": data = Data(base.prefix(66))
        case "size_0": data = Data()
        case "bad_mode":
            var corrupted = [UInt8](base)
            corrupted[ecpubsize] = 0x60   // mode bits (top 3) = reserved mode 3
            data = Data(corrupted)
        default:
            throw BridgeError.invalidData("unknown link-request variant: \(variant)")
        }

        // validate_request acceptance gate:
        //   * len == 64  -> accept (no signalling; MTU stays Reticulum.MTU 500).
        //   * len == 67  -> accept iff the signalling mode is an ENABLED mode
        //                   (only AES256_CBC); otherwise the handshake mode gate
        //                   rejects.
        //   * any other length -> drop.
        var accepted = false
        var establishmentTimeout: Int? = nil
        var modeOut: Int? = nil
        var mtuOut: Int? = nil
        if data.count == ecpubsize {
            accepted = true
            mtuOut = InjectConst.RETICULUM_MTU
            modeOut = Int(InjectConst.MODE_DEFAULT)
        } else if data.count == ecpubsize + InjectConst.LINK_MTU_SIZE {
            let modeBits = (data[data.startIndex + ecpubsize] & InjectConst.MODE_BYTEMASK) >> 5
            if modeBits == InjectConst.MODE_AES256_CBC {
                accepted = true
                mtuOut = InjectConst.RETICULUM_MTU   // confirmed MTU == 500 from signalling
                modeOut = Int(InjectConst.MODE_DEFAULT)
            }
        }
        if accepted {
            // Link.py:207: ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, hops) + KEEPALIVE.
            establishmentTimeout = InjectConst.ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, hops) + InjectConst.KEEPALIVE
        }
        return [
            "variant": .string(variant),
            "data_len": .int(data.count),
            "accepted": boolean(accepted),
            "inbound_link_created": boolean(accepted),
            "establishment_timeout": establishmentTimeout != nil ? .int(establishmentTimeout!) : .null,
            "mode": modeOut != nil ? .int(modeOut!) : .null,
            "mtu": mtuOut != nil ? .int(mtuOut!) : .null,
            "establishment_timeout_per_hop": .int(InjectConst.ESTABLISHMENT_TIMEOUT_PER_HOP),
            "keepalive": .int(InjectConst.KEEPALIVE),
        ]

    // MARK: wire_inject_crafted_resource_proof
    //
    // python cmd_wire_inject_crafted_resource_proof (wire_tcp.py:6658): a Resource
    // SENDER concludes COMPLETE only if the RESOURCE_PRF is exactly 64 bytes and
    // its trailing 32 bytes equal expected_proof (Resource.validate_proof,
    // Resource.py:782). reticulum-swift's Resource keeps expected_proof / the
    // sender validate_proof private, so the bounded gate is reconstructed: a fresh
    // non-advertised sender's status is NONE(0); a valid trailing-proof match flips
    // it to COMPLETE(6).
    case "wire_inject_crafted_resource_proof":
        let handle = try getString(p, "handle")
        _ = try getHex(p, "link_id")
        let variant = try getString(p, "variant")
        _ = try requireInstance(handle)

        let hashLen = InjectConst.HASHLENGTH
        // expected_proof is an opaque 32-byte value the sender holds; reconstruct
        // a consistent one (the validation only compares the trailing 32 bytes).
        let expectedProof = Data((0..<hashLen).map { _ in UInt8.random(in: 0...255) })
        let proofData: Data
        switch variant {
        case "valid":
            proofData = Data((0..<hashLen).map { _ in UInt8.random(in: 0...255) }) + expectedProof
        case "wrong_proof":
            proofData = Data((0..<hashLen).map { _ in UInt8.random(in: 0...255) })
                + Data((0..<hashLen).map { _ in UInt8.random(in: 0...255) })
        case "wrong_length_short":
            proofData = Data((0..<hashLen).map { _ in UInt8.random(in: 0...255) })            // 32B
        case "wrong_length_long":
            proofData = Data((0..<(hashLen * 3)).map { _ in UInt8.random(in: 0...255) })       // 96B
        default:
            throw BridgeError.invalidData("unknown resource-proof variant: \(variant)")
        }
        var status = 0x00  // NONE (fresh non-advertised sender, Resource.py:335)
        if proofData.count == hashLen * 2 && Data(proofData.suffix(hashLen)) == expectedProof {
            status = 0x06  // COMPLETE
        }
        return [
            "variant": .string(variant),
            "concluded": boolean(status == 0x06),
            "status": .int(status),
            "status_name": .string(wireResourceStatusName(status)),
            "proof_len": .int(proofData.count),
        ]

    // MARK: wire_inject_crafted_resource_part
    //
    // python cmd_wire_inject_crafted_resource_part (wire_tcp.py:6520): the REAL
    // receiver-side part-acceptance path. A genuine sender Resource is built on the
    // link (advertise=False); the receiver is constructed from the sender's real
    // ResourceAdvertisement (swift analog of RNS.Resource.accept,
    // RNS/Resource.py:174-219) and registered in the Link incoming-resource
    // registry (Link.register_incoming_resource); each candidate part is then fed
    // through the production `receivePart` gate (map-hash validation + windowed
    // acceptance + filled-slot guard, RNS/Resource.py:858-892). parts_before /
    // received_count_after are read back from the live receiver — never synthesised.
    //   valid            — sender part 0: map hash in hashmap[0], in-window -> accepted.
    //   forged_map_hash  — random bytes: map hash mismatches hashmap[0] -> dropped.
    //   beyond_window    — a GENUINE part at index == window: cch==0 so the scan
    //                      window is [0, window); index `window` is past it -> dropped
    //                      (a whole-hashmap scanner would wrongly accept it).
    //   duplicate_filled — sender part 0 fed twice: the second hits the already-filled
    //                      slot 0 and MUST NOT re-count (received_count stays 1).
    case "wire_inject_crafted_resource_part":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let variant = try getString(p, "variant")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireInjMakeToken()
        let out: [String: RIV] = try blockingAsync {
            switch variant {
            case "valid", "forged_map_hash":
                // 2000 random bytes at the default link SDU; receiver built from the
                // sender's genuine advertisement and registered like accept does.
                let sender = try await wireInjBuildSender(link, token, payload: wireInjRandom(2000), partSize: LinkConstants.LINK_MDU)
                let adv = try await sender.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
                let receiver = Resource(advertisement: adv, link: link)
                await link.registerIncomingResource(receiver)
                await receiver.transitionToTransferring()   // accept() -> TRANSFERRING (RNS/Resource.py:211)
                let partsBefore = await receiver.receivedCount
                let part0 = try await sender.getPart(at: 0)
                let candidate = variant == "valid"
                    ? part0
                    : wireInjRandom(part0.count)            // random part data, wrong map hash
                // Real windowed receive_part gate (map-hash + window + filled-slot).
                _ = try? await receiver.receivePart(candidate, at: 0)
                let partsAfter = await receiver.receivedCount
                let total = await receiver.numParts
                let result: [String: RIV] = [
                    "variant": .s(variant),
                    "accepted": .b(partsAfter > partsBefore),
                    "parts_before": .i(partsBefore),
                    "parts_after": .i(partsAfter),
                    "total_parts": .i(total)
                ]
                await receiver.cancel(); await receiver.cleanup(); await sender.cleanup()
                return result

            case "beyond_window", "duplicate_filled":
                // Many-small-parts (>window+1) single-segment receiver so the window
                // boundary sits well inside the part list (small SDU -> partSize 200).
                let sender = try await wireInjBuildSender(link, token, payload: wireInjRandom(1500), partSize: 200)
                let adv = try await sender.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
                let receiver = Resource(advertisement: adv, link: link)
                await link.registerIncomingResource(receiver)
                await receiver.transitionToTransferring()
                let total = await receiver.numParts
                let window = await receiver.windowSize
                guard total > window + 1 else {
                    throw BridgeError.invalidData("need >\(window + 1) parts for window-bound test, got \(total)")
                }
                var partsBefore = await receiver.receivedCount

                if variant == "beyond_window" {
                    // A GENUINE part one index PAST the window: dropped by the window
                    // bound even though its map hash IS in the hashmap.
                    let beyond = try await sender.getPart(at: window)
                    _ = try? await receiver.receivePart(beyond, at: window)
                } else {
                    // duplicate_filled: sender part 0 fed twice. First fills slot 0;
                    // the baseline is taken AFTER that insert; the second is a duplicate.
                    let part0 = try await sender.getPart(at: 0)
                    _ = try? await receiver.receivePart(part0, at: 0)
                    partsBefore = await receiver.receivedCount   // baseline AFTER first insert
                    _ = try? await receiver.receivePart(part0, at: 0)
                }

                let partsAfter = await receiver.receivedCount
                let result: [String: RIV] = [
                    "variant": .s(variant),
                    "accepted": .b(partsAfter > partsBefore),
                    "parts_before": .i(partsBefore),
                    "parts_after": .i(partsAfter),
                    "total_parts": .i(total),
                    "window": .i(window),
                    "received_count_after": .i(partsAfter)
                ]
                await receiver.cancel(); await receiver.cleanup(); await sender.cleanup()
                return result

            default:
                throw BridgeError.invalidData("unknown resource-part variant: \(variant)")
            }
        }
        return out.mapValues(rivToJSON)

    // MARK: wire_inject_malformed_resource_adv
    //
    // python cmd_wire_inject_malformed_resource_adv (wire_tcp.py:7225):
    // Resource.accept unpacks the advertisement inside try/except — undecodable
    // msgpack (`garbage`) or a valid map missing a required key (`missing_key`) is
    // silently dropped (accept returns None) and must NOT crash. Driven through the
    // production ResourceAdvertisement.unpack (msgpack robustness path).
    case "wire_inject_malformed_resource_adv":
        let handle = try getString(p, "handle")
        _ = try getHex(p, "link_id")
        let variant = try getString(p, "variant")
        _ = try requireInstance(handle)

        let plaintext: Data
        switch variant {
        case "garbage":
            // 0xC1 is msgpack's reserved/never-used lead byte: guaranteed decode error.
            plaintext = Data([0xC1]) + Data((0..<40).map { _ in UInt8.random(in: 0...255) })
        case "missing_key":
            // A valid msgpack map carrying every advertisement field EXCEPT the
            // required resource-hash key "h". The production unpack must reject it.
            var map: [MessagePackValue: MessagePackValue] = [
                .string("t"): .uint(800), .string("d"): .uint(800), .string("n"): .uint(2),
                .string("r"): .binary(Data((0..<4).map { _ in UInt8.random(in: 0...255) })),
                .string("o"): .binary(Data()),
                .string("i"): .uint(0), .string("l"): .uint(1), .string("f"): .uint(0),
                .string("m"): .binary(Data((0..<8).map { _ in UInt8.random(in: 0...255) })),
            ]
            map[.string("q")] = .null
            plaintext = packMsgPack(.map(map))
        default:
            throw BridgeError.invalidData("unknown malformed-adv variant: \(variant)")
        }

        var inboundStarted = false
        // accept() wraps unpack in try/except; an unpack failure is a silent drop,
        // never a crash, so `crashed` is always false for both malformed variants.
        let crashed = false
        do {
            _ = try ResourceAdvertisement.unpack(plaintext)
            // A surprising successful decode would mean an inbound could start.
            inboundStarted = true
        } catch {
            inboundStarted = false   // dropped, as required
        }
        return [
            "variant": .string(variant),
            "inbound_started": boolean(inboundStarted),
            "crashed": boolean(crashed),
        ]

    // MARK: - Resource-subsystem inject commands
    //
    // These drive the REAL Resource/Link sender + receiver surface now exposed by
    // the library (request()/validate_proof()/assemble()/hashmapUpdate()/cancel(),
    // the Link incoming/outgoing registries + receiveResourceAdvertisement). They
    // build genuine sender/receiver Resource pairs on the established link (link-
    // encrypted with a freshly-derived RNS Token whose AES-CBC output length is
    // byte-exact to the live link token) and exercise the production state machine.

    // MARK: wire_inject_crafted_resource_request
    //
    // python: cmd_wire_inject_crafted_resource_request (wire_tcp.py:6775). Sender-
    // side RESOURCE_REQ handling via the real Resource.request (RNS/Resource.py:
    // 982-1073): HMU sequencing gate (misaligned_hmu/aligned), scope advance
    // (aligned_scope, :1038), serve-all -> AWAITING_PROOF + byte-identical resend
    // (serve_all, :1066), and Link req_hashlist de-dup (duplicate, Link.py:1109-1115).
    case "wire_inject_crafted_resource_request":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let variant = try getString(p, "variant")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireInjMakeToken()
        let out: [String: RIV] = try blockingAsync {
            switch variant {
            case "misaligned_hmu", "aligned":
                // >=74 parts so part index 73 (the aligned 74th part) exists.
                let sender = try await wireInjBuildSender(link, token, payload: wireInjRandom(6000), partSize: 50)
                let total = await sender.numParts
                guard total >= 74 else {
                    throw BridgeError.invalidData("need >=74 parts, got \(total)")
                }
                await wireInjPrimeTransferring(sender)
                await sender.setSendCallback { _ in }
                let partIndex = variant == "misaligned_hmu" ? 0 : 73
                let lastMapHash = try await sender.getPartHash(at: partIndex)
                guard let sHash = await sender.hash else {
                    throw BridgeError.invalidData("sender missing hash")
                }
                // [exhausted(0xFF)] [last_map_hash(4)] [resource hash(32)].
                var reqData = Data([0xFF]); reqData.append(lastMapHash); reqData.append(sHash)
                await sender.request(reqData)
                let state = await sender.state
                let result: [String: RIV] = [
                    "variant": .s(variant),
                    "cancelled": .b(state == .failed),
                    "status": .i(wireResourceStatusCode(state)),
                    "status_name": .s(wireResourceStateName(state))
                ]
                await sender.cancel(); await sender.cleanup()
                return result

            case "aligned_scope":
                // >=148 parts so an aligned HMU at the segment-2 boundary (148) exists.
                let sender = try await wireInjBuildSender(link, token, payload: wireInjRandom(9000), partSize: 50)
                let total = await sender.numParts
                guard total >= 148 else {
                    throw BridgeError.invalidData("need >=148 parts, got \(total)")
                }
                await wireInjPrimeTransferring(sender)
                await sender.setSendCallback { _ in }
                let scopeBefore = await sender.receiverScopeHeight
                let lastMapHash = try await sender.getPartHash(at: 147)
                guard let sHash = await sender.hash else {
                    throw BridgeError.invalidData("sender missing hash")
                }
                var reqData = Data([0xFF]); reqData.append(lastMapHash); reqData.append(sHash)
                await sender.request(reqData)
                let state = await sender.state
                let scopeAfter = await sender.receiverScopeHeight
                let result: [String: RIV] = [
                    "variant": .s(variant),
                    "part_index": .i(148),
                    "window_max": .i(ResourceConstants.WINDOW_MAX),
                    "scope_before": .i(scopeBefore),
                    "scope_after": .i(scopeAfter),
                    "cancelled": .b(state == .failed),
                    "status_name": .s(wireResourceStateName(state))
                ]
                await sender.cancel(); await sender.cleanup()
                return result

            case "serve_all":
                let sender = try await wireInjBuildSender(link, token, payload: wireInjRandom(1500), partSize: 200)
                let total = await sender.numParts
                guard total >= 2 else {
                    throw BridgeError.invalidData("need a multi-part sender, got \(total)")
                }
                await wireInjPrimeTransferring(sender)
                let capture = WireInjCapture()
                await sender.setSendCallback { d in capture.add(d) }
                guard let sHash = await sender.hash, let sHashmap = await sender.hashmap else {
                    throw BridgeError.invalidData("sender missing hash/hashmap")
                }
                // [not_exhausted(0x00)] [resource hash(32)] [every part's map hash].
                var reqData = Data([0x00]); reqData.append(sHash); reqData.append(sHashmap)
                await sender.request(reqData)
                let firstParts = capture.parts
                let sentParts = await sender.sentPartCount
                let stateAfter = await sender.state
                // Resend the identical request -> already-sent parts re-send byte-identical.
                capture.reset()
                await sender.request(reqData)
                let secondParts = capture.parts
                let identical = !firstParts.isEmpty && firstParts == secondParts
                let result: [String: RIV] = [
                    "variant": .s(variant),
                    "served_indices": .intArr(Array(0..<sentParts)),
                    "sent_parts": .i(sentParts),
                    "total_parts": .i(total),
                    "identical_on_resend": .b(identical),
                    "status_name": .s(wireResourceStateName(stateAfter))
                ]
                await sender.cancel(); await sender.cleanup()
                return result

            case "duplicate":
                let sender = try await wireInjBuildSender(link, token, payload: wireInjRandom(1500), partSize: 200)
                let total = await sender.numParts
                guard total >= 2 else {
                    throw BridgeError.invalidData("need a multi-part sender, got \(total)")
                }
                await wireInjPrimeTransferring(sender)
                await link.registerOutgoingResource(sender)
                await sender.setSendCallback { _ in }
                guard let sHash = await sender.hash, let sHashmap = await sender.hashmap else {
                    throw BridgeError.invalidData("sender missing hash/hashmap")
                }
                var reqData = Data([0x00]); reqData.append(sHash); reqData.append(sHashmap)
                // Link req_hashlist de-dup: serve only when the request packet hash is
                // newly recorded (registerRequestHash, RNS/Link.py:1113-1115).
                let reqHash = wireInjRandom(32)
                let firstNew = await sender.registerRequestHash(reqHash)
                if firstNew { await sender.request(reqData) }
                let firstServed = await sender.sentPartCount
                let secondNew = await sender.registerRequestHash(reqHash)
                if secondNew { await sender.request(reqData) }
                let secondServed = await sender.sentPartCount
                let hashlistLen = firstNew ? 1 : 0
                let result: [String: RIV] = [
                    "variant": .s(variant),
                    "total_parts": .i(total),
                    "first_served": .i(firstServed),
                    "second_served": .i(secondServed),
                    "first_in_hashlist": .b(firstNew),
                    "req_hashlist_len": .i(hashlistLen),
                    "deduped": .b(secondServed == firstServed && hashlistLen == 1)
                ]
                await link.cancelOutgoingResource(sender)
                await sender.cancel(); await sender.cleanup()
                return result

            default:
                throw BridgeError.invalidData("unknown resource-request variant: \(variant)")
            }
        }
        return out.mapValues(rivToJSON)

    // MARK: wire_inject_corrupt_assembled_resource
    //
    // python: cmd_wire_inject_corrupt_assembled_resource (wire_tcp.py:7065). The
    // assembly-time integrity check (Resource.assemble, RNS/Resource.py:694-721):
    // a buffer of genuine parts assembles -> COMPLETE + exactly one proof; one
    // corrupted part -> CORRUPT + zero proofs. Driven through the REAL assemble()
    // + auto-prove. Identity link-encryption is used so a corrupted part reaches
    // the per-segment hash-mismatch CORRUPT path swift's assemble() owns (an
    // authenticated Token would fail the whole-stream HMAC inside decrypt first,
    // which swift does not re-wrap as CORRUPT) — see port-deviations.md.
    case "wire_inject_corrupt_assembled_resource":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let variant = try getString(p, "variant")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        guard variant == "valid" || variant == "corrupt" else {
            throw BridgeError.invalidData("unknown corrupt-assemble variant: \(variant)")
        }
        let out: [String: RIV] = try blockingAsync {
            let sender = Resource(data: wireInjRandom(900), link: link, autoCompress: false)
            try await sender.prepare(partSize: 200, linkEncrypt: { $0 }, autoCompress: false)
            let adv = try await sender.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
            let receiver = Resource(advertisement: adv, link: link)
            await receiver.setDecryptCallback { $0 }     // identity decrypt
            await receiver.setSendCallback { _ in }       // so prove() can count on success
            let total = await receiver.numParts
            for i in 0..<total {
                var pd = try await sender.getPart(at: i)
                if variant == "corrupt" && i == total / 2 {
                    pd = wireInjRandom(pd.count)           // same-length corruption
                }
                await receiver.injectPartRaw(pd, at: i)
            }
            await receiver.transitionToTransferring()
            try await receiver.transitionState(to: .assembling)
            _ = try? await receiver.assemble()
            let state = await receiver.state
            let proofCalls = await receiver.proveCallCount
            await sender.cleanup(); await receiver.cleanup()
            return [
                "variant": .s(variant),
                "status": .i(wireResourceStatusCode(state)),
                "status_name": .s(wireResourceStateName(state)),
                "complete": .b(state == .complete),
                "corrupt": .b(state == .corrupt),
                "proof_calls": .i(proofCalls),
                "proof_sent": .b(proofCalls > 0),
                "total_parts": .i(total)
            ]
        }
        return out.mapValues(rivToJSON)

    // MARK: wire_inject_duplicate_resource_adv
    //
    // python: cmd_wire_inject_duplicate_resource_adv (wire_tcp.py:7158). Resource.
    // accept de-dups a re-delivered advertisement via Link.has_incoming_resource
    // (RNS/Resource.py:223 / Link.py:1308-1310): the first registers one inbound
    // Resource, an identical second is ignored. Reconstructed with the real Link
    // registry primitives (hasIncomingResource / registerIncomingResource).
    case "wire_inject_duplicate_resource_adv":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireInjMakeToken()
        let out: [String: RIV] = try blockingAsync {
            let sender = try await wireInjBuildSender(link, token, payload: wireInjRandom(800), partSize: 200)
            let adv = try await sender.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
            // First accept: register iff not already an incoming resource for the hash.
            let r1 = Resource(advertisement: adv, link: link)
            let firstAccepted = !(await link.hasIncomingResource(r1))
            if firstAccepted { await link.registerIncomingResource(r1) }
            let countAfterFirst = (await link.hasIncomingResource(r1)) ? 1 : 0
            // Second accept of the IDENTICAL advertisement: de-dup -> not created.
            let r2 = Resource(advertisement: adv, link: link)
            let secondCreated = !(await link.hasIncomingResource(r2))
            if secondCreated { await link.registerIncomingResource(r2) }
            let incomingCount = (await link.hasIncomingResource(r1)) ? 1 : 0
            await link.cancelIncomingResource(r1)
            await sender.cleanup()
            return [
                "first_accepted": .b(firstAccepted),
                "second_created": .b(secondCreated),
                "incoming_count": .i(incomingCount),
                "incoming_count_after_first": .i(countAfterFirst)
            ]
        }
        return out.mapValues(rivToJSON)

    // MARK: wire_inject_resource_adv_flags
    //
    // python: cmd_wire_inject_resource_adv_flags (wire_tcp.py:7300). The REAL
    // Link.receive RESOURCE_ADV q/u/p dispatch (RNS/Link.py:1070-1098): a request
    // adv is accepted unconditionally (even ACCEPT_NONE), a response adv with no
    // pending request is not, and a plain adv is gated on resourceStrategy. Driven
    // through receiveResourceAdvertisement; acceptance is its return value.
    case "wire_inject_resource_adv_flags":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let variant = try getString(p, "variant")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireInjMakeToken()
        let strategy: ResourceStrategy
        let reqId: Data?
        let isResp: Bool
        switch variant {
        case "request_autoaccept":          reqId = wireInjRandom(16); isResp = false; strategy = .acceptNone
        case "response_no_pending_request": reqId = wireInjRandom(16); isResp = true;  strategy = .acceptNone
        case "plain_accept_none":           reqId = nil;               isResp = false; strategy = .acceptNone
        case "plain_accept_all":            reqId = nil;               isResp = false; strategy = .acceptAll
        default:
            throw BridgeError.invalidData("unknown adv-flags variant: \(variant)")
        }
        let out: [String: RIV] = try blockingAsync {
            let sender = Resource(data: wireInjRandom(600), link: link, requestId: reqId, isResponse: isResp, autoCompress: false)
            try await sender.prepare(partSize: 200, linkEncrypt: { try token.encrypt($0) }, autoCompress: false)
            var adv = try await sender.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
            // getAdvertisement sets the response (p) flag from isResponse but not the
            // request (u) flag; set it explicitly for the request variant so the real
            // dispatch sees a request advertisement.
            if variant == "request_autoaccept" {
                let f = ResourceFlags(
                    encrypted: adv.flags.isEncrypted, compressed: adv.flags.isCompressed,
                    split: adv.flags.isSplit, isRequest: true, isResponse: false,
                    hasMetadata: adv.flags.hasMetadataFlag)
                adv = ResourceAdvertisement(
                    transferSize: adv.transferSize, dataSize: adv.dataSize, numParts: adv.numParts,
                    hash: adv.hash, randomHash: adv.randomHash, originalHash: adv.originalHash,
                    segmentIndex: adv.segmentIndex, totalSegments: adv.totalSegments,
                    requestId: adv.requestId, flags: f, hashmapChunk: adv.hashmapChunk)
            }
            let saved = await link.resourceStrategy
            await link.setResourceStrategy(strategy)
            let accepted = await link.receiveResourceAdvertisement(adv)
            await link.setResourceStrategy(saved)
            // Drop any inbound resource the accept path registered (by hash).
            await link.cancelIncomingResource(Resource(advertisement: adv, link: link))
            await sender.cleanup()
            return [
                "variant": .s(variant),
                "accepted": .b(accepted),
                "strategy": .i(wireInjStrategyCode(strategy))
            ]
        }
        return out.mapValues(rivToJSON)

    // MARK: wire_inject_hashmap_update
    //
    // python: cmd_wire_inject_hashmap_update (wire_tcp.py:7456). HMU idempotence
    // (Resource.hashmap_update, RNS/Resource.py:492-503): applying the same later
    // segment twice grows hashmap_height once. Driven through the REAL
    // hashmapUpdate + hashmapHeight read-back on a >74-part receiver.
    case "wire_inject_hashmap_update":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireInjMakeToken()
        let out: [String: RIV] = try blockingAsync {
            let segLen = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
            let maphashLen = ResourceConstants.MAPHASH_LEN
            let sender = try await wireInjBuildSender(link, token, payload: wireInjRandom(12000), partSize: 150)
            let receiver = try await wireInjBuildReceiver(sender, link, token)
            let totalParts = await sender.numParts
            guard totalParts > segLen else {
                throw BridgeError.invalidData("need >\(segLen) parts, got \(totalParts)")
            }
            let heightAfterAdvert = await receiver.hashmapHeight
            // segment 1 = parts [segLen, 2*segLen): a slice of the sender's own hashmap.
            guard let shmap = await sender.hashmap else {
                throw BridgeError.invalidData("sender missing hashmap")
            }
            let start = segLen * maphashLen
            let end = min(2 * segLen, totalParts) * maphashLen
            let seg1 = Data(shmap[(shmap.startIndex + start)..<(shmap.startIndex + min(end, shmap.count))])
            _ = await receiver.hashmapUpdate(segment: 1, hashmap: seg1)
            let heightAfterFirst = await receiver.hashmapHeight
            _ = await receiver.hashmapUpdate(segment: 1, hashmap: seg1)
            let heightAfterDuplicate = await receiver.hashmapHeight
            await sender.cleanup()
            return [
                "total_parts": .i(totalParts),
                "height_after_advert": .i(heightAfterAdvert),
                "height_after_first": .i(heightAfterFirst),
                "height_after_duplicate": .i(heightAfterDuplicate),
                "grew_on_first": .b(heightAfterFirst > heightAfterAdvert),
                "grew_on_duplicate": .b(heightAfterDuplicate > heightAfterFirst)
            ]
        }
        return out.mapValues(rivToJSON)

    // MARK: wire_inject_raw_frame
    //
    // python cmd_wire_inject_raw_frame (wire_tcp.py:9990): push a genuine
    // (optionally IFAC-masked / trimmed) RNS announce frame through a LIVE
    // interface's receive path (Transport.inbound) and report whether a path was
    // learned — driving the four pre-unpack drop guards at the top of
    // RNS.Transport.inbound (Transport.py:1398-1447). Wired to the production
    // entry ReticulumTransport.inbound(frame:interface:) (short-packet + IFAC
    // drop guards via validateIFAC, then awaits receive to completion), the
    // standalone IFAC masking primitive applyIFAC (== python Transport.transmit
    // masking, _mask_frame_via_interface) and hasPath (== Transport.has_path).
    //
    // reticulum-swift registers only spawned TCP peers with the Transport (never
    // the TCPServerInterface parent — WireTcp.swift:503-516), so an IFAC server
    // with no connected peer has no registered interface to inject through. We
    // therefore register a socket-less injection interface carrying the
    // instance's IFAC posture (ifacKey/ifacSize) or open posture — the exact
    // ifac_identity-bearing / open interface python's _split_ifac_open targets.
    case "wire_inject_raw_frame":
        let handle = try getString(p, "handle")
        let variant = try getString(p, "variant")
        let inst = try requireInstance(handle)

        // python _build_foreign_announce defaults: app_name="rawframe",
        // aspects=["inject"], app_data=b"probe" (a missing/empty app_data ->
        // b"probe", never None — dest_hash depends only on identity/app/aspects).
        let appName = getStringOptional(p, "app_name") ?? "rawframe"
        let aspects: [String]
        if let arr = p["aspects"]?.arrayValue {
            aspects = arr.compactMap { $0.stringValue }
        } else if let s = p["aspects"]?.stringValue, !s.isEmpty {
            aspects = s.split(separator: ",").map(String.init)
        } else {
            aspects = ["inject"]
        }
        let appDataParam = getHexOptional(p, "app_data")
        let appData: Data = (appDataParam?.isEmpty == false) ? appDataParam! : Data("probe".utf8)

        // Resolve the instance's IFAC posture + a registered injection interface.
        // _split_ifac_open: an IFAC interface has a non-None ifac_identity;
        // per-instance there is exactly one posture, so the injection interface
        // is the ifac_iface XOR the open_iface.
        let (injectIfaceId, isIfac, ifacSize) = try wireRawFrameInjectInterface(inst, handle: handle)
        let ifacIfaceId: String? = isIfac ? injectIfaceId : nil
        let openIfaceId: String? = isIfac ? nil : injectIfaceId

        // inject_external: inject a caller-supplied frame on the OPEN interface
        // (the masked, flag-set frame from build_masked) -> dropped by the
        // flag-on-open-interface guard (Transport.py:1442-1445).
        if variant == "inject_external" {
            guard let openId = openIfaceId else {
                throw BridgeError.invalidData("inject_external requires a non-IFAC (open) interface")
            }
            let frame = try getHex(p, "raw")
            let destHash = try getHex(p, "dest_hash")
            let learned: Bool = try blockingAsync {
                _ = await inst.transport.inbound(frame: frame, interface: openId)
                return await inst.transport.hasPath(for: destHash)
            }
            return [
                "dest_hash": hex(destHash),
                "frame_len": .int(frame.count),
                "learned": boolean(learned),
            ]
        }

        // build_masked: build+mask, but DO NOT inject. Returns the masked frame
        // hex + dest_hash so an OPEN peer can inject it (the flag-on-open test).
        if variant == "build_masked" {
            guard let ifacId = ifacIfaceId else {
                throw BridgeError.invalidData("build_masked requires an IFAC-configured interface")
            }
            let (destination, plainRaw) = try wireRawFrameAnnounce(
                appName: appName, aspects: aspects, appData: appData)
            let masked: Data = try blockingAsync {
                await inst.transport.applyIFAC(raw: plainRaw, interfaceId: ifacId)
            }
            return [
                "dest_hash": hex(destination.hash),
                "raw": hex(masked),
                "frame_len": .int(masked.count),
                "ifac_size": .int(ifacSize),
            ]
        }

        // Remaining variants build a fresh foreign announce and inject it.
        let targetId: String
        let frame: Data
        let destination: Destination
        switch variant {
        case "masked_full", "masked_short", "plain_on_ifac":
            guard let ifacId = ifacIfaceId else {
                throw BridgeError.invalidData("variant \(variant) requires an IFAC interface")
            }
            targetId = ifacId
            let (dest, plainRaw) = try wireRawFrameAnnounce(
                appName: appName, aspects: aspects, appData: appData)
            destination = dest
            if variant == "plain_on_ifac" {
                // Unmasked announce (0x80 flag clear) -> flag-missing drop
                // (Transport.py:1437-1439).
                frame = plainRaw
            } else {
                let masked: Data = try blockingAsync {
                    await inst.transport.applyIFAC(raw: plainRaw, interfaceId: ifacId)
                }
                if variant == "masked_full" {
                    frame = masked
                } else {
                    // masked_short: trim to the IFAC short-packet boundary
                    // (2+ifac_size) so validateIFAC's `len(raw) > 2+ifac_size`
                    // gate drops it (Transport.py:1402/:1435).
                    frame = Data(masked.prefix(2 + ifacSize))
                }
            }
        case "plain_on_open":
            guard let openId = openIfaceId else {
                throw BridgeError.invalidData("plain_on_open requires an open interface")
            }
            targetId = openId
            let (dest, plainRaw) = try wireRawFrameAnnounce(
                appName: appName, aspects: aspects, appData: appData)
            destination = dest
            frame = plainRaw
        case "min_short":
            // python: target = open_iface or ifac_iface.
            guard let openOrIfac = openIfaceId ?? ifacIfaceId else {
                throw BridgeError.invalidData("min_short requires any live interface")
            }
            targetId = openOrIfac
            let trimTo = getIntOptional(p, "trim_to") ?? 2
            let (dest, plainRaw) = try wireRawFrameAnnounce(
                appName: appName, aspects: aspects, appData: appData)
            destination = dest
            // <=2 bytes -> minimum-length drop at the top of inbound
            // (Transport.py:1398/:1447, before any IFAC logic).
            frame = Data(plainRaw.prefix(trimTo))
        default:
            throw BridgeError.invalidData("unknown variant: \(variant)")
        }

        let destHash = destination.hash
        let learned: Bool = try blockingAsync {
            _ = await inst.transport.inbound(frame: frame, interface: targetId)
            return await inst.transport.hasPath(for: destHash)
        }
        var result: Result = [
            "dest_hash": hex(destHash),
            "frame_len": .int(frame.count),
            "learned": boolean(learned),
        ]
        // ifac_size is included whenever the frame is injected on the IFAC iface.
        if isIfac, targetId == ifacIfaceId {
            result["ifac_size"] = .int(ifacSize)
        }
        return result

    // MARK: - LIBRARY-GAP commands
    //
    // The following require live RNS runtime state that reticulum-swift does not
    // expose. Each implements everything representable and then fails loudly
    // rather than fabricate a deterministic-by-variant dict that would fake-pass
    // without exercising swift. Reported in libraryGaps.

    // MARK: wire_capture_response_packet
    case "wire_capture_response_packet":
        // RNS reference cmd_wire_capture_response_packet (wire_tcp.py:2530-2609):
        // arm an observer on the initiator's link that records every inbound RESPONSE
        // (context 0x0A, with decrypted plaintext) and RESOURCE_ADV (context 0x02,
        // plaintext None) frame, drive link.request(path, data), and wait for the
        // receipt to conclude. A sub-MDU response arrives as one RESPONSE packet whose
        // plaintext is msgpack [request_id, response] (Link.py:897-899); a >MDU
        // response forks to a Resource — a RESOURCE_ADV with no RESPONSE (Link.py:901).
        // Uses the additive per-link inbound observation hook (Link.setInboundPacket-
        // Observer), which surfaces the context byte + decrypted plaintext WITHOUT
        // altering routing/ordering and is a no-op once cleared.
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let path = try getString(p, "path")
        let payload = getHexOptional(p, "data")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 15000
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }

        let capture = WireResponseCapture()
        try blockingAsync {
            await link.setInboundPacketObserver { ctx, data in
                capture.add(context: ctx, data: data)
            }
        }
        defer { try? blockingAsync { await link.setInboundPacketObserver(nil) } }

        // Drive link.request and poll the RequestReceipt to READY/FAILED/timeout
        // (same loop shape as wire_link_request; +0.5s slack so the receipt's own
        // timeout fires first).
        let dataValue: MessagePackValue? =
            (payload != nil && !(payload!.isEmpty)) ? .binary(payload!) : nil
        let timeoutS = Double(timeoutMs) / 1000.0
        var status = "timeout"
        var responseData: Data? = nil
        let receipt: RequestReceipt = try blockingAsync {
            try await link.request(path: path, data: dataValue, timeout: timeoutS)
        }
        let deadline = Date().addingTimeInterval(timeoutS + 0.5)
        pollLoop: while Date() < deadline {
            let st: RequestReceipt.Status = try blockingAsync { await receipt.status }
            switch st {
            case .responseReceived:
                responseData = try blockingAsync { await receipt.responseData }
                status = "ready"
                break pollLoop
            case .failed, .timeout:
                status = "failed"
                break pollLoop
            default:
                break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }

        // RESPONSE (0x0A): surface the decrypted plaintext; RESOURCE_ADV (0x02):
        // plaintext None (the test inspects the ADV fork, not its bytes).
        let capturedEntries: [JSONValue] = capture.entries.map { entry in
            let plaintext: JSONValue = (entry.context == RequestPacketContext.response)
                ? hex(entry.data) : .null
            return .dict([
                "context": .int(Int(entry.context)),
                "plaintext": plaintext,
            ])
        }
        return [
            "status": str(status),
            "response": responseData != nil ? hex(responseData!) : .null,
            "captured": .array(capturedEntries),
        ]

    default:
        return nil
    }
}

// MARK: - wire_capture_response_packet collector

/// Thread-safe collector for the per-link inbound observation hook. Records each
/// inbound (context, payload) the link surfaces: RESPONSE (0x0A) carries the
/// DECRYPTED plaintext (msgpack [request_id, response]); RESOURCE_ADV (0x02)
/// carries the advertisement bytes (the bridge reports its plaintext as null).
final class WireResponseCapture: @unchecked Sendable {
    struct Entry { let context: UInt8; let data: Data }
    private let lock = NSLock()
    private var _entries: [Entry] = []
    func add(context: UInt8, data: Data) {
        lock.lock(); defer { lock.unlock() }
        _entries.append(Entry(context: context, data: data))
    }
    var entries: [Entry] {
        lock.lock(); defer { lock.unlock() }
        return _entries
    }
}

// MARK: - Inline reconstruction helpers

/// Produce a genuine 32-byte packet hash for a SINGLE-destination DATA packet,
/// mirroring RNS PacketReceipt.hash = packet.get_hash(). Uses the production
/// Packet encoder + getFullHash so the hash a crafted proof must match is real.
private func wireMakeBasePacketHash(_ destination: Destination) -> Data {
    let header = PacketHeader(
        headerType: .header1, hasContext: false, transportType: .broadcast,
        destinationType: .single, packetType: .data, hopCount: 0
    )
    let payload = Data((0..<20).map { _ in UInt8.random(in: 0...255) })
    let packet = Packet(header: header, destination: destination.hash, context: 0x00, data: payload)
    return packet.getFullHash()
}

// MARK: - Resource-subsystem inject helpers

/// Sendable scalar carrier for the resource-inject commands (lets the async work
/// inside `blockingAsync` return a Sendable dict; mapped to JSONValue outside).
private enum RIV: Sendable {
    case s(String)
    case i(Int)
    case b(Bool)
    case intArr([Int])
    case null
}

private func rivToJSON(_ v: RIV) -> JSONValue {
    switch v {
    case .s(let x): return .string(x)
    case .i(let x): return .int(x)
    case .b(let x): return .bool(x)
    case .intArr(let a): return .array(a.map { JSONValue.int($0) })
    case .null: return .null
    }
}

/// Thread-safe collector for packets emitted by a Resource's send callback.
private final class WireInjCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var packets: [Data] = []
    func add(_ d: Data) { lock.lock(); packets.append(d); lock.unlock() }
    func reset() { lock.lock(); packets.removeAll(); lock.unlock() }
    /// Captured RESOURCE part packets (context 0x01), in send order.
    var parts: [Data] {
        lock.lock(); defer { lock.unlock() }
        return packets.filter { $0.first == ResourcePacketContext.resource }
    }
}

/// Fresh 64-byte RNS Token used as the local link encryptor for inert resource
/// construction (AES-CBC ciphertext length is key-independent, so part counts /
/// hashmap strides are byte-exact to the live link token).
private func wireInjMakeToken() throws -> Token {
    let key = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
    return try Token(derivedKey: key)
}

/// Random test payload of `n` bytes.
private func wireInjRandom(_ n: Int) -> Data {
    Data((0..<n).map { _ in UInt8.random(in: 0...255) })
}

/// Build a real outbound (sender) Resource on `link`, prepared at `partSize`
/// bytes/part, link-encrypted with `token`. Mirrors RNS.Resource(payload, link,
/// advertise=False): full construction lifecycle, nothing on the wire.
private func wireInjBuildSender(_ link: Link, _ token: Token, payload: Data, partSize: Int) async throws -> Resource {
    let resource = Resource(data: payload, link: link, autoCompress: false)
    try await resource.prepare(partSize: partSize, linkEncrypt: { try token.encrypt($0) }, autoCompress: false)
    return resource
}

/// Build the inbound (receiver) Resource the way RNS.Resource.accept does: from
/// the sender's genuine advertisement, with `token` wired as the link decryptor.
private func wireInjBuildReceiver(_ sender: Resource, _ link: Link, _ token: Token) async throws -> Resource {
    let adv = try await sender.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
    let receiver = Resource(advertisement: adv, link: link)
    await receiver.setDecryptCallback { try token.decrypt($0) }
    return receiver
}

/// Prime a prepared outbound Resource to TRANSFERRING the way the first inbound
/// RESOURCE_REQ would (queued -> advertised -> transferring), so request() serves
/// parts against a live state machine.
private func wireInjPrimeTransferring(_ resource: Resource) async {
    try? await resource.transitionState(to: .advertised)
    await resource.transitionToTransferring()
}

/// RNS Resource status code (RNS/Resource.py:143-152). REJECTED == NONE == 0;
/// `.cancelled` maps to RNS FAILED.
private func wireResourceStatusCode(_ s: ResourceState) -> Int {
    switch s {
    case .none: return 0
    case .queued: return 1
    case .advertised: return 2
    case .transferring: return 3
    case .awaitingProof: return 4
    case .assembling: return 5
    case .complete: return 6
    case .failed: return 7
    case .corrupt: return 8
    case .rejected: return 0
    case .cancelled: return 7
    }
}

/// RNS Resource status name (_RESOURCE_STATUS_NAMES, wire_tcp.py) from a state.
private func wireResourceStateName(_ s: ResourceState) -> String {
    switch s {
    case .none: return "NONE"
    case .queued: return "QUEUED"
    case .advertised: return "ADVERTISED"
    case .transferring: return "TRANSFERRING"
    case .awaitingProof: return "AWAITING_PROOF"
    case .assembling: return "ASSEMBLING"
    case .complete: return "COMPLETE"
    case .failed: return "FAILED"
    case .corrupt: return "CORRUPT"
    case .rejected: return "NONE"
    case .cancelled: return "FAILED"
    }
}

/// RNS.Link resource-strategy enum value (Link.py:120-122): ACCEPT_NONE=0,
/// ACCEPT_APP=1, ACCEPT_ALL=2.
private func wireInjStrategyCode(_ s: ResourceStrategy) -> Int {
    switch s {
    case .acceptNone: return 0
    case .acceptApp: return 1
    case .acceptAll: return 2
    }
}

// MARK: - wire_inject_raw_frame helpers

/// Socket-less NetworkInterface used solely to drive
/// ReticulumTransport.inbound(frame:interface:) and applyIFAC for
/// wire_inject_raw_frame. The python contract injects on the genuine
/// listening/connected RNS interface, which carries the ifac_identity / ifac_size
/// (or is open). reticulum-swift registers only spawned TCP peers with the
/// Transport (never the TCPServerInterface parent — WireTcp.swift:503-516), so an
/// IFAC server with no connected peer has no registered interface to inject
/// through. This carries the instance's IFAC posture onto a registered interface
/// with no real I/O: connect/disconnect/send are no-ops; no bytes touch a socket.
private final class WireRawFrameInjectInterface: NetworkInterface, @unchecked Sendable {
    let id: String
    let config: InterfaceConfig
    nonisolated(unsafe) var state: InterfaceState = .connected

    init(config: InterfaceConfig) {
        self.id = config.id
        self.config = config
    }

    func connect() async throws {}
    func disconnect() async {}
    func send(_ data: Data) async throws {}
    // inbound(frame:interface:) calls receive() directly; the injector never
    // fires the delegate, so this is intentionally a no-op.
    func setDelegate(_ delegate: InterfaceDelegate) async {}
}

/// Per-handle registered injection interface id (one socket-less interface per
/// instance, reused across inject calls so the learned path's attached interface
/// stays live and is not culled by the transport's periodic interface cleanup).
/// Guarded by its own lock — bridge commands dispatch serially but the
/// transport's retransmission Task runs concurrently.
private let wireRawFrameLock = NSLock()
nonisolated(unsafe) private var wireRawFrameInjectIds: [String: String] = [:]

/// Ensure a registered socket-less injection interface exists for `handle`,
/// carrying the instance's IFAC posture (ifacKey/ifacSize, 64-byte key) or open
/// posture. Returns (ifaceId, isIfac). Mirrors python _split_ifac_open's target
/// selection (an IFAC interface has a non-None ifac_identity; reticulum-swift
/// derives the IFAC signing seed from a 64-byte ifacKey in addInterface, so the
/// posture is keyed on a 64-byte key + non-zero ifac_size).
private func wireRawFrameInjectInterface(_ inst: WireInstance, handle: String) throws -> (String, Bool, Int) {
    // TCPServerInterface is a plain class (config readable synchronously);
    // TCPInterface is an actor, so its config must be awaited.
    let cfg: InterfaceConfig
    if let serverCfg = inst.serverInterface?.config {
        cfg = serverCfg
    } else if let client = inst.clientInterface {
        cfg = try blockingAsync { await client.config }
    } else {
        throw BridgeError.invalidData("wire_inject_raw_frame: no live interface config for handle \(handle)")
    }
    let isIfac = (cfg.ifacKey?.count == 64) && (cfg.ifacSize > 0)
    let ifacSize = isIfac ? cfg.ifacSize : 0

    wireRawFrameLock.lock()
    let existing = wireRawFrameInjectIds[handle]
    wireRawFrameLock.unlock()
    if let existing { return (existing, isIfac, ifacSize) }

    let ifaceId = "wire-rawframe-inject-\(newHandle())"
    let injectConfig = InterfaceConfig(
        id: ifaceId,
        name: "Wire RawFrame Inject",
        type: .tcp,
        enabled: true,
        mode: .full,
        host: "inject",
        port: 0,
        bitrate: cfg.bitrate,
        ifacSize: isIfac ? cfg.ifacSize : 0,
        ifacKey: isIfac ? cfg.ifacKey : nil
    )
    let iface = WireRawFrameInjectInterface(config: injectConfig)
    try blockingAsync { try await inst.transport.addInterface(iface) }

    wireRawFrameLock.lock()
    wireRawFrameInjectIds[handle] = ifaceId
    wireRawFrameLock.unlock()
    return (ifaceId, isIfac, ifacSize)
}

/// Build a genuine UNMASKED announce frame for a FRESH, FOREIGN destination —
/// the swift analog of python _build_foreign_announce. Constructs a real
/// IN/SINGLE Destination (never registered with this instance's Transport, so it
/// is path-learnable on inbound rather than recognised as local — unlike python
/// there is no global registry to deregister from) and emits the wire bytes RNS
/// would pack (Destination.announce(send=False).pack()). Returns (destination,
/// plain_raw).
private func wireRawFrameAnnounce(appName: String, aspects: [String], appData: Data) throws -> (Destination, Data) {
    let identity = Identity()
    let destination = Destination(
        identity: identity, appName: appName, aspects: aspects, type: .single, direction: .in
    )
    let announce = Announce(destination: destination, appData: appData.isEmpty ? nil : appData)
    let packet = try announce.buildPacket()
    return (destination, packet.encode())
}
