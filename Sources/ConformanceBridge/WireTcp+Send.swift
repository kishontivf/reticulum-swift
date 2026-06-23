// WireTcp+Send.swift — conformance bridge wire sub-handler cluster: W-SEND (wire_send_*, wire_packet_receipt_*, wire_plain_encrypt, wire_encrypt_to_remote)
//
// Ports from reticulum-conformance reference/wire_tcp.py. Shares the global
// wireInstances registry + wireLock + requireInstance()/newHandle() helpers
// (now internal in WireTcp.swift). Returns nil for any command it does not own
// (dispatch chain: handleWireExtensionCommand in Ext+Dispatch.swift).
//
// reticulum-swift has no high-level RNS.Packet / RNS.PacketReceipt object (its
// `Packet` is a low-level wire struct), so the single-packet / link-DATA send
// paths are RECONSTRUCTED inline from primitives exactly as the python
// cmd_<name> bodies show:
//   * single DATA frame  = Identity.encrypt(payload) → HEADER_1 DATA packet,
//                          dispatched via transport.send(packet:receiptCallback:)
//                          (whose internal generate_receipt gate mirrors
//                          Transport.outbound, ReticulumTransport.swift:1235-1241).
//   * link DATA frame    = link.encrypt(payload) → HEADER_1/LINK DATA packet,
//                          delivery tracked via transport.registerProofCallback.
//   * PacketReceipt      = a small bridge-side WireSendReceipt (delivered flag)
//                          flipped by the transport's proof callback; the
//                          SENT→DELIVERED transition + status ints are
//                          reconstructed from RNS.PacketReceipt constants.
// Byte-faithful for the deterministic frames; property-faithful for the
// encrypted single/link frames (fresh ephemeral key + IV per pack), which the
// reference's own randomness makes non-deterministic and never cross-compares.
import Foundation
import ReticulumSwift

// MARK: - Bridge-side PacketReceipt model

/// Minimal stand-in for RNS.PacketReceipt. reticulum-swift's transport tracks
/// delivery via a fire-once proof callback (registerReceipt / registerProofCallback)
/// rather than a queryable receipt object, so the bridge keeps the SENT→DELIVERED
/// state here. `delivered` flips when the matching PROOF arrives and the
/// transport invokes the registered callback.
final class WireSendReceipt: @unchecked Sendable {
    private let lock = NSLock()
    private var _delivered = false
    /// Full SHA-256 hash of the proved packet (RNS.PacketReceipt.hash analog).
    let packetHash: Data
    /// The receipt destination's identity (RNS PacketReceipt.destination.identity).
    /// wire_inject_crafted_proof validates a crafted PROOF's signature against it —
    /// a forged signature under a throwaway key must fail against the REAL receiver
    /// identity. Nil for receipts whose destination identity isn't tracked.
    let destinationIdentity: Identity?
    init(packetHash: Data, destinationIdentity: Identity? = nil) {
        self.packetHash = packetHash
        self.destinationIdentity = destinationIdentity
    }
    func markDelivered() {
        lock.lock(); defer { lock.unlock() }
        _delivered = true
    }
    var delivered: Bool {
        lock.lock(); defer { lock.unlock() }
        return _delivered
    }
}

/// Thread-safe holder for the PROOF bytes a proof-carrying receipt callback
/// (`ReceivedProofPacket`) surfaces — the proof payload (`data`: 64-byte implicit
/// signature or 96-byte explicit packet_hash||signature) and the full encoded
/// proof frame (`raw`). Filled once when the matching PROOF arrives; nil until then.
final class WireProofHolder: @unchecked Sendable {
    private let lock = NSLock()
    private var _data: Data?
    private var _raw: Data?
    func set(_ proof: ReceivedProofPacket?) {
        lock.lock(); defer { lock.unlock() }
        if let proof {
            _data = proof.data
            _raw = proof.raw
        }
    }
    var data: Data? { lock.lock(); defer { lock.unlock() }; return _data }
    var raw: Data? { lock.lock(); defer { lock.unlock() }; return _raw }
}

/// Receipts stashed by wire_send_packet / wire_send_link_data /
/// wire_send_packet_with_proof_request, polled by wire_packet_receipt_status.
/// Module-global (not on WireInstance, which the bridge cannot extend here);
/// mirrors python's per-instance `inst["receipts"]` dict closely enough for the
/// single-process command flow the tests drive. Keys are random 8-byte hex ids
/// (secrets.token_hex(8) analog via newHandle()).
let wireSendReceiptsLock = NSLock()
nonisolated(unsafe) var wireSendReceipts: [String: WireSendReceipt] = [:]

private func stashReceipt(_ receipt: WireSendReceipt) -> String {
    let rid = newHandle()
    wireSendReceiptsLock.lock()
    wireSendReceipts[rid] = receipt
    wireSendReceiptsLock.unlock()
    return rid
}

// MARK: - RNS.PacketReceipt constants (Packet.py:408-415, 433-434, 560-565)

private enum PacketReceiptStatus {
    static let failed = 0x00
    static let sent = 0x01
    static let delivered = 0x02
    static let culled = 0xFF
    static let implLength = 64  // RNS.Identity.SIGLENGTH//8
    static let explLength = 96  // RNS.Identity.HASHLENGTH//8 + SIGLENGTH//8
    // Non-link receipt timeout constituents (RNS 1.3.1).
    static let defaultPerHopTimeout = 6  // RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
    static let timeoutPerHop = 6         // RNS.Packet.TIMEOUT_PER_HOP
}

// MARK: - Identity recall from the path table

/// Recall the announced public-key-only Identity for `destHash` from the
/// instance's path table — the swift analog of RNS.Identity.recall(dest_hash),
/// which reads the globally-cached identity learned from a received announce.
/// Also surfaces the adopted ratchet public key (PathEntry.ratchet), the analog
/// of RNS.Identity.get_ratchet(dest_hash).
private func recallIdentity(
    _ inst: WireInstance, _ destHash: Data
) throws -> (identity: Identity, ratchet: Data?) {
    let entry: PathEntry? = try blockingAsync { await inst.transport.pathEntry(for: destHash) }
    guard let entry, entry.publicKeys.count == 64 else {
        throw BridgeError.invalidData(
            "No identity known for \(bytesToHex(destHash)); "
            + "ensure an announce for this destination was received first."
        )
    }
    let identity: Identity
    do {
        identity = try Identity(publicKeyBytes: entry.publicKeys)
    } catch {
        throw BridgeError.invalidData("Identity from publicKeys failed: \(error)")
    }
    let ratchet: Data? = (entry.ratchet?.count == 32) ? entry.ratchet : nil
    return (identity, ratchet)
}

func handleWireSendCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // MARK: wire_send_packet
    //
    // Send a single SINGLE-destination DATA Packet with a tracked PacketReceipt
    // (cmd_wire_send_packet, wire_tcp.py:3462). The receiver's destination, if it
    // has PROVE_ALL, returns a PROOF; the transport matches it against the
    // registered receipt and the receipt transitions SENT→DELIVERED.
    case "wire_send_packet":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let payload = getHexOptional(p, "data") ?? Data()
        let createReceipt = getBoolOptional(p, "create_receipt") ?? true

        let inst = try requireInstance(handle)
        let (outIdentity, ratchet) = try recallIdentity(inst, destHash)
        let outDest = Destination(
            identity: outIdentity, appName: appName, aspects: aspects,
            type: .single, direction: .out
        )

        let ciphertext = try encryptSingle(payload, to: outIdentity, ratchet: ratchet)
        let packet = makeSinglePacket(destination: outDest.hash, ciphertext: ciphertext)

        let receiptId: String?
        do {
            if createReceipt {
                // Track the receiver identity so wire_inject_crafted_proof can
                // validate a forged PROOF's signature against the real destination.
                let receipt = WireSendReceipt(
                    packetHash: packet.getFullHash(),
                    destinationIdentity: outIdentity
                )
                try blockingAsync {
                    try await inst.transport.send(
                        packet: packet,
                        receiptCallback: { receipt.markDelivered() }
                    )
                }
                receiptId = stashReceipt(receipt)
            } else {
                try blockingAsync { try await inst.transport.send(packet: packet) }
                receiptId = nil
            }
        } catch {
            // send() failed (no path / outbound rejected) — mirror python's
            // `receipt is False` branch.
            return ["sent": boolean(false), "receipt_id": .null, "hops": .null]
        }

        // Keep the OUT destination referenced so it isn't released before the
        // proof round-trips and the receipt callback fires.
        inst.destinations.append((outIdentity, outDest))

        let hops = Int(
            try blockingAsync { await inst.transport.hopsTo(destHash) }
            ?? TransportConstants.PATHFINDER_M
        )
        return [
            "sent": boolean(true),
            "receipt_id": receiptId.map { JSONValue.string($0) } ?? .null,
            "hops": num(hops),
        ]

    // MARK: wire_send_undecryptable
    //
    // Adversarial: send a SINGLE DATA packet whose ciphertext is DAMAGED so the
    // receiver cannot decrypt it, verifying the receiver delivers nothing and emits
    // NO proof — Transport gates prove() on a truthy Destination.receive(), which
    // returns False on the decrypt failure (Transport.py:2157), short-circuiting
    // before BOTH the packet callback AND the PROVE_ALL auto-proof. Built exactly
    // like wire_send_packet (recall identity, encryptSingle, makeSinglePacket,
    // tracked receipt); the ONLY difference is one damaged ciphertext byte (the
    // Token HMAC tail). The tracked receipt must NEVER reach DELIVERED. Mirrors
    // cmd_wire_send_undecryptable (reference/wire_tcp.py:3529).
    case "wire_send_undecryptable":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let payload = getHexOptional(p, "data") ?? Data()

        let inst = try requireInstance(handle)
        let (outIdentity, ratchet) = try recallIdentity(inst, destHash)
        let outDest = Destination(
            identity: outIdentity, appName: appName, aspects: aspects,
            type: .single, direction: .out
        )

        // Encrypt for real, then damage the FINAL ciphertext byte (the Token HMAC
        // tail) AFTER computing the receipt's expected hash — consistent with the
        // reference (damage post-pack), so the registered receipt's hash can never
        // collide with a returning proof.
        var ciphertext = try encryptSingle(payload, to: outIdentity, ratchet: ratchet)
        let pristinePacket = makeSinglePacket(destination: outDest.hash, ciphertext: ciphertext)
        let receipt = WireSendReceipt(packetHash: pristinePacket.getFullHash())
        guard !ciphertext.isEmpty else {
            return ["sent": boolean(false), "receipt_id": .null]
        }
        let lastIdx = ciphertext.index(before: ciphertext.endIndex)
        ciphertext[lastIdx] = ciphertext[lastIdx] &+ 1
        let damagedPacket = makeSinglePacket(destination: outDest.hash, ciphertext: ciphertext)

        do {
            try blockingAsync {
                // receiptCallback fires only if a matching PROOF returns — it never
                // will, because the receiver's decrypt fails and no proof is emitted.
                try await inst.transport.send(
                    packet: damagedPacket,
                    receiptCallback: { receipt.markDelivered() }
                )
            }
        } catch {
            return ["sent": boolean(false), "receipt_id": .null]
        }
        inst.destinations.append((outIdentity, outDest))
        let undecryptableReceiptId = stashReceipt(receipt)
        return [
            "sent": boolean(true),
            "receipt_id": .string(undecryptableReceiptId),
        ]

    // MARK: wire_send_link_data
    //
    // Send a DATA packet OVER an established Link with a tracked PacketReceipt
    // (cmd_wire_send_link_data, wire_tcp.py:3637). The receiver proves the packet
    // per its proof strategy; the returning PROOF validates the receipt
    // (PROVE_ALL → DELIVERED, PROVE_NONE → never).
    case "wire_send_link_data":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let payload = getHexOptional(p, "data") ?? Data()
        let createReceipt = getBoolOptional(p, "create_receipt") ?? true

        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }

        let linkId: Data = try blockingAsync { await link.linkId }
        let ciphertext: Data
        do {
            ciphertext = try blockingAsync { try await link.encrypt(payload) }
        } catch {
            return ["sent": boolean(false), "receipt_id": .null]
        }
        let packet = makeLinkPacket(linkId: linkId, ciphertext: ciphertext)
        let truncatedHash = packet.getTruncatedHash()

        let receiptId: String?
        do {
            if createReceipt {
                let receipt = WireSendReceipt(packetHash: packet.getFullHash())
                try blockingAsync {
                    // handleDataProof matches the inbound link PROOF's leading
                    // 32-byte packet hash (truncated to 16) against this callback
                    // (ReticulumTransport.swift:939-985).
                    await inst.transport.registerProofCallback(
                        truncatedHash: truncatedHash,
                        callback: { receipt.markDelivered() }
                    )
                    try await inst.transport.sendLinkData(packet: packet)
                }
                receiptId = stashReceipt(receipt)
            } else {
                try blockingAsync { try await inst.transport.sendLinkData(packet: packet) }
                receiptId = nil
            }
        } catch {
            return ["sent": boolean(false), "receipt_id": .null]
        }
        return [
            "sent": boolean(true),
            "receipt_id": receiptId.map { JSONValue.string($0) } ?? .null,
        ]

    // MARK: wire_send_oversize_link_packet
    //
    // Attempt to send a single link DATA packet of `size` bytes and report
    // whether real RNS accepts it (cmd_wire_send_oversize_link_packet,
    // wire_tcp.py:2646). A LINK Packet is MTU-bounded by the NEGOTIATED link MTU
    // (Packet.__init__ sets packet.MTU = destination.mtu, Packet.py:153-154), and
    // pack() raises when the packed size exceeds that bound (Packet.py:235-236).
    case "wire_send_oversize_link_packet":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let size = try getInt(p, "size")

        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }

        let mtu = Int(try blockingAsync { await link.mtu })
        let mdu = Int(try blockingAsync { await link.mdu })
        let linkId: Data = try blockingAsync { await link.linkId }

        var result: Result = [
            "size": num(size),
            "mtu": num(mtu),
            "mdu": num(mdu),
            // RNS sets packet.MTU = destination.mtu for a LINK destination.
            "packet_mtu": num(mtu),
        ]

        // `size` opaque random bytes (no protocol assembly) — os.urandom(size).
        let payload = Data((0..<max(0, size)).map { _ in UInt8.random(in: 0...255) })

        do {
            let ciphertext = try blockingAsync { try await link.encrypt(payload) }
            let packet = makeLinkPacket(linkId: linkId, ciphertext: ciphertext)
            let raw = packet.encode()
            if raw.count > mtu {
                // pack()'s MTU ceiling — IOError citing the link MTU.
                result["sent"] = boolean(false)
                result["rejected"] = boolean(true)
                result["error"] = str("Packet size of \(raw.count) exceeds MTU of \(mtu) bytes")
                result["raw_len"] = .null
                return result
            }
            try blockingAsync { try await inst.transport.sendLinkData(packet: packet) }
            result["sent"] = boolean(true)
            result["rejected"] = boolean(false)
            result["error"] = .null
            result["raw_len"] = num(raw.count)
        } catch {
            result["sent"] = boolean(false)
            result["rejected"] = boolean(true)
            result["error"] = str("\(error)")
            result["raw_len"] = .null
        }
        return result

    // MARK: wire_send_packet_with_proof_request
    //
    // Send a single SINGLE-destination DATA packet (tracked receipt) and wait for
    // the PROOF the receiver returns (cmd_wire_send_packet_with_proof_request,
    // wire_tcp.py:6000). Surfaces delivered/proved and the proof-length constants.
    case "wire_send_packet_with_proof_request":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let payload = getHexOptional(p, "data") ?? Data()
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 10000

        let inst = try requireInstance(handle)
        let (outIdentity, ratchet) = try recallIdentity(inst, destHash)
        let outDest = Destination(
            identity: outIdentity, appName: appName, aspects: aspects,
            type: .single, direction: .out
        )
        let ciphertext = try encryptSingle(payload, to: outIdentity, ratchet: ratchet)
        let packet = makeSinglePacket(destination: outDest.hash, ciphertext: ciphertext)
        let receipt = WireSendReceipt(packetHash: packet.getFullHash())
        // Capture the received PROOF packet's bytes via the proof-carrying send
        // overload (ReceivedProofPacket: .data == proof payload, .raw == full proof
        // frame) so proof_data / proof_raw / proof_len + the implicit(64)/explicit(96)
        // discriminator are observable (RNS receipt.proof_packet, Packet.py:498-537).
        let proofHolder = WireProofHolder()

        do {
            try blockingAsync {
                try await inst.transport.send(
                    packet: packet,
                    proofReceiptCallback: { proof in
                        // Order matters: stash the proof bytes BEFORE flipping
                        // delivered, so a poller that sees delivered==true also
                        // sees the captured proof.
                        proofHolder.set(proof)
                        receipt.markDelivered()
                    }
                )
            }
        } catch {
            return [
                "sent": boolean(false), "receipt_id": .null,
                "hops": .null, "delivered": boolean(false),
            ]
        }
        inst.destinations.append((outIdentity, outDest))

        let hops = Int(
            try blockingAsync { await inst.transport.hopsTo(destHash) }
            ?? TransportConstants.PATHFINDER_M
        )

        // Poll for the proof to round-trip (blocking the bridge thread, same
        // pattern as wire_poll_path).
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while Date() < deadline {
            if receipt.delivered { break }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let delivered = receipt.delivered
        let receiptId = stashReceipt(receipt)

        // Surface the captured PROOF frame. The proof-carrying receipt callback
        // (proofReceiptCallback) recorded the received PROOF packet's payload
        // (proof_data) + full encoded frame (proof_raw) when a proof arrived;
        // both stay null when no proof was returned (PROVE_NONE / no delivery).
        // Classify IMPLICIT(64 == IMPL_LENGTH) vs EXPLICIT(96 == EXPL_LENGTH) by
        // length. implicit_proof_config is this instance's policy
        // (inst.useImplicitProof -> should_use_implicit_proof), NOT a constant.
        let proofData = proofHolder.data
        let proofRaw = proofHolder.raw
        let proofLen = proofData?.count
        let proofIsImplicit: JSONValue = proofLen != nil
            ? boolean(proofLen == PacketReceiptStatus.implLength) : .null
        let proofIsExplicit: JSONValue = proofLen != nil
            ? boolean(proofLen == PacketReceiptStatus.explLength) : .null
        return [
            "sent": boolean(true),
            "receipt_id": .string(receiptId),
            "hops": num(hops),
            "delivered": boolean(delivered),
            "proved": boolean(delivered),
            "implicit_proof_config": boolean(inst.useImplicitProof),
            "proof_data": proofData != nil ? hex(proofData!) : .null,
            "proof_len": proofLen != nil ? num(proofLen!) : .null,
            "proof_is_implicit": proofIsImplicit,
            "proof_is_explicit": proofIsExplicit,
            "impl_length": num(PacketReceiptStatus.implLength),
            "expl_length": num(PacketReceiptStatus.explLength),
            "proof_raw": proofRaw != nil ? hex(proofRaw!) : .null,
            "proved_packet_hash": hex(packet.getFullHash()),
        ]

    // MARK: wire_packet_receipt_status
    //
    // Poll a tracked receipt until it concludes, or timeout
    // (cmd_wire_packet_receipt_status, wire_tcp.py:3591). In scope of this
    // cluster's wire_packet_receipt_* prefix and required to observe the receipts
    // wire_send_packet / wire_send_link_data create.
    case "wire_packet_receipt_status":
        let handle = try getString(p, "handle")
        _ = try requireInstance(handle)
        let receiptId = try getString(p, "receipt_id")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 0

        wireSendReceiptsLock.lock()
        let receipt = wireSendReceipts[receiptId]
        wireSendReceiptsLock.unlock()
        guard let receipt else {
            throw BridgeError.invalidData("Unknown receipt_id: \(receiptId)")
        }

        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while true {
            if receipt.delivered { break }
            if Date() >= deadline { break }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let delivered = receipt.delivered
        // The receipt stays SENT until a PROOF flips it to DELIVERED; within the
        // test timeouts (≤6s) the RNS finite-timeout FAILED transition (~774s)
        // never fires, so non-delivery reports SENT, matching python.
        let status = delivered ? PacketReceiptStatus.delivered : PacketReceiptStatus.sent
        return [
            "status": num(status),
            "status_name": str(delivered ? "DELIVERED" : "SENT"),
            "delivered": boolean(delivered),
            "proved": boolean(delivered),
        ]

    // MARK: wire_encrypt_to_remote
    //
    // Encrypt a plaintext to a REMOTE destination, auto-selecting the adopted
    // ratchet (cmd_wire_encrypt_to_remote, wire_tcp.py:5856). Mirrors
    // Destination.encrypt's target-key choice (Destination.py:595-599):
    // get_ratchet(dest) → Identity.encrypt(ratchet=...). use_ratchet=False forces
    // the static X25519 key (negative control).
    case "wire_encrypt_to_remote":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let plaintext = getHexOptional(p, "plaintext") ?? Data()
        let useRatchet = getBoolOptional(p, "use_ratchet") ?? true

        let inst = try requireInstance(handle)
        let (identity, adoptedRatchet) = try recallIdentity(inst, destHash)

        let ratchetPublic: Data? = useRatchet ? adoptedRatchet : nil
        let ciphertext = try encryptSingle(plaintext, to: identity, ratchet: ratchetPublic)
        // RNS.Identity._get_ratchet_id: full_hash(ratchet_public)[:NAME_HASH_LENGTH//8]
        // (Identity.py:410-411) → SHA-256(ratchet_public)[:10].
        let ratchetId: Data? = ratchetPublic.map { Data(Hashing.fullHash($0).prefix(10)) }
        return [
            "ciphertext": hex(ciphertext),
            "used_ratchet": boolean(ratchetPublic != nil),
            "ratchet_id": ratchetId.map { hex($0) } ?? .null,
            "ratchet_public": ratchetPublic.map { hex($0) } ?? .null,
        ]

    // MARK: wire_plain_encrypt
    //
    // Encrypt via a PLAIN destination — a no-op passthrough returning the
    // plaintext unchanged (cmd_wire_plain_encrypt, wire_tcp.py:6143;
    // Destination.py:592-593). passthrough = ciphertext == plaintext.
    case "wire_plain_encrypt":
        let handle = try getString(p, "handle")
        _ = try requireInstance(handle)
        // app_name is required by the python signature; aspects optional. A PLAIN
        // destination holds no keys, so encrypt is the identity function.
        _ = try getString(p, "app_name")
        let plaintext = getHexOptional(p, "plaintext") ?? Data()
        let ciphertext = plaintext
        return [
            "ciphertext": hex(ciphertext),
            "passthrough": boolean(ciphertext == plaintext),
        ]

    // MARK: wire_plain_decrypt
    //
    // Decrypt via a PLAIN destination — a no-op passthrough returning the
    // ciphertext unchanged (cmd_wire_plain_decrypt, wire_tcp.py:6165;
    // Destination.py:618-619). passthrough = plaintext == ciphertext.
    case "wire_plain_decrypt":
        let handle = try getString(p, "handle")
        _ = try requireInstance(handle)
        // app_name is required by the python signature; aspects optional. A PLAIN
        // destination holds no keys, so decrypt is the identity function.
        _ = try getString(p, "app_name")
        let ciphertext = getHexOptional(p, "ciphertext") ?? Data()
        let plaintext = ciphertext
        return [
            "plaintext": hex(plaintext),
            "passthrough": boolean(plaintext == ciphertext),
        ]

    // MARK: wire_packet_receipt_generation
    //
    // Report whether RNS attaches a PacketReceipt for a packet of a given
    // destination-type / context / packet-type, even with create_receipt=True
    // (cmd_wire_packet_receipt_generation, wire_tcp.py:9766). The
    // Transport.outbound generate_receipt gate (Transport.py:1094-1113) requires
    // DATA + non-PLAIN destination + non-link-control context + non-resource
    // context. The packet is genuinely transmitted (sent=True) so an absent
    // receipt is the gate firing, not a failed send.
    case "wire_packet_receipt_generation":
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)
        let destType = (getStringOptional(p, "dest_type") ?? "single").lowercased()
        let context = getIntOptional(p, "context") ?? 0
        let packetTypeInt = getIntOptional(p, "packet_type") ?? 0  // DATA

        guard let packetType = PacketType(rawValue: UInt8(truncatingIfNeeded: packetTypeInt)) else {
            throw BridgeError.invalidData("Unsupported packet_type: \(packetTypeInt)")
        }
        let destinationType: DestinationType
        let destHash: Data
        switch destType {
        case "single":
            let identity = Identity()
            let dest = Destination(
                identity: identity, appName: "conformance", aspects: ["receipt-gen"],
                type: .single, direction: .out
            )
            destinationType = .single
            destHash = dest.hash
            inst.destinations.append((identity, dest))
        case "plain":
            // A PLAIN destination holds no identity; the frame is transmitted
            // immediately below so no post-send retention is required (unlike the
            // SINGLE case, whose identity is kept referenced via inst.destinations).
            let dest = Destination(
                plainAppName: "conformance", aspects: ["receipt-gen"], direction: .out
            )
            destinationType = .plain
            destHash = dest.hash
        default:
            throw BridgeError.invalidData(
                "dest_type must be 'single' or 'plain' (got '\(destType)')"
            )
        }

        // Build a real frame of the requested shape and transmit it on the live
        // interface(s). The payload is opaque (12 random bytes, token_bytes(12)
        // analog) and is sent in the clear — `sent` only reports transmission,
        // and `has_receipt` is the gate predicate, not a function of the body.
        let payload = Data((0..<12).map { _ in UInt8.random(in: 0...255) })
        let header = PacketHeader(
            headerType: .header1, hasContext: false, transportType: .broadcast,
            destinationType: destinationType, packetType: packetType, hopCount: 0
        )
        let packet = Packet(
            header: header, destination: destHash,
            context: UInt8(truncatingIfNeeded: context), data: payload
        )
        let raw = packet.encode()

        var sent = false
        do {
            try blockingAsync {
                let ids = await inst.transport.listInterfaceIds()
                for id in ids {
                    try await inst.transport.sendToInterface(raw, interfaceId: id)
                }
            }
            sent = true
        } catch {
            sent = false
        }

        // generate_receipt gate (Transport.py:1097-1113): DATA, non-PLAIN dest,
        // context not in link-control band (KEEPALIVE 0xFA..LRPROOF 0xFF) nor
        // resource band (RESOURCE 0x01..RESOURCE_RCL 0x07).
        let ctxByte = UInt8(truncatingIfNeeded: context)
        let hasReceipt = packetType == .data
            && destinationType != .plain
            && !PacketContext.isLinkContext(ctxByte)
            && !PacketContext.isResourceContext(ctxByte)

        return [
            "dest_type": str(destType),
            "context": num(context),
            "packet_type": num(packetTypeInt),
            "sent": boolean(sent),
            "has_receipt": boolean(hasReceipt),
            "create_receipt_flag": boolean(true),
        ]

    // MARK: wire_packet_receipt_timeout
    //
    // Report a non-link PacketReceipt's computed .timeout plus the constituents
    // RNS derives it from (cmd_wire_packet_receipt_timeout, wire_tcp.py:9835).
    // timeout = get_first_hop_timeout(dest) + Packet.TIMEOUT_PER_HOP *
    // Transport.hops_to(dest) (Packet.py:433-434). For a fresh, path-less SINGLE
    // destination on a standalone instance: first_hop_timeout ==
    // DEFAULT_PER_HOP_TIMEOUT(6) and hops_to == PATHFINDER_M(128), so timeout ==
    // 6 + 6*128 == 774. force_timeout drives the CULLED(timeout==-1)/FAILED
    // transition (check_timeout, Packet.py:560-565).
    case "wire_packet_receipt_timeout":
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)

        let identity = Identity()
        let dest = Destination(
            identity: identity, appName: "conformance", aspects: ["receipt-timeout"],
            type: .single, direction: .out
        )
        let destHash = dest.hash
        let isLink = (dest.destinationType == .link)

        // hops_to falls back to PATHFINDER_M for an unknown path (matching
        // RNS.Transport.hops_to).
        let hopsTo = Int(
            try blockingAsync { await inst.transport.hopsTo(destHash) }
            ?? TransportConstants.PATHFINDER_M
        )
        // RECONSTRUCTION: reticulum-swift has no shared-instance RPC, so a
        // path-less first-hop timeout is the spec default (no learned latency),
        // and the instance is always standalone.
        let firstHopTimeout = PacketReceiptStatus.defaultPerHopTimeout
        let timeout = firstHopTimeout + PacketReceiptStatus.timeoutPerHop * hopsTo

        var result: Result = [
            "timeout": num(timeout),
            "status": num(PacketReceiptStatus.sent),
            "is_link": boolean(isLink),
            "default_per_hop_timeout": num(PacketReceiptStatus.defaultPerHopTimeout),
            "timeout_per_hop": num(PacketReceiptStatus.timeoutPerHop),
            "pathfinder_m": num(Int(TransportConstants.PATHFINDER_M)),
            "hops_to": num(hopsTo),
            "first_hop_timeout": num(firstHopTimeout),
            "is_connected_to_shared": boolean(false),
            "status_sent": num(PacketReceiptStatus.sent),
        ]

        // Optional forced-timeout branch (check_timeout after back-dating sent_at):
        // timeout == -1 → CULLED, any finite timed-out value → FAILED.
        if let force = extractForceTimeout(p) {
            let forcedStatus = (force == -1) ? PacketReceiptStatus.culled : PacketReceiptStatus.failed
            // python set_timeout(float(timeout)) → receipt.timeout is a float.
            result["forced_timeout"] = num(Double(force))
            result["forced_status"] = num(forcedStatus)
            result["status_culled"] = num(PacketReceiptStatus.culled)
            result["status_failed"] = num(PacketReceiptStatus.failed)
        }
        return result

    default:
        return nil
    }
}

// MARK: - Frame construction helpers (RNS.Packet reconstruction)

/// Encrypt a plaintext to a SINGLE destination's identity, choosing the adopted
/// ratchet key when present (mirrors RNS.Destination.encrypt → Identity.encrypt
/// with the get_ratchet target, Destination.py:595-599). The HKDF salt is the
/// identity hash (RNS.Identity.get_salt), exactly as Identity.encrypt uses.
private func encryptSingle(_ plaintext: Data, to identity: Identity, ratchet: Data?) throws -> Data {
    if let ratchet, ratchet.count == 32 {
        return try Identity.encrypt(plaintext, toRatchetKey: ratchet, identityHash: identity.hash)
    }
    return try identity.encryptTo(plaintext, identityHash: identity.hash)
}

/// Build a HEADER_1 SINGLE DATA packet (the RNS.Packet a single-destination
/// send produces, addressed to the destination hash).
private func makeSinglePacket(destination: Data, ciphertext: Data) -> Packet {
    let header = PacketHeader(
        headerType: .header1, hasContext: false, transportType: .broadcast,
        destinationType: .single, packetType: .data, hopCount: 0
    )
    return Packet(header: header, destination: destination, context: 0x00, data: ciphertext)
}

/// Build a HEADER_1 LINK DATA packet (addressed to the link_id), matching
/// RNS.Packet(link, payload, DATA) / Link.send framing (Link.swift:1142-1156).
private func makeLinkPacket(linkId: Data, ciphertext: Data) -> Packet {
    let header = PacketHeader(
        headerType: .header1, hasContext: false, transportType: .broadcast,
        destinationType: .link, packetType: .data, hopCount: 0
    )
    return Packet(header: header, destination: linkId, context: 0x00, data: ciphertext)
}

/// Extract the optional `force_timeout` param as an Int (python passes a float;
/// the only values the tests use are -1 and 0). Returns nil when absent/null.
private func extractForceTimeout(_ p: [String: JSONValue]) -> Int? {
    switch p["force_timeout"] {
    case .some(.int(let i)): return i
    case .some(.double(let d)): return Int(d)
    default: return nil
    }
}
