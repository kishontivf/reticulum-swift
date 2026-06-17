// WireTcp+Resource.swift — conformance bridge wire sub-handler cluster: W-RESOURCE (wire_resource_* create/progress/receiver/window/constants)
//
// Ports from reticulum-conformance reference/wire_tcp.py. Shares the global
// wireInstances registry + wireLock + requireInstance()/newHandle() helpers
// (now internal in WireTcp.swift). Returns nil for any command it does not own
// (dispatch chain: handleWireExtensionCommand in Ext+Dispatch.swift).
//
// Reconstruction strategy (per the WIRE addendum DO-NOT-BAIL rule): the python
// reference builds real RNS.Resource objects on the established Link and reads
// their introspectable state. reticulum-swift's Resource is an actor with a
// public construction/prepare/accept surface, so this file rebuilds the same
// sender + receiver Resource pair INLINE from those primitives:
//   * outbound sender: `Resource(data:link:)` + `prepare(partSize:linkEncrypt:)`
//     — driven with a freshly-derived RNS `Token` as the link encryptor so the
//     bytes are real RNS token-encrypted (IV+ciphertext+HMAC) without needing
//     the live Link's private session token. AES-CBC output length is key-
//     independent, so transfer_size / num_parts / hashmap stride are byte-exact
//     to what the real link token would produce; only the (random, never cross-
//     impl-asserted) ciphertext bytes differ.
//   * inbound receiver: `Resource(advertisement:link:)` (the swift analog of
//     RNS.Resource.accept) + `setDecryptCallback`, fed genuine sender parts via
//     `receivePart(_:at:)`.
//
// The Resource + Link library now exposes the full sender/receiver hook surface
// (cancel/request/validate_proof/assemble/hashmapUpdate/getProgress, the Link
// incoming/outgoing registries + getLastResourceWindow + readyForNewResource +
// receiveResourceAdvertisement), so every command here drives the REAL APIs —
// there are no remaining LIBRARY-GAP bails in this cluster.
//
// One semantic adaptation remains, documented at its sites: swift's
// ResourceWindow tracks `consecutiveCompletedHeight` 0-based (next index to
// request) whereas RNS tracks it -1-based (last completed index), so the
// python-semantic value is reported as `swiftHeight - 1`. window_min/window_max
// are now surfaced directly via `Resource.windowMin`/`windowMax`.

import Foundation
import ReticulumSwift

// SDU overhead: RNS.Reticulum.HEADER_MAXSIZE (35) + IFAC_MIN_SIZE (1) = 36
// (Resource.py:338 sdu = link.mtu - 36).
private let wireSduOverhead = 36
// Receiver-side decompression bound wire_listen lowers inbound resources to
// (wire_tcp.py _WIRE_RX_MAX_DECOMPRESSED). Internal (not file-private) so the
// listener's WireResourceCallbacks.resourceStarted (WireTcp.swift) shares the
// same bound it applies to each inbound Resource for the bz2-bomb test.
let wireRxMaxDecompressed = 256 * 1024

func handleWireResourceCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // MARK: wire_resource_constants
    //
    // Reads the Resource / ResourceAdvertisement protocol constants. Sourced
    // from swift's ResourceConstants / ResourceHashmap formulas where exposed;
    // the handful swift does not surface as named constants are the RNS 1.3.1
    // spec literals every interoperating impl must agree on (FORCED DEVIATION,
    // documented in port report). python: cmd_wire_resource_constants
    // (wire_tcp.py:6727).
    case "wire_resource_constants":
        let hashmapMaxLen = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
        let collisionGuard = ResourceHashmap.collisionGuardSize(hashmapMaxLength: hashmapMaxLen)
        return [
            "WINDOW": num(ResourceConstants.WINDOW_INITIAL),
            "WINDOW_MIN": num(ResourceConstants.WINDOW_MIN),
            // RNS 1.3.1: WINDOW_MAX == WINDOW_MAX_FAST (75). Now a named swift
            // constant (ResourceConstants.WINDOW_MAX, RNS/Resource.py:74).
            "WINDOW_MAX": num(ResourceConstants.WINDOW_MAX),
            "MAPHASH_LEN": num(ResourceConstants.MAPHASH_LEN),
            "RANDOM_HASH_SIZE": num(ResourceConstants.RANDOM_HASH_SIZE),
            "HASHMAP_MAX_LEN": num(hashmapMaxLen),
            "COLLISION_GUARD_SIZE": num(collisionGuard),
            "MAX_EFFICIENT_SIZE": num(ResourceConstants.MAX_EFFICIENT_SIZE),
            // Named swift constant (RNS/Resource.py:120).
            "METADATA_MAX_SIZE": num(ResourceConstants.METADATA_MAX_SIZE),
            "MAX_RETRIES": num(ResourceConstants.RETRY_LIMIT),
            // FORCED DEVIATION: not a named swift constant — RNS spec literal.
            "MAX_ADV_RETRIES": num(4),
            // Markers swift uses verbatim in Resource.requestNextParts (0xFF / 0x00).
            "HASHMAP_IS_EXHAUSTED": num(0xFF),
            "HASHMAP_IS_NOT_EXHAUSTED": num(0x00),
            "WINDOW_MAX_SLOW": num(ResourceConstants.WINDOW_MAX_SLOW),
            "WINDOW_MAX_VERY_SLOW": num(ResourceConstants.WINDOW_MAX_VERY_SLOW),
            "WINDOW_MAX_FAST": num(ResourceConstants.WINDOW_MAX_FAST),
            "WINDOW_FLEXIBILITY": num(ResourceConstants.WINDOW_FLEXIBILITY),
            "FAST_RATE_THRESHOLD": num(ResourceConstants.FAST_RATE_THRESHOLD),
            "VERY_SLOW_RATE_THRESHOLD": num(ResourceConstants.VERY_SLOW_RATE_THRESHOLD),
            "RATE_FAST": num(ResourceConstants.RATE_FAST),
            "RATE_VERY_SLOW": num(ResourceConstants.RATE_VERY_SLOW),
            // FORCED DEVIATION: not named swift constants — RNS 1.3.1 spec literals.
            "PART_TIMEOUT_FACTOR": num(4),
            "PART_TIMEOUT_FACTOR_AFTER_RTT": num(2),
            "PROOF_TIMEOUT_FACTOR": num(4),
            "AUTO_COMPRESS_MAX_SIZE": num(ResourceConstants.AUTO_COMPRESS_MAX_SIZE)
        ]

    // MARK: wire_resource_create
    //
    // Constructs a real outbound Resource on the link and reports its
    // construction-time observables WITHOUT advertising/sending. python:
    // cmd_wire_resource_create (wire_tcp.py:2024).
    case "wire_resource_create":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let payload = getHexOptional(p, "data") ?? Data()
        let forceSdu = getIntOptional(p, "force_sdu")
        let includeParts = getBoolOptional(p, "include_parts") ?? true
        let autoCompress = getBoolOptional(p, "auto_compress") ?? true
        // metadata (hex) -> packed into the Resource 'x' field via the new
        // outbound metadata init arg (RNS/Resource.py:260-268).
        let metadata = getHexOptional(p, "metadata")

        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            let mtu = await link.mtu
            // python: resource.sdu == link.mtu - 36 (Resource.py:338). force_sdu
            // chunks at exactly that part size.
            let partSize = forceSdu ?? (mtu - wireSduOverhead)
            let sender = try await wireBuildSender(
                link: link, token: token, payload: payload,
                partSize: partSize, autoCompress: autoCompress, metadata: metadata
            )
            guard let hash = await sender.hash,
                  let randomHash = await sender.randomHash,
                  let hashmap = await sender.hashmap,
                  let originalHash = await sender.originalHash else {
                throw BridgeError.invalidData("wire_resource_create: sender missing prepared fields")
            }
            let numParts = await sender.numParts
            let transferSize = await sender.transferSize
            // python: resource.total_size == metadata_size + data_size
            // (Resource.py:283). totalDataSize folds the metadata block in.
            let totalSize = await sender.totalDataSize
            let segIndex = await sender.segmentIndex
            let totalSegments = await sender.totalSegments
            let split = await sender.split
            let compressed = await sender.compressed
            // Flags byte: pack via the real ResourceAdvertisement (Resource.py:1307
            // f = x<<5|p<<4|u<<3|s<<2|c<<1|e). swift ResourceFlags bit layout matches.
            let adv = try await sender.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
            let flags = Int(adv.flags.rawValue)
            // truncated_hash = first 16 bytes of the resource's own full hash
            // (Resource.py:442). swift does not surface it; the digest is already
            // computed, so truncate it inline.
            let truncated = Data(hash.prefix(16))
            // expected_proof = full_hash(segment_plaintext + hash) (Resource.py:443),
            // computed by prepare() over the REAL segment plaintext (metadata||data
            // for a metadata-bearing segment 1), so it is correct with or without
            // metadata. Read it back rather than recomputing from `payload`.
            guard let expectedProof = await sender.expectedProof else {
                throw BridgeError.invalidData("wire_resource_create: sender missing expected_proof")
            }
            var partsOut: [Data]? = nil
            if includeParts {
                var ps: [Data] = []
                ps.reserveCapacity(numParts)
                for i in 0..<numParts { ps.append(try await sender.getPart(at: i)) }
                partsOut = ps
            }
            await sender.cleanup()
            var dict: [String: WS] = [
                "hash": .h(hash),
                "truncated_hash": .h(truncated),
                "random_hash": .h(randomHash),
                "expected_proof": .h(expectedProof),
                "hashmap": .h(hashmap),
                "num_parts": .i(numParts),
                "encrypted": .b(true),
                "compressed": .b(compressed),
                "split": .b(split),
                "total_segments": .i(totalSegments),
                "segment_index": .i(segIndex),
                "original_hash": .h(originalHash),
                // has_metadata = adv flag bit 5 (x), set by getAdvertisement when
                // the resource carries metadata (RNS/Resource.py:1291/1307).
                "has_metadata": .b(adv.flags.hasMetadataFlag),
                "flags": .i(flags),
                "size": .i(transferSize),
                "total_size": .i(totalSize),
                "sdu": .i(partSize)
            ]
            if let partsOut { dict["parts"] = .hexArr(partsOut) }
            return dict
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_decompress_limit
    //
    // python: cmd_wire_resource_decompress_limit (wire_tcp.py:7960) reads
    // resource.max_decompressed_size / auto_compress_limit instance fields off a
    // real Resource. swift's Resource now exposes the per-instance
    // `maxDecompressedSize` (RNS/Resource.py:364), defaulting to
    // AUTO_COMPRESS_MAX_SIZE; read it straight off a real sender. swift folds the
    // auto_compress_limit into the same per-instance bound (no separate field), so
    // auto_compress_limit mirrors max_decompressed_size.
    case "wire_resource_decompress_limit":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            let sender = try await wireBuildSender(
                link: link, token: token, payload: wireRandomPayload(500),
                partSize: 200, autoCompress: false
            )
            let bound = await sender.maxDecompressedSize
            await sender.cleanup()
            return [
                "max_decompressed_size": .i(bound),
                "auto_compress_limit": .i(bound),
                "constant": .i(ResourceConstants.AUTO_COMPRESS_MAX_SIZE)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_part_count_derivation
    //
    // python: cmd_wire_resource_part_count_derivation (wire_tcp.py:7889). Builds
    // a sender, tampers ONLY adv.n (+5), and drives accept — RNS derives
    // total_parts = ceil(t/sdu) and ignores n. The inbound Resource's
    // `deriveReceiverPartCount(sdu:)` (RNS/Resource.py:187) recomputes the part
    // count from the receiver's OWN link SDU, so it ignores the tampered adv.n —
    // the Link calls it right after Resource.accept. Reproduced here.
    case "wire_resource_part_count_derivation":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            let forceSdu = 200
            let payload = wireRandomPayload(1500)
            let sender = try await wireBuildSender(
                link: link, token: token, payload: payload,
                partSize: forceSdu, autoCompress: false
            )
            let transferSize = await sender.transferSize
            let senderParts = await sender.numParts
            let genuine = try await sender.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
            let advNGenuine = genuine.numParts
            // Tamper ONLY the part-count field; keep every other field genuine.
            let tampered = ResourceAdvertisement(
                transferSize: genuine.transferSize,
                dataSize: genuine.dataSize,
                numParts: advNGenuine + 5,
                hash: genuine.hash,
                randomHash: genuine.randomHash,
                originalHash: genuine.originalHash,
                segmentIndex: genuine.segmentIndex,
                totalSegments: genuine.totalSegments,
                requestId: genuine.requestId,
                flags: genuine.flags,
                hashmapChunk: genuine.hashmapChunk
            )
            let receiver = Resource(advertisement: tampered, link: link)
            let receiverSdu = forceSdu
            // Derive total_parts = ceil(t/sdu) from the receiver's OWN SDU,
            // ignoring the tampered adv.n (RNS/Resource.py:187).
            await receiver.deriveReceiverPartCount(sdu: receiverSdu)
            let receiverTotalParts = await receiver.numParts
            let derivedExpected = (transferSize + receiverSdu - 1) / receiverSdu
            await sender.cleanup()
            return [
                "sender_parts": .i(senderParts),
                "adv_n_genuine": .i(advNGenuine),
                "adv_n_tampered": .i(advNGenuine + 5),
                "transfer_size": .i(transferSize),
                "receiver_sdu": .i(receiverSdu),
                "receiver_total_parts": .i(receiverTotalParts),
                "derived_expected": .i(derivedExpected)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_receiver_request_state
    //
    // python: cmd_wire_resource_receiver_request_state (wire_tcp.py:7383). Builds
    // a single-segment receiver, reads initial window/pointer state, feeds n
    // in-order parts and re-reads. consecutive height is reported -1-based to
    // match RNS (swift's window manager is 0-based; see file header).
    case "wire_resource_receiver_request_state":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let n = getIntOptional(p, "n") ?? 2
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            // ~8 parts (single hashmap segment) so the whole hashmap arrives in
            // the advertisement (hashmap_height == total_parts).
            let payload = wireRandomPayload(1500)
            let sender = try await wireBuildSender(
                link: link, token: token, payload: payload,
                partSize: 200, autoCompress: false
            )
            let receiver = try await wireBuildReceiver(sender: sender, link: link, token: token)

            let window = await receiver.windowSize
            // window_min / window_max now surfaced on the receiver (RNS/Resource.py:
            // 192-193); read them straight off the real window manager.
            let windowMin = await receiver.windowMin
            let windowMax = await receiver.windowMax
            let numParts = await receiver.numParts
            let consInitial = (await receiver.consecutiveHeight) - 1
            let coverageInitial = ((await receiver.hashmap)?.count ?? 0) / ResourceConstants.MAPHASH_LEN
            let waitingInitial = await receiver.waitingForHMU

            let fed = min(n, numParts)
            for i in 0..<fed {
                let part = try await sender.getPart(at: i)
                try await receiver.receivePart(part, at: i)
            }
            let receivedCount = await receiver.receivedCount
            let consAfter = (await receiver.consecutiveHeight) - 1
            let coverageAfter = ((await receiver.hashmap)?.count ?? 0) / ResourceConstants.MAPHASH_LEN
            await sender.cleanup()
            return [
                "window": .i(window),
                "window_min": .i(windowMin),
                "window_max": .i(windowMax),
                "total_parts": .i(numParts),
                "consecutive_height_initial": .i(consInitial),
                "hashmap_height_initial": .i(coverageInitial),
                "waiting_for_hmu_initial": .b(waitingInitial),
                "fed": .i(fed),
                "received_count": .i(receivedCount),
                "consecutive_height_after": .i(consAfter),
                "hashmap_height_after": .i(coverageAfter)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_request_next_content
    //
    // python: cmd_wire_resource_request_next_content (wire_tcp.py:7611). Drives
    // the real requestNextParts() and captures the genuine RESOURCE_REQ via a
    // recording send callback, then parses its requested map-hash list. consec.
    // height reported -1-based (see file header).
    case "wire_resource_request_next_content":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let variant = try getString(p, "variant")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            let payloadLen: Int
            let partSize: Int
            if variant == "exhausted" { payloadLen = 14000; partSize = 150 }
            else { payloadLen = 1500; partSize = 200 }
            let payload = wireRandomPayload(payloadLen)
            let sender = try await wireBuildSender(
                link: link, token: token, payload: payload,
                partSize: partSize, autoCompress: false
            )
            let receiver = try await wireBuildReceiver(sender: sender, link: link, token: token)

            let capture = WirePacketCapture()
            await receiver.setSendCallback { data in capture.add(data) }
            // requestNextParts requires .transferring; transitionToTransferring
            // sets that WITHOUT firing a request (unlike accept()).
            await receiver.transitionToTransferring()

            let segLen = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
            let feed: Int
            if variant == "after_parts" { feed = 2 }
            else if variant == "exhausted" { feed = segLen - 1 }
            else { feed = 0 }
            for i in 0..<feed {
                let part = try await sender.getPart(at: i)
                try await receiver.receivePart(part, at: i)
            }

            let window = await receiver.windowSize
            let heightSwift = await receiver.consecutiveHeight
            let numParts = await receiver.numParts
            let hmap = await receiver.hashmap
            let coverage = (hmap?.count ?? 0) / ResourceConstants.MAPHASH_LEN
            // Genuine expected hashes: scan from the first un-received index
            // (== swift's 0-based height), stop at the first un-arrived slot.
            var expected: [String] = []
            if let hmap {
                var pn = heightSwift
                while pn < numParts && expected.count < window {
                    if pn >= coverage { break }
                    let lo = hmap.startIndex + pn * ResourceConstants.MAPHASH_LEN
                    expected.append(bytesToHex(Data(hmap[lo..<lo + ResourceConstants.MAPHASH_LEN])))
                    pn += 1
                }
            }

            try await receiver.requestNextParts()
            let firstCount = capture.requestCount
            let waiting = await receiver.waitingForHMU
            // A follow-up must emit nothing while waiting_for_hmu is set.
            try await receiver.requestNextParts()
            let secondEmitted = capture.requestCount > firstCount

            guard let first = capture.firstRequest else {
                throw BridgeError.invalidData("request_next emitted no RESOURCE_REQ packet")
            }
            // packet = [context(1)][flag(1)][lastMapHash(4) iff exhausted][resHash(32)][hashes...]
            let bytes = [UInt8](first)
            let isExhausted = bytes.count > 1 && bytes[1] == 0xFF
            let bodyStart = 2 + (isExhausted ? ResourceConstants.MAPHASH_LEN : 0) + 32
            var requested: [String] = []
            var i = bodyStart
            while i + ResourceConstants.MAPHASH_LEN <= bytes.count {
                requested.append(bytesToHex(Data(bytes[i..<i + ResourceConstants.MAPHASH_LEN])))
                i += ResourceConstants.MAPHASH_LEN
            }
            await sender.cleanup()
            return [
                "variant": .s(variant),
                "window": .i(window),
                "total_parts": .i(numParts),
                "hashmap_height": .i(coverage),
                "consecutive_height": .i(heightSwift - 1),
                "requested": .strArr(requested),
                "expected": .strArr(expected),
                "exhausted": .b(isExhausted),
                "waiting_for_hmu": .b(waiting),
                "second_request_emitted": .b(secondEmitted)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_progress
    //
    // python: cmd_wire_resource_progress (wire_tcp.py:8066). progress ==
    // received_count / total_parts, callback once per accepted part. Driven
    // through the REAL Resource.getProgress() + setProgressCallback (RNS/Resource.py:
    // 884-887 / 1126-1181): install a counting progress callback, read
    // getProgress() before and after feeding half the parts.
    case "wire_resource_progress":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            let payload = wireRandomPayload(1500)
            let sender = try await wireBuildSender(
                link: link, token: token, payload: payload,
                partSize: 200, autoCompress: false
            )
            let receiver = try await wireBuildReceiver(sender: sender, link: link, token: token)
            let total = await receiver.numParts

            // Real progress callback, fired once per accepted part.
            let counter = WireCounter()
            await receiver.setProgressCallback { _ in counter.increment() }
            let progressInitial = await receiver.getProgress()

            let feed = total / 2
            for i in 0..<feed {
                let part = try await sender.getPart(at: i)
                try await receiver.receivePart(part, at: i)
            }
            let receivedCount = await receiver.receivedCount
            let progressMid = await receiver.getProgress()
            let callbackCalls = counter.value
            await sender.cleanup()
            return [
                "total_parts": .i(total),
                "fed": .i(feed),
                "received_count": .i(receivedCount),
                "progress_initial": .d(progressInitial),
                "progress_mid": .d(progressMid),
                "progress_callback_calls": .i(callbackCalls)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_receiver_proof_count
    //
    // python: cmd_wire_resource_receiver_proof_count (wire_tcp.py:7532). A
    // receiver emits ZERO per-part proofs and exactly ONE after assembly. swift
    // emits the single proof via Resource.sendProof (driven by the Link on the
    // real receive path); reproduced here by feeding all parts, assembling, then
    // sending the one proof. Proof emissions are counted by a recording send
    // callback filtering RESOURCE_PRF.
    case "wire_resource_receiver_proof_count":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            let payload = wireRandomPayload(1200)
            let sender = try await wireBuildSender(
                link: link, token: token, payload: payload,
                partSize: 200, autoCompress: false
            )
            let receiver = try await wireBuildReceiver(sender: sender, link: link, token: token)
            let total = await receiver.numParts
            guard total >= 2 else {
                throw BridgeError.invalidData("need a multi-part transfer, got \(total)")
            }
            let capture = WirePacketCapture()
            await receiver.setSendCallback { data in capture.add(data) }
            await receiver.transitionToTransferring()

            // Feed every part except the last — no assembly, no proof.
            for i in 0..<(total - 1) {
                let part = try await sender.getPart(at: i)
                try await receiver.receivePart(part, at: i)
            }
            let proofsBefore = capture.proofCount

            // Feed the last part, then assemble and emit the single proof.
            let last = try await sender.getPart(at: total - 1)
            try await receiver.receivePart(last, at: total - 1)
            try await receiver.transitionState(to: .assembling)
            _ = try await receiver.assemble()
            try await receiver.sendProof()

            let state = await receiver.state
            let proofsAfter = capture.proofCount
            await sender.cleanup()
            return [
                "total_parts": .i(total),
                "proofs_before_final": .i(proofsBefore),
                "proofs_after_assembly": .i(proofsAfter),
                "status_name": .s(wireResourceStatusName(state)),
                "complete": .b(state == .complete)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_window_inheritance
    //
    // python: cmd_wire_resource_window_inheritance (wire_tcp.py:7994). A second
    // inbound transfer inherits the first's final window via
    // Link.get_last_resource_window (RNS/Link.py:1284/1314-1315) +
    // Resource.accept window inheritance (RNS/Resource.py:216-219). Driven through
    // the real APIs: the first receiver is registered + concluded so the link
    // records its grown window, then the second receiver applies the inherited
    // window the way accept() does.
    case "wire_resource_window_inheritance":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            // First inbound transfer -> COMPLETE. Register it so resourceConcluded
            // records its final window (RNS/Link.py:1281-1290).
            let sender1 = try await wireBuildSender(
                link: link, token: token, payload: wireRandomPayload(1500),
                partSize: 150, autoCompress: false
            )
            let receiver1 = try await wireBuildReceiver(sender: sender1, link: link, token: token)
            await link.registerIncomingResource(receiver1)
            let total1 = await receiver1.numParts
            await receiver1.transitionToTransferring()
            // Feeding in-order parts drains successive request windows and grows
            // the window past the WINDOW=4 default (RNS/Resource.py:899-901).
            for i in 0..<total1 {
                let part = try await sender1.getPart(at: i)
                try await receiver1.receivePart(part, at: i)
            }
            try await receiver1.transitionState(to: .assembling)
            _ = try await receiver1.assemble()
            let windowAfter = await receiver1.windowSize
            let completed1 = (await receiver1.state) == .complete
            // Conclusion records last_resource_window = receiver.window.
            await link.resourceConcluded(receiver1)
            let linkLastWindow = await link.getLastResourceWindow()

            // Second inbound transfer on the SAME link inherits the recorded window
            // (RNS/Resource.py:216-219).
            let token2 = try wireMakeToken()
            let sender2 = try await wireBuildSender(
                link: link, token: token2, payload: wireRandomPayload(1500),
                partSize: 150, autoCompress: false
            )
            let receiver2 = try await wireBuildReceiver(sender: sender2, link: link, token: token2)
            if let inherited = linkLastWindow {
                await receiver2.applyInheritedWindow(inherited)
            }
            let window2Initial = await receiver2.windowSize
            await sender1.cleanup()
            await sender2.cleanup()
            return [
                "default_window": .i(ResourceConstants.WINDOW_INITIAL),
                "total_parts_1": .i(total1),
                "completed_1": .b(completed1),
                "window_after_complete": .i(windowAfter),
                "link_last_window": linkLastWindow.map { WS.i($0) } ?? .null,
                "window2_initial": .i(window2Initial)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_late_after_cancel
    //
    // python: cmd_wire_resource_late_after_cancel (wire_tcp.py:7765). Each late
    // entry point is FAILED-guarded (RNS/Resource.py:492/783/857/984). Driven
    // through the real Resource.cancel() / receivePart / hashmapUpdate (receiver)
    // and cancel() / request() / validate_proof() (sender), plus a fresh-sender
    // positive control proving the proof shape WOULD conclude an un-cancelled sender.
    case "wire_resource_late_after_cancel":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            let maphashLen = ResourceConstants.MAPHASH_LEN
            let segLen = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)

            // ---- RECEIVER path ----
            let rsender = try await wireBuildSender(
                link: link, token: token, payload: wireRandomPayload(12000),
                partSize: 150, autoCompress: false
            )
            let receiver = try await wireBuildReceiver(sender: rsender, link: link, token: token)
            await receiver.transitionToTransferring()
            // Real cancel() -> FAILED (RNS/Resource.py:1075-1104).
            await receiver.cancel()
            let recvStatus = wireResourceStatusName(await receiver.state)
            let recvReceivedBefore = await receiver.receivedCount
            let recvHeightBefore = await receiver.hashmapHeight

            // Late genuine part: FAILED-guarded receivePart drops it.
            let p0 = try await rsender.getPart(at: 0)
            _ = try? await receiver.receivePart(p0, at: 0)
            let recvReceivedAfterPart = await receiver.receivedCount

            // Late genuine hashmap segment (segment 1 slice): FAILED-guarded.
            if let shmap = await rsender.hashmap {
                let totalParts = await rsender.numParts
                let start = segLen * maphashLen
                let end = min(2 * segLen, totalParts) * maphashLen
                if start < shmap.count {
                    let lo = shmap.startIndex + start
                    let hi = shmap.startIndex + min(end, shmap.count)
                    _ = await receiver.hashmapUpdate(segment: 1, hashmap: Data(shmap[lo..<hi]))
                }
            }
            let recvHeightAfterHmu = await receiver.hashmapHeight

            // ---- SENDER path ----
            let sender = try await wireBuildSender(
                link: link, token: token, payload: wireRandomPayload(1500),
                partSize: 200, autoCompress: false
            )
            // Prime TRANSFERRING then cancel() -> FAILED.
            try await sender.transitionState(to: .advertised)
            await sender.transitionToTransferring()
            await sender.cancel()
            let sendStatus = wireResourceStatusName(await sender.state)
            let sendSentBefore = await sender.sentPartCount

            // Late serve-all request: FAILED-guarded request() serves nothing.
            if let sHash = await sender.hash, let sHashmap = await sender.hashmap {
                var reqData = Data([0x00])  // HASHMAP_IS_NOT_EXHAUSTED
                reqData.append(sHash)
                reqData.append(sHashmap)
                await sender.request(reqData)
            }
            let sendSentAfterRequest = await sender.sentPartCount

            // Late valid proof: FAILED-guarded validate_proof() must NOT conclude.
            if let expectedProof = await sender.expectedProof {
                var proof = wireRandomPayload(32)
                proof.append(expectedProof)
                await sender.validate_proof(proof)
            }
            let sendStatusAfterProof = wireResourceStatusName(await sender.state)

            // ---- Positive control: a fresh AWAITING_PROOF sender DOES conclude on
            // the same proof shape (proves the late-proof guard, not a bad proof,
            // is what blocked the cancelled sender). ----
            let token2 = try wireMakeToken()
            let ctl = try await wireBuildSender(
                link: link, token: token2, payload: wireRandomPayload(1500),
                partSize: 200, autoCompress: false
            )
            try await ctl.transitionState(to: .advertised)
            await ctl.transitionToTransferring()
            try await ctl.transitionState(to: .awaitingProof)
            var ctlStatusAfterProof: String? = nil
            if let ctlExpected = await ctl.expectedProof {
                var ctlProof = wireRandomPayload(32)
                ctlProof.append(ctlExpected)
                await ctl.validate_proof(ctlProof)
                ctlStatusAfterProof = wireResourceStatusName(await ctl.state)
            }

            await rsender.cleanup()
            await sender.cleanup()
            await ctl.cleanup()
            return [
                "receiver_status": .s(recvStatus),
                "receiver_received_before": .i(recvReceivedBefore),
                "receiver_received_after_late_part": .i(recvReceivedAfterPart),
                "receiver_height_before": .i(recvHeightBefore),
                "receiver_height_after_late_hmu": .i(recvHeightAfterHmu),
                "sender_status": .s(sendStatus),
                "sender_sent_before": .i(sendSentBefore),
                "sender_sent_after_late_request": .i(sendSentAfterRequest),
                "sender_status_after_late_proof": .s(sendStatusAfterProof),
                "control_status_after_proof": ctlStatusAfterProof.map { WS.s($0) } ?? .null
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_send_bomb
    //
    // python: cmd_wire_resource_send_bomb (wire_tcp.py:1889). Sends a crafted
    // bz2-compressible payload that decompresses past the receiver's bound,
    // tripping the CORRUPT decompression-bomb guard. Link.sendResource now takes
    // an `autoCompress` flag (RNS/Resource.py:366): a zeros payload compresses to a
    // tiny advertised transfer that re-inflates past the receiver's lowered bound,
    // so the receiver marks it CORRUPT and the sender's transfer ends terminal
    // (success == false).
    case "wire_resource_send_bomb":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let requested = getIntOptional(p, "decompressed_size") ?? (wireRxMaxDecompressed + 1024 * 1024)
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 30000
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // Match python's crafted-size clamp (kept below MAX_EFFICIENT_SIZE so the
        // resource is a single segment).
        let floor = wireRxMaxDecompressed + 1
        let ceil = min(wireRxMaxDecompressed * 2, ResourceConstants.MAX_EFFICIENT_SIZE - 1)
        let crafted = max(floor, min(requested, ceil))
        let resourceId = wireRandomPayload(8).map { String(format: "%02x", $0) }.joined()
        let out: [String: WS] = try blockingAsync {
            let payload = Data(count: crafted) // zeros: bz2-compress to a tiny advert
            let resource = try await link.sendResource(data: payload, autoCompress: true)
            let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
            var state = await resource.state
            while Date() < deadline && !state.isTerminal {
                try? await Task.sleep(nanoseconds: 100_000_000)
                state = await resource.state
            }
            return [
                "success": .b(state == .complete),
                "status": .i(wireResourceStatusCode(state)),
                "size": .i(crafted),
                "resource_id": .s(resourceId)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_force_collision
    //
    // python: cmd_wire_resource_force_collision (wire_tcp.py:8133) monkeypatches
    // Resource.get_map_hash to force a hashmap collision and observe the random-
    // hash regeneration / rebuild loop. reticulum-swift's prepare() now runs the
    // collision-guard remap loop (RNS/Resource.py:436-474) and exposes the
    // `setMapHashInjector` test seam: the injector forces parts 0 and 1 to share a
    // map hash on the FIRST build pass (collision -> rebuild with a fresh
    // random_hash), then returns the genuine map hash on the rebuild pass.
    case "wire_resource_force_collision":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            // Several small parts so a collision is possible (a single-part
            // resource cannot collide). partSize 200 over 4000 random bytes.
            let collide = WireCollisionInjector()
            let resource = Resource(data: wireRandomPayload(4000), link: link, autoCompress: false)
            await resource.setMapHashInjector { randomHash, partIndex, defaultMapHash in
                collide.mapHash(randomHash: randomHash, partIndex: partIndex, defaultMapHash: defaultMapHash)
            }
            try await resource.prepare(
                partSize: 200,
                linkEncrypt: { try token.encrypt($0) },
                autoCompress: false
            )
            await resource.setMapHashInjector(nil)
            let rhBefore = collide.randomHashBefore
            let rhAfter = collide.randomHashAfter
            let finalRandomHash = await resource.randomHash
            let rebuilds = await resource.hashmapRebuildCount
            let numParts = await resource.numParts
            await resource.cleanup()
            // remapped: a fresh random_hash was drawn on the rebuild pass.
            let remapped = rebuilds > 0 && rhBefore != nil && rhAfter != nil && rhBefore != rhAfter
            // The object adopted the rebuilt (post-collision) random_hash.
            let hashmapChanged = remapped && finalRandomHash == rhAfter
            return [
                "remapped": .b(remapped),
                "random_hash_before": rhBefore.map { WS.h($0) } ?? .null,
                "random_hash_after": rhAfter.map { WS.h($0) } ?? .null,
                "hashmap_changed": .b(hashmapChanged),
                "num_parts": .i(numParts)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_outgoing_queue_state
    //
    // python: cmd_wire_resource_outgoing_queue_state (wire_tcp.py:8207) exercises
    // Link.ready_for_new_resource / register_outgoing_resource and the second-
    // resource QUEUED spin. reticulum-swift now exposes readyForNewResource() +
    // registerOutgoingResource() (RNS/Link.py:1328-1330/1302-1303) and the
    // one-outgoing-at-a-time gate in sendResource (a second resource advertised
    // while one is registered stays QUEUED in pendingOutgoingQueue,
    // RNS/Resource.py:522-524).
    case "wire_resource_outgoing_queue_state":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 5000
        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        let token = try wireMakeToken()
        let out: [String: WS] = try blockingAsync {
            // Positive control: an idle link admits a new outgoing resource.
            let readyEmpty = await link.readyForNewResource()

            // Build the first resource inert and register it as in flight.
            let first = try await wireBuildSender(
                link: link, token: token, payload: wireRandomPayload(800),
                partSize: 200, autoCompress: false
            )
            await link.registerOutgoingResource(first)
            // Negative control: with one registered, the link refuses a new one.
            let readyWithOne = await link.readyForNewResource()

            // A SECOND resource advertised now stays QUEUED behind the first.
            let second = try await link.sendResource(data: wireRandomPayload(800))
            let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
            var secondState = await second.state
            while Date() < deadline && secondState != .queued && !secondState.isTerminal {
                try? await Task.sleep(nanoseconds: 20_000_000)
                secondState = await second.state
            }
            let firstState = await first.state

            // Cleanup: cancel the queued second, unregister the inert first.
            await second.cancel()
            await link.cancelOutgoingResource(first)
            await first.cleanup()

            return [
                "ready_empty": .b(readyEmpty),
                "ready_with_one": .b(readyWithOne),
                "first_status": .i(wireResourceStatusCode(firstState)),
                "first_status_name": .s(wireResourceStatusName(firstState)),
                "second_status": .i(wireResourceStatusCode(secondState)),
                "second_status_name": .s(wireResourceStatusName(secondState)),
                "queued": .b(secondState == .queued)
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_receiver_status
    //
    // python: cmd_wire_resource_receiver_status (wire_tcp.py:1960). Reads the
    // receiver-side state of the MOST-RECENT inbound Resource on a listening
    // destination — the discriminating observable for the HMU handshake, metadata
    // round-trip, cancel (RESOURCE_ICL → FAILED) and bz2-bomb (CORRUPT) cases.
    //
    // swift's WireListener buffers only completed payload bytes, so the inbound
    // Resource objects are retained instead by WireResourceCallbacks.resourceStarted
    // into the module-level observation registry below (mirrors python's
    // listener["incoming_resources"] list, wire_tcp.py:1316/:1368-1407). Every
    // observable here is read straight off the real retained RNS-equivalent
    // Resource actor — status / corrupt / hashmap_height / max_decompressed_size /
    // compressed / hmuRequestsSent / hashmapUpdatesReceived / receivedMetadata /
    // assembledData — none recomputed. Optionally polls up to timeout_ms for an
    // inbound Resource to appear / reach a terminal status (COMPLETE/FAILED/CORRUPT).
    case "wire_resource_receiver_status":
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 0

        let inst = try requireInstance(handle)
        guard inst.listeners[destHashHex] != nil else {
            throw BridgeError.invalidData(
                "No listener registered for destination_hash=\(destHashHex)")
        }

        // Poll up to timeout_ms for an inbound Resource to appear / conclude
        // (python terminal = {COMPLETE, FAILED, CORRUPT}, wire_tcp.py:1985-1996;
        // ResourceState.isTerminal covers those + cancelled/rejected).
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while true {
            let recs = wireInboundResourceList(destHashHex)
            if let last = recs.last {
                let st: ResourceState = try blockingAsync { await last.state }
                if st.isTerminal || Date() >= deadline { break }
            } else if Date() >= deadline {
                break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }

        let recs = wireInboundResourceList(destHashHex)
        guard let last = recs.last else {
            // python: {"found": False, "resource_count": 0} (wire_tcp.py:2001).
            return ["found": boolean(false), "resource_count": .int(0)]
        }
        let resourceCount = recs.count
        let out: [String: WS] = try blockingAsync {
            let state = await last.state
            let meta = await last.receivedMetadata
            let data = await last.assembledData
            let hashmapHeight = await last.hashmapHeight
            let maxDecompressed = await last.maxDecompressedSize
            let compressed = await last.compressed
            let hmuRequests = await last.hmuRequestsSent
            let hashmapUpdates = await last.hashmapUpdatesReceived
            return [
                "found": .b(true),
                "resource_count": .i(resourceCount),
                "status": .i(wireResourceStatusCode(state)),
                "status_name": .s(wireResourceStatusName(state)),
                "corrupt": .b(state == .corrupt),
                "hmu_requests_sent": .i(hmuRequests),
                "hashmap_updates_received": .i(hashmapUpdates),
                "hashmap_height": .i(hashmapHeight),
                "max_decompressed_size": .i(maxDecompressed),
                "compressed": .b(compressed),
                // python: bool(resource.has_metadata). The receiver sets
                // receivedMetadata only when segment 1 carried an 'x' field
                // (RNS/Resource.py:696-704), so its presence IS has_metadata.
                "has_metadata": .b(meta != nil),
                "metadata": meta.map { WS.h($0) } ?? .null,
                "data": data.map { WS.h($0) } ?? .null
            ]
        }
        return out.mapValues(wsToJSON)

    // MARK: wire_resource_cancel
    //
    // python: cmd_wire_resource_cancel (wire_tcp.py:1859-1886). Aborts an
    // in-flight outbound Resource started by wire_resource_send(wait=False):
    // looks it up by resource_id in inst.outResources and calls the real
    // Resource.cancel(), which emits RESOURCE_ICL to the receiver
    // (RNS/Resource.py:1075-1095 → RNS/Link.py:1131-1138). The initiator's own
    // Resource lands at FAILED (swift cancel() sets .failed, status code 7,
    // mirroring RNS FAILED). Returns {cancelled, resource_id, status}.
    case "wire_resource_cancel":
        let handle = try getString(p, "handle")
        let resourceId = try getString(p, "resource_id")
        let inst = try requireInstance(handle)
        guard let resource = inst.outResources[resourceId] else {
            throw BridgeError.invalidData("Unknown resource_id: \(resourceId)")
        }
        let statusCode: Int = try blockingAsync {
            await resource.cancel()
            return wireResourceStatusCode(await resource.state)
        }
        return [
            "cancelled": boolean(true),
            "resource_id": .string(resourceId),
            "status": .int(statusCode)
        ]

    default:
        return nil
    }
}

// MARK: - Receiver-side inbound Resource observation registry
//
// python keeps a per-listener `incoming_resources` list, one record per inbound
// Resource, populated by a resource_started hook and read by
// cmd_wire_resource_receiver_status (wire_tcp.py:1316/:1368-1407/:1988-2021).
// swift's WireListener buffers only completed payload bytes, so this module-level
// registry mirrors that list: WireResourceCallbacks.resourceStarted (WireTcp.swift)
// appends each inbound Resource here, keyed by the listener's IN destination-hash
// hex, retaining the actor so its terminal state / receivedMetadata / assembledData
// / HMU counters stay readable after conclusion (Resource.cleanup keeps assembledData
// + receivedMetadata in RAM). Order-preserving so `.last` is the most-recent transfer
// and `.count` is the inbound-Resource count, matching the python list semantics.
private let wireInboundLock = NSLock()
nonisolated(unsafe) private var wireInboundResources: [String: [Resource]] = [:]

/// Append an inbound Resource as it starts. Called from
/// WireResourceCallbacks.resourceStarted (WireTcp.swift) — `internal` so the
/// listener-side callback can reach it across the cluster boundary.
func wireRegisterInboundResource(destinationHashHex: String, _ resource: Resource) {
    wireInboundLock.lock(); defer { wireInboundLock.unlock() }
    wireInboundResources[destinationHashHex, default: []].append(resource)
}

/// Snapshot the ordered inbound-Resource records for a destination hash.
private func wireInboundResourceList(_ destinationHashHex: String) -> [Resource] {
    wireInboundLock.lock(); defer { wireInboundLock.unlock() }
    return wireInboundResources[destinationHashHex] ?? []
}

// MARK: - Cluster helpers

/// Sendable scalar carrier — lets the async work inside `blockingAsync` return a
/// `[String: WS]` (Dictionary of Sendable values is Sendable) without capturing
/// the non-Sendable JSONValue helpers across the actor boundary. Mapped to
/// JSONValue outside the closure.
private enum WS: Sendable {
    case s(String)
    case i(Int)
    case d(Double)
    case b(Bool)
    case h(Data)
    case hexArr([Data])
    case strArr([String])
    case null
}

private func wsToJSON(_ w: WS) -> JSONValue {
    switch w {
    case .s(let v): return .string(v)
    case .i(let v): return .int(v)
    case .d(let v): return .double(v)
    case .b(let v): return .bool(v)
    case .h(let v): return hex(v)
    case .hexArr(let a): return .array(a.map { JSONValue.string(bytesToHex($0)) })
    case .strArr(let a): return .array(a.map { JSONValue.string($0) })
    case .null: return .null
    }
}

/// Thread-safe collector for packets emitted by a Resource's send callback.
private final class WirePacketCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var packets: [Data] = []

    func add(_ d: Data) { lock.lock(); packets.append(d); lock.unlock() }

    /// Number of captured RESOURCE_REQ packets.
    var requestCount: Int {
        lock.lock(); defer { lock.unlock() }
        return packets.filter { $0.first == ResourcePacketContext.resourceRequest }.count
    }

    /// Number of captured RESOURCE_PRF packets.
    var proofCount: Int {
        lock.lock(); defer { lock.unlock() }
        return packets.filter { $0.first == ResourcePacketContext.resourceProof }.count
    }

    /// First captured RESOURCE_REQ packet (full frame incl. context byte).
    var firstRequest: Data? {
        lock.lock(); defer { lock.unlock() }
        return packets.first { $0.first == ResourcePacketContext.resourceRequest }
    }
}

/// Thread-safe call counter for the Resource progress callback (@Sendable hop).
private final class WireCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
}

/// Drives the `setMapHashInjector` test seam for wire_resource_force_collision.
/// On the FIRST build pass it returns part 0's genuine map hash again for part 1
/// (a forced collision -> the prepare() loop rebuilds with a fresh random_hash);
/// every other call returns the genuine map hash. Records the random_hash seen on
/// the first (colliding) pass and on the rebuild pass so the bridge can assert the
/// remap drew a fresh one. Mirrors python's get_map_hash monkeypatch
/// (wire_tcp.py:8167-8179); the only synthetic byte is one repeated genuine hash.
private final class WireCollisionInjector: @unchecked Sendable {
    private let lock = NSLock()
    private var phase1Done = false
    private var firstRandomHash: Data?
    private var collideHash: Data?
    private var rhBefore: Data?
    private var rhAfter: Data?

    func mapHash(randomHash: Data, partIndex: Int, defaultMapHash: Data) -> Data {
        lock.lock(); defer { lock.unlock() }
        if !phase1Done {
            if firstRandomHash == nil { firstRandomHash = randomHash; rhBefore = randomHash }
            if randomHash == firstRandomHash {
                if partIndex == 0 {
                    collideHash = defaultMapHash
                    return defaultMapHash
                } else if partIndex == 1, let collide = collideHash {
                    // Collision: hand back part 0's map hash -> guard trips -> rebuild.
                    phase1Done = true
                    return collide
                }
                return defaultMapHash
            }
        }
        // Rebuild pass (fresh random_hash): genuine map hashes, no collision.
        if randomHash != firstRandomHash { rhAfter = randomHash }
        return defaultMapHash
    }

    var randomHashBefore: Data? { lock.lock(); defer { lock.unlock() }; return rhBefore }
    var randomHashAfter: Data? { lock.lock(); defer { lock.unlock() }; return rhAfter }
}

/// Fresh 64-byte RNS Token used as the local link encryptor for inert resource
/// construction. AES-CBC ciphertext length is key-independent, so transfer
/// sizes / part counts / hashmap strides are byte-exact to the live link token.
private func wireMakeToken() throws -> Token {
    let key = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
    return try Token(derivedKey: key)
}

/// Random test payload of `n` bytes.
private func wireRandomPayload(_ n: Int) -> Data {
    Data((0..<n).map { _ in UInt8.random(in: 0...255) })
}

/// Build a real outbound Resource on `link`, prepared at `partSize` bytes/part,
/// link-encrypted with `token`. Mirrors RNS.Resource(payload, link,
/// advertise=False): full construction lifecycle (random_hash + hash + hashmap +
/// packed parts) with nothing on the wire.
private func wireBuildSender(
    link: Link, token: Token, payload: Data, partSize: Int, autoCompress: Bool,
    metadata: Data? = nil
) async throws -> Resource {
    let resource = Resource(data: payload, link: link, metadata: metadata, autoCompress: autoCompress)
    try await resource.prepare(
        partSize: partSize,
        linkEncrypt: { try token.encrypt($0) },
        autoCompress: autoCompress
    )
    return resource
}

/// Build the inbound receiver the way RNS.Resource.accept does: from the
/// sender's genuine ResourceAdvertisement, with `token` wired as the link
/// decryptor so assemble() can recover the plaintext.
private func wireBuildReceiver(sender: Resource, link: Link, token: Token) async throws -> Resource {
    let adv = try await sender.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
    let receiver = Resource(advertisement: adv, link: link)
    await receiver.setDecryptCallback { try token.decrypt($0) }
    return receiver
}

/// RNS Resource status code (Resource.py:143-152). REJECTED == NONE == 0;
/// swift's `.cancelled` maps to RNS FAILED (RNS cancel() -> FAILED).
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

/// RNS Resource status name (_RESOURCE_STATUS_NAMES, wire_tcp.py:223).
private func wireResourceStatusName(_ s: ResourceState) -> String {
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
