// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  AnnounceHandler.swift
//  ReticulumSwift
//
//  Processes received announce packets according to Reticulum protocol rules.
//  Validates signatures, records paths, and determines rebroadcast behavior.
//
//  The AnnounceHandler implements:
//  - Hop limit enforcement (128 max)
//  - Signature validation using AnnounceValidator
//  - Path recording with mode-specific expiration (replay protection is owned by
//    PathTable.record's random_blob check, mirroring RNS — there is NO separate
//    per-announce-hash dedup, Transport.py:1755-1823)
//  - Mode-based rebroadcast decisions
//

import Foundation
import os.log

private let logger = Logger(subsystem: "net.reticulum", category: "AnnounceHandler")

// MARK: - Process Result

/// Result of processing an announce packet.
public enum AnnounceProcessResult: Sendable, Equatable {
    /// Packet was ignored (not processed).
    case ignored(reason: AnnounceIgnoreReason)

    /// Path was recorded but not rebroadcast.
    case recorded(destinationHash: Data)

    /// Path was recorded and packet should be rebroadcast.
    case recordedAndRebroadcast(destinationHash: Data, packet: Packet)
}

/// Reason why an announce was ignored.
public enum AnnounceIgnoreReason: Sendable, Equatable {
    /// Announce was already seen (duplicate).
    ///
    /// Returned when `PathTable.record` rejects the announce — a replayed
    /// random_blob, or a worse-hop announce that did not meet the
    /// expired/fresher/unresponsive replacement criteria. RNS gates replay
    /// purely on the random_blob check inside the path-table decision tree
    /// (Transport.py:1755-1823); there is NO separate per-announce-hash dedup.
    case alreadySeen

    /// Hop count exceeds maximum limit.
    case hopLimitExceeded

    /// Signature verification failed.
    case invalidSignature

    /// Packet format is invalid.
    case invalidFormat
}

// MARK: - Announce Handler Protocol (RNS register_announce_handler duck type)

/// An externally-registered announce handler, modelling the RNS duck-typed
/// handler accepted by `Transport.register_announce_handler` (Transport.py:
/// 2465-2477) and invoked by the inbound dispatch loop (Transport.py:2034-2086).
///
/// RNS handlers are arbitrary objects with:
///   - an `aspect_filter` attribute (`None` matches every announce, otherwise a
///     dotted `"app.aspect1.aspect2"` name compared via
///     `Destination.hash_from_name_and_identity`),
///   - a `received_announce(...)` callable whose PARAMETER COUNT (3/4/5) selects
///     how much is delivered (always `destination_hash, announced_identity,
///     app_data`; 4 adds `announce_packet_hash`; 5 adds `is_path_response`),
///   - an optional `receive_path_responses` flag (PATH_RESPONSE-context
///     announces are delivered only to handlers that opt in).
///
/// Swift cannot introspect a closure's arity the way python's
/// `inspect.signature` does, so `callbackParameterCount` is modelled explicitly
/// (forced category-(a) deviation, see port-deviations.md). Likewise per-handler
/// exception isolation (Transport.py:2083-2086) is modelled by the dispatch loop
/// catching a `throw` from `receivedAnnounce` instead of python's try/except.
public protocol AnnounceHandlerProtocol: AnyObject, Sendable {
    /// `handler.aspect_filter` — `nil` matches every announce; otherwise the
    /// dotted `"app.aspect…"` name the announced destination hash must equal.
    var aspectFilter: String? { get }

    /// Models `hasattr(handler, "aspect_filter")` — the registration guard
    /// (Transport.py:2476-2477) only registers a handler that HAS the attribute.
    /// A swift handler that semantically lacks an aspect filter returns `false`
    /// here (distinct from `aspectFilter == nil`, which is "match all").
    var hasAspectFilter: Bool { get }

    /// `handler.receive_path_responses == True` — opt-in to PATH_RESPONSE-context
    /// announces (Transport.py:2049-2053). Defaults to `false` semantics.
    var receivePathResponses: Bool { get }

    /// The `received_announce` parameter count (3, 4, or 5) selecting the dispatch
    /// arity (Transport.py:2055-2069). Any other value is an invalid signature.
    var callbackParameterCount: Int { get }

    /// Deliver an announce. `announcePacketHash` is non-nil only for a 4/5-param
    /// handler; `isPathResponse` is non-nil only for a 5-param handler. Throwing
    /// is isolated per-handler by the dispatch loop (a raising handler must not
    /// prevent a later well-behaved handler from running).
    func receivedAnnounce(
        destinationHash: Data,
        announcedIdentity: Identity?,
        appData: Data?,
        announcePacketHash: Data?,
        isPathResponse: Bool?
    ) throws
}

// MARK: - Announce Handler

/// Actor that processes received announce packets.
///
/// AnnounceHandler implements the Reticulum announce processing protocol:
/// 1. Hop limit: Enforces maximum 128 hops
/// 2. Validation: Verifies signatures for SINGLE/GROUP/LINK destinations
/// 3. Path recording: Updates path table with learned routes (the path-table
///    random_blob check is the sole replay gate, mirroring RNS)
/// 4. Rebroadcast: Determines whether to propagate based on interface mode
///
/// Example usage:
/// ```swift
/// let handler = AnnounceHandler(pathTable: pathTable)
/// let result = try await handler.process(
///     packet: announcePacket,
///     from: "tcp-1",
///     interfaceMode: .full
/// )
/// switch result {
/// case .ignored(let reason):
///     print("Announce ignored: \(reason)")
/// case .recorded(let hash):
///     print("Path recorded for \(hash.hexDescription)")
/// case .recordedAndRebroadcast(let hash, let packet):
///     print("Rebroadcasting announce for \(hash.hexDescription)")
///     // Send packet to other interfaces
/// }
/// ```
public actor AnnounceHandler {

    // MARK: - Properties

    /// Path table for recording learned routes.
    private let pathTable: PathTable

    /// Maximum hop count allowed (Reticulum standard is 128).
    public let maxHops: UInt8 = TransportConstants.PATHFINDER_M

    /// The per-announce cheap `ANNOUNCE recorded=` line logs every time; the EXPENSIVE full
    /// path-table snapshot (allEntries + sort over hundreds of mesh entries) only every
    /// `snapshotEvery` announces. Running the snapshot per-announce serialized on this actor
    /// throttled announce processing to ~0.5/s under a reconnect announce flood (session 6),
    /// stalling a contact's TCP announce for ~115s behind the mesh backlog.
    private static let snapshotEvery = 25
    private var snapshotThrottleCounter = 0

    // MARK: - Initialization

    /// Create an announce handler with the specified path table.
    ///
    /// - Parameter pathTable: Path table for recording paths.
    public init(pathTable: PathTable) {
        self.pathTable = pathTable
    }

    // MARK: - Processing

    /// Process a received announce packet.
    ///
    /// Processing steps:
    /// 1. Check hop limit (return .ignored if exceeded)
    /// 2. Parse and validate announce (signature verification)
    /// 3. Remember identity + app_data + ratchet (unconditional, RNS validate_announce)
    /// 4. Record path in path table with mode-specific expiration (random_blob
    ///    replay gate lives here — no separate per-announce-hash dedup)
    /// 5. Determine rebroadcast based on interface mode
    ///
    /// - Parameters:
    ///   - packet: The announce packet to process
    ///   - interfaceId: ID of the interface that received the packet
    ///   - interfaceMode: Mode of the receiving interface
    /// - Returns: Processing result indicating action taken
    /// - Throws: Never (errors are returned as .ignored results)
    public func process(
        packet: Packet,
        from interfaceId: String,
        interfaceMode: InterfaceMode
    ) async -> AnnounceProcessResult {
        logger.debug("Processing announce from \(interfaceId), hops=\(packet.header.hopCount), data=\(packet.data.count) bytes")

        // RNS performs NO per-announce-hash deduplication on the inbound path
        // (Transport.py:1687-1823). Replay protection is owned entirely by the
        // random_blob check inside PathTable.record (`if not random_blob in
        // random_blobs`, Transport.py:1763/1796/1808). Re-evaluating every
        // signature-valid announce is required so that a re-heard announce whose
        // stored path has since EXPIRED or been marked UNRESPONSIVE can take the
        // replacement branches (Transport.py:1790-1823).

        // 1. Check hop limit
        if packet.header.hopCount >= maxHops {
            logger.warning("Ignored: hop limit exceeded (\(packet.header.hopCount) >= \(self.maxHops))")
            NetworkLog.debug("[ANNDROP] \(NetworkLog.hex8(packet.destination)) hop-limit \(packet.header.hopCount)>=\(maxHops) iface=\(interfaceId)")
            return .ignored(reason: .hopLimitExceeded)
        }

        // 2. Parse and validate announce
        let parsed: ParsedAnnounce
        let isPlain = packet.header.destinationType == .plain
        logger.debug("Parsing announce, isPlain=\(isPlain)")

        do {
            parsed = try AnnounceValidator.parseAndValidate(packet: packet, isPlain: isPlain)
            logger.debug("Parsed successfully: destHash=\(parsed.destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined())")
        } catch {
            logger.warning("Parse/validate error: \(error)")
            NetworkLog.debug("[ANNDROP] \(NetworkLog.hex8(packet.destination)) parse/validate FAILED iface=\(interfaceId) hops=\(packet.header.hopCount): \(error)")
            // Determine if it's a format or signature error
            if let validationError = error as? AnnounceValidationError {
                switch validationError {
                case .signatureInvalid:
                    return .ignored(reason: .invalidSignature)
                case .hashMismatch:
                    // Destination hash does not derive from the announced keys:
                    // an identity-spoofing attempt. Drop as an authenticity failure.
                    return .ignored(reason: .invalidSignature)
                default:
                    break
                }
            }
            return .ignored(reason: .invalidFormat)
        }

        // 3. Refresh known_destinations + adopted ratchet UNCONDITIONALLY on every
        // validated announce, mirroring RNS.Identity.validate_announce. RNS calls
        // Identity.remember (Identity.py:591) and Identity._remember_ratchet
        // (Identity.py:612) here, independent of any path-table acceptance/freshness
        // gate. Doing it before the PathTable.record below (which may reject a
        // same/near-second re-announce as not fresher) is what lets recall/get_ratchet
        // see the newest app_data / ratchet — RNS overwrites known_destinations
        // in place (Identity.py:108-113) and adopts the newest ratchet unconditionally.
        // SECURITY (known-key collision guard) — RNS Identity.py:588-596. Even with a
        // valid signature AND a correct destination binding, refuse to overwrite the
        // public key already known for this destination with a *different* key. This is
        // only reachable via a truncated-hash collision (the binding check in
        // parseAndValidate makes it astronomically unlikely), but RNS rejects rather than
        // permit a path/key swap, so we mirror that.
        if let publicKeys = parsed.publicKeys,
           let knownKeys = Identity.recall(parsed.destinationHash)?.publicKeys,
           knownKeys != publicKeys {
            logger.warning("Rejected announce: destination already known with a different public key (possible hash collision / path-modification attempt)")
            NetworkLog.debug("[ANNDROP] \(NetworkLog.hex8(packet.destination)) known-key-mismatch iface=\(interfaceId)")
            return .ignored(reason: .invalidSignature)
        }

        if let publicKeys = parsed.publicKeys, publicKeys.count == PUBLIC_KEYS_LENGTH {
            // RNS Identity.py:591 — Identity.remember(packet.get_hash(), destination_hash, public_key, app_data)
            //
            // app_data must honour the RNS validate_announce None-vs-empty rule
            // (Identity.py:542,560-561): app_data initialises to b"" and is nulled
            // ONLY when len(packet.data) <= KEYSIZE+NAME_HASH+10+SIG (=148, i.e. NO
            // ratchet AND no trailing app_data). A ratcheted-but-app_data-less
            // announce is >=180 bytes, so its app_data stays b"" (empty, not None).
            // AnnounceValidator yields parsed.appData == nil for any announce with
            // no trailing bytes; `announceAppData` reconstructs the distinction from
            // the ratchet presence so it survives into Identity.recall/recallAppData.
            try? Identity.remember(
                packetHash: packet.getFullHash(),
                destinationHash: parsed.destinationHash,
                publicKey: publicKeys,
                appData: Identity.announceAppData(
                    rawAppData: parsed.appData,
                    hasRatchet: parsed.ratchet?.isEmpty == false
                )
            )
        }
        if let ratchet = parsed.ratchet {
            // RNS Identity.py:612 — if ratchet: Identity._remember_ratchet(destination_hash, ratchet)
            Identity.rememberRatchet(destinationHash: parsed.destinationHash, ratchet: ratchet)
        }

        // 4. Record path in path table
        // For PLAIN destinations, we need to handle missing public keys
        let publicKeys = parsed.publicKeys ?? Data(repeating: 0, count: 64)

        // Extract nextHop from announces
        // - HEADER_2 packets: use transportAddress (the transport node that relayed)
        // - HEADER_1 packets with hops > 0: use destination hash (mirrors Python's received_from = destination_hash)
        //   This enables HEADER_2 conversion for multi-hop routing even when transport node is unknown
        let nextHop: Data?
        if packet.header.headerType == .header2,
           let transportAddr = packet.transportAddress,
           !transportAddr.allSatisfy({ $0 == 0 }) {
            // Real relaying transport node.
            nextHop = transportAddr
        } else if packet.header.hopCount > 0 {
            // HEADER_1 with hops>0, OR a HEADER_2 carrying a null (all-zero) transport
            // address — the relaying node is unknown, so fall back to the destination
            // hash (Python's received_from = destination_hash) rather than recording a
            // dead all-zero next hop that can never route.
            // Python behavior: for HEADER_1 announces, received_from = destination_hash
            // This allows HEADER_2 routing to work - the relay will forward appropriately
            nextHop = parsed.destinationHash
        } else {
            nextHop = nil
        }

        // Debug: Log announce header type and nextHop extraction
        let destHex = parsed.destinationHash.prefix(8).map { String(format: "%02x", $0) }.joined()
        logger.debug("Announce processing: dest=\(destHex), headerType=\(String(describing: packet.header.headerType)), hopCount=\(packet.header.hopCount)")
        if let nh = nextHop {
            let nhHex = nh.prefix(8).map { String(format: "%02x", $0) }.joined()
            if packet.header.headerType == .header2 {
                logger.debug("HEADER_2 announce: nextHop=\(nhHex) (from transportAddress)")
            } else {
                logger.debug("HEADER_1 announce with hops>0: nextHop=\(nhHex) (set to destHash for relay forwarding)")
            }
        } else {
            logger.debug("Direct announce (hops=0): no nextHop needed")
        }

        let pathRecorded = await pathTable.record(
            destinationHash: parsed.destinationHash,
            publicKeys: publicKeys,
            randomBlob: parsed.randomHash,
            interfaceId: interfaceId,
            hopCount: packet.header.hopCount + 1, // Increment for next hop
            expiration: interfaceMode.pathExpiration,
            ratchet: parsed.ratchet,  // Pass ratchet for forward secrecy encryption
            appData: parsed.appData,
            nextHop: nextHop,  // Pass transport address for multi-hop routing
            announceData: packet.data  // Cache raw announce payload for path responses
        )

        // NETWORK LOG: after every announce, log what was learned plus a path-table
        // summary, so the announce store can be followed over time. The full table is
        // often hundreds of stale/persisted mesh entries — too noisy to dump in full —
        // so we summarise the counts and list only the *routable/relevant* entries
        // (a real non-zero next hop, a direct neighbour, or a named node).
        if NetworkLog.isEnabled {
            let nhDesc: String
            if let nh = nextHop {
                nhDesc = nh.allSatisfy { $0 == 0 } ? "ZERO(\(nh.count)B)" : NetworkLog.hex8(nh)
            } else {
                nhDesc = "direct"
            }
            // Cheap, per-announce — this is what following a route needs (grepped as "ANNOUNCE recorded=").
            NetworkLog.log("ANNOUNCE recorded=\(pathRecorded) dest=\(destHex) hops=\(packet.header.hopCount) "
                + "header=\(packet.header.headerType) computedNextHop=\(nhDesc) iface=\(interfaceId)")

            // Expensive table SNAPSHOT — throttled (see `snapshotEvery`): allEntries() copies the
            // whole table off the PathTable actor and sorts it, so doing it per-announce serialized
            // announce processing under a flood. Emitting it periodically keeps the store followable
            // without throttling the pipeline.
            snapshotThrottleCounter += 1
            if snapshotThrottleCounter >= Self.snapshotEvery {
                snapshotThrottleCounter = 0
                let entries = await pathTable.allEntries()
                let zero = entries.filter { NetworkLog.hasZeroNextHop($0) }.count
                let direct = entries.filter { $0.nextHop == nil }.count
                let routed = entries.count - zero - direct          // real non-zero next hop
                let responsive = entries.filter { $0.pathState == 2 }.count
                // Only the *routable* entries — a direct neighbour (nil next hop) or a real
                // non-zero next hop. The hundreds of ZERO-next-hop mesh entries are covered by
                // the summary counts; listing them all just buries the paths that can carry traffic.
                let relevant = entries
                    .filter { $0.nextHop == nil || !NetworkLog.hasZeroNextHop($0) }
                    .sorted { NetworkLog.hex8($0.destinationHash) < NetworkLog.hex8($1.destinationHash) }
                var dump = "  PATHTABLE total=\(entries.count) zeroNextHop=\(zero) direct=\(direct) "
                    + "routed=\(routed) responsive=\(responsive) — \(relevant.count) relevant:"
                for entry in relevant.prefix(30) {
                    dump += "\n    " + NetworkLog.describe(entry)
                }
                if relevant.count > 30 { dump += "\n    … +\(relevant.count - 30) more relevant" }
                NetworkLog.log(dump)
            }
        }

        // Only proceed if path was actually recorded (RNS should_add==True).
        guard pathRecorded else {
            // PathTable.record rejected the announce (duplicate random_blob, or a
            // worse-hop announce not meeting the expired/fresher/unresponsive
            // replacement criteria) — RNS should_add==False: no rebroadcast and no
            // external announce-handler dispatch (Transport.py:1755-1823).
            return .ignored(reason: .alreadySeen)
        }

        // 5. Determine rebroadcast based on interface mode
        if interfaceMode.shouldPropagateAnnounces {
            // Create rebroadcast packet with incremented hop count
            let rebroadcastPacket = createRebroadcastPacket(from: packet)
            return .recordedAndRebroadcast(
                destinationHash: parsed.destinationHash,
                packet: rebroadcastPacket
            )
        } else {
            return .recorded(destinationHash: parsed.destinationHash)
        }
    }

    // MARK: - Private Helpers

    /// Create a rebroadcast packet with incremented hop count.
    ///
    /// - Parameter original: Original packet to rebroadcast
    /// - Returns: New packet with hop count + 1
    private func createRebroadcastPacket(from original: Packet) -> Packet {
        // Create new header with incremented hop count
        let newHeader = PacketHeader(
            headerType: original.header.headerType,
            hasContext: original.header.hasContext,
            hasIFAC: original.header.hasIFAC,
            transportType: original.header.transportType,
            destinationType: original.header.destinationType,
            packetType: original.header.packetType,
            hopCount: original.header.hopCount + 1
        )

        return Packet(
            header: newHeader,
            destination: original.destination,
            transportAddress: original.transportAddress,
            context: original.context,
            data: original.data
        )
    }
}
