// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  PathTable.swift
//  ReticulumSwift
//
//  Path table for storing learned routes from announces with SQLite persistence.
//  When an announce is received and validated, the path is recorded here.
//  When sending a packet, the path table is consulted to find the route.
//

import Foundation
import SQLite3
import os.log

/// SQLite destructor sentinel meaning "copy the value; caller's buffer may be freed".
/// SQLITE_STATIC is 0 (default when nil is passed). SQLITE_TRANSIENT is -1.
/// This MUST be used whenever the value is backed by a Swift temporary buffer
/// (e.g. `sqlite3_bind_text(..., someSwiftString, ...)`), otherwise SQLite
/// holds a dangling pointer and reads corrupted bytes when the statement
/// actually executes.
private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

private let logger = Logger(subsystem: "net.reticulum", category: "PathTable")

// MARK: - Path Table Errors

/// Errors from path table operations
public enum PathTableError: Error, Sendable, Equatable {
    /// Path not found in table
    case pathNotFound

    /// Path exists but has expired
    case pathExpired

    /// Database error
    case databaseError(String)
}

// MARK: - Path Table

/// Path table for routing with optional SQLite persistence.
///
/// The path table stores routing information learned from validated announces.
/// It enables routing packets to known destinations by looking up the best path.
///
/// Key operations:
/// - **record()**: Store a path from a validated announce
/// - **lookup()**: Find a path for a destination hash
/// - **cleanup()**: Remove expired entries
/// - **pathUpdates**: AsyncStream for real-time path notifications
///
/// Thread safety is ensured via actor isolation.
/// When initialized with a database path, paths persist across app launches.
public actor PathTable {

    // MARK: - Storage

    /// Paths indexed by destination hash (in-memory cache)
    private var paths: [Data: PathEntry] = [:]

    /// Interfaces treated as low-priority *fallback* links (configured by the embedder). A path on
    /// a normal interface always out-ranks a path on a fallback interface for the same destination
    /// — regardless of hop count — and a fallback path is only kept while it's the sole path.
    /// This is a generic routing knob; the embedder decides which interfaces are fallback (e.g. an
    /// app's virtual BLE carrier, so TCP is preferred when it exists and the carrier is used only
    /// when there's no other route). Hop counts are never altered, so direct-vs-routed send
    /// behaviour is unaffected.
    private var fallbackInterfaceIds: Set<String> = []

    /// How long (wall-clock seconds) a destination's normal interface may go *silent* — no announce
    /// received on any non-fallback interface — before the carrier is allowed to take the route over.
    /// Liveness, not freshness: while the peer's normal announces keep arriving (even though the
    /// carrier re-announces far more often and its copies always look "fresher"), the normal path is
    /// considered alive and the carrier cannot flip the route. The carrier adopts a destination only
    /// once its normal announces have actually stopped for this long. Should exceed one announce
    /// interval plus slack so a single missed/late announce doesn't trigger a spurious takeover
    /// (at 45s ≈ 1.5× a 30s interval one late announce flapped; 75s ≈ 2.5× tolerates it).
    public static var fallbackTakeoverGraceSeconds: UInt64 = 75

    /// DEPRECATED / no longer consulted (kept for API/source stability). Promotion of a normal
    /// interface over a fallback is now UNCONDITIONAL when the destination is unpinned — see the
    /// promote branch in `record()`. A freshness/lag gate here let the direct carrier win the
    /// announce race indefinitely and hold the route (session-3 ~140s BLE→TCP return), so it was
    /// removed; the pin (offline hold) and the 75s liveness window (anti-flap) are the real guards.
    public static var fallbackPromoteMaxLagSeconds: UInt64 = 90

    /// Destinations pinned to their fallback interface: while pinned, announces from NON-fallback
    /// interfaces are rejected, so the destination stays on the fallback path and can't be pulled
    /// back onto a stale/relayed normal-interface route. The embedder pins a peer it knows is only
    /// reachable over the fallback (e.g. one that signalled it lost internet, whose old TCP path a
    /// transport node may keep re-announcing) and unpins it when that's no longer true.
    private var fallbackPinnedDestinations: Set<Data> = []

    /// Per-destination, per-interface wall-clock time of the last announce received on that interface.
    /// Drives the liveness-based carrier takeover (see `fallbackTakeoverGraceSeconds`): the normal
    /// path counts as "alive" while some non-fallback interface here was heard within the takeover
    /// window, regardless of how often the carrier re-announces. Pruned alongside `paths`.
    private var lastHeardByInterface: [Data: [String: Date]] = [:]

    /// Interface IDs whose transport link is currently `.connected`, pushed periodically by the
    /// transport (`setConnectedInterfaces`). Used as a *connectivity* liveness signal for the
    /// carrier takeover: while a destination's incumbent normal interface is still connected (and the
    /// destination isn't pinned offline), the peer is reachable over it, so the carrier stays on
    /// standby even if its announces arrive less often than the carrier's direct re-announce.
    ///
    /// Announce-recency alone is not a reliable liveness signal here: a peer's announce reaches us
    /// over TCP via a rate-limiting relay far less often than it reaches us directly over the BLE
    /// carrier, so a live TCP route can go "announce-silent" past the window while its socket is
    /// perfectly up (session-4: argonath stayed connected the whole run yet the carrier took over
    /// after 75s). The PIN (`fallbackPinnedDestinations`, set from the peer's internet-lost signal)
    /// remains the authoritative offline trigger and overrides this connectivity check.
    private var connectedInterfaces: Set<String> = []

    /// SQLite database handle for persistence
    private var db: OpaquePointer?

    /// Path to database file (nil for in-memory only)
    private let databasePath: String?

    // MARK: - Event Stream

    /// Continuation for emitting path updates
    private var pathUpdateContinuation: AsyncStream<PathEntry>.Continuation?

    /// Stream of path updates for real-time UI notifications.
    /// Emits whenever a new path is recorded (not duplicates or worse paths).
    public nonisolated var pathUpdates: AsyncStream<PathEntry> {
        AsyncStream { continuation in
            Task {
                await self.setPathUpdateContinuation(continuation)
            }
        }
    }

    /// Set the continuation for path updates (called from AsyncStream initializer)
    private func setPathUpdateContinuation(_ continuation: AsyncStream<PathEntry>.Continuation) {
        self.pathUpdateContinuation = continuation
        continuation.onTermination = { @Sendable _ in
            Task { await self.clearPathUpdateContinuation() }
        }
    }

    /// Clear the continuation when stream is terminated
    private func clearPathUpdateContinuation() {
        self.pathUpdateContinuation = nil
    }

    // MARK: - Initialization

    /// Create a path table with optional SQLite persistence.
    ///
    /// - Parameter databasePath: Path to SQLite database file, or nil for in-memory only
    /// - Throws: PathTableError.databaseError if database cannot be opened
    public init(databasePath: String? = nil) throws {
        self.databasePath = databasePath

        if let dbPath = databasePath {
            // Open or create database
            if sqlite3_open(dbPath, &db) != SQLITE_OK {
                let error = String(cString: sqlite3_errmsg(db))
                throw PathTableError.databaseError("Failed to open database: \(error)")
            }

            #if os(iOS)
            // NE-safe SQLite (iOS only — this DB is the Network-Extension writer, shared
            // read-only with the app). WAL keeps write locks short; busy_timeout rides
            // out cross-process contention instead of failing fast. Other platforms keep
            // the default journal/synchronous so single-process embedders are unaffected.
            sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", nil, nil, nil)
            sqlite3_exec(db, "PRAGMA busy_timeout=5000;", nil, nil, nil)
            // `PRAGMA journal_mode=WAL` is *accepted* even when WAL doesn't actually engage
            // (it reports the resulting mode as a result row, not via the return code). Run
            // it via prepare/step so we can read the result back and warn on a silent
            // fallback to DELETE mode — which would reintroduce the cross-process lock/busy
            // failures the NE-safe open exists to prevent.
            var walStmt: OpaquePointer?
            if sqlite3_prepare_v2(db, "PRAGMA journal_mode=WAL;", -1, &walStmt, nil) == SQLITE_OK {
                if sqlite3_step(walStmt) == SQLITE_ROW, let modePtr = sqlite3_column_text(walStmt, 0) {
                    let mode = String(cString: modePtr)
                    if mode.lowercased() != "wal" {
                        logger.error("PathTable: WAL did not engage (journal_mode=\(mode)) — NE cross-process safety degraded")
                    }
                }
                sqlite3_finalize(walStmt)
            } else {
                logger.error("PathTable: could not set WAL journal mode — NE cross-process safety degraded")
            }
            #endif

            // Create table with random_blobs column (JSON-encoded [Data])
            let createSQL = """
                CREATE TABLE IF NOT EXISTS paths (
                    destination_hash BLOB PRIMARY KEY,
                    public_keys BLOB NOT NULL,
                    interface_id TEXT NOT NULL,
                    hop_count INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    expires REAL NOT NULL,
                    random_blobs TEXT NOT NULL,
                    ratchet BLOB,
                    app_data BLOB,
                    next_hop BLOB,
                    announce_data BLOB
                )
                """
            if sqlite3_exec(db, createSQL, nil, nil, nil) != SQLITE_OK {
                let error = String(cString: sqlite3_errmsg(db))
                throw PathTableError.databaseError("Failed to create table: \(error)")
            }

            #if os(iOS)
            // Deliver-while-locked: the NE writes learned paths after first unlock even
            // when the device is later locked. Pin the data-protection class on the DB +
            // its WAL/SHM sidecars to CompleteUntilFirstUserAuthentication, matching the
            // LXMF store — otherwise iOS 0xDEAD10CC-kills the NE when it touches a
            // Complete-protected file while suspended. (CREATE above created -wal/-shm.)
            let fm = FileManager.default
            for suffix in ["", "-wal", "-shm"] where fm.fileExists(atPath: dbPath + suffix) {
                do {
                    try fm.setAttributes(
                        [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                        ofItemAtPath: dbPath + suffix
                    )
                } catch {
                    // A silent failure here can let the NE 0xDEAD10CC when the device
                    // locks — surface it so the resulting crash is diagnosable.
                    logger.error("PathTable: data-protection setAttributes failed for \(suffix.isEmpty ? "db" : suffix): \(error.localizedDescription)")
                }
            }
            #endif

            // Migrate and load in a Task to satisfy actor isolation
            Task { [self] in
                await migrateRandomBlobColumn()
                await migrateAnnounceDataColumn()
                await loadFromDatabase()
                let pathCount = await self.paths.count
                logger.info("Loaded \(pathCount) paths from database: \(dbPath)")
            }
        }
    }

    deinit {
        if let db = db {
            sqlite3_close(db)
        }
    }

    /// Create an empty in-memory path table (convenience initializer).
    public init() {
        self.databasePath = nil
        self.db = nil
    }

    // MARK: - Path State Management

    /// Path states indexed by destination hash.
    /// Separate from PathEntry to match Python's Transport.path_states dict.
    private var pathStates: [Data: Int] = [:]

    /// Mark a path as unresponsive (failed communication attempt).
    public func markPathUnresponsive(_ destinationHash: Data) {
        guard paths[destinationHash] != nil else { return }
        pathStates[destinationHash] = TransportConstants.PATH_STATE_UNRESPONSIVE
    }

    /// Reset a path to unknown state (e.g., when a new announce is accepted).
    public func markPathUnknownState(_ destinationHash: Data) {
        guard paths[destinationHash] != nil else { return }
        pathStates[destinationHash] = TransportConstants.PATH_STATE_UNKNOWN
    }

    /// Check if a path is marked unresponsive.
    public func isPathUnresponsive(_ destinationHash: Data) -> Bool {
        return pathStates[destinationHash] == TransportConstants.PATH_STATE_UNRESPONSIVE
    }

    /// Mark a path as responsive after successful communication (M10).
    /// Called after link establishment confirms the path is alive.
    public func markPathResponsive(_ destinationHash: Data) {
        guard paths[destinationHash] != nil else { return }
        pathStates[destinationHash] = TransportConstants.PATH_STATE_RESPONSIVE
    }

    // MARK: - Record (Python 5-path decision tree)

    /// Record a path entry using Python-compatible acceptance logic.
    ///
    /// Implements the 5-path decision tree from Python Transport.py:1614-1686:
    ///
    /// 1. **Unknown destination** → accept
    /// 2. **Equal/better hops + new blob + fresher timestamp** → accept
    /// 3. **Worse hops + expired path + new blob** → accept
    /// 4. **Worse hops + not expired + fresher emission + new blob** → accept
    /// 5. **Same emission + unresponsive path** → accept
    ///
    /// On accept: merges blob lists (cap at MAX_RANDOM_BLOBS), resets path state.
    ///
    /// - Parameter entry: Path entry to record
    /// - Returns: true if path was recorded, false if rejected
    /// Mark (or unmark) an interface as a low-priority fallback. See `fallbackInterfaceIds`.
    public func setFallbackInterface(_ interfaceId: String, isFallback: Bool = true) {
        if isFallback {
            fallbackInterfaceIds.insert(interfaceId)
        } else {
            fallbackInterfaceIds.remove(interfaceId)
        }
        NetworkLog.debug("[FALLBACK] register \(interfaceId) isFallback=\(isFallback) → fallbackSet=\(fallbackInterfaceIds.sorted())")
    }

    /// Update the set of interfaces whose transport link is currently `.connected`. The transport
    /// pushes this (e.g. from its periodic maintenance) so the carrier-takeover decision can tell a
    /// live-but-quiet normal interface from a genuinely dead one. See `connectedInterfaces`.
    public func setConnectedInterfaces(_ ids: Set<String>) {
        connectedInterfaces = ids
    }

    /// The fallback (carrier) interface IDs registered via `setFallbackInterface`. Used by the
    /// dual-dispatch delivery path to know which interfaces are carriers.
    public func fallbackInterfaceIdsList() -> [String] {
        Array(fallbackInterfaceIds)
    }

    /// Whether `destination`'s announce was heard on `interfaceId` within the given window — i.e.
    /// the peer is currently reachable over that specific (e.g. carrier) interface. Used to gate a
    /// dual-dispatch carrier copy so it's only sent to a peer that is actually nearby on the carrier.
    public func wasHeardOnInterface(_ destination: Data, interfaceId: String, within seconds: TimeInterval) -> Bool {
        guard let at = lastHeardByInterface[destination]?[interfaceId] else { return false }
        return Date().timeIntervalSince(at) <= seconds
    }

    /// Whether the destination's current best path already routes over a fallback (carrier)
    /// interface — in which case the normal send already used the carrier and a dual-dispatch copy
    /// would be redundant.
    public func isBestPathFallback(_ destination: Data) -> Bool {
        guard let entry = paths[destination] else { return false }
        return fallbackInterfaceIds.contains(entry.interfaceId)
    }

    /// Pin (or unpin) a destination to its fallback interface. See `fallbackPinnedDestinations`.
    public func setDestinationPinnedToFallback(_ destinationHash: Data, _ pinned: Bool) {
        if pinned {
            fallbackPinnedDestinations.insert(destinationHash)
        } else {
            fallbackPinnedDestinations.remove(destinationHash)
        }
    }

    /// Whether `destination` was heard on any NON-fallback (normal) interface within the given window
    /// — i.e. its normal path is still delivering announces and shouldn't yet yield to the carrier.
    /// Fallback interfaces are excluded, so a fast-re-announcing carrier can never mask a dead normal.
    private func normalInterfaceHeardRecently(_ destination: Data, within seconds: UInt64) -> Bool {
        guard let heard = lastHeardByInterface[destination] else { return false }
        let cutoff = Date().addingTimeInterval(-Double(seconds))
        for (interfaceId, at) in heard where !fallbackInterfaceIds.contains(interfaceId) {
            if at >= cutoff { return true }
        }
        return false
    }

    @discardableResult
    public func record(entry: PathEntry) -> Bool {
        let key = entry.destinationHash
        let keyHex = key.prefix(8).map { String(format: "%02x", $0) }.joined()
        let newBlob = entry.randomBlob
        let announceEmitted = PathEntry.emissionTimestamp(from: newBlob)

        // A destination pinned to its fallback (carrier) — e.g. a nearby peer that told us over the
        // side channel that it lost internet — rejects announces on NON-fallback interfaces. A
        // transport node may keep relaying that peer's now-dead TCP/LAN path for a while; without
        // this, each stale relay refreshes the liveness signal below and keeps the carrier from ever
        // taking over (the 90s+ takeover seen when only silence-timeout drove it). While pinned only
        // the carrier can hold the route; the embedder clears the pin when the peer signals it's back.
        if fallbackPinnedDestinations.contains(key), !fallbackInterfaceIds.contains(entry.interfaceId) {
            logger.debug("Ignored \(keyHex): dest pinned to carrier, rejecting normal \(entry.interfaceId)")
            NetworkLog.log("[FALLBACK] REJECT \(keyHex): \(entry.interfaceId) — dest PINNED to carrier (peer offline)")
            return false
        }

        // Track when we last heard this destination on each interface (local wall-clock). This is the
        // liveness signal the carrier-takeover decision uses instead of announce-emission freshness —
        // recorded before any early return so it captures every arrival, including duplicate blobs.
        lastHeardByInterface[key, default: [:]][entry.interfaceId] = Date()

        guard let existing = paths[key] else {
            // Path 1: Unknown destination → accept
            paths[key] = entry
            pathStates[key] = TransportConstants.PATH_STATE_UNKNOWN
            saveToDatabase(entry)
            let nextHopStr = entry.nextHop?.prefix(8).map { String(format: "%02x", $0) }.joined() ?? "nil"
            logger.info("Recorded NEW path to \(keyHex), hops=\(entry.hopCount), nextHop=\(nextHopStr)")
            pathUpdateContinuation?.yield(entry)
            return true
        }

        let existingBlobs = existing.randomBlobs
        let isNewBlob = !existingBlobs.contains(newBlob)
        let pathTimebase = existing.latestEmissionTimestamp

        // Fallback-interface priority, resolved by announce FRESHNESS (not hop count). A fallback
        // link (e.g. an app's BLE carrier) is direct/low-hop and would otherwise always out-rank a
        // real route on hops — but the two must be distinguished by *which announce is newer*:
        //   • Both endpoints online → the peer's latest announce reaches us over BOTH its normal
        //     interface and the fallback with the SAME emission timestamp → we keep the normal path.
        //   • Peer offline → its latest announce now arrives ONLY over the fallback (fresher than
        //     the stale normal path a transport node keeps relaying) → the fallback takes over.
        // So: the strictly-fresher announce wins; on an emission tie, the normal interface wins.
        let newIsFallback = fallbackInterfaceIds.contains(entry.interfaceId)
        let existingIsFallback = fallbackInterfaceIds.contains(existing.interfaceId)
        if newIsFallback != existingIsFallback {
            let emitDelta = Int64(bitPattern: announceEmitted) - Int64(bitPattern: pathTimebase)
            if newIsFallback {
                // Candidate = carrier, incumbent = normal. Take over only once the normal path has
                // gone SILENT — no announce on any non-fallback interface for the takeover window.
                // Liveness beats freshness: the carrier re-announces far more often than the periodic
                // normal announce, so its copies always look "fresher"; comparing emission timestamps
                // let it flip the route back and forth (the session-37 flapping). Instead we keep the
                // normal path while it's still delivering announces — tracked in lastHeardByInterface,
                // with the incumbent's own timestamp as a startup fallback before any arrival is
                // recorded — and adopt the carrier only when those announces have actually stopped.
                let window = Self.fallbackTakeoverGraceSeconds
                // Connectivity is the primary liveness signal: while the incumbent normal interface's
                // socket is still connected, the peer is reachable over it, so the carrier stays on
                // standby — no matter how sparsely the peer's relay-forwarded announces arrive versus
                // the carrier's direct re-announce (the false takeover of a live TCP route, session-4).
                // Excluded when the destination is PINNED: a peer that signalled it lost internet must
                // still yield to the carrier even though our socket to the relay is up.
                //
                // NOTE (session-13): keying on any-connected-normal-interface was too aggressive — for a
                // peer on 5G behind carrier NAT the multi-hop TCP path resolves but never DELIVERS, and
                // keeping TCP then blocks the carrier (the only working path). The right signal is
                // delivery success, not connectivity; that is being handled via the delivery-failure
                // demotion path, not by widening this check.
                // DELIVERY-AWARE: if LXMF has marked this path unresponsive (repeated delivery
                // failures — e.g. a peer on 5G whose multi-hop TCP path resolves but never delivers),
                // stop keeping TCP and let the carrier take over, no matter the interface connectivity
                // or announce recency. This is the real "should we fall to the carrier" signal —
                // delivery success, not connectivity. It also un-blocks the demotion failover
                // (LXMRouter.markPathUnresponsive → Path 5 below), which this branch otherwise
                // short-circuits by returning false before Path 5 can run (session-13: message stuck
                // onroute on a live-but-undelivering TCP path while the working carrier was rejected).
                let pathResponsive = !isPathUnresponsive(key)
                let incumbentNormalConnected = !fallbackPinnedDestinations.contains(key)
                    && connectedInterfaces.contains(existing.interfaceId)
                // Announce-recency remains a backstop for when the incumbent interface is gone from the
                // connected set (e.g. we lost internet) but a normal announce is still fresh; the
                // startup-timestamp term covers the window before any arrival is recorded.
                let normalLive = pathResponsive && (
                    incumbentNormalConnected
                    || normalInterfaceHeardRecently(key, within: window)
                    || Date().timeIntervalSince(existing.timestamp) < Double(window))
                if normalLive {
                    let reason = incumbentNormalConnected ? "interface connected" : "heard < \(window)s ago"
                    logger.debug("Ignored \(keyHex): normal \(existing.interfaceId) still live; carrier \(entry.interfaceId) stands by")
                    NetworkLog.log("[FALLBACK] REJECT \(keyHex): normal \(existing.interfaceId) \(reason) "
                        + "(alive) → keep TCP, carrier \(entry.interfaceId) stands by")
                    return false
                }
                // Reaching here: the normal path is not "live" — either silent past the window, or
                // marked unresponsive by delivery failures. Distinguish for the log.
                let takeoverReason = pathResponsive ? "SILENT > \(window)s" : "UNRESPONSIVE (delivery failing)"
                // Normal path is silent past the window or unresponsive → adopt the carrier.
                NetworkLog.log("[FALLBACK] ACCEPT \(keyHex): normal \(existing.interfaceId) \(takeoverReason) "
                    + "→ carrier \(entry.interfaceId) takes over")
            } else {
                // Candidate = normal, incumbent = fallback (carrier). Reaching here means the dest is
                // NOT pinned (a pinned dest's normal announces are rejected at the top of record), i.e.
                // the peer is considered ONLINE — so TCP reclaims the route from the carrier
                // IMMEDIATELY, on the first normal announce, regardless of emission freshness or
                // whether this exact announce already arrived over the carrier first.
                //
                // Why unconditional: the two links carry the SAME peer's announces, and the direct
                // carrier (1 hop, physically adjacent) beats the relayed normal copy to every one — so
                // any freshness/emitΔ gate lets the carrier hold the route indefinitely once it wins.
                // Session-3 saw a ~140s BLE→TCP return for exactly this reason. The authoritative
                // holds are elsewhere: the PIN keeps the carrier while the peer is offline, and the
                // 75s liveness window (takeover branch above) stops a flap back to carrier once TCP is
                // in. So an unconditional promote here is both safe and the point of a "fallback".
                NetworkLog.log("[FALLBACK] PROMOTE \(keyHex): normal \(entry.interfaceId) replaces "
                    + "fallback \(existing.interfaceId) (emitΔ=\(emitDelta)s, unpinned → TCP wins) → back to TCP")
                markPathUnknownState(key)
                var updated = entry
                updated.randomBlobs = mergeBlobs(existing: existingBlobs, new: newBlob)
                updated.pathState = TransportConstants.PATH_STATE_UNKNOWN
                paths[key] = updated
                saveToDatabase(updated)
                logger.info("Promoted \(keyHex): \(entry.interfaceId) (hops \(entry.hopCount)) replaces fallback \(existing.interfaceId)")
                pathUpdateContinuation?.yield(updated)
                return true
            }
        }

        if entry.hopCount <= existing.hopCount {
            // Path 2: Equal or better hops + new blob + fresher timestamp
            if isNewBlob && announceEmitted > pathTimebase {
                markPathUnknownState(key)
                let merged = mergeBlobs(existing: existingBlobs, new: newBlob)
                var updated = entry
                updated.randomBlobs = merged
                updated.pathState = TransportConstants.PATH_STATE_UNKNOWN
                paths[key] = updated
                saveToDatabase(updated)
                logger.info("Updated \(keyHex): equal/better hops (\(entry.hopCount) <= \(existing.hopCount)), fresh emit")
                if newIsFallback || existingIsFallback {
                    NetworkLog.debug("[RECORD] ACCEPT \(keyHex): \(entry.interfaceId) equal/better hops (\(entry.hopCount)<=\(existing.hopCount)) + fresh emit")
                }
                pathUpdateContinuation?.yield(updated)
                return true
            }
            // Path 2b: a STRICTLY shorter-hops copy of an announce we already hold (same
            // blob). This is the same announce reaching us by a better route — e.g. the
            // direct (1-hop) copy arriving after a relayed multi-hop copy already won the
            // arrival race. Adopt the shorter path so we don't keep the worse (often
            // dead-next-hop) route and flicker the destination in and out of reachability.
            // Keep the existing blobs/timebase since the announce identity is unchanged.
            if entry.hopCount < existing.hopCount {
                markPathUnknownState(key)
                var updated = entry
                updated.randomBlobs = existingBlobs
                updated.pathState = TransportConstants.PATH_STATE_UNKNOWN
                paths[key] = updated
                saveToDatabase(updated)
                logger.info("Upgraded \(keyHex): shorter path \(entry.hopCount) < \(existing.hopCount) for the same announce")
                if newIsFallback || existingIsFallback {
                    NetworkLog.debug("[RECORD] ACCEPT \(keyHex): \(entry.interfaceId) shorter path (\(entry.hopCount)<\(existing.hopCount)) same announce")
                }
                pathUpdateContinuation?.yield(updated)
                return true
            }
            logger.debug("Ignored \(keyHex): equal/better hops but duplicate blob or stale emit")
            if newIsFallback || existingIsFallback {
                NetworkLog.debug("[RECORD] IGNORE \(keyHex): \(entry.interfaceId) vs \(existing.interfaceId) — equal/better hops but DUPLICATE blob or stale emit")
            }
            return false
        }

        // Worse hops (entry.hopCount > existing.hopCount)
        let now = Date()

        // Path 3: Expired path + new blob
        if now >= existing.expires {
            if isNewBlob {
                markPathUnknownState(key)
                let merged = mergeBlobs(existing: existingBlobs, new: newBlob)
                var updated = entry
                updated.randomBlobs = merged
                updated.pathState = TransportConstants.PATH_STATE_UNKNOWN
                paths[key] = updated
                saveToDatabase(updated)
                logger.info("Updated \(keyHex): expired path replaced, hops=\(entry.hopCount)")
                if newIsFallback || existingIsFallback {
                    NetworkLog.debug("[RECORD] ACCEPT \(keyHex): \(entry.interfaceId) replaced EXPIRED path hops=\(entry.hopCount)")
                }
                pathUpdateContinuation?.yield(updated)
                return true
            }
            logger.debug("Ignored \(keyHex): expired path but duplicate blob")
            if newIsFallback || existingIsFallback {
                NetworkLog.debug("[RECORD] IGNORE \(keyHex): \(entry.interfaceId) vs \(existing.interfaceId) — expired path but DUPLICATE blob")
            }
            return false
        }

        // Path 4: Not expired + fresher emission + new blob
        if announceEmitted > pathTimebase {
            if isNewBlob {
                markPathUnknownState(key)
                let merged = mergeBlobs(existing: existingBlobs, new: newBlob)
                var updated = entry
                updated.randomBlobs = merged
                updated.pathState = TransportConstants.PATH_STATE_UNKNOWN
                paths[key] = updated
                saveToDatabase(updated)
                logger.info("Updated \(keyHex): fresher emission with worse hops (\(entry.hopCount) > \(existing.hopCount))")
                if newIsFallback || existingIsFallback {
                    NetworkLog.debug("[RECORD] ACCEPT \(keyHex): \(entry.interfaceId) fresher emission, worse hops (\(entry.hopCount)>\(existing.hopCount))")
                }
                pathUpdateContinuation?.yield(updated)
                return true
            }
            logger.debug("Ignored \(keyHex): fresher emission but duplicate blob")
            if newIsFallback || existingIsFallback {
                NetworkLog.debug("[RECORD] IGNORE \(keyHex): \(entry.interfaceId) vs \(existing.interfaceId) — fresher emission but DUPLICATE blob")
            }
            return false
        }

        // Path 5: Same emission + unresponsive path
        if announceEmitted == pathTimebase && isPathUnresponsive(key) {
            var updated = entry
            updated.randomBlobs = mergeBlobs(existing: existingBlobs, new: newBlob)
            updated.pathState = TransportConstants.PATH_STATE_UNKNOWN
            paths[key] = updated
            pathStates[key] = TransportConstants.PATH_STATE_UNKNOWN
            saveToDatabase(updated)
            logger.info("Updated \(keyHex): same emission but path was unresponsive")
            if newIsFallback || existingIsFallback {
                NetworkLog.debug("[RECORD] ACCEPT \(keyHex): \(entry.interfaceId) same emission, prior path unresponsive")
            }
            pathUpdateContinuation?.yield(updated)
            return true
        }

        logger.debug("Ignored \(keyHex): worse hops, not expired, not fresher, not unresponsive")
        if newIsFallback || existingIsFallback {
            NetworkLog.debug("[RECORD] IGNORE \(keyHex): \(entry.interfaceId) vs \(existing.interfaceId) — worse hops, not expired/fresher/unresponsive")
        }
        return false
    }

    /// Merge a new blob into existing blobs list, capped at MAX_RANDOM_BLOBS.
    private func mergeBlobs(existing: [Data], new: Data) -> [Data] {
        var merged = existing
        if !merged.contains(new) {
            merged.append(new)
        }
        // Keep only the most recent MAX_RANDOM_BLOBS
        if merged.count > TransportConstants.MAX_RANDOM_BLOBS {
            merged = Array(merged.suffix(TransportConstants.MAX_RANDOM_BLOBS))
        }
        return merged
    }

    // MARK: - Database Migration

    /// Migrate old random_blob BLOB column to random_blobs TEXT (JSON-encoded).
    private func migrateRandomBlobColumn() {
        guard let db = db else { return }

        // Check if old column exists by querying table info
        var hasOldColumn = false
        var hasNewColumn = false
        var infoStmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "PRAGMA table_info(paths)", -1, &infoStmt, nil) == SQLITE_OK {
            while sqlite3_step(infoStmt) == SQLITE_ROW {
                if let namePtr = sqlite3_column_text(infoStmt, 1) {
                    let name = String(cString: namePtr)
                    if name == "random_blob" { hasOldColumn = true }
                    if name == "random_blobs" { hasNewColumn = true }
                }
            }
            sqlite3_finalize(infoStmt)
        }

        guard hasOldColumn && !hasNewColumn else { return }

        // Old schema detected: add new column, migrate data, then recreate table
        logger.info("Migrating random_blob to random_blobs")

        // Read old data
        struct OldRow {
            var destHash: Data; var pubKeys: Data; var interfaceId: String
            var hopCount: Int32; var timestamp: Double; var expires: Double
            var randomBlob: Data; var ratchet: Data?; var appData: Data?; var nextHop: Data?
        }
        var oldRows: [OldRow] = []
        var selectStmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT destination_hash, public_keys, interface_id, hop_count, timestamp, expires, random_blob, ratchet, app_data, next_hop FROM paths", -1, &selectStmt, nil) == SQLITE_OK {
            while sqlite3_step(selectStmt) == SQLITE_ROW {
                guard let dhPtr = sqlite3_column_blob(selectStmt, 0) else { continue }
                let dh = Data(bytes: dhPtr, count: Int(sqlite3_column_bytes(selectStmt, 0)))
                guard let pkPtr = sqlite3_column_blob(selectStmt, 1) else { continue }
                let pk = Data(bytes: pkPtr, count: Int(sqlite3_column_bytes(selectStmt, 1)))
                guard let iiCStr = sqlite3_column_text(selectStmt, 2) else { continue }
                let ii = String(cString: iiCStr)
                let hc = sqlite3_column_int(selectStmt, 3)
                let ts = sqlite3_column_double(selectStmt, 4)
                let ex = sqlite3_column_double(selectStmt, 5)
                guard let rbPtr = sqlite3_column_blob(selectStmt, 6) else { continue }
                let rb = Data(bytes: rbPtr, count: Int(sqlite3_column_bytes(selectStmt, 6)))
                var ra: Data? = nil
                if let raPtr = sqlite3_column_blob(selectStmt, 7) {
                    ra = Data(bytes: raPtr, count: Int(sqlite3_column_bytes(selectStmt, 7)))
                }
                var ad: Data? = nil
                if let adPtr = sqlite3_column_blob(selectStmt, 8) {
                    ad = Data(bytes: adPtr, count: Int(sqlite3_column_bytes(selectStmt, 8)))
                }
                var nh: Data? = nil
                if let nhPtr = sqlite3_column_blob(selectStmt, 9) {
                    nh = Data(bytes: nhPtr, count: Int(sqlite3_column_bytes(selectStmt, 9)))
                }
                oldRows.append(OldRow(destHash: dh, pubKeys: pk, interfaceId: ii, hopCount: hc, timestamp: ts, expires: ex, randomBlob: rb, ratchet: ra, appData: ad, nextHop: nh))
            }
            sqlite3_finalize(selectStmt)
        }

        // Drop and recreate with new schema
        sqlite3_exec(db, "DROP TABLE paths", nil, nil, nil)
        let createSQL = """
            CREATE TABLE paths (
                destination_hash BLOB PRIMARY KEY,
                public_keys BLOB NOT NULL,
                interface_id TEXT NOT NULL,
                hop_count INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                expires REAL NOT NULL,
                random_blobs TEXT NOT NULL,
                ratchet BLOB,
                app_data BLOB,
                next_hop BLOB
            )
            """
        sqlite3_exec(db, createSQL, nil, nil, nil)

        // Re-insert with wrapped blobs
        for row in oldRows {
            _ = Self.encodeRandomBlobs([row.randomBlob])
            let entry = PathEntry(
                destinationHash: row.destHash,
                publicKeys: row.pubKeys,
                interfaceId: row.interfaceId,
                hopCount: UInt8(row.hopCount),
                timestamp: Date(timeIntervalSince1970: row.timestamp),
                expires: Date(timeIntervalSince1970: row.expires),
                randomBlob: row.randomBlob,
                ratchet: row.ratchet,
                appData: row.appData,
                nextHop: row.nextHop
            )
            saveToDatabase(entry)
        }
        logger.info("Migration complete, \(oldRows.count) rows migrated")
    }

    /// Add announce_data column if it doesn't exist (migration for existing databases).
    private func migrateAnnounceDataColumn() {
        guard let db = db else { return }

        var hasColumn = false
        var infoStmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "PRAGMA table_info(paths)", -1, &infoStmt, nil) == SQLITE_OK {
            while sqlite3_step(infoStmt) == SQLITE_ROW {
                if let namePtr = sqlite3_column_text(infoStmt, 1) {
                    if String(cString: namePtr) == "announce_data" { hasColumn = true }
                }
            }
            sqlite3_finalize(infoStmt)
        }

        guard !hasColumn else { return }
        logger.info("Migrating: adding announce_data column")
        sqlite3_exec(db, "ALTER TABLE paths ADD COLUMN announce_data BLOB", nil, nil, nil)
    }

    // MARK: - Database Persistence

    /// Encode random blobs array as JSON string for storage.
    private static func encodeRandomBlobs(_ blobs: [Data]) -> String {
        let hexArray = blobs.map { $0.map { String(format: "%02x", $0) }.joined() }
        guard let jsonData = try? JSONSerialization.data(withJSONObject: hexArray),
              let jsonString = String(data: jsonData, encoding: .utf8) else {
            return "[]"
        }
        return jsonString
    }

    /// Decode random blobs array from JSON string.
    private static func decodeRandomBlobs(_ json: String) -> [Data] {
        guard let jsonData = json.data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: jsonData) as? [String] else {
            return []
        }
        return array.compactMap { hex in
            var data = Data()
            var index = hex.startIndex
            while index < hex.endIndex {
                let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
                if let byte = UInt8(hex[index..<nextIndex], radix: 16) {
                    data.append(byte)
                }
                index = nextIndex
            }
            return data.isEmpty ? nil : data
        }
    }

    /// Load all paths from database into memory cache.
    private func loadFromDatabase() {
        guard let db = db else { return }

        let selectSQL = "SELECT destination_hash, public_keys, interface_id, hop_count, timestamp, expires, random_blobs, ratchet, app_data, next_hop, announce_data FROM paths"
        var stmt: OpaquePointer?

        guard sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nil) == SQLITE_OK else {
            logger.error("Failed to prepare select statement")
            return
        }
        defer { sqlite3_finalize(stmt) }

        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let destHashPtr = sqlite3_column_blob(stmt, 0) else { continue }
            let destHashLen = sqlite3_column_bytes(stmt, 0)
            let destinationHash = Data(bytes: destHashPtr, count: Int(destHashLen))

            guard let pubKeysPtr = sqlite3_column_blob(stmt, 1) else { continue }
            let pubKeysLen = sqlite3_column_bytes(stmt, 1)
            let publicKeys = Data(bytes: pubKeysPtr, count: Int(pubKeysLen))

            guard let interfaceIdCStr = sqlite3_column_text(stmt, 2) else { continue }
            let interfaceId = String(cString: interfaceIdCStr)

            let hopCount = UInt8(sqlite3_column_int(stmt, 3))
            let timestamp = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
            let expires = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 5))

            // random_blobs is JSON text
            guard let blobsTextPtr = sqlite3_column_text(stmt, 6) else { continue }
            let blobsJson = String(cString: blobsTextPtr)
            let randomBlobs = Self.decodeRandomBlobs(blobsJson)

            var ratchet: Data? = nil
            if let ratchetPtr = sqlite3_column_blob(stmt, 7) {
                let ratchetLen = sqlite3_column_bytes(stmt, 7)
                ratchet = Data(bytes: ratchetPtr, count: Int(ratchetLen))
            }

            var appData: Data? = nil
            if let appDataPtr = sqlite3_column_blob(stmt, 8) {
                let appDataLen = sqlite3_column_bytes(stmt, 8)
                appData = Data(bytes: appDataPtr, count: Int(appDataLen))
            }

            var nextHop: Data? = nil
            if let nextHopPtr = sqlite3_column_blob(stmt, 9) {
                let nextHopLen = sqlite3_column_bytes(stmt, 9)
                nextHop = Data(bytes: nextHopPtr, count: Int(nextHopLen))
            }

            var announceData: Data? = nil
            if let announceDataPtr = sqlite3_column_blob(stmt, 10) {
                let announceDataLen = sqlite3_column_bytes(stmt, 10)
                announceData = Data(bytes: announceDataPtr, count: Int(announceDataLen))
            }

            let firstBlob = randomBlobs.first ?? Data()
            let entry = PathEntry(
                destinationHash: destinationHash,
                publicKeys: publicKeys,
                interfaceId: interfaceId,
                hopCount: hopCount,
                timestamp: timestamp,
                expires: expires,
                randomBlob: firstBlob,
                randomBlobs: randomBlobs,
                ratchet: ratchet,
                appData: appData,
                nextHop: nextHop,
                announceData: announceData
            )

            // Only load non-expired entries
            if !entry.isExpired {
                paths[destinationHash] = entry
            }
        }
    }

    /// Save a path entry to the database.
    private func saveToDatabase(_ entry: PathEntry) {
        guard let db = db else { return }

        let upsertSQL = """
            INSERT OR REPLACE INTO paths (destination_hash, public_keys, interface_id, hop_count, timestamp, expires, random_blobs, ratchet, app_data, next_hop, announce_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
        var stmt: OpaquePointer?

        guard sqlite3_prepare_v2(db, upsertSQL, -1, &stmt, nil) == SQLITE_OK else {
            logger.error("Failed to prepare insert statement")
            return
        }
        defer { sqlite3_finalize(stmt) }

        _ = entry.destinationHash.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, 1, ptr.baseAddress, Int32(entry.destinationHash.count), nil)
        }
        _ = entry.publicKeys.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, 2, ptr.baseAddress, Int32(entry.publicKeys.count), nil)
        }
        sqlite3_bind_text(stmt, 3, entry.interfaceId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int(stmt, 4, Int32(entry.hopCount))
        sqlite3_bind_double(stmt, 5, entry.timestamp.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 6, entry.expires.timeIntervalSince1970)

        // random_blobs as JSON text
        let blobsJson = Self.encodeRandomBlobs(entry.randomBlobs)
        sqlite3_bind_text(stmt, 7, blobsJson, -1, SQLITE_TRANSIENT)

        if let ratchet = entry.ratchet {
            _ = ratchet.withUnsafeBytes { ptr in
                sqlite3_bind_blob(stmt, 8, ptr.baseAddress, Int32(ratchet.count), nil)
            }
        } else {
            sqlite3_bind_null(stmt, 8)
        }

        if let appData = entry.appData {
            _ = appData.withUnsafeBytes { ptr in
                sqlite3_bind_blob(stmt, 9, ptr.baseAddress, Int32(appData.count), nil)
            }
        } else {
            sqlite3_bind_null(stmt, 9)
        }

        if let nextHop = entry.nextHop {
            _ = nextHop.withUnsafeBytes { ptr in
                sqlite3_bind_blob(stmt, 10, ptr.baseAddress, Int32(nextHop.count), nil)
            }
        } else {
            sqlite3_bind_null(stmt, 10)
        }

        if let announceData = entry.announceData {
            _ = announceData.withUnsafeBytes { ptr in
                sqlite3_bind_blob(stmt, 11, ptr.baseAddress, Int32(announceData.count), nil)
            }
        } else {
            sqlite3_bind_null(stmt, 11)
        }

        if sqlite3_step(stmt) != SQLITE_DONE {
            logger.error("Failed to save path: \(String(cString: sqlite3_errmsg(db)))")
        }
    }

    /// Remove a path from the database.
    private func removeFromDatabase(_ destinationHash: Data) {
        guard let db = db else { return }

        let deleteSQL = "DELETE FROM paths WHERE destination_hash = ?"
        var stmt: OpaquePointer?

        guard sqlite3_prepare_v2(db, deleteSQL, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        _ = destinationHash.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, 1, ptr.baseAddress, Int32(destinationHash.count), nil)
        }

        _ = sqlite3_step(stmt)
    }

    /// Record a path from announce parameters.
    ///
    /// Convenience method for recording directly from announce data.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - publicKeys: 64-byte concatenated public keys
    ///   - randomBlob: 10-byte random blob from announce
    ///   - interfaceId: Interface identifier where path was learned
    ///   - hopCount: Number of hops to destination
    ///   - expiration: Time interval until expiration (defaults to 7 days)
    ///   - ratchet: Optional 32-byte ratchet public key for forward secrecy
    ///   - appData: Optional application data from announce
    ///   - nextHop: Optional 16-byte next hop transport node hash for routing
    ///   - announceData: Optional cached raw announce payload for path responses
    /// - Returns: true if path was recorded, false if ignored
    @discardableResult
    public func record(
        destinationHash: Data,
        publicKeys: Data,
        randomBlob: Data,
        interfaceId: String,
        hopCount: UInt8,
        expiration: TimeInterval = PathEntry.standardExpiration,
        ratchet: Data? = nil,
        appData: Data? = nil,
        nextHop: Data? = nil,
        announceData: Data? = nil
    ) -> Bool {
        let entry = PathEntry(
            destinationHash: destinationHash,
            publicKeys: publicKeys,
            interfaceId: interfaceId,
            hopCount: hopCount,
            expiration: expiration,
            randomBlob: randomBlob,
            ratchet: ratchet,
            appData: appData,
            nextHop: nextHop,
            announceData: announceData
        )
        return record(entry: entry)
    }

    // MARK: - Lookup

    /// Look up a path for a destination.
    ///
    /// Returns the path entry if found and not expired.
    /// Returns nil if not found or expired.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: Path entry if found and valid, nil otherwise
    public func lookup(destinationHash: Data) -> PathEntry? {
        guard let entry = paths[destinationHash] else {
            return nil
        }

        // Don't return expired entries
        if entry.isExpired {
            return nil
        }

        return entry
    }

    /// Look up a path, throwing on not found or expired.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: Path entry
    /// - Throws: `PathTableError.pathNotFound` or `PathTableError.pathExpired`
    public func lookupOrThrow(destinationHash: Data) throws -> PathEntry {
        guard let entry = paths[destinationHash] else {
            throw PathTableError.pathNotFound
        }

        if entry.isExpired {
            throw PathTableError.pathExpired
        }

        return entry
    }

    // MARK: - Touch

    /// Update the timestamp of an existing path entry (e.g., after transport forwarding).
    /// Also extends the expiration time (M7).
    /// Python reference: Transport.py line 1504
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    public func touch(destinationHash: Data) {
        guard let entry = paths[destinationHash] else { return }
        // M7: Refresh both timestamp and expiration
        let newExpires = Date().addingTimeInterval(PathEntry.standardExpiration)
        let touched = PathEntry(
            destinationHash: entry.destinationHash,
            publicKeys: entry.publicKeys,
            interfaceId: entry.interfaceId,
            hopCount: entry.hopCount,
            timestamp: Date(),
            expires: newExpires,
            randomBlob: entry.randomBlob,
            randomBlobs: entry.randomBlobs,
            pathState: entry.pathState,
            ratchet: entry.ratchet,
            appData: entry.appData,
            nextHop: entry.nextHop,
            announceData: entry.announceData
        )
        paths[destinationHash] = touched
        saveToDatabase(touched)
    }

    /// M6: Force-expire a path to trigger rediscovery.
    /// Called when a link to a non-transport destination is closed.
    /// Python reference: Transport.py:699
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    public func expirePath(destinationHash: Data) {
        guard let entry = paths[destinationHash] else { return }
        let expired = PathEntry(
            destinationHash: entry.destinationHash,
            publicKeys: entry.publicKeys,
            interfaceId: entry.interfaceId,
            hopCount: entry.hopCount,
            timestamp: entry.timestamp,
            expires: Date(timeIntervalSince1970: 0),
            randomBlob: entry.randomBlob,
            randomBlobs: entry.randomBlobs,
            pathState: entry.pathState,
            ratchet: entry.ratchet,
            appData: entry.appData,
            nextHop: entry.nextHop,
            announceData: entry.announceData
        )
        paths[destinationHash] = expired
        saveToDatabase(expired)
    }

    // MARK: - Removal

    /// Remove a path from the table.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    public func remove(destinationHash: Data) {
        paths.removeValue(forKey: destinationHash)
        lastHeardByInterface.removeValue(forKey: destinationHash)
        removeFromDatabase(destinationHash)
    }

    /// Atomically remove a path only if it currently references the given
    /// interface id. Use when invalidating a stale entry whose interface is
    /// missing: if a fresh announce for the same destination has replaced the
    /// entry with a different interface id, this call becomes a no-op so the
    /// freshly-learned path is preserved.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - interfaceId: the interface id the stale entry was expected to reference
    /// - Returns: true if the entry was removed, false if it was preserved or absent
    @discardableResult
    public func remove(destinationHash: Data, ifInterface interfaceId: String) -> Bool {
        guard let current = paths[destinationHash], current.interfaceId == interfaceId else {
            return false
        }
        paths.removeValue(forKey: destinationHash)
        lastHeardByInterface.removeValue(forKey: destinationHash)
        removeFromDatabase(destinationHash)
        return true
    }

    /// Remove all paths from the table and database.
    public func removeAll() {
        paths.removeAll()
        lastHeardByInterface.removeAll()
        clearDatabase()
    }

    /// Clear all paths from the database.
    private func clearDatabase() {
        guard let db = db else { return }
        sqlite3_exec(db, "DELETE FROM paths", nil, nil, nil)
    }

    // MARK: - Cleanup

    /// Remove expired entries and paths for dead interfaces from memory and database.
    ///
    /// - Parameter activeInterfaceIds: Optional set of currently-active interface IDs.
    ///   If provided, paths referencing interfaces not in this set are also removed (H4).
    /// - Returns: Number of entries removed
    @discardableResult
    public func cleanup(activeInterfaceIds: Set<String>? = nil) -> Int {
        let beforeCount = paths.count

        // Remove expired entries
        let expiredKeys = paths.filter { $0.value.isExpired }.map { $0.key }
        for key in expiredKeys {
            paths.removeValue(forKey: key)
            pathStates.removeValue(forKey: key)
            lastHeardByInterface.removeValue(forKey: key)
            removeFromDatabase(key)
        }

        // H4: Remove paths for dead interfaces
        if let activeIds = activeInterfaceIds {
            let deadKeys = paths.filter {
                !$0.value.interfaceId.isEmpty && !activeIds.contains($0.value.interfaceId)
            }.map { $0.key }
            for key in deadKeys {
                paths.removeValue(forKey: key)
                pathStates.removeValue(forKey: key)
                lastHeardByInterface.removeValue(forKey: key)
                removeFromDatabase(key)
            }
        }

        return beforeCount - paths.count
    }

    // MARK: - Properties

    /// Number of valid (non-expired) paths in the table.
    public var count: Int {
        paths.values.filter { !$0.isExpired }.count
    }

    /// Total number of entries including expired ones.
    ///
    /// Expired entries are lazily removed by cleanup() or filtered by lookup().
    public var totalCount: Int {
        paths.count
    }

    /// All destination hashes with valid paths.
    public var destinations: [Data] {
        paths.filter { !$0.value.isExpired }.map { $0.key }
    }

    /// Check if a path exists for a destination (and is not expired).
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: true if valid path exists
    public func hasPath(for destinationHash: Data) -> Bool {
        guard let entry = paths[destinationHash] else {
            return false
        }
        return !entry.isExpired
    }
}

// MARK: - Debug Support

extension PathTable {
    /// Get all entries for debugging (includes expired).
    ///
    /// Not for production use.
    public func allEntries() -> [PathEntry] {
        Array(paths.values)
    }
}
