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
//  Multi-path deviation from Python RNS: paths are stored per
//  (destination, interface) pair instead of one entry per destination, so a
//  destination reachable over both a direct interface (BLE/MPC) and an
//  infrastructure interface (TCP) keeps both routes. Wire behavior is
//  unchanged; only local route selection differs. See port-deviations.md.
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
/// Entries are kept per (destination, interface) pair so multiple concurrent
/// routes to the same destination (e.g. BLE mesh and TCP relay) coexist.
///
/// Key operations:
/// - **record()**: Store a path from a validated announce
/// - **lookup()**: Find the best path for a destination hash
/// - **lookupAll()**: All valid paths for a destination (one per interface)
/// - **removeAll(forInterface:)**: Drop every path learned on an interface
/// - **cleanup()**: Remove expired entries
/// - **pathUpdates**: AsyncStream for real-time path notifications
///
/// Thread safety is ensured via actor isolation.
/// When initialized with a database path, paths persist across app launches.
public actor PathTable {

    // MARK: - Storage

    /// Schema version for the persisted paths table (PRAGMA user_version).
    /// Version 2 introduced the composite (destination_hash, interface_id)
    /// primary key for multi-path storage.
    private static let schemaVersion: Int32 = 2

    /// Paths indexed by destination hash, then by interface id (in-memory cache)
    private var paths: [Data: [String: PathEntry]] = [:]

    /// Maximum number of distinct destinations retained in the in-memory path table.
    ///
    /// Announces are cheap to generate, so without a cap an attacker could install
    /// an unbounded number of long-lived (up to 7-day) routes, exhausting memory.
    /// When exceeded, expired destinations are dropped first, then the
    /// soonest-to-expire ones.
    private let maxDestinations = 8192

    /// SQLite database handle for persistence
    private var db: OpaquePointer?

    /// Path to database file (nil for in-memory only)
    private let databasePath: String?

    // MARK: - Event Stream

    /// Continuation for emitting path updates
    private var pathUpdateContinuation: AsyncStream<PathEntry>.Continuation?

    /// Stream of path updates for real-time UI notifications.
    /// Emits whenever a new path is recorded (not duplicates or worse paths).
    /// With multi-path storage, entries are per (destination, interface) —
    /// consumers may see one event per interface for the same destination.
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

            // Create table (v2 schema with composite primary key).
            // Pre-v2 databases are rebuilt by migrateToMultiPathSchema below.
            if sqlite3_exec(db, Self.createTableSQL, nil, nil, nil) != SQLITE_OK {
                let error = String(cString: sqlite3_errmsg(db))
                throw PathTableError.databaseError("Failed to create table: \(error)")
            }

            // Migrate and load in a Task to satisfy actor isolation
            Task { [self] in
                await migrateRandomBlobColumn()
                await migrateAnnounceDataColumn()
                await migrateToMultiPathSchema()
                await loadFromDatabase()
                let pathCount = await self.entryCount
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

    /// v2 schema: one row per (destination, interface) pair.
    private static let createTableSQL = """
        CREATE TABLE IF NOT EXISTS paths (
            destination_hash BLOB NOT NULL,
            public_keys BLOB NOT NULL,
            interface_id TEXT NOT NULL,
            hop_count INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            expires REAL NOT NULL,
            random_blobs TEXT NOT NULL,
            ratchet BLOB,
            app_data BLOB,
            next_hop BLOB,
            announce_data BLOB,
            PRIMARY KEY (destination_hash, interface_id)
        )
        """

    // MARK: - Path State Management

    /// Path states indexed by destination hash.
    /// Separate from PathEntry to match Python's Transport.path_states dict.
    /// Kept per destination (not per interface) to match Python semantics.
    private var pathStates: [Data: Int] = [:]

    /// Mark a path as unresponsive (failed communication attempt).
    public func markPathUnresponsive(_ destinationHash: Data) {
        guard paths[destinationHash]?.isEmpty == false else { return }
        pathStates[destinationHash] = TransportConstants.PATH_STATE_UNRESPONSIVE
    }

    /// Reset a path to unknown state (e.g., when a new announce is accepted).
    public func markPathUnknownState(_ destinationHash: Data) {
        guard paths[destinationHash]?.isEmpty == false else { return }
        pathStates[destinationHash] = TransportConstants.PATH_STATE_UNKNOWN
    }

    /// Check if a path is marked unresponsive.
    public func isPathUnresponsive(_ destinationHash: Data) -> Bool {
        return pathStates[destinationHash] == TransportConstants.PATH_STATE_UNRESPONSIVE
    }

    /// Mark a path as responsive after successful communication (M10).
    /// Called after link establishment confirms the path is alive.
    public func markPathResponsive(_ destinationHash: Data) {
        guard paths[destinationHash]?.isEmpty == false else { return }
        pathStates[destinationHash] = TransportConstants.PATH_STATE_RESPONSIVE
    }

    // MARK: - Record (Python 5-path decision tree, per interface)

    /// Record a path entry using Python-compatible acceptance logic.
    ///
    /// Implements the 5-path decision tree from Python Transport.py:1614-1686,
    /// applied per (destination, interface) bucket, plus one multi-path rule:
    ///
    /// 1. **Unknown destination** → accept
    /// 1b. **Known destination, first path on this interface** → accept iff the
    ///     announce emission timestamp is >= the destination's timebase (the
    ///     latest emission seen on any interface). ">=" so the *same* announce
    ///     heard moments later on a second interface is accepted, while a
    ///     replayed old capture on a new medium is rejected.
    /// 2. **Equal/better hops + new blob + fresher timestamp** → accept
    /// 3. **Worse hops + expired path + new blob** → accept
    /// 4. **Worse hops + not expired + fresher emission + new blob** → accept
    /// 5. **Same emission + unresponsive path** → accept
    ///
    /// On accept: merges blob lists (cap at MAX_RANDOM_BLOBS), resets path state.
    ///
    /// - Parameter entry: Path entry to record
    /// - Returns: true if path was recorded, false if rejected
    @discardableResult
    public func record(entry: PathEntry) -> Bool {
        let key = entry.destinationHash
        let keyHex = key.prefix(8).map { String(format: "%02x", $0) }.joined()
        let newBlob = entry.randomBlob
        let announceEmitted = PathEntry.emissionTimestamp(from: newBlob)
        let bucket = paths[key] ?? [:]

        guard let existing = bucket[entry.interfaceId] else {
            if bucket.isEmpty {
                // Path 1: Unknown destination → accept (bounding total destinations first)
                evictDestinationsForCapacityIfNeeded()
                paths[key] = [entry.interfaceId: entry]
                pathStates[key] = TransportConstants.PATH_STATE_UNKNOWN
                saveToDatabase(entry)
                let nextHopStr = entry.nextHop?.prefix(8).map { String(format: "%02x", $0) }.joined() ?? "nil"
                logger.info("Recorded NEW path to \(keyHex) via \(entry.interfaceId, privacy: .public), hops=\(entry.hopCount), nextHop=\(nextHopStr)")
                pathUpdateContinuation?.yield(entry)
                return true
            }

            // Path 1b: Known destination, first path on this interface.
            // Accept only if the announce is at least as fresh as anything we
            // have seen on other interfaces — blocks replayed old announces
            // from hijacking the route via a new medium.
            let destinationTimebase = bucket.values.map { $0.latestEmissionTimestamp }.max() ?? 0
            if announceEmitted >= destinationTimebase {
                var stored = bucket
                stored[entry.interfaceId] = entry
                paths[key] = stored
                markPathUnknownState(key)
                saveToDatabase(entry)
                logger.info("Recorded ADDITIONAL path to \(keyHex) via \(entry.interfaceId, privacy: .public), hops=\(entry.hopCount)")
                pathUpdateContinuation?.yield(entry)
                return true
            }
            logger.debug("Ignored \(keyHex) on \(entry.interfaceId, privacy: .public): emission older than destination timebase")
            return false
        }

        let existingBlobs = existing.randomBlobs
        let isNewBlob = !existingBlobs.contains(newBlob)
        let pathTimebase = existing.latestEmissionTimestamp

        if entry.hopCount <= existing.hopCount {
            // Path 2: Equal or better hops + new blob + fresher timestamp
            if isNewBlob && announceEmitted > pathTimebase {
                accept(entry, mergingBlobsFrom: existingBlobs)
                logger.info("Updated \(keyHex) via \(entry.interfaceId, privacy: .public): equal/better hops (\(entry.hopCount) <= \(existing.hopCount)), fresh emit")
                return true
            }
            logger.debug("Ignored \(keyHex) on \(entry.interfaceId, privacy: .public): equal/better hops but duplicate blob or stale emit")
            return false
        }

        // Worse hops (entry.hopCount > existing.hopCount)
        let now = Date()

        // Path 3: Expired path + new blob
        if now >= existing.expires {
            if isNewBlob {
                accept(entry, mergingBlobsFrom: existingBlobs)
                logger.info("Updated \(keyHex) via \(entry.interfaceId, privacy: .public): expired path replaced, hops=\(entry.hopCount)")
                return true
            }
            logger.debug("Ignored \(keyHex) on \(entry.interfaceId, privacy: .public): expired path but duplicate blob")
            return false
        }

        // Path 4: Not expired + fresher emission + new blob
        if announceEmitted > pathTimebase {
            if isNewBlob {
                accept(entry, mergingBlobsFrom: existingBlobs)
                logger.info("Updated \(keyHex) via \(entry.interfaceId, privacy: .public): fresher emission with worse hops (\(entry.hopCount) > \(existing.hopCount))")
                return true
            }
            logger.debug("Ignored \(keyHex) on \(entry.interfaceId, privacy: .public): fresher emission but duplicate blob")
            return false
        }

        // Path 5: Same emission + unresponsive path
        if announceEmitted == pathTimebase && isPathUnresponsive(key) {
            accept(entry, mergingBlobsFrom: existingBlobs)
            logger.info("Updated \(keyHex) via \(entry.interfaceId, privacy: .public): same emission but path was unresponsive")
            return true
        }

        logger.debug("Ignored \(keyHex) on \(entry.interfaceId, privacy: .public): worse hops, not expired, not fresher, not unresponsive")
        return false
    }

    /// Store an accepted entry into its bucket with merged blobs and reset state.
    private func accept(_ entry: PathEntry, mergingBlobsFrom existingBlobs: [Data]) {
        let key = entry.destinationHash
        var updated = entry
        updated.randomBlobs = mergeBlobs(existing: existingBlobs, new: entry.randomBlob)
        updated.pathState = TransportConstants.PATH_STATE_UNKNOWN
        var bucket = paths[key] ?? [:]
        bucket[entry.interfaceId] = updated
        paths[key] = bucket
        pathStates[key] = TransportConstants.PATH_STATE_UNKNOWN
        saveToDatabase(updated)
        pathUpdateContinuation?.yield(updated)
    }

    /// Evict destinations when the in-memory table reaches its capacity.
    ///
    /// Drops fully-expired destinations first; if still over capacity (active
    /// flood), evicts the destinations whose newest path expires soonest. Only
    /// affects the in-memory cache (not the local persistence DB).
    private func evictDestinationsForCapacityIfNeeded() {
        guard paths.count >= maxDestinations else { return }
        let now = Date()

        for (key, bucket) in paths where bucket.values.allSatisfy({ now >= $0.expires }) {
            paths.removeValue(forKey: key)
            pathStates.removeValue(forKey: key)
        }

        if paths.count >= maxDestinations {
            let removeCount = (paths.count - maxDestinations) + maxDestinations / 10
            let ranked = paths.sorted { lhs, rhs in
                let l = lhs.value.values.map { $0.expires }.max() ?? .distantPast
                let r = rhs.value.values.map { $0.expires }.max() ?? .distantPast
                return l < r
            }
            for (key, _) in ranked.prefix(removeCount) {
                paths.removeValue(forKey: key)
                pathStates.removeValue(forKey: key)
            }
        }
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

        // Drop and recreate with new schema (announce_data and composite PK
        // are added by the follow-up migrations)
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

    /// Migrate to the v2 multi-path schema: composite primary key on
    /// (destination_hash, interface_id). Existing rows carry over verbatim —
    /// each becomes the sole entry for its stored interface id.
    private func migrateToMultiPathSchema() {
        guard let db = db else { return }

        var version: Int32 = 0
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nil) == SQLITE_OK {
            if sqlite3_step(stmt) == SQLITE_ROW {
                version = sqlite3_column_int(stmt, 0)
            }
            sqlite3_finalize(stmt)
        }
        guard version < Self.schemaVersion else { return }

        logger.info("Migrating paths table to multi-path schema (v\(Self.schemaVersion))")
        let rebuildSQL = """
            CREATE TABLE paths_v2 (
                destination_hash BLOB NOT NULL,
                public_keys BLOB NOT NULL,
                interface_id TEXT NOT NULL,
                hop_count INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                expires REAL NOT NULL,
                random_blobs TEXT NOT NULL,
                ratchet BLOB,
                app_data BLOB,
                next_hop BLOB,
                announce_data BLOB,
                PRIMARY KEY (destination_hash, interface_id)
            );
            INSERT OR IGNORE INTO paths_v2
                SELECT destination_hash, public_keys, interface_id, hop_count,
                       timestamp, expires, random_blobs, ratchet, app_data,
                       next_hop, announce_data
                FROM paths;
            DROP TABLE paths;
            ALTER TABLE paths_v2 RENAME TO paths;
            PRAGMA user_version = \(Self.schemaVersion);
            """
        if sqlite3_exec(db, rebuildSQL, nil, nil, nil) != SQLITE_OK {
            logger.error("Multi-path schema migration failed: \(String(cString: sqlite3_errmsg(db)))")
        }
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
                paths[destinationHash, default: [:]][interfaceId] = entry
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

    /// Remove all rows for a destination from the database.
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

    /// Remove a single (destination, interface) row from the database.
    private func removeFromDatabase(_ destinationHash: Data, interfaceId: String) {
        guard let db = db else { return }

        let deleteSQL = "DELETE FROM paths WHERE destination_hash = ? AND interface_id = ?"
        var stmt: OpaquePointer?

        guard sqlite3_prepare_v2(db, deleteSQL, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        _ = destinationHash.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, 1, ptr.baseAddress, Int32(destinationHash.count), nil)
        }
        sqlite3_bind_text(stmt, 2, interfaceId, -1, SQLITE_TRANSIENT)

        _ = sqlite3_step(stmt)
    }

    /// Remove all rows referencing an interface from the database.
    private func removeFromDatabase(interfaceId: String) {
        guard let db = db else { return }

        let deleteSQL = "DELETE FROM paths WHERE interface_id = ?"
        var stmt: OpaquePointer?

        guard sqlite3_prepare_v2(db, deleteSQL, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, interfaceId, -1, SQLITE_TRANSIENT)

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

    /// Order entries best-first: fewest hops, then most recently learned.
    private static func isBetter(_ a: PathEntry, than b: PathEntry) -> Bool {
        if a.hopCount != b.hopCount { return a.hopCount < b.hopCount }
        return a.timestamp > b.timestamp
    }

    /// Best non-expired entry in a bucket (min hops, newest tiebreak).
    private static func bestEntry(in bucket: [String: PathEntry]) -> PathEntry? {
        bucket.values
            .filter { !$0.isExpired }
            .min { isBetter($0, than: $1) }
    }

    /// Look up the best path for a destination.
    ///
    /// Returns the best (fewest hops, newest tiebreak) non-expired entry
    /// across all interfaces. Returns nil if not found or all expired.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: Path entry if found and valid, nil otherwise
    public func lookup(destinationHash: Data) -> PathEntry? {
        guard let bucket = paths[destinationHash] else {
            return nil
        }
        return Self.bestEntry(in: bucket)
    }

    /// All non-expired paths for a destination, one per interface, best first.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: Valid path entries (empty if none)
    public func lookupAll(destinationHash: Data) -> [PathEntry] {
        guard let bucket = paths[destinationHash] else { return [] }
        return bucket.values
            .filter { !$0.isExpired }
            .sorted { Self.isBetter($0, than: $1) }
    }

    /// Look up the path for a destination on a specific interface.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - interfaceId: Interface the path must have been learned on
    /// - Returns: Path entry if present and not expired, nil otherwise
    public func lookup(destinationHash: Data, interfaceId: String) -> PathEntry? {
        guard let entry = paths[destinationHash]?[interfaceId], !entry.isExpired else {
            return nil
        }
        return entry
    }

    /// Look up the best path, throwing on not found or expired.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: Path entry
    /// - Throws: `PathTableError.pathNotFound` or `PathTableError.pathExpired`
    public func lookupOrThrow(destinationHash: Data) throws -> PathEntry {
        guard let bucket = paths[destinationHash], !bucket.isEmpty else {
            throw PathTableError.pathNotFound
        }

        guard let best = Self.bestEntry(in: bucket) else {
            throw PathTableError.pathExpired
        }

        return best
    }

    // MARK: - Touch

    /// Update the timestamp of existing path entries (e.g., after transport forwarding).
    /// Also extends the expiration time (M7).
    /// Python reference: Transport.py line 1504
    ///
    /// Touches every entry for the destination — successful traffic confirms
    /// the destination is alive, regardless of which interface carried it.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    public func touch(destinationHash: Data) {
        guard let bucket = paths[destinationHash] else { return }
        // M7: Refresh both timestamp and expiration
        let newExpires = Date().addingTimeInterval(PathEntry.standardExpiration)
        for (interfaceId, entry) in bucket {
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
            paths[destinationHash]?[interfaceId] = touched
            saveToDatabase(touched)
        }
    }

    /// M6: Force-expire all paths to a destination to trigger rediscovery.
    /// Called when a link to a non-transport destination is closed.
    /// Python reference: Transport.py:699
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    public func expirePath(destinationHash: Data) {
        guard let bucket = paths[destinationHash] else { return }
        for (interfaceId, entry) in bucket {
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
            paths[destinationHash]?[interfaceId] = expired
            saveToDatabase(expired)
        }
    }

    // MARK: - Removal

    /// Remove all paths to a destination from the table.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    public func remove(destinationHash: Data) {
        paths.removeValue(forKey: destinationHash)
        pathStates.removeValue(forKey: destinationHash)
        removeFromDatabase(destinationHash)
    }

    /// Remove only the path entry learned on the given interface, preserving
    /// paths to the same destination on other interfaces. Use when
    /// invalidating a stale entry whose interface is missing.
    ///
    /// - Parameters:
    ///   - destinationHash: 16-byte destination hash
    ///   - interfaceId: the interface whose entry should be removed
    /// - Returns: true if an entry was removed, false if absent
    @discardableResult
    public func remove(destinationHash: Data, ifInterface interfaceId: String) -> Bool {
        guard paths[destinationHash]?[interfaceId] != nil else {
            return false
        }
        paths[destinationHash]?.removeValue(forKey: interfaceId)
        if paths[destinationHash]?.isEmpty == true {
            paths.removeValue(forKey: destinationHash)
            pathStates.removeValue(forKey: destinationHash)
        }
        removeFromDatabase(destinationHash, interfaceId: interfaceId)
        return true
    }

    /// Remove every path learned on the given interface (e.g. when a BLE/MPC
    /// peer interface detaches). Paths to the same destinations on other
    /// interfaces are preserved.
    ///
    /// - Parameter interfaceId: the interface being removed
    /// - Returns: destination hashes whose entry on this interface was removed
    @discardableResult
    public func removeAll(forInterface interfaceId: String) -> [Data] {
        var affected: [Data] = []
        for (destination, bucket) in paths where bucket[interfaceId] != nil {
            affected.append(destination)
            paths[destination]?.removeValue(forKey: interfaceId)
            if paths[destination]?.isEmpty == true {
                paths.removeValue(forKey: destination)
                pathStates.removeValue(forKey: destination)
            }
        }
        if !affected.isEmpty {
            removeFromDatabase(interfaceId: interfaceId)
        }
        return affected
    }

    /// Remove all paths from the table and database.
    public func removeAll() {
        paths.removeAll()
        pathStates.removeAll()
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
        var removed = 0

        for (destination, bucket) in paths {
            for (interfaceId, entry) in bucket {
                let isDead = activeInterfaceIds.map {
                    !interfaceId.isEmpty && !$0.contains(interfaceId)
                } ?? false
                if entry.isExpired || isDead {
                    paths[destination]?.removeValue(forKey: interfaceId)
                    removeFromDatabase(destination, interfaceId: interfaceId)
                    removed += 1
                }
            }
            if paths[destination]?.isEmpty == true {
                paths.removeValue(forKey: destination)
                pathStates.removeValue(forKey: destination)
            }
        }

        return removed
    }

    // MARK: - Properties

    /// Number of destinations with at least one valid (non-expired) path.
    public var count: Int {
        paths.values.filter { Self.bestEntry(in: $0) != nil }.count
    }

    /// Total number of entries including expired ones, across all interfaces.
    ///
    /// Expired entries are lazily removed by cleanup() or filtered by lookup().
    public var totalCount: Int {
        paths.values.reduce(0) { $0 + $1.count }
    }

    /// Total number of (destination, interface) entries including expired ones.
    public var entryCount: Int {
        totalCount
    }

    /// All destination hashes with valid paths.
    public var destinations: [Data] {
        paths.filter { Self.bestEntry(in: $0.value) != nil }.map { $0.key }
    }

    /// Check if a path exists for a destination (and is not expired) on any interface.
    ///
    /// - Parameter destinationHash: 16-byte destination hash
    /// - Returns: true if valid path exists
    public func hasPath(for destinationHash: Data) -> Bool {
        guard let bucket = paths[destinationHash] else {
            return false
        }
        return Self.bestEntry(in: bucket) != nil
    }
}

// MARK: - Debug Support

extension PathTable {
    /// Get all entries for debugging (includes expired).
    ///
    /// Not for production use.
    public func allEntries() -> [PathEntry] {
        paths.values.flatMap { $0.values }
    }
}
