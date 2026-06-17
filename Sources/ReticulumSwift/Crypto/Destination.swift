// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Destination.swift
//  ReticulumSwift
//
//  Reticulum destination with full state management.
//  Destinations identify message recipients and are derived from identity public keys
//  and name aspects.
//
//  Matches Python RNS Destination.py for byte-perfect interoperability.
//

import Foundation

// MARK: - Destination Types

/// Destination types matching RNS
public enum DestType: UInt8, Sendable {
    case single = 0x00   // Single destination (specific identity)
    case group = 0x01    // Group destination (shared key)
    case plain = 0x02    // Plain destination (unencrypted)
    case link = 0x03     // Link destination (for link establishment)
}

/// Direction for callback registration
public enum DestinationDirection: Sendable {
    case `in`   // Incoming packets
    case out    // Outgoing packets
}

// MARK: - Destination Errors

/// Errors during destination operations
public enum DestinationError: Error, Sendable, Equatable {
    /// SINGLE/GROUP destination requires an identity
    case identityRequired

    /// PLAIN destinations cannot announce (no identity to sign)
    case plainCannotAnnounce

    /// Invalid app name (empty or contains invalid characters)
    case invalidAppName

    /// Callback manager not set
    case callbackManagerNotSet

    /// register_request_handler called with an empty/invalid path.
    /// Mirrors RNS `raise ValueError("Invalid path specified")` (Destination.py:381).
    case invalidPath

    /// register_request_handler called with an `allow` value not in
    /// {ALLOW_NONE, ALLOW_ALL, ALLOW_LIST}.
    /// Mirrors RNS `raise ValueError("Invalid request policy")` (Destination.py:383).
    case invalidRequestPolicy

    /// set_proof_strategy called with a value not in
    /// {PROVE_NONE, PROVE_APP, PROVE_ALL}.
    /// Mirrors RNS `raise TypeError("Unsupported proof strategy")` (Destination.py:366).
    case unsupportedProofStrategy
}

// MARK: - Callback Types

/// Packet callback type - receives decrypted data and original packet
public typealias PacketCallback = @Sendable (Data, Packet) -> Void

/// Protocol for destination callback manager
public protocol DestinationCallbackManager: AnyObject, Sendable {
    func register(destinationHash: Data, callback: @escaping PacketCallback)
    func createStream(for destinationHash: Data) -> AsyncStream<(Data, Packet)>
}

/// Callback consulted on the `PROVE_APP` proof strategy to decide whether a
/// proof should be returned for a received packet.
///
/// Mirrors RNS `Callbacks.proof_requested` with signature `callback(packet) -> bool`
/// (Destination.py:43,:349-357). Returning `true` requests a proof be sent.
public typealias ProofRequestedCallback = @Sendable (Packet) -> Bool

// MARK: - Request Handling Types

/// The result a `ResponseGenerator` returns for an inbound request, which the
/// responder `Link` forks on to choose how (and whether) to send a response.
///
/// Mirrors RNS `Link.handle_request` response forking (Link.py:877-901):
/// - `None`                         -> `.none`  (no response sent)
/// - bytes / structured (<= MDU)    -> `.bytes` (RESPONSE packet, else Resource by size)
/// - file with metadata             -> `.file`  (metadata-bearing Resource, never umsgpack-wrapped)
public enum RequestResponse: Sendable {
    /// Generator returned nil — NO response is sent (the receipt concludes via timeout).
    /// RNS: `if response != None:` guard (Link.py:893).
    case none

    /// A bytes / structured response. The responder `Link` picks a sub-MDU RESPONSE
    /// packet vs a `>MDU` response Resource by size (respond(to:with:)).
    case bytes(Data)

    /// A file response carrying optional metadata, shipped as a metadata-bearing
    /// Resource and never umsgpack-wrapped (respond(to:file:metadata:)).
    case file(Data, metadata: Data?)
}

/// A response generator invoked by `Link.handleRequest` when an allowed request
/// arrives for a registered path.
///
/// Mirrors RNS `response_generator(path, data, request_id, link_id, remote_identity, requested_at)`
/// (Destination.py:375). RNS inspects the generator's arity to call it with 5 or 6
/// args; the swift port fixes a single 6-argument form (category (a) — swift has no
/// runtime arity inspection). The generator returns a `RequestResponse` instead of a
/// raw value/`None`, so the `.none` case faithfully maps to RNS returning `None`.
public typealias ResponseGenerator = @Sendable (
    _ path: String,
    _ data: Data,
    _ requestId: Data,
    _ linkId: Data,
    _ remoteIdentity: Identity?,
    _ requestedAt: Double
) async -> RequestResponse

/// A registered request handler for a destination path.
///
/// Mirrors the RNS list `[path, response_generator, allow, allowed_list, auto_compress]`
/// stored in `request_handlers[path_hash]` (Destination.py:386).
public struct RequestHandler: Sendable {
    /// The request path (human-readable string the handler was registered under).
    public let path: String

    /// The generator that produces the response for an allowed request.
    public let generator: ResponseGenerator

    /// The request policy: one of `ALLOW_NONE`, `ALLOW_ALL`, `ALLOW_LIST`.
    public let allow: UInt8

    /// For `ALLOW_LIST`, the list of permitted identity hashes; otherwise nil.
    public let allowedList: [Data]?

    /// Whether automatic compression of responses should be carried out.
    public let autoCompress: Bool

    public init(
        path: String,
        generator: @escaping ResponseGenerator,
        allow: UInt8,
        allowedList: [Data]?,
        autoCompress: Bool
    ) {
        self.path = path
        self.generator = generator
        self.allow = allow
        self.allowedList = allowedList
        self.autoCompress = autoCompress
    }
}

// MARK: - Destination Class

/// Reticulum destination with full state management.
///
/// A Destination identifies a message recipient and is derived from an identity
/// and name aspects. It holds all state needed for announcing, receiving packets,
/// and managing callbacks.
///
/// Destination types:
/// - **SINGLE**: One-to-one encrypted communication with a specific identity
/// - **PLAIN**: Unencrypted broadcast (no identity required)
/// - **GROUP**: Shared-key encrypted group communication
/// - **LINK**: Over an established link (special case)
public final class Destination: @unchecked Sendable {

    // MARK: - Properties

    /// The identity this destination belongs to (nil for PLAIN destinations)
    public let identity: Identity?

    /// Application name (first aspect of the destination name)
    public let appName: String

    /// Additional name aspects (e.g., ["delivery"] for lxmf.delivery)
    public let aspects: [String]

    /// Destination type (single, plain, group, link)
    public let destinationType: DestType

    /// Direction for callback registration
    public var direction: DestinationDirection

    /// Optional application data to include in announces
    public var appData: Data?

    /// Callback manager for packet delivery (weak reference, set externally)
    public weak var callbackManager: (any DestinationCallbackManager)?

    /// Ratchet manager for forward secrecy (nil if ratchets not enabled)
    public var ratchetManager: RatchetManager?

    /// Whether ratchets are enabled for this destination
    public private(set) var ratchetsEnabled: Bool = false

    /// Whether ratchets are enforced (reject non-ratcheted messages)
    public private(set) var ratchetsEnforced: Bool = false

    /// `latest_ratchet_id` — id of the ratchet a real `encrypt`/`decrypt` last
    /// used, or nil (nil until a real op runs; nil when the static key was used /
    /// enforcement rejected). Mirrors RNS `Destination.latest_ratchet_id`
    /// (Destination.py:167,:596-599). Lock-guarded (see `stateLock`).
    private var _latestRatchetId: Data?

    /// `ratchet_interval` — per-destination minimum rotation interval in seconds.
    /// Defaults to RNS `Destination.RATCHET_INTERVAL` (1800s, Destination.py:163).
    /// Lock-guarded (see `stateLock`).
    private var _ratchetInterval: Int = Int(RatchetManager.RATCHET_INTERVAL)

    /// `retained_ratchets` — per-destination retained-ratchet cap. Defaults to RNS
    /// `Destination.RATCHET_COUNT` (512, Destination.py:165). Lock-guarded.
    private var _retainedRatchets: Int = RatchetManager.RATCHET_COUNT

    // MARK: - Proof Strategy & Request Policy Constants

    /// Proof strategy: never return proofs. Default. (Destination.py:69)
    public static let PROVE_NONE: UInt8 = 0x21
    /// Proof strategy: consult `proofRequestedCallback` per packet. (Destination.py:70)
    public static let PROVE_APP: UInt8 = 0x22
    /// Proof strategy: always return proofs. (Destination.py:71)
    public static let PROVE_ALL: UInt8 = 0x23
    /// Valid proof strategies. (Destination.py:72)
    public static let proofStrategies: [UInt8] = [PROVE_NONE, PROVE_APP, PROVE_ALL]

    /// Request policy: respond to no requests. Default. (Destination.py:74)
    public static let ALLOW_NONE: UInt8 = 0x00
    /// Request policy: respond to all requests. (Destination.py:75)
    public static let ALLOW_ALL: UInt8 = 0x01
    /// Request policy: respond only to identified peers in `allowedList`. (Destination.py:76)
    public static let ALLOW_LIST: UInt8 = 0x02
    /// Valid request policies. (Destination.py:77)
    public static let requestPolicies: [UInt8] = [ALLOW_NONE, ALLOW_ALL, ALLOW_LIST]

    // MARK: - Request / Proof / Links State
    //
    // Destination is a (non-actor) `final class @unchecked Sendable` shared between
    // the Transport actor, the Link actor, and the conformance-bridge threads. RNS
    // stores these as plain instance attributes mutated under the GIL (Destination.py:
    // 157,:160,:172,:194). Swift has no GIL, so every mutation+read of the request
    // handler map, links list, proof strategy and proof callback is guarded by this
    // NSLock. Category (a) deviation — documented in port-deviations.md.
    private let stateLock = NSLock()

    /// `request_handlers` keyed by `path_hash = truncatedHash(path.utf8)`.
    /// Mirrors RNS `self.request_handlers = {}` (Destination.py:157).
    private var _requestHandlers: [Data: RequestHandler] = [:]

    /// `proof_strategy`, default PROVE_NONE. Mirrors RNS (Destination.py:160).
    private var _proofStrategy: UInt8 = Destination.PROVE_NONE

    /// `callbacks.proof_requested`. Mirrors RNS (Destination.py:43,:357).
    private var _proofRequestedCallback: ProofRequestedCallback?

    /// `self.links` — responder (inbound) Links accepted for this destination.
    /// Mirrors RNS `self.links = []` (Destination.py:172).
    private var _links: [Link] = []

    /// The destination's proof strategy. Read by `Transport.handleLinkData` on the
    /// link-DATA NONE path. Mirrors RNS `self.proof_strategy` (Destination.py:160).
    /// Lock-guarded read (see `stateLock`).
    public var proofStrategy: UInt8 {
        stateLock.withLock { _proofStrategy }
    }

    /// The proof-requested callback consulted on `PROVE_APP`.
    /// Mirrors RNS `self.callbacks.proof_requested` (Destination.py:43,:357).
    /// Lock-guarded read (see `stateLock`).
    public var proofRequestedCallback: ProofRequestedCallback? {
        stateLock.withLock { _proofRequestedCallback }
    }

    /// The responder (inbound) Links accepted for this destination, surfaced via
    /// `Transport.linksForDestination`. Mirrors RNS `self.links` (Destination.py:172).
    /// Lock-guarded read (see `stateLock`).
    public var links: [Link] {
        stateLock.withLock { _links }
    }

    /// `latest_ratchet_id` — id of the ratchet a real `encrypt`/`decrypt` last
    /// used (nil for none/static/rejected). Mirrors RNS (Destination.py:167).
    /// Lock-guarded; settable so `Identity.decrypt` can write it through the
    /// `RatchetIdReceiver` conformance.
    public var latestRatchetId: Data? {
        get { stateLock.withLock { _latestRatchetId } }
        set { stateLock.withLock { _latestRatchetId = newValue } }
    }

    /// `ratchet_interval` — per-destination minimum rotation interval in seconds.
    /// Mirrors RNS `self.ratchet_interval` (Destination.py:163). Lock-guarded read.
    public var ratchetInterval: Int {
        stateLock.withLock { _ratchetInterval }
    }

    /// `retained_ratchets` — per-destination retained-ratchet cap.
    /// Mirrors RNS `self.retained_ratchets` (Destination.py:165). Lock-guarded read.
    public var retainedRatchets: Int {
        stateLock.withLock { _retainedRatchets }
    }

    // MARK: - Computed Properties

    /// 16-byte destination hash
    ///
    /// Computed based on destination type:
    /// - SINGLE: truncated_hash(nameHash + identityHash)
    /// - PLAIN/GROUP: truncated_hash(nameHash)
    public var hash: Data {
        switch destinationType {
        case .single, .link:
            guard let identity = identity else {
                // Fallback to plain hash if no identity (shouldn't happen for SINGLE)
                return computePlainHash()
            }
            return Destination.hash(identity: identity, appName: appName, aspects: aspects)

        case .plain, .group:
            return computePlainHash()
        }
    }

    /// 64-byte concatenated public keys (encryption || signing)
    /// Returns nil for PLAIN destinations (no identity)
    public var publicKeys: Data? {
        return identity?.publicKeys
    }

    /// 10-byte name hash for destination hash computation.
    ///
    /// Computes SHA-256 of the full dotted name (e.g., "lxmf.delivery") and returns
    /// the first 10 bytes (NAME_HASH_LENGTH = 80 bits).
    ///
    /// This is used for computing destination hashes. For announce payloads,
    /// use `announceNameHash` instead which uses concatenated 16-byte aspect hashes.
    ///
    /// Python RNS equivalent:
    /// ```python
    /// self.name_hash = RNS.Identity.full_hash(
    ///     self.expand_name(None, app_name, *aspects).encode("utf-8")
    /// )[:(RNS.Identity.NAME_HASH_LENGTH//8)]
    /// ```
    public var nameHash: Data {
        return Hashing.destinationNameHash(appName: appName, aspects: aspects)
    }

    /// Full destination name as a dot-separated string
    ///
    /// Format: "appName.aspect1.aspect2...."
    public var fullName: String {
        if aspects.isEmpty {
            return appName
        }
        return appName + "." + aspects.joined(separator: ".")
    }

    /// Name hash for use in announce packets.
    ///
    /// Concatenated 16-byte truncated hashes of each aspect (including app name).
    /// This matches Python RNS announce format for the name_hash field in announce payloads.
    /// Total length = 16 bytes * number of aspects (app_name counts as first aspect).
    ///
    /// Note: This is DIFFERENT from the `nameHash` property which is used for
    /// destination hash computation (10 bytes of full name hash).
    public var announceNameHash: Data {
        return Hashing.aspectNameHash(appName: appName, aspects: aspects)
    }

    /// Hex string representation of the destination hash
    public var hexHash: String {
        hash.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Initialization

    /// Create a destination with identity (for SINGLE, GROUP, LINK types)
    ///
    /// - Parameters:
    ///   - identity: The identity this destination belongs to
    ///   - appName: Application name (first aspect)
    ///   - aspects: Additional name aspects
    ///   - type: Destination type (defaults to .single)
    ///   - direction: Direction for callbacks (defaults to .in)
    public init(
        identity: Identity,
        appName: String,
        aspects: [String] = [],
        type: DestType = .single,
        direction: DestinationDirection = .in
    ) {
        self.identity = identity
        self.appName = appName
        self.aspects = aspects
        self.destinationType = type
        self.direction = direction
        self.appData = nil
        self.callbackManager = nil
    }

    /// Create a PLAIN destination (no identity required)
    ///
    /// - Parameters:
    ///   - appName: Application name (first aspect)
    ///   - aspects: Additional name aspects
    ///   - direction: Direction for callbacks (defaults to .in)
    public init(
        plainAppName appName: String,
        aspects: [String] = [],
        direction: DestinationDirection = .in
    ) {
        self.identity = nil
        self.appName = appName
        self.aspects = aspects
        self.destinationType = .plain
        self.direction = direction
        self.appData = nil
        self.callbackManager = nil
    }

    // MARK: - Private Helpers

    private func computePlainHash() -> Data {
        return Destination.plainHash(appName: appName, aspects: aspects)
    }

    // MARK: - Callback Management

    /// Set the callback manager for packet delivery
    ///
    /// - Parameter manager: The callback manager to use
    public func setCallbackManager(_ manager: any DestinationCallbackManager) {
        self.callbackManager = manager
    }

    /// Register a callback for incoming packets
    ///
    /// - Parameter callback: Callback to invoke when packets arrive
    /// - Throws: `DestinationError.callbackManagerNotSet` if no manager configured
    public func registerCallback(_ callback: @escaping PacketCallback) throws {
        guard let manager = callbackManager else {
            throw DestinationError.callbackManagerNotSet
        }
        manager.register(destinationHash: self.hash, callback: callback)
    }

    /// Create an async stream of incoming packets
    ///
    /// - Returns: AsyncStream of (decrypted data, original packet) tuples,
    ///            or nil if no callback manager is set
    public func createPacketStream() -> AsyncStream<(Data, Packet)>? {
        guard let manager = callbackManager else {
            return nil
        }
        return manager.createStream(for: self.hash)
    }

    // MARK: - Request Handler Management

    /// Registers a request handler.
    ///
    /// Mirrors RNS `register_request_handler` (Destination.py:370-387). Validates the
    /// path is non-empty and `allow` is a valid request policy (throwing instead of
    /// RNS's `raise ValueError`), then stores the handler keyed by
    /// `path_hash = truncatedHash(path.utf8)` — the identical hash `Link.request`
    /// (Link+Request.swift:64) and `Link.handleRequest` use to look the handler up.
    ///
    /// - Parameters:
    ///   - path: The path for the request handler. Must be non-empty.
    ///   - responseGenerator: Invoked to produce the response for an allowed request.
    ///   - allow: One of `ALLOW_NONE` (default), `ALLOW_ALL`, `ALLOW_LIST`.
    ///   - allowedList: For `ALLOW_LIST`, the permitted identity hashes.
    ///   - autoCompress: Whether responses should be auto-compressed (default true).
    /// - Throws: `DestinationError.invalidPath` for an empty path;
    ///           `DestinationError.invalidRequestPolicy` for an unknown `allow`.
    public func registerRequestHandler(
        path: String,
        responseGenerator: @escaping ResponseGenerator,
        allow: UInt8 = Destination.ALLOW_NONE,
        allowedList: [Data]? = nil,
        autoCompress: Bool = true
    ) throws {
        // RNS: if path == None or path == "": raise ValueError (Destination.py:381)
        guard !path.isEmpty else { throw DestinationError.invalidPath }
        // RNS: elif not allow in Destination.request_policies: raise ValueError (Destination.py:383)
        guard Destination.requestPolicies.contains(allow) else {
            throw DestinationError.invalidRequestPolicy
        }
        // RNS: path_hash = RNS.Identity.truncated_hash(path.encode("utf-8")) (Destination.py:385)
        let pathHash = Hashing.truncatedHash(Data(path.utf8))
        let handler = RequestHandler(
            path: path,
            generator: responseGenerator,
            allow: allow,
            allowedList: allowedList,
            autoCompress: autoCompress
        )
        // RNS: self.request_handlers[path_hash] = request_handler (Destination.py:387)
        stateLock.withLock { _requestHandlers[pathHash] = handler }
    }

    /// Deregisters a request handler.
    ///
    /// Mirrors RNS `deregister_request_handler` (Destination.py:389-401).
    ///
    /// - Parameter path: The path for the request handler to be deregistered.
    /// - Returns: `true` if a handler existed and was removed, otherwise `false`.
    @discardableResult
    public func deregisterRequestHandler(_ path: String) -> Bool {
        // RNS: path_hash = RNS.Identity.truncated_hash(path.encode("utf-8")) (Destination.py:396)
        let pathHash = Hashing.truncatedHash(Data(path.utf8))
        return stateLock.withLock {
            // RNS: if path_hash in self.request_handlers: pop -> True else False (Destination.py:397-401)
            if _requestHandlers.removeValue(forKey: pathHash) != nil {
                return true
            }
            return false
        }
    }

    /// Looks up the registered handler for a request path hash.
    ///
    /// The accessor `Link.handleRequest` uses to resolve the handler from the
    /// `path_hash` carried in the request (RNS reads `self.request_handlers[path_hash]`
    /// at Link.py:859-865). Returns nil when no handler is registered.
    ///
    /// - Parameter pathHash: `truncatedHash(path.utf8)` from the inbound request.
    /// - Returns: The matching `RequestHandler`, or nil.
    public func requestHandler(forPathHash pathHash: Data) -> RequestHandler? {
        stateLock.withLock { _requestHandlers[pathHash] }
    }

    // MARK: - Proof Strategy Management

    /// Sets the destination's proof strategy.
    ///
    /// Mirrors RNS `set_proof_strategy` (Destination.py:359-368). Validates membership
    /// in `proofStrategies` (throwing instead of RNS's `raise TypeError`).
    ///
    /// - Parameter proofStrategy: One of `PROVE_NONE`, `PROVE_APP`, `PROVE_ALL`.
    /// - Throws: `DestinationError.unsupportedProofStrategy` for an unknown value.
    public func setProofStrategy(_ proofStrategy: UInt8) throws {
        // RNS: if not proof_strategy in Destination.proof_strategies: raise TypeError (Destination.py:365-366)
        guard Destination.proofStrategies.contains(proofStrategy) else {
            throw DestinationError.unsupportedProofStrategy
        }
        // RNS: self.proof_strategy = proof_strategy (Destination.py:368)
        stateLock.withLock { _proofStrategy = proofStrategy }
    }

    /// Registers a callback consulted (on `PROVE_APP`) to decide whether a proof
    /// should be returned for a received packet.
    ///
    /// Mirrors RNS `set_proof_requested_callback` (Destination.py:349-357), which
    /// stores `self.callbacks.proof_requested = callback`. The callback returns
    /// `true` to send a proof, `false` to suppress it.
    ///
    /// - Parameter callback: The proof-requested callback, or nil to clear it.
    public func setProofRequestedCallback(_ callback: ProofRequestedCallback?) {
        stateLock.withLock { _proofRequestedCallback = callback }
    }

    // MARK: - Inbound Link Tracking

    /// Appends a responder (inbound) Link accepted for this destination.
    ///
    /// Mirrors RNS `incoming_link_request` appending the validated link to
    /// `self.links` (Destination.py:420-424). Called by `Transport.handleLinkRequest`
    /// when it accepts a responder link; the list is surfaced via
    /// `Transport.linksForDestination`.
    ///
    /// - Parameter link: The newly accepted responder link.
    public func appendLink(_ link: Link) {
        // RNS: self.links.append(link) (Destination.py:424)
        stateLock.withLock { _links.append(link) }
    }

    // MARK: - Ratchet Management

    /// Enable ratchets for forward secrecy.
    ///
    /// Mirrors RNS `Destination.enable_ratchets` (Destination.py:466-489): loads
    /// existing ratchets from disk or generates an initial ratchet, leaving the
    /// destination with `count >= 1` and a valid current ratchet id. Once enabled,
    /// announces include the current ratchet public key and the decrypt path tries
    /// ratchet keys before the base identity key.
    ///
    /// The current ratchet is also remembered into `Identity.knownRatchets` keyed
    /// by this destination's hash, mirroring the effect of RNS's announce-time
    /// `Identity._remember_ratchet(self.hash, ratchets[0])` (Destination.py:286).
    /// The swift port has no `Destination.announce()` method (announces are
    /// assembled separately), so the remember happens here so `encrypt`'s
    /// `Identity.getRatchet(self.hash)` selection finds the destination's own
    /// current ratchet. See port-deviations.md.
    ///
    /// - Parameter storagePath: File path for persistent ratchet storage
    public func enableRatchets(storagePath: String) async throws {
        guard let identity = identity, identity.hasPrivateKeys else { return }
        let manager = RatchetManager(storagePath: storagePath, identity: identity)
        try await manager.loadOrCreate()
        self.ratchetManager = manager
        self.ratchetsEnabled = true
        // Remember the current ratchet for self so encrypt() can select it.
        if let currentPub = await manager.currentRatchetPublicBytes() {
            Identity.rememberRatchet(destinationHash: self.hash, ratchet: currentPub)
        }
    }

    /// Enforce ratchets — reject messages not encrypted to a ratchet key.
    ///
    /// Mirrors RNS `Destination.enforce_ratchets` (Destination.py:490-501). Only
    /// effective if ratchets are already enabled. When enforced, messages
    /// encrypted to the base identity key are dropped (decrypt returns nil).
    public func enforceRatchets() {
        guard ratchetsEnabled else { return }
        self.ratchetsEnforced = true
    }

    /// `set_ratchet_interval(interval)` (Destination.py:519-531): set the minimum
    /// interval in seconds between ratchet rotations. Accepts only a positive
    /// integer (else leaves the interval unchanged and returns false).
    ///
    /// - Returns: true if the interval was accepted.
    @discardableResult
    public func setRatchetInterval(_ interval: Int) -> Bool {
        // RNS Destination.py:526-530 — isinstance int and interval > 0
        guard interval > 0 else { return false }
        stateLock.withLock { _ratchetInterval = interval }
        return true
    }

    /// `set_retained_ratchets(retained)` (Destination.py:504-517): set the number
    /// of previously-generated ratchets to retain, then run `_clean_ratchets`.
    /// Accepts only a positive integer (else returns false, unchanged).
    ///
    /// - Returns: true if the cap was accepted.
    @discardableResult
    public func setRetainedRatchets(_ retained: Int) async -> Bool {
        // RNS Destination.py:511-516 — isinstance int and retained_ratchets > 0
        guard retained > 0 else { return false }
        stateLock.withLock { _retainedRatchets = retained }
        // RNS Destination.py:514 — self._clean_ratchets()
        await ratchetManager?.cleanRatchets(retained: retained)
        return true
    }

    /// `rotate_ratchets()` (Destination.py:227-241): insert a new newest ratchet
    /// only when `now > latestRatchetTime + ratchetInterval`; the prior current
    /// becomes the previous; the list is cleaned to `retainedRatchets`; persisted.
    /// Honors this destination's configured interval (not the static one).
    ///
    /// - Returns: true if a new ratchet was inserted (the gate opened).
    @discardableResult
    public func rotateRatchets() async -> Bool {
        guard let manager = ratchetManager else { return false }
        let interval = self.ratchetInterval
        let retained = self.retainedRatchets
        let rotated = await manager.rotate(interval: TimeInterval(interval), retained: retained)
        // Mirror RNS announce-time `Identity._remember_ratchet(self.hash, ratchets[0])`
        // (Destination.py:286): after a rotation makes a new ratchet current, keep
        // `encrypt`'s `Identity.getRatchet(self.hash)` selection in sync with it.
        if rotated, let currentPub = await manager.currentRatchetPublicBytes() {
            Identity.rememberRatchet(destinationHash: self.hash, ratchet: currentPub)
        }
        return rotated
    }

    /// `Destination.encrypt(plaintext)` for SINGLE+identity (Destination.py:585-599).
    ///
    /// Selects the destination's current ratchet via `Identity.getRatchet(self.hash)`;
    /// when present, records `latestRatchetId = _getRatchetId(selected)` and encrypts
    /// to that ratchet public key (forward secrecy), else encrypts to the base
    /// identity key. The HKDF salt is the identity hash (RNS `Identity.get_salt`).
    /// PLAIN destinations return the plaintext unchanged (Destination.py:583).
    ///
    /// - Returns: Ciphertext token (ephemeral pub || token).
    /// - Throws: `DestinationError.identityRequired` for SINGLE without an identity;
    ///   group/unsupported types are out of scope this session.
    public func encrypt(_ plaintext: Data) throws -> Data {
        // RNS Destination.py:582-583 — PLAIN passthrough.
        if destinationType == .plain {
            return plaintext
        }
        // RNS Destination.py:585-590 — SINGLE + identity.
        guard destinationType == .single || destinationType == .link,
              let identity = identity else {
            throw DestinationError.identityRequired
        }
        // RNS Destination.py:586 — selected_ratchet = RNS.Identity.get_ratchet(self.hash)
        let selectedRatchet = Identity.getRatchet(self.hash)
        if let selected = selectedRatchet {
            // RNS Destination.py:587-588 — latest_ratchet_id = _get_ratchet_id(selected)
            self.latestRatchetId = Identity._getRatchetId(selected)
            // RNS Destination.py:590 — identity.encrypt(plaintext, ratchet=selected)
            return try Identity.encrypt(plaintext, toRatchetKey: selected, identityHash: identity.hash)
        }
        // RNS Destination.py:590 with ratchet=None — base identity key.
        return try identity.encryptTo(plaintext, identityHash: identity.hash)
    }

    /// `Destination.decrypt(ciphertext)` for SINGLE+identity (Destination.py:602-643).
    ///
    /// Passes `ratchet_id_receiver=self`, so `Identity.decrypt` records which
    /// ratchet (or the static key) decrypted into `latestRatchetId`. When ratchets
    /// are present they are tried first (newest first); enforcement rejects (nil)
    /// a message no ratchet can decrypt before the static fallback. PLAIN
    /// destinations return the ciphertext unchanged (Destination.py:607).
    ///
    /// - Returns: Plaintext, or nil on failure / enforcement rejection.
    public func decrypt(_ ciphertext: Data) async -> Data? {
        // RNS Destination.py:606-607 — PLAIN passthrough.
        if destinationType == .plain {
            return ciphertext
        }
        guard destinationType == .single || destinationType == .link,
              let identity = identity else {
            return nil
        }
        // RNS Destination.py:609-643 — pass ratchet_id_receiver=self.
        let ratchets = await ratchetManager?.allRatchetPrivateKeys()
        return identity.decrypt(
            ciphertext,
            identityHash: identity.hash,
            ratchets: ratchets,
            enforceRatchets: self.ratchetsEnforced,
            ratchetIdReceiver: self
        )
    }

    // MARK: - Static Hash Methods (Backward Compatibility)

    /// Calculate destination hash from identity and name aspects.
    ///
    /// Hash = truncated_hash(name_hash(10 bytes) || identity_hash(16 bytes))
    /// where name_hash = full_hash("appName.aspect1.aspect2...")[:10]
    ///
    /// The destination hash uniquely identifies a recipient in the Reticulum network.
    /// It combines the identity's cryptographic hash with the hashed full name to allow
    /// multiple destinations per identity (e.g., different apps on the same device).
    ///
    /// - Parameters:
    ///   - identity: The identity this destination belongs to
    ///   - appName: Application name (first aspect)
    ///   - aspects: Additional name aspects
    /// - Returns: 16-byte destination hash
    public static func hash(
        identity: Identity,
        appName: String,
        aspects: [String] = []
    ) -> Data {
        // Compute 10-byte name hash from full dotted name
        let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)

        // Combine name hash (10 bytes) with identity hash (16 bytes)
        var combined = nameHash
        combined.append(identity.hash)

        // Final destination hash is truncated hash of combined (16 bytes)
        return Hashing.truncatedHash(combined)
    }

    /// Calculate destination hash for a plain destination (no identity).
    /// Used for broadcast/multicast destinations.
    ///
    /// Plain destinations don't have an associated identity, so the hash is
    /// computed only from the name hash (10 bytes).
    ///
    /// - Parameters:
    ///   - appName: Application name
    ///   - aspects: Additional name aspects
    /// - Returns: 16-byte destination hash
    public static func plainHash(
        appName: String,
        aspects: [String] = []
    ) -> Data {
        // Plain destinations use name hash only (10 bytes)
        let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
        return Hashing.truncatedHash(nameHash)
    }

    /// Calculate destination hash from raw public keys and name aspects.
    ///
    /// This variant is useful when you have public keys but not a full Identity object
    /// (e.g., received from a network announce).
    ///
    /// - Parameters:
    ///   - encryptionPublicKey: 32-byte X25519 public key
    ///   - signingPublicKey: 32-byte Ed25519 public key
    ///   - appName: Application name (first aspect)
    ///   - aspects: Additional name aspects
    /// - Returns: 16-byte destination hash
    public static func hash(
        encryptionPublicKey: Data,
        signingPublicKey: Data,
        appName: String,
        aspects: [String] = []
    ) -> Data {
        // Compute identity hash from public keys (16 bytes)
        let identityHash = Hashing.identityHash(
            encryptionPublicKey: encryptionPublicKey,
            signingPublicKey: signingPublicKey
        )

        // Compute 10-byte name hash from full dotted name
        let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)

        // Combine name hash (10 bytes) with identity hash (16 bytes)
        var combined = nameHash
        combined.append(identityHash)

        // Final destination hash is truncated hash of combined (16 bytes)
        return Hashing.truncatedHash(combined)
    }
}

// MARK: - RatchetIdReceiver

/// `Destination` is the RNS `ratchet_id_receiver` passed to `Identity.decrypt`
/// (Destination.py:627/:641): the decrypt path writes `self.latest_ratchet_id`.
/// The protocol requirement is satisfied by the lock-guarded `latestRatchetId`
/// accessor declared on the class.
extension Destination: RatchetIdReceiver {}

// MARK: - CustomStringConvertible

extension Destination: CustomStringConvertible {
    public var description: String {
        let typeStr: String
        switch destinationType {
        case .single: typeStr = "SINGLE"
        case .group: typeStr = "GROUP"
        case .plain: typeStr = "PLAIN"
        case .link: typeStr = "LINK"
        }

        var name = appName
        if !aspects.isEmpty {
            name += "." + aspects.joined(separator: ".")
        }

        return "Destination<\(typeStr):\(name):\(hexHash.prefix(8))...>"
    }
}
