// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Resource.swift
//  ReticulumSwift
//
//  Actor-based resource transfer management for RNS large data transfers.
//  Manages state machine, data preparation, compression, and part assembly.
//
//  Matches Python RNS Resource.py for interoperability.
//

import Foundation
import CryptoKit
import os.log

private let logger = Logger(subsystem: "net.reticulum", category: "Resource")

// MARK: - Resource

/// Actor-based resource transfer for large data over links.
///
/// Resource implements the Reticulum resource protocol:
/// - State machine: none -> queued -> advertised -> transferring -> awaitingProof -> complete
/// - Data preparation: compression, random hash, hashmap generation
/// - Part assembly: hash validation, decompression
/// - AsyncStream for state observation
///
/// Example usage (outbound):
/// ```swift
/// let resource = Resource(
///     data: largeData,
///     link: activeLink,
///     requestId: nil,
///     isResponse: false,
///     autoCompress: true
/// )
/// try await resource.prepare(partSize: link.sdu)
/// let advertisement = resource.getAdvertisement(segment: 1, linkMDU: link.mdu)
/// ```
///
/// Example usage (inbound):
/// ```swift
/// let resource = Resource(advertisement: adv, link: activeLink)
/// let partData = ... // received from network
/// try await resource.receivePart(partData, at: partIndex)
/// if await resource.isComplete {
///     let originalData = try await resource.assemble()
/// }
/// ```
public actor Resource {

    // MARK: - Identity

    /// Resource hash (SHA256 of random_hash || data)
    public private(set) var hash: Data?

    /// Random hash (4 bytes, for collision detection)
    public private(set) var randomHash: Data?

    /// Associated request ID (16 bytes) or nil
    public let requestId: Data?

    /// Whether this is a response resource
    public let isResponse: Bool

    /// Whether this side initiated the transfer (sender). Mirrors python
    /// `self.initiator` — True for an outbound `Resource(data, ...)`
    /// (RNS/Resource.py:385) and False for an inbound `Resource.accept`
    /// (RNS/Resource.py:184). Drives `cancel()` (ICL vs. incoming cleanup) and
    /// `getProgress()` (sent vs. received branch).
    public let isInitiator: Bool

    // MARK: - Proof / Corruption

    /// Reason an inbound assembly was marked `.corrupt`. Distinguishes the two
    /// python CORRUPT sites so the Link can branch teardown: a bz2 over-size
    /// overflow (RNS/Resource.py:688-692) tears the link down, a per-segment hash
    /// mismatch (RNS/Resource.py:715) concludes quietly.
    public enum CorruptReason: Sendable {
        /// Per-segment integrity hash mismatch (RNS/Resource.py:715).
        case hashMismatch
        /// Decompressed bz2 stream exceeded `maxDecompressedSize`
        /// (RNS/Resource.py:688-692).
        case decompressionOverflow
    }

    /// Set by `assemble()` alongside `state = .corrupt`. Read by the Link after it
    /// catches `ResourceError.corruptResource`.
    public private(set) var corruptReason: CorruptReason?

    /// Expected proof for THIS segment, computed in `prepare()` as
    /// `full_hash(segment_plaintext + hash)` (RNS/Resource.py:443). Consumed by the
    /// sender's `validate_proof(_:)`.
    public private(set) var expectedProof: Data?

    /// Number of RESOURCE_PRF proof packets this receiver has actually sent.
    /// `prove()` sends at most once (idempotent); used by the bridge corrupt test
    /// (valid -> 1, corrupt -> 0).
    public private(set) var proveCallCount: Int = 0

    /// Per-instance decompression ceiling. Mirrors python
    /// `self.max_decompressed_size` (RNS/Resource.py:364). `assemble()` rejects a
    /// bz2 stream that decompresses beyond this as `.corrupt`/`.decompressionOverflow`.
    /// Defaults to `AUTO_COMPRESS_MAX_SIZE`; the Link lowers it for the bomb test.
    public var maxDecompressedSize: Int = ResourceConstants.AUTO_COMPRESS_MAX_SIZE

    /// Lower (or raise) the per-resource bz2 decompression bound from outside the
    /// actor.
    ///
    /// RNS exposes `max_decompressed_size` as a plain attribute the receiving app
    /// mutates directly in its `resource_started` callback (RNS/Resource.py:364);
    /// the conformance harness drops it to 256 KiB there so a decompression bomb
    /// trips the bounded-decompressor guard (RNS/Resource.py:686-692). Swift actor
    /// isolation forbids cross-actor stored-property mutation, so this is the
    /// external setter. It MUST be called before `assemble()` runs — i.e. from the
    /// Link's `resourceStarted` hook, which fires before `accept()` — for the bound
    /// to be in effect at decompression time.
    public func setMaxDecompressedSize(_ size: Int) {
        maxDecompressedSize = size
    }

    /// Full per-segment plaintext (metadata included) retained by `assemble()` for
    /// `prove()`. Mirrors python `self.data` at prove time (RNS/Resource.py:684/755):
    /// the decompressed, random-hash-stripped stream BEFORE the metadata prefix is
    /// split off (so the proof matches the sender's `expected_proof`).
    private var provePlaintext: Data?

    /// Unpacked metadata recovered from segment 1 (RNS/Resource.py:698-731). nil
    /// when the resource carried no metadata. Surfaced after the final segment.
    public private(set) var receivedMetadata: Data?

    // MARK: - Sender Part-Serving State

    /// Per-part "already sent" flags (sender). Mirrors python `part.sent`
    /// (RNS/Resource.py:1013). First send increments `sentPartCount`; a repeat
    /// request re-sends the byte-identical part without re-counting.
    private var sentFlags: [Bool] = []

    /// Number of distinct parts sent. Mirrors python `self.sent_parts`
    /// (RNS/Resource.py:431/1015). When it reaches `numParts` the resource moves to
    /// `.awaitingProof` (RNS/Resource.py:1066-1067).
    public private(set) var sentPartCount: Int = 0

    /// Sliding sender scope floor. Mirrors python `receiver_min_consecutive_height`
    /// (RNS/Resource.py:377/1000/1038): the lowest part index still eligible to be
    /// served, advanced on an aligned hashmap-exhausted request.
    public private(set) var receiverScopeHeight: Int = 0

    /// De-dup set of already-served RESOURCE_REQ packet hashes. Mirrors python
    /// `self.req_hashlist` (RNS/Resource.py:376); the Link checks/append here before
    /// serving (RNS/Link.py:1113-1115) so a re-delivered request does not re-serve.
    private var reqHashlist: Set<Data> = []

    /// Count of hashmap-exhausted requests sent (receiver). Surfaced for the HMU
    /// handshake test. Incremented in `requestNextParts()` per EXHAUSTED request.
    public private(set) var hmuRequestsSent: Int = 0

    /// Count of hashmap-update packets applied (receiver). Incremented in
    /// `hashmapUpdate(...)`. Surfaced for the HMU handshake test.
    public private(set) var hashmapUpdatesReceived: Int = 0

    /// Number of times the collision-guard loop rebuilt the hashmap in `prepare()`.
    /// Mirrors the python remap loop re-running on a map-hash collision
    /// (RNS/Resource.py:457-460). Zero in the common (no-collision) case.
    public private(set) var hashmapRebuildCount: Int = 0

    /// PORT-DEVIATION test seam (python uses monkeypatching). When set, the
    /// collision-guard loop runs each part's computed map-hash through this closure
    /// before the collision check, so a test can force a collision. MUST be inert
    /// (nil) in production — see port-deviations.md.
    private var mapHashInjector: (@Sendable (_ randomHash: Data, _ partIndex: Int, _ defaultMapHash: Data) -> Data)?

    /// Progress callback fired once per accepted part (receiver) and once per
    /// `request()` (sender). Mirrors python `self.__progress_callback`
    /// (RNS/Resource.py:350/884-887/1070-1073).
    private var progressCallback: (@Sendable (Resource) async -> Void)?

    /// Resource-conclusion callback. Mirrors python `self.callback`
    /// (RNS/Resource.py:185/350, set in `accept`/`__init__`). RNS runs the Link's
    /// `resource_concluded` bookkeeping + this callback ONLY when it is registered
    /// (e.g. cancel(), RNS/Resource.py:1099-1104). This port routes the normal
    /// success conclusion through the Link's `ResourceCallbacks`, so this optional
    /// is usually nil; it exists so cancel() can faithfully gate
    /// `link.resourceConcluded(self)` on callback presence (a cancelled/FAILED
    /// transfer must not record/propagate its window unless a callback was set).
    private var completionCallback: (@Sendable (Resource) async -> Void)?

    // MARK: - Data

    /// Original uncompressed data (outbound only)
    private var originalData: Data?

    /// Original uncompressed size
    public private(set) var originalSize: Int = 0

    /// Prepared data (compressed if beneficial, with random hash prepended)
    private var preparedData: Data?

    /// Transfer size (prepared data size)
    public private(set) var transferSize: Int = 0

    /// Whether data was compressed
    public private(set) var compressed: Bool = false

    /// Assembled data (available after assemble() completes successfully).
    ///
    /// For multi-segment inbound transfers this is read back from the on-disk
    /// `storagepath` after the final segment assembles. Mirrors python's
    /// `self.data = open(self.storagepath, "rb")` surfacing (Resource.py:737),
    /// while preserving the existing in-RAM `Data` contract for callers.
    public private(set) var assembledData: Data?

    /// Forward hook: file URL of the assembled (decrypted, decompressed,
    /// metadata-stripped) resource bytes for inbound transfers. New addition
    /// (see port-deviations.md) — python surfaces a file handle
    /// (Resource.py:737); we additionally expose the URL so callers can stream
    /// large resources from disk instead of materializing `assembledData`.
    public private(set) var assembledFileURL: URL?

    // MARK: - Segmentation (Outbound)
    //
    // Faithful port of python RNS Resource segmentation (Resource.py:273-314,
    // :765-821). Data larger than MAX_EFFICIENT_SIZE is staged (metadata+data)
    // to a temp file and split into a chain of <=MAX_EFFICIENT_SIZE segments.
    // Each segment is an independent Resource (own random_hash / hashmap /
    // encryption) reading its plaintext chunk from the shared input file via
    // seek/read, exactly as python's `Resource(self.input_file, ...)` does.

    /// Outbound staging tempfile holding metadata||plaintext for split
    /// resources. Mirrors python `self.input_file` (Resource.py:277, :314).
    /// nil for single-segment (<=MAX_EFFICIENT_SIZE) transfers.
    private var inputFileURL: URL?

    /// Open read handle into `inputFileURL` for seek/read of segment chunks.
    private var inputFileHandle: FileHandle?

    /// Whether this segment owns `inputFileURL` (the first segment that staged
    /// the file). Only the owner unlinks it on cleanup, so later segments
    /// sharing the same file don't delete it out from under siblings — though
    /// in practice segments are processed strictly sequentially.
    private var ownsInputFile: Bool = false

    /// Total plaintext size (metadata_size + data_size). Drives total_segments.
    /// Mirrors python `self.total_size` (Resource.py:283).
    private var totalPlaintextSize: Int = 0

    /// Packed metadata prefix (3-byte big-endian length || msgpack) prepended
    /// to segment 1 only. Mirrors python `self.metadata` (Resource.py:266).
    /// Empty when there is no metadata.
    private var metadata: Data = Data()

    /// Size of the packed metadata prefix. Mirrors python `self.metadata_size`
    /// (Resource.py:258, :267).
    public private(set) var metadataSize: Int = 0

    /// 1-based index of this segment. Mirrors python `self.segment_index`
    /// (Resource.py:286/300).
    public private(set) var segmentIndex: Int = 1

    /// Total number of segments in the logical resource. Mirrors python
    /// `self.total_segments` (Resource.py:286/299).
    public private(set) var totalSegments: Int = 1

    /// Whether this logical resource is split into >1 segment. Mirrors python
    /// `self.split` (Resource.py:288/301).
    public private(set) var split: Bool = false

    /// First-segment hash, used as the `o` (original_hash) advertisement field
    /// and the inbound storagepath key for every segment of the chain.
    /// Mirrors python `self.original_hash` (Resource.py:446/448).
    public private(set) var originalHash: Data?

    /// Whether bz2 auto-compression was requested. Carried to next segments.
    /// Mirrors python `self.auto_compress_option` (Resource.py:366).
    private var autoCompressOption: Bool = true

    /// The eagerly-prepared next segment (if any). Mirrors python
    /// `self.next_segment` (Resource.py:255).
    public private(set) var nextSegment: Resource?

    /// Whether next-segment preparation has begun. Mirrors python
    /// `self.preparing_next_segment` (Resource.py:254).
    private var preparingNextSegment: Bool = false

    /// Stored linkEncrypt closure so segments after the first can prepare
    /// themselves (the Link passes it in once on the first segment). Swift
    /// adaptation: python re-uses `self.link.encrypt` directly; the swift
    /// Resource doesn't reach into Link for the token, so the closure is
    /// captured here and threaded to child segments.
    private var linkEncryptClosure: ((Data) throws -> Data)?

    // MARK: - Segmentation (Inbound)

    /// Inbound on-disk storagepath that decrypted plaintext is appended to as
    /// each segment assembles. Mirrors python `self.storagepath`
    /// (Resource.py:199, open("ab") at :708).
    private var storageFileURL: URL?

    /// Whether the inbound advertisement set the metadata flag (adv.x). Mirrors
    /// python `self.has_metadata` (Resource.py:207-208). Used to strip the
    /// metadata prefix from segment 1 during assemble (Resource.py:696).
    private var inboundHasMetadata: Bool = false

    // MARK: - Parts

    /// Size of each part (Link SDU)
    public private(set) var partSize: Int = 0

    /// Number of parts
    public private(set) var numParts: Int = 0

    /// Parts array (for inbound resources)
    private var parts: [Data?] = []

    /// Hashmap (4-byte hash per part)
    public private(set) var hashmap: Data?

    // MARK: - State

    /// Current resource state
    public private(set) var state: ResourceState = .none

    /// State observation stream continuation
    private var stateContinuation: AsyncStream<ResourceState>.Continuation?

    // MARK: - Link

    /// Associated link (weak to avoid retain cycles)
    public weak var link: Link?

    /// Send callback for encrypted packet transmission
    private var sendCallback: ((Data) async throws -> Void)?

    /// Decrypt callback for link decryption of assembled resource data
    private var decryptCallback: ((Data) throws -> Data)?

    // MARK: - Window Management

    /// Window manager for flow control
    private let windowManager: ResourceWindow = ResourceWindow()

    /// Transfer start time (for rate calculation)
    private var transferStartTime: Date?

    /// Last request time (for timeout detection)
    private var lastRequestTime: Date?

    /// Parts received status (true if received)
    private var partsReceived: [Bool] = []

    /// Current hashmap segment (1-based, incremented as HMU requests arrive)
    public private(set) var currentHashmapSegment: Int = 1

    /// Total hashmap segments needed
    public private(set) var totalHashmapSegments: Int = 1

    /// Whether we're waiting for a hashmap update (HMU) from the sender.
    /// When true, no further RESOURCE_REQ should be sent until HMU arrives.
    public private(set) var waitingForHMU: Bool = false

    // MARK: - Initialization (Outbound)

    /// Create outbound resource with data to send.
    ///
    /// Mirrors python `Resource.__init__(data, link, ...)` for the entry path
    /// where `data` is a bytes object (Resource.py:248, :316-323). The actual
    /// segmentation/staging decision is deferred to `prepare()` (the swift
    /// analog of where python's __init__ does its tempfile staging at
    /// :273-314), because staging requires the metadata size and part size
    /// which the swift port resolves at prepare-time.
    ///
    /// - Parameters:
    ///   - data: Original data to transfer
    ///   - link: Associated link for transfer
    ///   - requestId: Associated request ID (16 bytes) or nil
    ///   - isResponse: Whether this is a response resource
    ///   - autoCompress: Whether to attempt bz2 compression
    public init(
        data: Data,
        link: Link,
        metadata: Data? = nil,
        requestId: Data? = nil,
        isResponse: Bool = false,
        autoCompress: Bool = true
    ) {
        self.originalData = data
        self.originalSize = data.count
        self.link = link
        self.requestId = requestId
        self.isResponse = isResponse
        self.isInitiator = true
        self.autoCompressOption = autoCompress
        self.state = .none

        // Metadata packing (RNS/Resource.py:260-268): pack the metadata bytes as a
        // msgpack binary, prefix its length as a 3-byte big-endian header
        // (`struct.pack(">I", n)[1:]`), and flag the resource as metadata-bearing.
        // `metadataSize` (== self.metadata.count) is folded into `total_size` by
        // resolveSegmentPlaintext and surfaced via adv flag bit5 (`x`).
        if let metadata = metadata {
            let packed = packMsgPack(.binary(metadata))
            // python raises SystemError if packed_metadata > METADATA_MAX_SIZE
            // (RNS/Resource.py:263-264). Here we clamp by simply not attaching
            // oversized metadata (logged) so construction can't throw — see
            // port-deviations.md.
            if packed.count <= ResourceConstants.METADATA_MAX_SIZE {
                var meta = Data()
                let n = packed.count
                meta.append(UInt8((n >> 16) & 0xFF))
                meta.append(UInt8((n >> 8) & 0xFF))
                meta.append(UInt8(n & 0xFF))
                meta.append(packed)
                self.metadata = meta
                self.metadataSize = meta.count
            } else {
                logger.error("Resource metadata size \(packed.count) exceeds METADATA_MAX_SIZE; dropping metadata")
            }
        }
    }

    /// Create an outbound *segment* resource backed by a shared input file.
    ///
    /// Faithful port of python `__prepare_next_segment` (Resource.py:765-780),
    /// which constructs `Resource(self.input_file, self.link, ...,
    /// segment_index = self.segment_index+1, original_hash=self.original_hash,
    /// ...)`. The plaintext for this segment is read (via seek/read) from the
    /// shared `inputFileURL` during `prepare()` → `resolveSegmentPlaintext()`.
    ///
    /// - Parameters:
    ///   - inputFileURL: Shared staging file (metadata||plaintext).
    ///   - totalPlaintextSize: metadata_size + data_size (python total_size).
    ///   - metadataSize: Size of the metadata prefix (python sent_metadata_size).
    ///   - segmentIndex: 1-based index of this segment.
    ///   - originalHash: First segment's hash (python original_hash).
    ///   - link: Associated link.
    ///   - requestId: Associated request ID or nil.
    ///   - isResponse: Whether this is a response resource.
    ///   - autoCompress: Whether to attempt bz2 compression.
    ///   - linkEncrypt: Closure to link-encrypt this segment's blob.
    private init(
        inputFileURL: URL,
        totalPlaintextSize: Int,
        metadataSize: Int,
        segmentIndex: Int,
        originalHash: Data?,
        link: Link,
        requestId: Data?,
        isResponse: Bool,
        autoCompress: Bool,
        linkEncrypt: @escaping (Data) throws -> Data
    ) {
        self.inputFileURL = inputFileURL
        self.totalPlaintextSize = totalPlaintextSize
        self.metadataSize = metadataSize
        self.segmentIndex = segmentIndex
        self.originalHash = originalHash
        self.link = link
        self.requestId = requestId
        self.isResponse = isResponse
        self.isInitiator = true
        self.autoCompressOption = autoCompress
        self.linkEncryptClosure = linkEncrypt
        self.state = .none
    }

    // MARK: - Initialization (Inbound)

    /// Create inbound resource from advertisement.
    ///
    /// Mirrors python `Resource.accept` field assignment (Resource.py:174-205),
    /// including the segmentation fields (`segment_index`=adv.i,
    /// `total_segments`=adv.l, `split`=adv.l>1, `original_hash`=adv.o) that
    /// drive multi-segment storagepath append/conclude logic.
    ///
    /// - Parameters:
    ///   - advertisement: Resource advertisement packet
    ///   - link: Associated link for transfer
    public init(advertisement: ResourceAdvertisement, link: Link) {
        self.hash = advertisement.hash
        self.randomHash = advertisement.randomHash
        self.transferSize = advertisement.transferSize
        self.originalSize = advertisement.dataSize
        // python `self.total_size = adv.d` (RNS/Resource.py:176) — drives
        // `totalDataSize` / split progress. Same value for every segment.
        self.totalPlaintextSize = advertisement.dataSize
        self.numParts = advertisement.numParts
        self.requestId = advertisement.requestId
        self.isResponse = advertisement.flags.isResponseFlag
        self.isInitiator = false
        self.compressed = advertisement.flags.isCompressed
        self.link = link
        self.state = .advertised

        // Segmentation fields (python Resource.accept :201-205, :207-208).
        self.originalHash = advertisement.originalHash
        self.segmentIndex = advertisement.segmentIndex
        self.totalSegments = advertisement.totalSegments
        self.split = advertisement.totalSegments > 1
        self.inboundHasMetadata = advertisement.flags.hasMetadataFlag

        // Initialize parts array with nil placeholders
        self.parts = Array(repeating: nil, count: advertisement.numParts)

        // Store hashmap chunk from first segment
        self.hashmap = advertisement.hashmapChunk

        // Initialize parts received tracking
        self.partsReceived = Array(repeating: false, count: advertisement.numParts)

        // Start transfer timer
        self.transferStartTime = Date()
    }

    // MARK: - State Observation

    /// AsyncStream for observing resource state changes.
    ///
    /// Yields the current state immediately upon subscription, then yields
    /// each subsequent state change. The stream finishes when the resource
    /// reaches a terminal state.
    ///
    /// - Returns: AsyncStream that yields ResourceState values
    public var stateUpdates: AsyncStream<ResourceState> {
        AsyncStream { continuation in
            self.stateContinuation = continuation
            continuation.yield(self.state)

            continuation.onTermination = { @Sendable _ in
                // Cleanup if needed
            }
        }
    }

    /// Transition to a new state.
    ///
    /// State transitions are validated to ensure they follow the expected
    /// lifecycle. Terminal states (.complete, .failed, .rejected, .cancelled)
    /// cannot be transitioned from.
    ///
    /// - Parameter newState: Target state
    /// - Throws: ResourceError.invalidState if transition is invalid
    public func transitionState(to newState: ResourceState) throws {
        guard state != newState else { return }

        // Validate transition
        guard ResourceState.canTransition(from: state, to: newState) else {
            throw ResourceError.invalidState(
                expected: "valid transition from \(state)",
                actual: "\(newState)"
            )
        }

        state = newState
        stateContinuation?.yield(newState)
    }

    /// Transition from advertised to transferring state.
    ///
    /// Called by the sender when the first RESOURCE_REQ is received from the peer.
    /// This matches Python's behavior where `Resource.request()` transitions to
    /// TRANSFERRING on the first incoming request.
    public func transitionToTransferring() {
        if state == .advertised {
            state = .transferring
            stateContinuation?.yield(.transferring)
        }
    }

    // MARK: - Send Callback

    /// Set the callback for sending encrypted packets via the link.
    ///
    /// The send callback is invoked when the resource needs to send packets
    /// (advertisement, parts, hashmap updates) over the link. The link handles
    /// encryption and framing.
    ///
    /// - Parameter callback: Async closure that encrypts and sends data
    public func setSendCallback(_ callback: @escaping (Data) async throws -> Void) {
        self.sendCallback = callback
    }

    /// Set the callback for link-decrypting assembled resource data.
    ///
    /// Called by the receiver to decrypt the assembled encrypted parts
    /// before stripping the random prefix and decompressing.
    public func setDecryptCallback(_ callback: @escaping (Data) throws -> Data) {
        self.decryptCallback = callback
    }

    // MARK: - Outbound Transfer

    /// Send resource advertisement over the link.
    ///
    /// Prepares and sends the advertisement packet for THIS resource segment.
    /// The advertisement contains resource metadata (size, hash, flags) and the
    /// first hashmap (HMU) chunk. A resource segment whose part count exceeds
    /// HASHMAP_MAX_LEN ships its remaining hashmap via sendHashmapUpdate().
    ///
    /// Flow:
    /// 1. Check state is queued (after prepare())
    /// 2. Get advertisement for this segment (segmentIndex)
    /// 3. Encode with MessagePack
    /// 4. Frame with resourceAdvertisement context (0x01)
    /// 5. Send via callback (link encrypts and sends)
    /// 6. Transition to advertised state
    ///
    /// - Parameter linkMDU: Link MDU for hashmap segmentation
    /// - Throws: ResourceError if state is invalid or send fails
    public func sendAdvertisement(linkMDU: Int) async throws {
        guard state == .queued else {
            throw ResourceError.invalidState(
                expected: "queued",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        // Get advertisement for THIS segment. python advertises with the
        // segment's own index (ResourceAdvertisement(self), i=self.segment_index,
        // Resource.py:1292); the hashmap chunk packed is always HMU-chunk 0
        // (pack(segment=0), Resource.py:1333).
        let advertisement = try getAdvertisement(segment: segmentIndex, linkMDU: linkMDU)

        // Encode with MessagePack
        let advertisementData = try advertisement.pack()

        // Frame with context byte
        var packet = Data()
        packet.append(ResourcePacketContext.resourceAdvertisement)
        packet.append(advertisementData)

        // Send via link (encrypts and sends)
        try await send(packet)

        // Transition to advertised
        try transitionState(to: .advertised)
    }

    /// Send a resource part over the link.
    ///
    /// Sends a single part with its index. The receiver uses the index to
    /// validate the part hash against the hashmap and store it in the correct
    /// position for assembly.
    ///
    /// Packet format:
    /// - Context byte: 0x03 (resourceData)
    /// - Part index: 2 bytes big-endian
    /// - Part data: variable length
    ///
    /// - Parameter index: Part index (0-based)
    /// - Throws: ResourceError if state is invalid or send fails
    public func sendPart(at index: Int) async throws {
        guard state == .transferring else {
            throw ResourceError.invalidState(
                expected: "transferring",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        // Get part data
        let partData = try getPart(at: index)

        // Frame: context (1) + part data
        // Python identifies parts by hash, NOT by index.
        // Python receive_part(): part_hash = get_map_hash(packet.data)
        // So we send raw part data only (no index prefix).
        var packet = Data()
        packet.append(ResourcePacketContext.resource)
        packet.append(partData)

        // Send via link (encrypts and sends)
        try await send(packet)
    }

    /// Send hashmap update for additional segments.
    ///
    /// For resources requiring multiple hashmap segments (due to size constraints),
    /// this sends raw hashmap bytes for the next segment. The receiver uses these
    /// to build the complete hashmap for part validation.
    ///
    /// Python wire format (Resource.py line 1000):
    ///   `hmu = self.hash + umsgpack.packb([segment, hashmap])`
    /// Python receiver (Resource.py line 442):
    ///   `update = umsgpack.unpackb(plaintext[HASHLENGTH//8:])`
    ///   `self.hashmap_update(update[0], update[1])`
    ///
    /// Packet format:
    /// - Context byte: 0x04 (resourceHMU)
    /// - Resource hash: 32 bytes
    /// - Msgpack([segment_index, raw_hashmap_bytes])
    ///
    /// - Parameters:
    ///   - segment: Segment number (1-based internal, converted to 0-based for wire)
    ///   - linkMDU: Link MDU for hashmap segmentation
    /// - Throws: ResourceError if state is invalid or send fails
    public func sendHashmapUpdate(segment: Int, linkMDU: Int) async throws {
        guard state == .transferring else {
            throw ResourceError.invalidState(
                expected: "transferring",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        guard let resourceHash = hash, let fullHashmap = hashmap else {
            throw ResourceError.invalidState(
                expected: "prepared (hash/hashmap available)",
                actual: "\(state)"
            )
        }

        // Convert 1-based segment to 0-based for hashmap indexing
        let zeroBasedSegment = segment - 1
        let maxLength = ResourceHashmap.hashmapMaxLength(linkMDU: linkMDU)
        guard let hashmapChunk = ResourceHashmap.getHashmapSegment(
            hashmap: fullHashmap,
            segment: zeroBasedSegment,
            maxLength: maxLength
        ) else {
            throw ResourceError.transferFailed(reason: "Hashmap segment \(segment) out of range")
        }

        // Python wire format: resource_hash(32) + msgpack([segment, hashmap_bytes])
        let hmuPayload = packMsgPack(.array([
            .int(Int64(zeroBasedSegment)),
            .binary(Data(hashmapChunk))
        ]))

        // Frame: context byte + resource hash + msgpack payload
        var packet = Data()
        packet.append(ResourcePacketContext.resourceHMU)
        packet.append(resourceHash)
        packet.append(hmuPayload)

        // Send via link (encrypts and sends)
        try await send(packet)
    }

    /// Send the next hashmap segment when the receiver reports exhaustion.
    ///
    /// Called by the Link when a RESOURCE_REQ arrives with exhausted=true,
    /// meaning the receiver has used all part hashes from the current segment
    /// and needs more.
    ///
    /// - Parameter linkMDU: Link MDU for segmentation calculation
    /// - Returns: True if a new segment was sent, false if all segments already sent
    public func sendNextHashmapSegment(linkMDU: Int) async throws -> Bool {
        let nextSegment = currentHashmapSegment + 1
        guard nextSegment <= totalHashmapSegments else {
            return false
        }
        currentHashmapSegment = nextSegment
        try await sendHashmapUpdate(segment: nextSegment, linkMDU: linkMDU)
        return true
    }

    /// Send hashmap update for a specific wire segment (0-based).
    ///
    /// Used when computing the segment from `last_map_hash` in the exhaustion
    /// request (matches Python RNS behavior). Python computes:
    ///   `segment = part_index // HASHMAP_MAX_LEN`
    /// where `part_index` is looked up from the receiver's `last_map_hash`.
    /// The next segment (segment + 1) is then sent as the HMU.
    ///
    /// This is more robust than the sequential counter approach because it
    /// handles duplicate exhaustion requests, retransmissions, and packet loss
    /// correctly — the sender always sends the segment the receiver actually needs.
    ///
    /// - Parameters:
    ///   - wireSegment: 0-based wire segment to send
    ///   - linkMDU: Link MDU for segmentation calculation
    /// - Returns: True if the segment was sent, false if out of range
    public func sendHashmapForWireSegment(_ wireSegment: Int, linkMDU: Int) async throws -> Bool {
        // Convert wire segment (0-based) to internal (1-based)
        let internalSegment = wireSegment + 1
        guard internalSegment <= totalHashmapSegments else {
            return false
        }
        // Update tracking to match actual state
        currentHashmapSegment = internalSegment
        try await sendHashmapUpdate(segment: internalSegment, linkMDU: linkMDU)
        return true
    }

    /// Apply a hashmap segment received from the sender.
    ///
    /// Canonical RNS-faithful name and contract for `hashmap_update(segment,
    /// hashmap)` (RNS/Resource.py:492-503): write the 4-byte map-hashes of `chunk`
    /// into the receiver's hashmap at slot `i + segment * HASHMAP_MAX_LEN`, growing
    /// `hashmapHeight` for each newly-filled slot, then clear the HMU wait flag and
    /// resume requesting parts. FAILED-guarded (RNS/Resource.py:493). Idempotent:
    /// re-applying an already-covered segment grows nothing and returns `false`.
    ///
    /// PORT-DEVIATION (see port-deviations.md): RNS keeps `self.hashmap` as a list
    /// of per-slot entries (`[None]*total_parts`); this port keeps a CONTIGUOUS
    /// blob that grows as sequentially-numbered segments arrive (the order RNS's
    /// HMU handshake actually uses). `hashmapHeight` is therefore the contiguous
    /// coverage rather than an out-of-order filled-slot count.
    ///
    /// - Parameters:
    ///   - segment: 0-based wire segment number from the HMU packet.
    ///   - chunk: Concatenated 4-byte map-hashes for this segment.
    /// - Returns: `true` if coverage grew (newly-applied segment), `false` if it
    ///   was a duplicate.
    @discardableResult
    public func hashmapUpdate(segment: Int, hashmap chunk: Data) async -> Bool {
        // FAILED / terminal late-packet guard (RNS/Resource.py:493).
        guard state != .failed && state != .cancelled && state != .corrupt && state != .rejected else {
            return false
        }

        // RNS hashmap_update unconditionally sets status = TRANSFERRING (when not
        // FAILED) at its top, before request_next (RNS/Resource.py:493-494). This
        // self-heals an inbound receiver that took an HMU while still ADVERTISED
        // (an HMU racing ahead of the accept()/TRANSFERRING transition), rather
        // than relying entirely on the Link having ordered accept() before any
        // HMU. Only ADVERTISED→TRANSFERRING is a meaningful self-heal here; the
        // other non-terminal states for a hashmap-receiving resource are already
        // TRANSFERRING.
        if state == .advertised {
            state = .transferring
            stateContinuation?.yield(.transferring)
        }

        hashmapUpdatesReceived += 1

        let maxLength = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
        let beforeCoverage = (hashmap?.count ?? 0) / ResourceConstants.MAPHASH_LEN
        let segmentStartPart = segment * maxLength

        var grew = false
        if segmentStartPart < beforeCoverage {
            // Duplicate HMU for a segment we already cover — ignore (idempotent).
            logger.debug("Ignoring duplicate HMU segment \(segment) (coverage=\(beforeCoverage))")
        } else {
            if segmentStartPart > beforeCoverage {
                // Gap: segment is ahead of our contiguous coverage.
                logger.warning("HMU segment \(segment) starts at part \(segmentStartPart) but coverage is \(beforeCoverage)")
            }
            if var existing = hashmap {
                existing.append(chunk)
                hashmap = existing
            } else {
                hashmap = chunk
            }
            grew = ((hashmap?.count ?? 0) / ResourceConstants.MAPHASH_LEN) > beforeCoverage
        }

        // Clear HMU wait flag and resume requesting parts (RNS/Resource.py:502-503).
        waitingForHMU = false
        if state == .transferring {
            try? await requestNextParts()
        }
        return grew
    }

    /// Number of contiguous hashmap slots currently filled. Mirrors python
    /// `self.hashmap_height` (RNS/Resource.py:211/499) for the sequential-HMU model.
    public var hashmapHeight: Int {
        (hashmap?.count ?? 0) / ResourceConstants.MAPHASH_LEN
    }

    /// Backwards-compatible thin alias for `hashmapUpdate(segment:hashmap:)`.
    ///
    /// The Link (RNS/Link.py HMU handler) and the conformance bridge call this
    /// name; it forwards to the canonical `hashmapUpdate` so existing call sites
    /// keep compiling during the migration.
    @discardableResult
    public func appendHashmapSegment(_ segmentData: Data, wireSegment: Int) async -> Bool {
        await hashmapUpdate(segment: wireSegment, hashmap: segmentData)
    }

    // MARK: - Data Preparation (Outbound)

    /// Prepare resource for transfer.
    ///
    /// Performs data preparation steps:
    /// 1. Compress data with bz2 (fallback to uncompressed if larger)
    /// 2. Generate 4-byte random hash
    /// 3. Prepend random hash to data
    /// 4. Calculate resource hash (SHA256 of random_hash || data)
    /// 5. Generate hashmap (4-byte hash per part)
    /// 6. Transition to queued state
    ///
    /// - Parameters:
    ///   - partSize: Size of each part (Link SDU)
    ///   - autoCompress: Whether to attempt compression (default true)
    /// - Throws: ResourceError if state is invalid or compression fails
    /// Prepare resource for transfer.
    ///
    /// Follows Python RNS Resource.__init__() sequence:
    /// 1. Compress data if beneficial
    /// 2. Prepend random data prefix (4 bytes) to compressed data
    /// 3. Link-encrypt the entire blob (random prefix + compressed data)
    /// 4. Generate SEPARATE random_hash (4 bytes) for hashmap computation
    /// 5. Compute resource hash = SHA256(original_data + random_hash)
    /// 6. Generate hashmap from encrypted data parts + random_hash
    /// 7. Split encrypted data for transfer
    ///
    /// - Parameters:
    ///   - partSize: Maximum part size (Link SDU/MDU)
    ///   - linkEncrypt: Closure to link-encrypt the data blob
    ///   - autoCompress: Whether to auto-compress data
    public func prepare(partSize: Int, linkEncrypt: @escaping (Data) throws -> Data, autoCompress: Bool = true) throws {
        guard state == .none else {
            throw ResourceError.invalidState(expected: "none", actual: "\(state)")
        }

        // Capture so child segments can prepare themselves without reaching
        // into the Link for the token (see linkEncryptClosure note).
        self.linkEncryptClosure = linkEncrypt
        self.autoCompressOption = autoCompress
        self.partSize = partSize

        // Resolve this segment's plaintext (metadata||chunk for segment 1, or
        // just the chunk for later segments) and the chain's total_segments.
        // Mirrors python __init__ staging (Resource.py:273-323): bytes data
        // larger than MAX_EFFICIENT_SIZE is staged to a tempfile and split.
        let segmentPlaintext = try resolveSegmentPlaintext()

        // ---- From here down mirrors python __init__ :384-478 / the existing
        // single-segment pipeline, but operating on THIS segment's plaintext. ----

        // Step 1: Compress this segment's plaintext if beneficial.
        // python only compresses when data_size <= auto_compress_limit
        // (Resource.py:390); compress() already short-circuits on autoCompress.
        let compressionResult = try ResourceCompression.compress(
            segmentPlaintext,
            autoCompress: autoCompress
        )
        self.compressed = compressionResult.compressed

        // Step 2: Generate random data prefix (4 bytes) — prepended before encryption
        // This is NOT the same as self.randomHash (used for hashmap)
        var randomPrefix = Data(count: ResourceConstants.RANDOM_HASH_SIZE)
        _ = randomPrefix.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, ResourceConstants.RANDOM_HASH_SIZE, buffer.baseAddress!)
        }

        // Step 3: Build pre-encryption blob: random_prefix + compressed_data
        var preEncryptionData = Data()
        preEncryptionData.append(randomPrefix)
        preEncryptionData.append(compressionResult.data)

        // Step 4: Link-encrypt the entire blob
        let encryptedData = try linkEncrypt(preEncryptionData)
        self.preparedData = encryptedData
        self.transferSize = encryptedData.count

        // Number of parts from the encrypted blob (python `hashmap_entries`,
        // RNS/Resource.py:432-433).
        self.numParts = (encryptedData.count + partSize - 1) / partSize
        self.sentFlags = Array(repeating: false, count: self.numParts)

        // Steps 5-7: collision-guarded random_hash + hash + expected_proof + hashmap.
        //
        // Faithful port of python's `while not hashmap_ok` remap loop
        // (RNS/Resource.py:435-474): a fresh random_hash is drawn, hash /
        // expected_proof are derived, then each part's map_hash is checked against
        // a sliding collision-guard window (capped at COLLISION_GUARD_SIZE,
        // RNS/Resource.py:464-465). On a duplicate map_hash the loop restarts with a
        // new random_hash (RNS/Resource.py:457-460). In the common case the loop
        // runs exactly once and produces byte-identical output to the previous
        // single-pass generation.
        //
        // PORT-DEVIATION (see port-deviations.md): a fresh random_hash CANNOT break a
        // collision between two BYTE-IDENTICAL encrypted parts (both hash to the same
        // map_hash regardless of random_hash). RNS never hits this because real link
        // encryption makes every part unique; an identity/echo encryptor over
        // repetitive plaintext does not, which would spin this loop forever. We
        // therefore cap the retries (RETRY_LIMIT) and, on the final attempt, accept
        // the hashmap even with a duplicate map_hash — exactly the old single-pass
        // behavior — so the loop always terminates.
        let collisionGuardSize = ResourceHashmap.collisionGuardSize(
            hashmapMaxLength: ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
        )
        var hashmapOK = false
        var attempt = 0
        while !hashmapOK {
            attempt += 1
            // Final attempt: accept duplicates rather than spin forever on
            // genuinely-identical parts.
            let ignoreCollisions = attempt >= ResourceConstants.RETRY_LIMIT

            // Fresh random_hash (RNS/Resource.py:440).
            var randomBytes = Data(count: ResourceConstants.RANDOM_HASH_SIZE)
            _ = randomBytes.withUnsafeMutableBytes { buffer in
                SecRandomCopyBytes(kSecRandomDefault, ResourceConstants.RANDOM_HASH_SIZE, buffer.baseAddress!)
            }

            // hash = full_hash(plaintext + random_hash) (RNS/Resource.py:441).
            var hashInput = Data(segmentPlaintext)
            hashInput.append(randomBytes)
            let computedHash = Hashing.fullHash(hashInput)

            // expected_proof = full_hash(plaintext + hash) (RNS/Resource.py:443).
            var proofInput = Data(segmentPlaintext)
            proofInput.append(computedHash)
            let computedProof = Hashing.fullHash(proofInput)

            // Build the hashmap over the ENCRYPTED parts, with the collision guard.
            var builtHashmap = Data()
            var guardList: [Data] = []
            hashmapOK = true
            for i in 0..<self.numParts {
                let lo = encryptedData.startIndex + i * partSize
                let hi = min(lo + partSize, encryptedData.endIndex)
                let partData = Data(encryptedData[lo..<hi])
                var mapHash = ResourceHashmap.partHash(partData, randomHash: randomBytes)
                // PORT-DEVIATION test seam (see port-deviations.md): force-remap hook,
                // inert when unset.
                if let inj = mapHashInjector {
                    mapHash = inj(randomBytes, i, mapHash)
                }
                if !ignoreCollisions && guardList.contains(mapHash) {
                    // Collision — restart with a new random_hash (RNS/Resource.py:457-460).
                    hashmapOK = false
                    self.hashmapRebuildCount += 1
                    break
                }
                guardList.append(mapHash)
                if guardList.count > collisionGuardSize {
                    guardList.removeFirst()
                }
                builtHashmap.append(mapHash)
            }

            if hashmapOK {
                self.randomHash = randomBytes
                self.hash = computedHash
                self.expectedProof = computedProof
                self.hashmap = builtHashmap
                // original_hash = first segment's hash; later segments inherit it
                // (set in the segment initializer). RNS/Resource.py:445-448.
                if self.originalHash == nil {
                    self.originalHash = computedHash
                }
            }
        }

        // Step 8: Transition to queued
        try transitionState(to: .queued)
    }

    /// PORT-DEVIATION test seam (python uses monkeypatching of `get_map_hash`):
    /// install a closure consulted per part during the `prepare()` collision-guard
    /// loop so a test can deterministically force a map-hash collision and exercise
    /// the remap path. MUST be cleared (or never set) in production. See
    /// port-deviations.md.
    public func setMapHashInjector(
        _ fn: (@Sendable (_ randomHash: Data, _ partIndex: Int, _ defaultMapHash: Data) -> Data)?
    ) {
        self.mapHashInjector = fn
    }

    /// Resolve this segment's plaintext bytes, staging to a tempfile and
    /// computing `total_segments` for oversized data.
    ///
    /// Faithful port of python `Resource.__init__` data handling
    /// (Resource.py:273-323):
    /// - For a bytes payload whose `metadata_size + len(data)` exceeds
    ///   MAX_EFFICIENT_SIZE, python copies it to a `tempfile.TemporaryFile()`
    ///   (:274-279) and then takes the file branch.
    /// - The file branch computes `total_segments = ((total_size-1)//
    ///   MAX_EFFICIENT_SIZE)+1` (:299), seeks to this segment's position
    ///   (:305-312) and reads its chunk (:313). Segment 1's first read is
    ///   `MAX_EFFICIENT_SIZE - metadata_size` because the metadata prefix
    ///   occupies part of the first segment's budget (:303,:307).
    /// - The metadata prefix is prepended to the chunk for segment 1 only
    ///   (:331-333) — note: python writes metadata into the staging file is
    ///   NOT done; metadata lives in `self.metadata` and is concatenated after
    ///   the read. The staging file holds ONLY the data bytes; segment seek
    ///   positions therefore account for metadata_size via first_read_size.
    private func resolveSegmentPlaintext() throws -> Data {
        // Segment >1: read from the shared input file (set by the segment
        // initializer). python file branch with segment_index > 1.
        if segmentIndex > 1 {
            guard let url = inputFileURL else {
                throw ResourceError.transferFailed(reason: "Segment \(segmentIndex) has no input file")
            }
            // total_segments was computed by segment 1; recompute identically
            // here so the advertisement carries the right value.
            self.totalSegments = ((totalPlaintextSize - 1) / ResourceConstants.MAX_EFFICIENT_SIZE) + 1
            self.split = true
            let handle = try openInputHandle(url)
            // python Resource.py:303,309-310:
            //   first_read_size = MAX_EFFICIENT_SIZE - metadata_size
            //   seek_position   = first_read_size + ((seek_index-1)*MAX_EFFICIENT_SIZE)
            //   segment_read_size = MAX_EFFICIENT_SIZE
            let firstReadSize = ResourceConstants.MAX_EFFICIENT_SIZE - metadataSize
            let seekIndex = segmentIndex - 1
            let seekPosition = firstReadSize + ((seekIndex - 1) * ResourceConstants.MAX_EFFICIENT_SIZE)
            try handle.seek(toOffset: UInt64(seekPosition))
            let chunk = (try handle.read(upToCount: ResourceConstants.MAX_EFFICIENT_SIZE)) ?? Data()
            // Later segments carry no metadata prefix (python :331-333 only
            // prepends when has_metadata AND we're building segment 1's data;
            // for later segments self.metadata is empty).
            return chunk
        }

        // Segment 1 (or single-segment). Need the source bytes.
        guard let data = originalData else {
            throw ResourceError.transferFailed(reason: "No original data to prepare")
        }

        let totalSize = data.count + metadataSize
        self.totalPlaintextSize = totalSize

        if totalSize <= ResourceConstants.MAX_EFFICIENT_SIZE {
            // Single in-RAM segment — python :285-290. No tempfile.
            self.totalSegments = 1
            self.segmentIndex = 1
            self.split = false
            // python :331-333: prepend metadata prefix when present.
            if metadataSize > 0 {
                var out = Data(metadata)
                out.append(data)
                return out
            }
            return data
        }

        // Oversized: stage the DATA bytes to a tempfile and split.
        // python :274-279 (copy bytes to tempfile) then :299-313 (file branch).
        self.totalSegments = ((totalSize - 1) / ResourceConstants.MAX_EFFICIENT_SIZE) + 1
        self.segmentIndex = 1
        self.split = true

        let url = try stageInputFile(data)
        self.inputFileURL = url
        self.ownsInputFile = true
        // Release the in-RAM copy now that it's on disk — python `del
        // original_data` (Resource.py:279) frees the in-RAM copy; the
        // remaining segments stream from `input_file`.
        self.originalData = nil

        let handle = try openInputHandle(url)
        // python :305-307: segment 1 seeks to 0 and reads first_read_size.
        let firstReadSize = ResourceConstants.MAX_EFFICIENT_SIZE - metadataSize
        try handle.seek(toOffset: 0)
        let chunk = (try handle.read(upToCount: firstReadSize)) ?? Data()

        // python :331-333: prepend metadata prefix to segment 1's chunk.
        if metadataSize > 0 {
            var out = Data(metadata)
            out.append(chunk)
            return out
        }
        return chunk
    }

    /// Stage `data` into a per-extension-private tempfile under
    /// NSTemporaryDirectory(), named by original-hash-or-uuid. Returns its URL.
    ///
    /// Swift adaptation of python `tempfile.TemporaryFile()` (Resource.py:277)
    /// — see port-deviations.md (temp-file location). We can't know the
    /// resource hash before hashing, so the OUTBOUND staging file is named by
    /// a fresh UUID (the inbound storagepath, which CAN use the hash, is named
    /// by hash hex — matching python's resourcepath/<original_hash.hex()>).
    private func stageInputFile(_ data: Data) throws -> URL {
        let name = "rns_resource_out_\(UUID().uuidString)"
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(name)
        try data.write(to: url, options: .atomic)
        return url
    }

    /// Open (or reuse) the read handle into the shared input file.
    private func openInputHandle(_ url: URL) throws -> FileHandle {
        if let h = inputFileHandle { return h }
        let h = try FileHandle(forReadingFrom: url)
        self.inputFileHandle = h
        return h
    }

    /// Get part data at specified index.
    ///
    /// - Parameter index: Part index (0-based)
    /// - Returns: Part data (may be smaller than partSize for last part)
    /// - Throws: ResourceError if index out of range or data not prepared
    public func getPart(at index: Int) throws -> Data {
        guard let data = preparedData else {
            throw ResourceError.invalidState(
                expected: "queued or later (data prepared)",
                actual: "\(state)"
            )
        }

        guard index >= 0 && index < numParts else {
            throw ResourceError.partMissing(index: index)
        }

        let startOffset = index * partSize
        let endOffset = min(startOffset + partSize, data.count)
        return data[startOffset..<endOffset]
    }

    /// Get advertisement for a specific segment.
    ///
    /// - Parameters:
    ///   - segment: Segment index (1-based)
    ///   - linkMDU: Link MDU for hashmap segmentation
    /// - Returns: ResourceAdvertisement for the specified segment
    /// - Throws: ResourceError if data not prepared
    public func getAdvertisement(segment: Int, linkMDU: Int) throws -> ResourceAdvertisement {
        guard let resourceHash = hash,
              let randomHash = randomHash,
              let hashmap = hashmap else {
            throw ResourceError.invalidState(
                expected: "queued (data prepared)",
                actual: "\(state)"
            )
        }

        guard let firstSegmentHash = originalHash else {
            throw ResourceError.invalidState(
                expected: "queued (original hash set)",
                actual: "\(state)"
            )
        }

        // Calculate hashmap segments needed for HMU tracking.
        // NOTE: hashmap segments (HMU chunks) are DISTINCT from resource
        // segments. A single resource segment whose part count exceeds
        // HASHMAP_MAX_LEN still ships its hashmap across multiple HMU chunks;
        // that is tracked here. Resource segmentation (data > MAX_EFFICIENT_SIZE)
        // is tracked by segmentIndex/totalSegments below.
        let maxLength = ResourceHashmap.hashmapMaxLength(linkMDU: linkMDU)
        let hashmapSegments = ResourceHashmap.segmentCount(
            totalParts: numParts,
            maxLength: maxLength
        )
        // Cache for HMU tracking (number of hashmap chunks, not resource segments)
        self.totalHashmapSegments = hashmapSegments

        // Flags. python sets s=split, x=has_metadata (Resource.py:1290-1291,
        // packed at :1307). has_metadata is true on every segment of a
        // metadata-bearing chain (sent_metadata_size>0 → Resource.py:271);
        // here metadataSize>0 only ever holds for segment 1 in this port's
        // current callers (no metadata API yet), so x tracks metadataSize>0.
        //
        // u (bit3, is_request) and p (bit4, is_response) are derived from the
        // request_id, NOT a bare `isResponse` flag — faithful port of
        // ResourceAdvertisement.__init__ (RNS/Resource.py:1295-1307):
        //   self.u = self.p = False
        //   if self.q != None:
        //       if not resource.is_response: self.u = True;  self.p = False
        //       else:                        self.u = False; self.p = True
        // i.e. both bits are ZERO when there is no associated request_id, u is
        // set for an outbound request (q!=nil & !is_response) and p for a
        // response (q!=nil & is_response). The previous code passed only
        // `isResponse` and never set u, so a swift-originated request advertised
        // with u=0 and a python peer's ResourceAdvertisement.is_request()
        // (q!=None && u, Resource.py:1242-1247) treated it as a plain resource —
        // breaking Link request/response interop.
        let advertisesRequestId = requestId != nil
        let isRequestAdv = advertisesRequestId && !isResponse
        let isResponseAdv = advertisesRequestId && isResponse
        let flags = ResourceFlags(
            encrypted: true,  // Always encrypted for link-based resources
            compressed: compressed,
            split: split,
            isRequest: isRequestAdv,
            isResponse: isResponseAdv,
            hasMetadata: metadataSize > 0
        )

        // Faithful segment advertisement. `d`(dataSize) = total chain plaintext
        // size (python self.d = resource.total_size, Resource.py:1282) — the
        // SAME value for every segment. `o`(originalHash) = first segment hash
        // (Resource.py:1286). `i`/`l` = this segment's index / chain total.
        return ResourceAdvertisement.create(
            transferSize: transferSize,
            dataSize: totalPlaintextSize,
            numParts: numParts,
            resourceHash: resourceHash,
            randomHash: randomHash,
            hashmap: hashmap,
            originalHash: firstSegmentHash,
            segment: segment,
            totalSegments: totalSegments,
            requestId: requestId,
            flags: flags,
            linkMDU: linkMDU
        )
    }

    // MARK: - Outbound Segmentation

    /// Whether there are more segments after this one. Mirrors python
    /// `self.segment_index < self.total_segments` (Resource.py:516, :788).
    public var hasMoreSegments: Bool {
        segmentIndex < totalSegments
    }

    /// Eagerly prepare the next segment as a new Resource backed by the shared
    /// input file.
    ///
    /// Faithful port of python `__prepare_next_segment` (Resource.py:765-780):
    /// constructs the next `Resource(self.input_file, self.link, ...,
    /// segment_index=self.segment_index+1, original_hash=self.original_hash,
    /// ...)`, then calls `prepare()` on it (python defers prepare to the new
    /// Resource's __init__; in this port prepare() is a separate step, so we
    /// invoke it here to materialize the next segment's hash/hashmap before
    /// advertising). Idempotent: returns the already-prepared next segment.
    ///
    /// - Parameter linkEncrypt: closure to link-encrypt the segment's blob;
    ///   defaults to the captured `linkEncryptClosure`.
    /// - Returns: the prepared next-segment Resource, or nil if this is the
    ///   final segment.
    ///
    /// Concurrency adaptation (see port-deviations.md): python prepares the
    /// next segment on a daemon thread (`__prepare_next_segment` via
    /// `threading.Thread`, Resource.py:517/768). This port prepares it inline
    /// in an async call, which is the faithful actor-model equivalent — the
    /// next segment isn't advertised until preparation completes either way.
    @discardableResult
    public func prepareNextSegment(linkEncrypt: ((Data) throws -> Data)? = nil) async throws -> Resource? {
        guard hasMoreSegments else { return nil }
        if let existing = nextSegment { return existing }

        guard let link = link else {
            throw ResourceError.transferFailed(reason: "No link for next segment preparation")
        }
        guard let url = inputFileURL else {
            throw ResourceError.transferFailed(reason: "No input file for next segment preparation")
        }
        guard let encrypt = linkEncrypt ?? linkEncryptClosure else {
            throw ResourceError.transferFailed(reason: "No linkEncrypt closure for next segment preparation")
        }

        self.preparingNextSegment = true

        // python Resource.py:769-778
        let next = Resource(
            inputFileURL: url,
            totalPlaintextSize: totalPlaintextSize,
            metadataSize: metadataSize,
            segmentIndex: segmentIndex + 1,
            originalHash: originalHash,
            link: link,
            requestId: requestId,
            isResponse: isResponse,
            autoCompress: autoCompressOption,
            linkEncrypt: encrypt
        )
        // Prepare the next segment now (reads its chunk via seek/read).
        try await next.prepare(partSize: partSize, linkEncrypt: encrypt, autoCompress: autoCompressOption)

        // Propagate the progress callback to the new segment (python
        // __prepare_next_segment :779-780).
        if let cb = progressCallback {
            await next.setProgressCallback(cb)
        }

        self.nextSegment = next
        return next
    }

    /// Hand off ownership of the shared input file (and its open handle) to the
    /// next segment, so the chain's staging tempfile survives until the LAST
    /// segment concludes. Mirrors python's implicit sharing of `self.input_file`
    /// across segments (the same file object is passed to each
    /// `Resource(self.input_file, ...)`, Resource.py:769) and the close of it
    /// only on the final segment's proof (Resource.py:796-797).
    ///
    /// Called by the Link right before advertising the next segment, paralleling
    /// python `validate_proof` nulling out the current segment's `input_file`
    /// (Resource.py:816) once the next segment holds it.
    public func transferInputFileOwnership(to next: Resource) async {
        // Close our own read handle (the next segment opens its own on demand);
        // do NOT unlink — the next segment now owns the file.
        try? inputFileHandle?.close()
        inputFileHandle = nil
        let url = inputFileURL
        let owns = ownsInputFile
        ownsInputFile = false
        inputFileURL = nil
        if let url = url {
            await next.adoptInputFile(url, owns: owns)
        }
    }

    /// Adopt the shared input file from the previous segment (assume ownership
    /// so cleanup unlinks it once this segment — if final — concludes).
    public func adoptInputFile(_ url: URL, owns: Bool) {
        // Only set if not already pointing at it (prepareNextSegment already
        // wired inputFileURL via the initializer); take over ownership flag.
        if inputFileURL == nil { inputFileURL = url }
        if owns { ownsInputFile = true }
    }

    // MARK: - Inbound Transfer

    /// Accept an advertised resource and begin transfer.
    ///
    /// Called by the receiver after receiving an advertisement to indicate
    /// they want to receive this resource. Transitions to transferring state
    /// and prepares to request parts.
    ///
    /// Flow:
    /// 1. Check state is advertised (after receiving advertisement)
    /// 2. Record transfer start time
    /// 3. Transition to transferring state
    /// 4. Request first batch of parts via requestNextParts()
    ///
    /// - Throws: ResourceError if state is invalid
    public func accept() async throws {
        guard state == .advertised else {
            throw ResourceError.invalidState(
                expected: "advertised",
                actual: "\(state)"
            )
        }

        // Set transfer start time for rate calculation
        transferStartTime = Date()

        // Transition to transferring
        try transitionState(to: .transferring)

        // Request first batch of parts
        try await requestNextParts()
    }

    /// Reject an advertised resource.
    ///
    /// Called by the receiver to indicate they do not want to receive this
    /// resource. Sends a reject packet and transitions to rejected state.
    ///
    /// Packet format:
    /// - Context byte: 0x07 (resourceReject)
    ///
    /// - Throws: ResourceError if state is invalid or send fails
    public func reject() async throws {
        guard state == .advertised else {
            throw ResourceError.invalidState(
                expected: "advertised",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        // Send reject packet
        var packet = Data()
        packet.append(ResourcePacketContext.resourceReject)

        try await send(packet)

        // Transition to rejected
        try transitionState(to: .rejected)
    }

    /// Mark this (initiator) outbound resource REJECTED on receipt of a
    /// RESOURCE_RCL from the receiver.
    ///
    /// Faithful port of RNS `_rejected()` (RNS/Resource.py:1106-1117): the
    /// receiver sends a RESOURCE_RCL when it declines an advertisement
    /// (ACCEPT_APP predicate false, RNS/Link.py:1094) or aborts an in-flight
    /// transfer (its bz2 decompression-overflow CORRUPT teardown,
    /// RNS/Resource.py:1081-1084); the Link's RCL dispatch then drives the
    /// matching outgoing Resource here (RNS/Link.py:1145-1147). RNS sets
    /// `status = REJECTED` for ANY `status < COMPLETE` — ADVERTISED, TRANSFERRING
    /// and AWAITING_PROOF alike (the decompression-bomb sender has already sent
    /// every part, so it sits in AWAITING_PROOF when the RCL lands). The staged
    /// `transitionState`/`canTransition` FSM only permits `.advertised → .rejected`,
    /// so this mirrors RNS's direct status assignment and deliberately bypasses
    /// it. The Link performs the surrounding cancel_outgoing_resource +
    /// resource_concluded bookkeeping (RNS/Resource.py:1110-1115 → Link), so this
    /// method only flips the state + notifies observers.
    public func markRejected() {
        // RNS guard: only `status < COMPLETE` is rejectable (RNS/Resource.py:1107);
        // a resource already in a terminal state is left untouched.
        guard !state.isTerminal else { return }
        state = .rejected
        stateContinuation?.yield(.rejected)
    }

    /// Release any disk / file-handle resources held by this transfer.
    ///
    /// Closes the outbound input-file read handle and unlinks the outbound
    /// staging tempfile (only if this segment owns it) and the inbound
    /// storagepath tempfile. Safe to call multiple times (idempotent).
    ///
    /// Mirrors python's resource teardown: the input_file is closed on the
    /// final segment's proof (Resource.py:796-797) and the inbound storagepath
    /// is unlinked after the assembled callback (Resource.py:744). This port
    /// consolidates both into one idempotent method invoked on every terminal
    /// path (complete, corrupt/.failed, link close, cancel, reject).
    ///
    /// - Parameter abandonChain: when true, unlink the inbound storagepath even
    ///   for a NON-final segment. Used on abnormal teardown (corrupt segment,
    ///   cancel, reject, link close) where the whole chain is being abandoned,
    ///   so the partial on-disk file must not leak. Defaults to false so the
    ///   normal per-segment conclusion only unlinks on the final segment
    ///   (matching python's unlink-after-final-callback, Resource.py:744).
    public func cleanup(abandonChain: Bool = false) {
        // Close + unlink outbound input file (python input_file close :796-797).
        try? inputFileHandle?.close()
        inputFileHandle = nil
        if ownsInputFile, let url = inputFileURL {
            try? FileManager.default.removeItem(at: url)
        }
        inputFileURL = nil
        ownsInputFile = false

        // Unlink inbound storagepath (python os.unlink(storagepath) :744).
        // Normal path: only the FINAL segment unlinks (earlier segments leave
        // the file for the next segment to append to). Abnormal teardown
        // (abandonChain) unlinks unconditionally so a partial file can't leak.
        if let url = storageFileURL {
            // The assembled bytes are already preserved in RAM (assembledData)
            // by the time the final segment concludes, so unlinking here doesn't
            // strand a reader. assembledFileURL still references the (now-removed)
            // path as a forward hook — callers wanting the on-disk file must copy
            // it out before the resource concludes (see port-deviations.md).
            if abandonChain || segmentIndex >= totalSegments {
                try? FileManager.default.removeItem(at: url)
                storageFileURL = nil
            }
        }
    }

    /// Request next batch of parts from sender.
    ///
    /// Uses window manager to determine which parts should be requested based
    /// on current window size and consecutive completion height. Sends a request
    /// packet containing the 4-byte truncated hashes of the desired parts.
    ///
    /// Packet format:
    /// - Context byte: 0x02 (resourceRequest)
    /// - Part hashes: sequence of 4-byte truncated hashes from hashmap
    ///
    /// - Throws: ResourceError if state is invalid or send fails
    public func requestNextParts() async throws {
        guard state == .transferring else {
            throw ResourceError.invalidState(
                expected: "transferring",
                actual: "\(state)"
            )
        }

        // Don't send requests while waiting for a hashmap update
        guard !waitingForHMU else { return }

        // RNS resets outstanding_parts to 0 at the very top of request_next, then
        // counts only the parts requested in THIS batch (RNS/Resource.py:937). The
        // counter therefore always reflects the in-flight request, never drifting
        // across batches. `markRequested(count:)` below re-adds the batch count.
        windowManager.resetOutstanding()

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        guard let resHash = hash else {
            throw ResourceError.transferFailed(reason: "No resource hash available for request")
        }

        // Get indices of parts to request
        let indices = getNextPartIndices()

        guard !indices.isEmpty else {
            // No parts to request (all received or window full)
            return
        }

        // Determine hashmap coverage: how many parts have hashmap entries
        let hashmapCoverage = (hashmap?.count ?? 0) / ResourceConstants.MAPHASH_LEN

        // Separate indices into those we have hashes for and those beyond hashmap
        var requestableIndices: [Int] = []
        var hashmapExhausted = false
        for index in indices {
            if index < hashmapCoverage {
                requestableIndices.append(index)
            } else {
                hashmapExhausted = true
            }
        }

        // Build request data:
        // Python Resource.request_next():
        //   flag = 0x00 (normal) or 0xFF (hashmap exhausted)
        //   If exhausted: flag(0xFF) + last_map_hash(4) + resource_hash(32) + part_hashes
        //   If normal: flag(0x00) + resource_hash(32) + part_hashes
        var requestData = Data()

        // Track how many parts we're actually requesting (for window outstanding count).
        // Only count indices we actually send hashes for — NOT indices beyond hashmap.
        let actualRequestCount: Int

        if hashmapExhausted {
            // Hashmap exhausted: need HMU from sender
            // last_map_hash = hash of the last part we know about in the hashmap
            let lastKnownIndex = hashmapCoverage - 1
            let lastMapHash: Data
            if lastKnownIndex >= 0 {
                lastMapHash = (try? getPartHash(at: lastKnownIndex)) ?? Data(repeating: 0, count: ResourceConstants.MAPHASH_LEN)
            } else {
                lastMapHash = Data(repeating: 0, count: ResourceConstants.MAPHASH_LEN)
            }
            requestData.append(0xFF) // HASHMAP_IS_EXHAUSTED
            requestData.append(lastMapHash) // 4-byte last map hash
            requestData.append(resHash) // 32-byte resource hash
            for index in requestableIndices {
                let partHash = try getPartHash(at: index)
                requestData.append(partHash)
            }
            actualRequestCount = requestableIndices.count
            waitingForHMU = true
            // Count hashmap-exhausted requests (HMU handshake observability,
            // RNS/Resource.py:959-963).
            hmuRequestsSent += 1
        } else {
            // Normal request: all indices have hashmap entries
            requestData.append(0x00) // HASHMAP_IS_NOT_EXHAUSTED
            requestData.append(resHash)
            for index in requestableIndices {
                let partHash = try getPartHash(at: index)
                requestData.append(partHash)
            }
            actualRequestCount = requestableIndices.count
        }

        // Mark only actually-sent parts as outstanding (not beyond-hashmap indices)
        windowManager.markRequested(count: actualRequestCount)

        // Frame with context byte
        var packet = Data()
        packet.append(ResourcePacketContext.resourceRequest)
        packet.append(requestData)

        // Send via link (encrypts and sends)
        try await send(packet)
    }

    /// Handle received part packet.
    ///
    /// Parses the part index and data from a received DATA packet, validates
    /// the part hash, stores the part, and checks for transfer completion.
    /// If the window allows, requests more parts automatically.
    ///
    /// Packet format:
    /// - Part index: 2 bytes big-endian
    /// - Part data: variable length
    ///
    /// - Parameter data: Part packet data (index + part data)
    /// - Returns: true if transfer is complete (all parts received)
    /// - Throws: ResourceError if parsing or validation fails
    public func handlePartPacket(_ data: Data) async throws -> Bool {
        guard data.count > 0 else {
            throw ResourceError.transferFailed(
                reason: "Part packet empty"
            )
        }

        // Python identifies parts by content hash, NOT by index prefix.
        // Compute SHA256(partData + randomHash)[:4] and find matching entry in hashmap.
        guard let rHash = randomHash, let hmap = hashmap else {
            throw ResourceError.transferFailed(
                reason: "No randomHash or hashmap available for part identification"
            )
        }

        let partData = Data(data)
        let contentHash = ResourceHashmap.partHash(partData, randomHash: rHash)

        // Resolve the part's index by scanning ONLY the current sliding window
        // hashmap[consecutive_index : consecutive_index+window] (RNS/Resource.py:
        // 863-866), NOT the whole hashmap. The 4-byte map-hash is only guaranteed
        // collision-unique within COLLISION_GUARD_SIZE = 2*WINDOW_MAX +
        // HASHMAP_MAX_LEN; on a large resource two parts farther apart than that
        // guard can share a 4-byte map-hash, so a global first-match scan can
        // return the wrong (earlier) index — receivePart's window check then drops
        // it and the real part is never stored (stall/retransmit). Python's
        // windowed search is immune by construction. `cch` is swift's window
        // height (0-based count of leading completed parts; see the receivePart
        // windowed-acceptance note + port-deviations.md for the height model).
        let hashLen = ResourceConstants.MAPHASH_LEN
        let cch = windowManager.height
        let scanEnd = min(cch + windowManager.currentWindow, numParts)
        var index: Int? = nil
        var i = cch
        while i < scanEnd {
            let start = i * hashLen
            let end = start + hashLen
            guard end <= hmap.count else { break }
            if hmap[start..<end] == contentHash {
                index = i
                break
            }
            i += 1
        }

        // A part whose map-hash isn't in the current window is silently dropped —
        // RNS receive_part inserts nothing and leaves received_count untouched
        // when no in-window slot matches (RNS/Resource.py:863-892); it does NOT
        // raise. The batch-drain re-request below still runs so the handshake
        // recovers on the next request cycle.
        if let foundIndex = index {
            // Store part (windowed acceptance + hash validation; drops out-of-window
            // / duplicate / mismatching parts rather than throwing).
            _ = try await receivePart(partData, at: foundIndex)
        }

        // Check if all parts received (don't use isComplete which has a state guard)
        if partsReceived.allSatisfy({ $0 }) {
            // All parts received, transition to assembling
            try transitionState(to: .assembling)
            return true
        }

        // Issue the next RESOURCE_REQ only when the current batch has fully drained
        // (outstanding_parts == 0), matching RNS receive_part's `elif
        // self.outstanding_parts == 0: ... self.request_next()` branch
        // (RNS/Resource.py:897-926). The window growth on the same condition is
        // applied inside receivePart. Re-requesting on every part (outstanding <
        // window) produced far chattier traffic and redundant re-sends vs python's
        // batch model.
        if windowManager.outstanding == 0 {
            try await requestNextParts()
        }

        return false
    }

    /// Prove successful resource assembly to the sender.
    ///
    /// Faithful port of python `prove()` (RNS/Resource.py:752-763): compute
    /// `proof = full_hash(self.data + self.hash)` over the FULL per-segment
    /// plaintext (metadata included — `provePlaintext`, NOT the metadata-stripped
    /// `assembledData`) and send `[RESOURCE_PRF][hash(32)][proof(32)]` so it
    /// matches the sender's `expected_proof = full_hash(plaintext + hash)`.
    ///
    /// Called INTERNALLY by `assemble()` on success (RNS/Resource.py:713) — the
    /// auto-prove. Idempotent: sends at most once (`proveCallCount`), so a stray
    /// legacy `sendProof()` call from the Link cannot emit a second RESOURCE_PRF
    /// (would break the no-per-part-proofs invariant). No-op unless the resource is
    /// `.complete`, has not already proven, and has a send callback + plaintext.
    public func prove() async {
        guard state == .complete, proveCallCount == 0 else { return }
        guard let send = sendCallback,
              let resourceHash = hash,
              let plaintext = provePlaintext else { return }

        // proof = full_hash(plaintext + hash) (RNS/Resource.py:755).
        var proofInput = Data(plaintext)
        proofInput.append(resourceHash)
        let proof = Hashing.fullHash(proofInput)

        // Frame: [RESOURCE_PRF][hash(32)][proof(32)]. Sent as a PROOF packet by the
        // link layer (RNS/Resource.py:757).
        var packet = Data()
        packet.append(ResourcePacketContext.resourceProof)
        packet.append(resourceHash)
        packet.append(proof)

        do {
            try await send(packet)
            proveCallCount += 1
        } catch {
            // RNS cancels on proof-send failure (RNS/Resource.py:760-763); here the
            // link's own retry/watchdog handles re-delivery, so we just log to avoid
            // re-entering the Link mid-assemble.
            logger.debug("Resource proof send failed: \(String(describing: error))")
        }
    }

    /// Backwards-compatible thin alias of `prove()`.
    ///
    /// Retained ONLY so existing source (the Link's legacy receive path and the
    /// conformance bridge) keeps compiling during the migration to auto-prove.
    /// Because `prove()` is idempotent, calling this after `assemble()` already
    /// auto-proved is a no-op (CRITICAL: prevents the double-prove that would break
    /// test_resource_no_per_part_proofs). See port-deviations.md.
    public func sendProof() async throws {
        await prove()
    }

    /// Validate a proof received from the receiver (sender side).
    ///
    /// Faithful port of python `validate_proof` (RNS/Resource.py:782-826): ignore
    /// while FAILED (RNS/Resource.py:783); accept only a 64-byte proof whose second
    /// 32 bytes equal `expectedProof`, in which case the resource moves to
    /// `.complete`. PORT-DEVIATION: unlike RNS this does NOT call back into the Link
    /// (`resource_concluded` / next-segment advance) to avoid actor reentrancy — the
    /// Link calls this and then inspects `state` to decide conclude-vs-advance.
    public func validate_proof(_ proofData: Data) async {
        // FAILED / terminal late guard (RNS/Resource.py:783).
        guard state != .failed && state != .cancelled && state != .corrupt && state != .rejected else {
            return
        }
        // Proof is 2*HASHLENGTH bytes = 64 (RNS/Resource.py:784).
        guard proofData.count == 64, let expected = expectedProof else { return }
        let received = Data(proofData.suffix(32))
        guard received == expected else {
            // Mismatch: silently ignore (RNS/Resource.py:822-823).
            return
        }
        // Mark COMPLETE (RNS/Resource.py:786). The Link concludes/advances segments.
        state = .complete
        stateContinuation?.yield(.complete)
    }

    // MARK: - Part Reception (Inbound)

    /// Receive a part from the network with windowed acceptance.
    ///
    /// Faithful port of python `receive_part` (RNS/Resource.py:858-892): a part is
    /// accepted ONLY if its map-hash falls in the current sliding window
    /// `hashmap[cch ..< cch+window]` and its slot is still empty. A part beyond the
    /// window is DROPPED (returned `false`); a duplicate into a filled slot is NOT
    /// recounted. `received_count` increments and the progress callback fires once
    /// per newly-accepted part (RNS/Resource.py:872/884-887). After cancel()/FAILED
    /// every late part is a no-op (RNS/Resource.py:858).
    ///
    /// - Parameters:
    ///   - partData: Part data received.
    ///   - index: Part index (0-based) resolved from the part's map-hash.
    /// - Returns: `true` if the part was newly accepted, `false` if dropped.
    /// - Throws: `ResourceError.partMissing` only for an out-of-range index.
    @discardableResult
    public func receivePart(_ partData: Data, at index: Int) async throws -> Bool {
        // FAILED / terminal late-packet guard (RNS/Resource.py:858).
        guard state != .failed && state != .cancelled && state != .corrupt && state != .rejected else {
            return false
        }
        guard index >= 0 && index < numParts else {
            throw ResourceError.partMissing(index: index)
        }

        // Windowed acceptance: index must lie in [height, height+window).
        //
        // HEIGHT-MODEL NOTE (port-deviations.md): this port's `windowManager.height`
        // is a 0-based EXCLUSIVE count of leading consecutively-completed parts,
        // whereas python's `consecutive_completed_height` is a -1-based INCLUSIVE
        // index (starts at -1, RNS/Resource.py:214). So swift `height` ==
        // python `cch + 1`, and this accept window [height, height+window) is the
        // python window [cch, cch+window) shifted UP by one. It is NOT the literal
        // python window, but it IS internally self-consistent: the request range
        // (getNextPartIndices, also anchored at `height`) and this accept range
        // share the same lower bound, and a sender only sends parts it was asked
        // for, so every accepted part is in-window and interop holds. The
        // conformance bridge reports python-semantic height as `height - 1`.
        // Beyond-window parts are dropped.
        let cch = windowManager.height
        let windowEnd = cch + windowManager.currentWindow
        guard index >= cch && index < windowEnd else {
            return false
        }

        // Don't recount a duplicate into a filled slot (RNS/Resource.py:867).
        guard parts[index] == nil else {
            return false
        }

        // Validate the part's map-hash against the hashmap slot; drop on mismatch
        // (RNS only inserts when `map_hash == part_hash`, RNS/Resource.py:866) or
        // when the slot's hashmap entry hasn't been delivered yet (`== None`).
        if let hashmap = hashmap, let randomHash = randomHash {
            guard let expectedHash = ResourceHashmap.getPartHash(from: hashmap, at: index) else {
                return false
            }
            let actualHash = ResourceHashmap.partHash(partData, randomHash: randomHash)
            guard expectedHash == actualHash else {
                return false
            }
        }

        // Store part (newly-filled slot).
        parts[index] = partData
        partsReceived[index] = true

        // Update window manager (received_count, outstanding, consecutive height).
        windowManager.markReceived(index: index, totalParts: numParts)
        windowManager.updateConsecutiveHeight(parts: partsReceived)

        // RNS receive_part grows the window ONLY when the in-flight request batch
        // fully drains (outstanding_parts == 0) AND the transfer is not yet
        // complete (RNS/Resource.py:894-904): the `if received_count == total ->
        // assemble` branch does NOT grow the window, while the `elif
        // outstanding_parts == 0` branch does (window += 1 toward window_max).
        // Previously this port grew the window only once at full completion,
        // pinning it at WINDOW for the whole transfer and defeating RNS adaptive
        // flow control. (onAllPartsReceived's window_min recompute still differs
        // from RNS's +1 ratchet — a regression-test-constrained deviation, see
        // port-deviations.md.) State transitions stay with the caller
        // (handlePartPacket inbound, handleResourceProof outbound) because inbound
        // goes transferring→assembling→complete and outbound goes
        // transferring→awaitingProof→complete.
        if !partsReceived.allSatisfy({ $0 }) && windowManager.outstanding == 0 {
            windowManager.onAllPartsReceived(transferRate: calculateTransferRate())
        }

        // Per-part progress callback (RNS/Resource.py:884-887).
        await fireProgressCallback()
        return true
    }

    /// PORT-DEVIATION test seam (see port-deviations.md): store a raw part directly
    /// into `parts[index]` WITHOUT per-part map-hash validation, so a deliberately
    /// corrupt part reaches `assemble()`'s full-stream integrity check. Used by the
    /// conformance corrupt-assembly inject command. No equivalent in RNS (which has
    /// no monkeypatch-free way to bypass the per-part check).
    public func injectPartRaw(_ data: Data, at index: Int) async {
        guard index >= 0 && index < numParts else { return }
        parts[index] = data
        partsReceived[index] = true
        windowManager.updateConsecutiveHeight(parts: partsReceived)
    }

    /// Fire the progress callback once (if set). Mirrors python invoking
    /// `self.__progress_callback(self)` (RNS/Resource.py:884-887/1070-1073).
    private func fireProgressCallback() async {
        if let cb = progressCallback {
            await cb(self)
        }
    }

    /// Calculate current transfer rate in bytes per second.
    ///
    /// - Returns: Transfer rate (bytes/sec), or 0 if timing not available
    private func calculateTransferRate() -> Double {
        guard let startTime = transferStartTime else { return 0.0 }

        let elapsed = Date().timeIntervalSince(startTime)
        guard elapsed > 0 else { return 0.0 }

        return Double(transferSize) / elapsed
    }

    // MARK: - Window Flow Control

    /// Get indices of next parts to request.
    ///
    /// Uses window manager to determine which parts should be requested
    /// based on current window size and consecutive completion height.
    ///
    /// NOTE: Does NOT call markRequested — the caller (requestNextParts)
    /// must mark only the indices that are actually sent in the request,
    /// since hashmap exhaustion may reduce the set of requestable indices.
    ///
    /// - Returns: Array of part indices to request
    public func getNextPartIndices() -> [Int] {
        lastRequestTime = Date()
        return windowManager.getRequestRange(parts: partsReceived)
    }

    /// Handle timeout for outstanding parts.
    ///
    /// Reduces window size and returns indices of parts to re-request.
    ///
    /// - Returns: Array of part indices to re-request
    public func handleTimeout() -> [Int] {
        windowManager.onTimeout()

        // Return indices of incomplete parts up to new window size
        return windowManager.getRequestRange(parts: partsReceived)
    }

    // MARK: - Window Accessors

    /// Current window size.
    public var windowSize: Int {
        windowManager.currentWindow
    }

    /// Number of parts currently outstanding (requested but not received).
    public var outstandingCount: Int {
        windowManager.outstanding
    }

    /// Highest consecutive completed part index.
    public var consecutiveHeight: Int {
        windowManager.height
    }

    // MARK: - Part Assembly

    /// Get expected hash for a part from hashmap.
    ///
    /// - Parameter index: Part index (0-based)
    /// - Returns: 4-byte expected hash from hashmap
    /// - Throws: ResourceError if hashmap not available or index out of range
    public func getPartHash(at index: Int) throws -> Data {
        guard let hashmap = hashmap else {
            throw ResourceError.invalidState(
                expected: "hashmap available",
                actual: "no hashmap"
            )
        }

        guard index >= 0 && index < numParts else {
            throw ResourceError.partMissing(index: index)
        }

        let startByte = index * ResourceConstants.MAPHASH_LEN
        let endByte = startByte + ResourceConstants.MAPHASH_LEN

        guard endByte <= hashmap.count else {
            throw ResourceError.partMissing(index: index)
        }

        return hashmap[startByte..<endByte]
    }

    /// Check if all parts have been received.
    public var isComplete: Bool {
        get {
            guard state == .assembling || state == .awaitingProof || state == .complete else {
                return false
            }
            return partsReceived.allSatisfy { $0 }
        }
    }

    /// Count of received parts.
    public var receivedCount: Int {
        get {
            return partsReceived.filter { $0 }.count
        }
    }

    /// Assemble this segment's received parts and append the plaintext to the
    /// per-resource on-disk storagepath.
    ///
    /// Faithful port of python `Resource.assemble` (Resource.py:672-716):
    /// 1. Join parts → stream; link-decrypt (`:676-679`).
    /// 2. Strip the random-hash prefix (`:682`).
    /// 3. Decompress if compressed, with the bz2 max-decompressed-size bound
    ///    (`:684-692`).
    /// 4. Validate `full_hash(self.data + random_hash) == self.hash` — the
    ///    per-segment integrity check (`:694-695`). A mismatch is the CORRUPT
    ///    path (`:715`); we throw, and the Link maps that to `.failed`.
    /// 5. On segment 1 with metadata, split the 3-byte-length-prefixed metadata
    ///    off the front (`:696-704`) — currently this port's senders attach no
    ///    metadata, but the receive path mirrors python so interop with a
    ///    metadata-bearing python sender works.
    /// 6. Append the resulting plaintext to `storagepath` opened "ab"
    ///    (`:708-710`), then mark COMPLETE.
    ///
    /// The chain-completion surfacing (read storagepath back, fire callback,
    /// unlink) is the Link's responsibility (mirrors python `assemble`
    /// `:725-747` running inside the same method, but split out here so the
    /// Link owns inbound-resource lifecycle / dict bookkeeping).
    ///
    /// On a CORRUPT outcome (per-segment hash mismatch, RNS/Resource.py:715, or bz2
    /// over-size overflow, RNS/Resource.py:688-692) this sets `state = .corrupt` +
    /// `corruptReason` and throws `ResourceError.corruptResource`. On success it
    /// auto-proves via `prove()` (RNS/Resource.py:713). PORT-DEVIATION: unlike RNS,
    /// it does NOT call `link.resource_concluded(self)` itself (avoids actor
    /// reentrancy) — the Link concludes after `assemble()` returns/throws.
    ///
    /// - Returns: For the FINAL segment, the fully assembled resource bytes
    ///   (read back from storagepath). For non-final segments, this segment's
    ///   plaintext chunk (the Link does not deliver it).
    /// - Throws: `ResourceError.corruptResource` on the CORRUPT case, or other
    ///   ResourceError on missing parts / decrypt failure.
    public func assemble() async throws -> Data {
        guard state == .assembling || state == .awaitingProof else {
            throw ResourceError.invalidState(
                expected: "assembling or awaitingProof",
                actual: "\(state)"
            )
        }

        // Verify all parts received
        guard isComplete else {
            let missing = partsReceived.enumerated()
                .filter { !$0.element }
                .map { $0.offset }
            throw ResourceError.transferFailed(
                reason: "Missing parts: \(missing)"
            )
        }

        // Step 1: Concatenate all parts (python `stream = b"".join(self.parts)`)
        var assembled = Data()
        for part in parts {
            guard let partData = part else {
                throw ResourceError.transferFailed(reason: "Part is nil despite isComplete check")
            }
            assembled.append(partData)
        }

        // Verify assembled (encrypted) size matches the advertised transfer
        // size. python has no explicit check here, but transferSize is this
        // segment's own `t`; a mismatch means lost/extra parts → corrupt.
        guard assembled.count == transferSize else {
            throw ResourceError.transferFailed(
                reason: "Assembled size \(assembled.count) != transfer size \(transferSize)"
            )
        }

        // Step 2: Link-decrypt the assembled data (python `:678`).
        let decrypted: Data
        if let decrypt = decryptCallback {
            decrypted = try decrypt(assembled)
        } else {
            decrypted = assembled
        }

        // Step 3: Remove random hash prefix (4 bytes) (python `:682`).
        guard decrypted.count >= ResourceConstants.RANDOM_HASH_SIZE else {
            throw ResourceError.transferFailed(
                reason: "Decrypted data too short to contain random hash prefix"
            )
        }
        let dataWithoutRandomHash = decrypted.dropFirst(ResourceConstants.RANDOM_HASH_SIZE)

        // Step 4: Decompress if needed (python `:684-692`). This yields
        // `self.data` — this segment's plaintext (metadata||chunk for seg 1). A bz2
        // stream that decompresses past `maxDecompressedSize` is the CORRUPT /
        // overflow case (RNS/Resource.py:688-692): mark `.corrupt` /
        // `.decompressionOverflow` and throw `corruptResource` (the Link tears the
        // link down). Any other decompress failure is treated as corrupt data.
        let segmentPlaintext: Data
        if compressed {
            do {
                segmentPlaintext = try ResourceCompression.bz2Decompress(
                    Data(dataWithoutRandomHash),
                    expectedSize: originalSize,
                    maxDecompressedSize: self.maxDecompressedSize
                )
            } catch let e as BZ2Error {
                if case .exceedsMaxDecompressedSize = e {
                    markCorrupt(.decompressionOverflow)
                } else {
                    markCorrupt(.hashMismatch)
                }
                throw ResourceError.corruptResource
            } catch {
                markCorrupt(.hashMismatch)
                throw ResourceError.corruptResource
            }
        } else {
            segmentPlaintext = Data(dataWithoutRandomHash)
        }

        // Step 5: Per-segment integrity check (python `:694-695`):
        //   calculated_hash = full_hash(self.data + random_hash); == self.hash ?
        if let randomHash = randomHash, let expectedHash = hash {
            var hashInput = Data(segmentPlaintext)
            hashInput.append(randomHash)
            let calculatedHash = Hashing.fullHash(hashInput)
            guard calculatedHash == expectedHash else {
                // python CORRUPT branch (`:715`): hash mismatch. Receiver concludes
                // quietly (no teardown) — the Link branches on corruptReason.
                markCorrupt(.hashMismatch)
                throw ResourceError.corruptResource
            }
        }

        // Retain the FULL plaintext (metadata included) for prove(), mirroring
        // python keeping `self.data` (RNS/Resource.py:684/755) while the local
        // `data` written to disk is metadata-stripped.
        self.provePlaintext = segmentPlaintext

        // Step 6: Strip metadata prefix on segment 1 (python `:696-704`:
        // `if self.has_metadata and self.segment_index == 1:`).
        var plaintextToStore = segmentPlaintext
        if inboundHasMetadata, segmentIndex == 1, plaintextToStore.count >= 3 {
            // 3-byte big-endian metadata length, then that many metadata bytes
            // (python `:698-699`).
            let b = plaintextToStore
            let mlen = (Int(b[b.startIndex]) << 16) | (Int(b[b.startIndex + 1]) << 8) | Int(b[b.startIndex + 2])
            if 3 + mlen <= plaintextToStore.count {
                // Recover the metadata for delivery (python unpacks it from
                // meta_storagepath, RNS/Resource.py:730-731). We packed it as a
                // msgpack binary on send, so unwrap the `.binary` value back to the
                // original metadata bytes; fall back to the raw packed bytes.
                let lo = b.startIndex + 3
                let hi = lo + mlen
                let packed = Data(b[lo..<hi])
                if let v = try? unpackMsgPack(packed), case .binary(let m) = v {
                    self.receivedMetadata = m
                } else {
                    self.receivedMetadata = packed
                }
                // Remaining data (`data = self.data[3+metadata_size:]`, `:704`).
                plaintextToStore = Data(plaintextToStore.dropFirst(3 + mlen))
            }
        }

        // Step 7: Append plaintext to storagepath ("ab") (python `:708-710`).
        try appendToStorage(plaintextToStore)

        // Mark this segment COMPLETE (python `:711`).
        try transitionState(to: .complete)

        // Auto-prove on success (python `self.prove()` at RNS/Resource.py:713).
        // Idempotent: sends at most one RESOURCE_PRF. No-op when no send callback
        // is wired (e.g. unit tests that drive assemble directly).
        await prove()

        // Surface: on the final segment read the whole storagepath back; this
        // mirrors python `self.data = open(self.storagepath, "rb")` (`:737`)
        // while preserving the in-RAM `assembledData` contract. Non-final
        // segments return their own plaintext (undelivered by the Link).
        if segmentIndex == totalSegments {
            let assembledURL = storageFileURL
            let finalData: Data
            if let url = assembledURL {
                // Read the whole assembled storagepath back. Must THROW on failure, not
                // fall back to `plaintextToStore` — that holds only the LAST segment's
                // chunk, so a silent fallback would deliver a truncated multi-segment
                // payload with no error. A throw routes to the Link's corrupt-assembly
                // handler (non-COMPLETE → resourceConcluded), matching python `assemble()`
                // where a storagepath read failure is caught and sets status=CORRUPT
                // (RNS/Resource.py:47-50, final read at :66).
                finalData = try Data(contentsOf: url)
            } else {
                finalData = plaintextToStore
            }
            self.assembledData = finalData
            self.assembledFileURL = assembledURL
            return finalData
        } else {
            // Non-final segment: data continues accumulating on disk. Expose
            // what we have so far for diagnostics; the Link awaits the next
            // segment advertisement before concluding (python `:748-749`).
            self.assembledFileURL = storageFileURL
            return plaintextToStore
        }
    }

    /// Set the terminal `.corrupt` state + reason (RNS/Resource.py:689/715/721).
    private func markCorrupt(_ reason: CorruptReason) {
        self.corruptReason = reason
        self.state = .corrupt
        stateContinuation?.yield(.corrupt)
    }

    // MARK: - Sender Part-Serving (RNS/Resource.py:982-1073)

    /// Record a RESOURCE_REQ packet hash, returning whether it was newly inserted.
    ///
    /// Storage half of python `self.req_hashlist` (RNS/Resource.py:376). The dedup
    /// CHECK lives in the Link (`if packet.packet_hash not in resource.req_hashlist`,
    /// RNS/Link.py:1113-1115): the Link calls this before serving and only calls
    /// `request(_:)` when it returns `true`, so a re-delivered request never
    /// re-serves. `request()` itself does not re-dedup (single source of truth).
    ///
    /// - Returns: `true` if newly inserted (serve), `false` if a duplicate (skip).
    public func registerRequestHash(_ packetHash: Data) -> Bool {
        if reqHashlist.contains(packetHash) { return false }
        reqHashlist.insert(packetHash)
        return true
    }

    /// Serve parts for an incoming RESOURCE_REQ (sender side).
    ///
    /// Faithful port of python `request(request_data)` (RNS/Resource.py:982-1073):
    /// move to TRANSFERRING; parse the exhausted flag + requested map-hashes; serve
    /// every part in the sliding scope `parts[scope ..< scope+COLLISION_GUARD_SIZE]`
    /// whose map-hash was requested (first send increments `sentPartCount`, a repeat
    /// re-sends byte-identical); on a hashmap-exhausted request resolve the part
    /// index from `last_map_hash`, advance `receiverScopeHeight`, and either cancel
    /// on a misaligned boundary or send the next HMU; finally move to AWAITING_PROOF
    /// when all parts are sent and fire the progress callback.
    public func request(_ requestData: Data) async {
        // FAILED / terminal late guard (RNS/Resource.py:983).
        guard state != .failed && state != .cancelled && state != .corrupt && state != .rejected else {
            return
        }
        guard hash != nil else { return }
        // Sender-only: a prepared outbound resource has per-part sent flags sized to
        // numParts. Guards against indexing an unprepared/inbound resource.
        guard sentFlags.count == numParts, numParts > 0 else { return }

        // -> TRANSFERRING on the first request (RNS/Resource.py:988-990).
        if state != .transferring {
            try? transitionState(to: .transferring)
        }

        let req = Data(requestData)
        guard let first = req.first else { return }
        // HASHMAP_IS_EXHAUSTED == 0xFF (RNS/Resource.py:140/994).
        let wantsMoreHashmap = first == 0xFF
        // pad = 1 + MAPHASH_LEN when exhausted else 1 (RNS/Resource.py:995).
        let pad = wantsMoreHashmap ? (1 + ResourceConstants.MAPHASH_LEN) : 1
        let hashesStart = pad + 32  // + HASHLENGTH//8 (resource hash) (RNS/Resource.py:997)

        // Parse requested 4-byte map-hashes (RNS/Resource.py:1003-1006).
        var requestedMapHashes: [Data] = []
        if req.count > hashesStart {
            let hashesData = Data(req[(req.startIndex + hashesStart)...])
            let count = hashesData.count / ResourceConstants.MAPHASH_LEN
            for i in 0..<count {
                let lo = hashesData.startIndex + i * ResourceConstants.MAPHASH_LEN
                let hi = lo + ResourceConstants.MAPHASH_LEN
                requestedMapHashes.append(Data(hashesData[lo..<hi]))
            }
        }

        // Sliding search scope (RNS/Resource.py:1000-1001/1008-1009).
        let collisionGuardSize = ResourceHashmap.collisionGuardSize(
            hashmapMaxLength: ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
        )
        let searchStart = receiverScopeHeight
        let searchEnd = min(receiverScopeHeight + collisionGuardSize, numParts)

        // Serve matching parts (RNS/Resource.py:1011-1025).
        if searchStart < searchEnd {
            for i in searchStart..<searchEnd {
                guard let mapHash = try? getPartHash(at: i) else { continue }
                guard requestedMapHashes.contains(mapHash) else { continue }
                guard let partData = try? getPart(at: i) else { continue }
                var packet = Data()
                packet.append(ResourcePacketContext.resource)
                packet.append(partData)
                try? await sendCallback?(packet)
                if !sentFlags[i] {
                    sentFlags[i] = true
                    sentPartCount += 1
                }
            }
        }

        // Hashmap-exhausted handling: advance scope + send next HMU (RNS/Resource.py:1027-1064).
        if wantsMoreHashmap && req.count >= 1 + ResourceConstants.MAPHASH_LEN {
            let lastMapHash = Data(req[(req.startIndex + 1)..<(req.startIndex + 1 + ResourceConstants.MAPHASH_LEN)])
            var partIndex = receiverScopeHeight
            if searchStart < searchEnd {
                for i in searchStart..<searchEnd {
                    partIndex += 1
                    if (try? getPartHash(at: i)) == lastMapHash { break }
                }
            }
            // Advance the sender scope floor (RNS/Resource.py:1038).
            receiverScopeHeight = max(partIndex - 1 - ResourceConstants.WINDOW_MAX, 0)

            let hashmapMaxLen = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
            if partIndex % hashmapMaxLen != 0 {
                // Sequencing error (RNS/Resource.py:1040-1043).
                await cancel()
                return
            }
            // segment = part_index // HASHMAP_MAX_LEN (RNS/Resource.py:1045); send it
            // as a 0-based wire HMU.
            let segment = partIndex / hashmapMaxLen
            _ = try? await sendHashmapForWireSegment(segment, linkMDU: LinkConstants.LINK_MDU)
        }

        // All parts sent -> AWAITING_PROOF (RNS/Resource.py:1066-1067).
        if sentPartCount == numParts {
            try? transitionState(to: .awaitingProof)
        }

        // Progress callback (RNS/Resource.py:1070-1073).
        await fireProgressCallback()
    }

    // MARK: - Cancellation (RNS/Resource.py:1075-1104)

    /// Cancel this transfer.
    ///
    /// Faithful port of python `cancel()` (RNS/Resource.py:1075-1104): recurse into
    /// the next segment; if already `.corrupt` the Link owns teardown (this is
    /// reentrancy-safe and a no-op here — RNS/Resource.py:1081-1084 is driven from
    /// the Link via `cancelIncomingResource(corrupt:)`); otherwise move to `.failed`
    /// and, for an initiator, emit RESOURCE_ICL (when the link is active) then ask
    /// the Link to drop the outgoing resource; for a receiver, drop the incoming
    /// resource. Finally run Link conclusion bookkeeping.
    public func cancel() async {
        // Recurse into the next segment first (RNS/Resource.py:1079).
        if let next = nextSegment {
            await next.cancel()
        }

        // CORRUPT path is owned by the Link (no Resource->Link reentrancy here).
        if state == .corrupt {
            return
        }

        // Only cancel from a non-terminal state (RNS/Resource.py:1086 `< COMPLETE`).
        guard !state.isTerminal else { return }

        state = .failed
        stateContinuation?.yield(.failed)

        if isInitiator {
            // Emit RESOURCE_ICL only while the link is active (RNS/Resource.py:1089-1094).
            if let link = link, await link.state == .active,
               let resourceHash = hash, let send = sendCallback {
                var icl = Data()
                icl.append(ResourcePacketContext.resourceCancel)
                icl.append(resourceHash)
                try? await send(icl)
            }
            await link?.cancelOutgoingResource(self)
        } else {
            await link?.cancelIncomingResource(self, corrupt: false)
        }

        // Link conclusion bookkeeping + conclusion callback, gated on a registered
        // callback EXACTLY as RNS (RNS/Resource.py:1099-1104):
        //   if self.callback != None:
        //       self.link.resource_concluded(self)
        //       self.callback(self)
        // `resource_concluded` is the site that records the link's
        // last_resource_window (RNS/Link.py:1284); python deliberately skips it
        // for a FAILED/cancelled transfer with no callback so a cancelled
        // transfer's window is never propagated to the next inbound resource.
        // (The cancel_*_resource removal above also de-lists the resource, so
        // resourceConcluded would be a window-recording no-op anyway, but we
        // mirror the python gate rather than rely on that.)
        if let cb = completionCallback {
            await link?.resourceConcluded(self)
            await cb(self)
        }
    }

    // MARK: - Progress (RNS/Resource.py:1122-1192)

    /// Install the progress callback, fired once per accepted part (receiver) and
    /// once per `request()` (sender). Mirrors python `progress_callback`
    /// (RNS/Resource.py:1122-1124). PORT-DEVIATION: propagation to an
    /// already-prepared `nextSegment` is best-effort and deferred to
    /// `prepareNextSegment` (which copies the callback) to avoid an async hop here.
    public func setProgressCallback(_ cb: @escaping @Sendable (Resource) async -> Void) {
        self.progressCallback = cb
    }

    /// Install the resource-conclusion callback. Mirrors python setting
    /// `resource.callback` (RNS/Resource.py:185/350). When set, cancel() runs the
    /// Link conclusion bookkeeping + this callback, exactly as RNS gates them on
    /// `self.callback != None` (RNS/Resource.py:1099-1104).
    public func setCompletionCallback(_ cb: @escaping @Sendable (Resource) async -> Void) {
        self.completionCallback = cb
    }

    /// Current transfer progress in `[0.0, 1.0]`.
    ///
    /// Faithful port of python `get_progress` (RNS/Resource.py:1126-1181): 1.0 when
    /// COMPLETE on the final segment; otherwise sent/received parts over total
    /// parts, with the split-resource per-segment scaling (RNS/Resource.py:1138-1177).
    public func getProgress() -> Double {
        if state == .complete && segmentIndex == totalSegments {
            return 1.0
        }

        let processed: Double
        let total: Double
        if !split {
            processed = Double(isInitiator ? sentPartCount : receivedCount)
            total = Double(numParts)
        } else {
            // sdu: sender knows partSize; receiver derived it (fall back to a per-part
            // estimate so we never divide by zero).
            let sdu = partSize > 0 ? partSize : max(1, transferSize / max(numParts, 1))
            let maxPartsPerSegment = ceil(Double(ResourceConstants.MAX_EFFICIENT_SIZE) / Double(sdu))
            let processedSegments = Double(segmentIndex - 1)
            let previouslyProcessed = processedSegments * maxPartsPerSegment
            let currentSegmentParts = Double(numParts)
            let factor = currentSegmentParts < maxPartsPerSegment && currentSegmentParts > 0
                ? maxPartsPerSegment / currentSegmentParts
                : 1.0
            let base = Double(isInitiator ? sentPartCount : receivedCount)
            processed = previouslyProcessed + base * factor
            total = Double(totalSegments) * maxPartsPerSegment
        }

        guard total > 0 else { return 0.0 }
        return min(1.0, processed / total)
    }

    // MARK: - Receiver Sizing / Window (RNS/Resource.py:187, :216-219, :192-193)

    /// Derive the receiver's part count from its OWN link SDU instead of trusting
    /// the (tamper-prone) advertised `n`. Mirrors python `total_parts =
    /// ceil(size/sdu)` (RNS/Resource.py:187). Resizes the parts / received buffers.
    /// OWNERSHIP: the Link, if it ever wires this, MUST pass the RESOURCE SDU
    /// (`self.mtu - HEADER_MAXSIZE(35) - IFAC_MIN_SIZE(1)` == `self.mtu - 36`,
    /// RNS/Resource.py:338), NEVER `self.mdu` (the link-encrypted MDU, 431 @ MTU
    /// 500). Passing `self.mdu` would re-derive a SMALLER sdu than a correct
    /// python/swift sender uses (which splits at mtu-36), over-counting parts and
    /// breaking reassembly. Currently this is left unwired: the receiver keys
    /// `numParts` off the advertised `n` (init :491), which is exactly right once
    /// the sender splits at mtu-36 (Link.sendResource).
    public func deriveReceiverPartCount(sdu: Int) async {
        guard sdu > 0 else { return }
        self.partSize = sdu
        let derived = Int(ceil(Double(transferSize) / Double(sdu)))
        guard derived != numParts else { return }
        self.numParts = derived
        self.parts = Array(repeating: nil, count: derived)
        self.partsReceived = Array(repeating: false, count: derived)
        // The hashmap is (re)loaded by the Link via hashmapUpdate(0, adv.m) after
        // this call; leave it untouched here.
    }

    /// Seed the receiver's starting window from the link's last concluded window.
    ///
    /// Mirrors python `if previous_window: resource.window = previous_window`
    /// (RNS/Resource.py:216-219). Cross-actor call from the Link, hence `async`.
    public func applyInheritedWindow(_ window: Int) async {
        windowManager.setInitialWindow(window)
    }

    /// Receiver window lower bound. Mirrors python `self.window_min`
    /// (RNS/Resource.py:193). Default WINDOW_MIN (2).
    public var windowMin: Int { windowManager.windowMin }

    /// Receiver window upper bound. Mirrors python `self.window_max`
    /// (RNS/Resource.py:192). Default WINDOW_MAX_SLOW (10) until upgraded.
    public var windowMax: Int { windowManager.windowMax }

    /// Total logical data size of the resource (metadata + data). Mirrors python
    /// `get_data_size` / `self.total_size` (RNS/Resource.py:283/1200-1204).
    public var totalDataSize: Int { totalPlaintextSize }

    /// Append decrypted plaintext to the inbound storagepath, creating/opening
    /// it in append mode. Faithful to python `open(self.storagepath,"ab")`
    /// (Resource.py:708). The file is named by original-hash hex under
    /// NSTemporaryDirectory() (see port-deviations.md for the path choice;
    /// python uses RNS.Reticulum.resourcepath, Resource.py:199).
    private func appendToStorage(_ data: Data) throws {
        let url = try storageURL()
        let fm = FileManager.default
        // Segment 1 starts a fresh stream: remove any stale storagepath left by
        // an aborted prior transfer of the same logical resource (python relies
        // on unlink-after-completion + a random original_hash so this file
        // never pre-exists; this is a defensive guard for the same-process
        // crash-restart case and doesn't change observable wire behavior).
        if segmentIndex == 1, fm.fileExists(atPath: url.path) {
            try? fm.removeItem(at: url)
        }
        if !fm.fileExists(atPath: url.path) {
            // Create empty file first so FileHandle(forWritingTo:) succeeds.
            fm.createFile(atPath: url.path, contents: nil)
        }
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        try handle.seekToEnd()
        try handle.write(contentsOf: data)
    }

    /// Resolve (memoized) the inbound storagepath URL.
    ///
    /// Keyed DETERMINISTICALLY by the chain's original_hash hex (NO uuid),
    /// faithfully mirroring python `self.storagepath = resourcepath + "/" +
    /// original_hash.hex()` (Resource.py:199). This determinism is REQUIRED for
    /// multi-segment: each inbound segment is a fresh `Resource` (the Link
    /// accepts a new advertisement per segment), and they must all append to
    /// the SAME file — so the key cannot include a per-instance uuid. (The
    /// OUTBOUND staging file, owned by a single Resource, does use a uuid; see
    /// port-deviations.md for the per-side naming rationale.)
    private func storageURL() throws -> URL {
        if let url = storageFileURL { return url }
        let keyHex = (originalHash ?? hash ?? Data()).map { String(format: "%02x", $0) }.joined()
        let name = "rns_resource_in_\(keyHex)"
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(name)
        storageFileURL = url
        return url
    }
}
