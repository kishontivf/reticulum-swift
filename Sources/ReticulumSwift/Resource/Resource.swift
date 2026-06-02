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
        requestId: Data? = nil,
        isResponse: Bool = false,
        autoCompress: Bool = true
    ) {
        self.originalData = data
        self.originalSize = data.count
        self.link = link
        self.requestId = requestId
        self.isResponse = isResponse
        self.autoCompressOption = autoCompress
        self.state = .none
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
        self.numParts = advertisement.numParts
        self.requestId = advertisement.requestId
        self.isResponse = advertisement.flags.isResponseFlag
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

    /// Append a hashmap segment for large resource transfers.
    ///
    /// Called when receiving RESOURCE_HMU packets containing additional
    /// hashmap segments for resources that exceed HASHMAP_MAX_LEN parts.
    ///
    /// Python's `hashmap_update(segment, hashmap)` uses the segment number
    /// as a positional index: `self.hashmap[i + segment * seg_len]`.
    /// We validate the segment matches our current position and append.
    ///
    /// - Parameters:
    ///   - segmentData: Additional hashmap segment data (4-byte hashes)
    ///   - wireSegment: 0-based wire segment number from HMU packet
    public func appendHashmapSegment(_ segmentData: Data, wireSegment: Int) async {
        let maxLength = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
        let currentCoverage = (hashmap?.count ?? 0) / ResourceConstants.MAPHASH_LEN
        let segmentStartPart = wireSegment * maxLength

        if segmentStartPart < currentCoverage {
            // Duplicate HMU for a segment we already have — ignore
            logger.debug("Ignoring duplicate HMU segment \(wireSegment) (coverage=\(currentCoverage))")
            waitingForHMU = false
            if state == .transferring {
                try? await requestNextParts()
            }
            return
        }

        if segmentStartPart > currentCoverage {
            // Gap detected — segment is ahead of our current position
            logger.warning("HMU segment \(wireSegment) starts at part \(segmentStartPart) but coverage is \(currentCoverage)")
        }

        if var existing = hashmap {
            existing.append(segmentData)
            hashmap = existing
        } else {
            hashmap = segmentData
        }
        // Clear HMU wait flag and resume requesting parts
        waitingForHMU = false
        if state == .transferring {
            try? await requestNextParts()
        }
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

        // Step 5: Generate SEPARATE random_hash for hashmap (4 bytes)
        var randomBytes = Data(count: ResourceConstants.RANDOM_HASH_SIZE)
        _ = randomBytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, ResourceConstants.RANDOM_HASH_SIZE, buffer.baseAddress!)
        }
        self.randomHash = randomBytes

        // Step 6: Calculate resource hash = SHA256(segment_plaintext + random_hash)
        // Python: self.hash = RNS.Identity.full_hash(data+self.random_hash)
        // (Resource.py:441) where `data` is this segment's plaintext
        // (metadata+chunk for segment 1, chunk otherwise — Resource.py:331-333).
        var hashInput = Data(segmentPlaintext)
        hashInput.append(randomBytes)
        self.hash = Hashing.fullHash(hashInput)

        // original_hash = first segment's hash; later segments inherit it
        // (set in the segment initializer). python Resource.py:445-448.
        if self.originalHash == nil {
            self.originalHash = self.hash
        }

        // Step 7: Generate hashmap from ENCRYPTED data parts + random_hash
        // Python: get_map_hash(encrypted_segment) = SHA256(encrypted_segment + random_hash)[:4]
        self.hashmap = ResourceHashmap.generateHashmap(
            data: encryptedData,
            partSize: partSize,
            randomHash: randomBytes
        )

        // Calculate number of parts from encrypted data size
        self.numParts = (encryptedData.count + partSize - 1) / partSize

        // Step 8: Transition to queued
        try transitionState(to: .queued)
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
        let flags = ResourceFlags(
            encrypted: true,  // Always encrypted for link-based resources
            compressed: compressed,
            split: split,
            isResponse: isResponse,
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

        // Search hashmap for matching 4-byte hash
        let hashLen = ResourceConstants.MAPHASH_LEN
        var index: Int? = nil
        for i in 0..<numParts {
            let start = i * hashLen
            let end = start + hashLen
            guard end <= hmap.count else { break }
            if hmap[start..<end] == contentHash {
                index = i
                break
            }
        }

        guard let foundIndex = index else {
            throw ResourceError.transferFailed(
                reason: "Part hash not found in hashmap"
            )
        }

        // Store part (validates hash)
        try receivePart(partData, at: foundIndex)

        // Check if all parts received (don't use isComplete which has a state guard)
        if partsReceived.allSatisfy({ $0 }) {
            // All parts received, transition to assembling
            try transitionState(to: .assembling)
            return true
        }

        // Request more parts if window allows
        if windowManager.outstanding < windowManager.currentWindow {
            try await requestNextParts()
        }

        return false
    }

    /// Send proof of successful resource assembly.
    ///
    /// Called by the receiver after successfully assembling all parts.
    /// Python Resource.prove() sends:
    ///   proof = SHA256(assembled_data + resource_hash)
    ///   proof_data = resource_hash(32) + proof(32) = 64 bytes
    /// Python sender validates: proof_data[32:] == expected_proof
    /// where expected_proof = SHA256(original_data + resource_hash)
    ///
    /// Packet format:
    /// - Context byte: 0x05 (resourceProof)
    /// - resource_hash (32 bytes)
    /// - SHA256(assembledData + resource_hash) (32 bytes)
    ///
    /// IMPORTANT: This must be sent as packet_type=PROOF (not DATA).
    /// Python's Link.receive() routes RESOURCE_PRF only in the PROOF branch.
    ///
    /// - Throws: ResourceError if state is invalid or send fails
    public func sendProof() async throws {
        guard state == .complete else {
            throw ResourceError.invalidState(
                expected: "complete",
                actual: "\(state)"
            )
        }

        guard let send = sendCallback else {
            throw ResourceError.transferFailed(reason: "No send callback set")
        }

        guard let resourceHash = hash else {
            throw ResourceError.transferFailed(reason: "No resource hash available")
        }

        guard let assembled = assembledData else {
            throw ResourceError.transferFailed(reason: "No assembled data available for proof")
        }

        // Compute proof = SHA256(assembled_data + resource_hash)
        // Python: proof = RNS.Identity.full_hash(self.data + self.hash)
        var proofInput = assembled
        proofInput.append(resourceHash)
        let proof = Data(SHA256.hash(data: proofInput))

        // Frame: context byte + resource_hash(32) + proof(32) = 65 bytes
        // Python: proof_data = self.hash + proof
        var packet = Data()
        packet.append(ResourcePacketContext.resourceProof)
        packet.append(resourceHash)
        packet.append(proof)

        // Send via link (encrypts and sends as PROOF packet type)
        try await send(packet)
    }

    // MARK: - Part Reception (Inbound)

    /// Receive a part from the network.
    ///
    /// Validates the part hash against the hashmap, stores the part, and
    /// updates window management tracking. When all parts are received,
    /// calculates transfer rate and adjusts window accordingly.
    ///
    /// - Parameters:
    ///   - partData: Part data received
    ///   - index: Part index (0-based)
    /// - Throws: ResourceError if validation fails
    public func receivePart(_ partData: Data, at index: Int) throws {
        guard index >= 0 && index < numParts else {
            throw ResourceError.partMissing(index: index)
        }

        // Validate part hash if hashmap and randomHash available
        if let hashmap = hashmap, let randomHash = randomHash {
            let expectedHash = ResourceHashmap.getPartHash(
                from: hashmap,
                at: index
            )
            let actualHash = ResourceHashmap.partHash(partData, randomHash: randomHash)

            guard expectedHash == actualHash else {
                throw ResourceError.hashmapMismatch(partIndex: index)
            }
        }

        // Store part
        parts[index] = partData
        partsReceived[index] = true

        // Update window manager
        windowManager.markReceived(index: index, totalParts: numParts)
        windowManager.updateConsecutiveHeight(parts: partsReceived)

        // Check if all parts received
        if partsReceived.allSatisfy({ $0 }) {
            // Calculate transfer rate and adjust window
            let rate = calculateTransferRate()
            windowManager.onAllPartsReceived(transferRate: rate)
            // State transition is handled by the caller (handlePartPacket for inbound,
            // handleResourceProof for outbound). Don't transition here because
            // inbound goes transferring→assembling→complete while outbound goes
            // transferring→awaitingProof→complete.
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
    /// - Returns: For the FINAL segment, the fully assembled resource bytes
    ///   (read back from storagepath). For non-final segments, this segment's
    ///   plaintext chunk (the Link does not deliver it).
    /// - Throws: ResourceError on missing parts, decrypt/decompress failure, or
    ///   the per-segment hash-mismatch CORRUPT case.
    public func assemble() throws -> Data {
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
        // `self.data` — this segment's plaintext (metadata||chunk for seg 1).
        let segmentPlaintext: Data
        if compressed {
            // Bound decompression to AUTO_COMPRESS_MAX_SIZE (python
            // max_decompressed_size, Resource.py:687). The buffer hint is the
            // chain total `d` (originalSize) — an upper bound for any one
            // segment's plaintext.
            segmentPlaintext = try ResourceCompression.decompress(Data(dataWithoutRandomHash), expectedSize: originalSize)
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
                // python CORRUPT branch (`:715`). Link maps to `.failed`.
                throw ResourceError.transferFailed(
                    reason: "Segment \(segmentIndex) hash mismatch (corrupt)"
                )
            }
        }

        // Step 6: Strip metadata prefix on segment 1 (python `:696-704`:
        // `if self.has_metadata and self.segment_index == 1:`).
        var plaintextToStore = segmentPlaintext
        if inboundHasMetadata, segmentIndex == 1, plaintextToStore.count >= 3 {
            // 3-byte big-endian metadata length, then that many metadata bytes
            // (python `:698-699`).
            let b = plaintextToStore
            let mlen = (Int(b[b.startIndex]) << 16) | (Int(b[b.startIndex + 1]) << 8) | Int(b[b.startIndex + 2])
            if 3 + mlen <= plaintextToStore.count {
                // python writes the metadata to meta_storagepath (`:700-702`)
                // for the assembled callback. This port has no metadata-consuming
                // callback yet, so the metadata bytes are parsed-and-dropped from
                // the stored stream (see port-deviations.md). The remaining data
                // (`data = self.data[3+metadata_size:]`, `:704`) is what's stored.
                plaintextToStore = Data(plaintextToStore.dropFirst(3 + mlen))
            }
        }

        // Step 7: Append plaintext to storagepath ("ab") (python `:708-710`).
        try appendToStorage(plaintextToStore)

        // Mark this segment COMPLETE (python `:711`).
        try transitionState(to: .complete)

        // Surface: on the final segment read the whole storagepath back; this
        // mirrors python `self.data = open(self.storagepath, "rb")` (`:737`)
        // while preserving the in-RAM `assembledData` contract. Non-final
        // segments return their own plaintext (undelivered by the Link).
        if segmentIndex == totalSegments {
            let assembledURL = storageFileURL
            let finalData: Data
            if let url = assembledURL {
                finalData = (try? Data(contentsOf: url)) ?? plaintextToStore
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
