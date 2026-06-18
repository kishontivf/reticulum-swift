// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ResourceSegmentationTests.swift
//  ReticulumSwiftTests
//
//  Coverage for resource SEGMENTATION (perf/resource-disk-streaming) — the
//  faithful port of python RNS Resource segmentation (Resource.py:273-314,
//  :672-749, :765-821). Drives the real production segmentation code:
//   - prepare() staging + total_segments math (Resource.py:299)
//   - getPart() reading the current segment's file-backed chunk
//   - getAdvertisement() emitting per-segment i/l/o/d fields (Resource.py:1281-1307)
//   - prepareNextSegment() building the next segment from the shared input file
//     (Resource.py:765-780)
//   - assemble() per-segment hash check + storagepath append (Resource.py:694-710)
//
//  These exercise production code only (no reimplementation of the wire logic):
//  a large payload is split, every segment's encrypted parts are pulled via the
//  real getPart()/hashmap, fed into a fresh inbound Resource per segment via the
//  real receivePart()/assemble(), and the on-disk reassembly is compared to the
//  original bytes.
//

import XCTest
@testable import ReticulumSwift

final class ResourceSegmentationTests: XCTestCase {

    private func makeLink() -> Link {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["resource"])
        return Link(destination: dest, identity: identity)
    }

    /// Pull every part of one prepared outbound segment via the real getPart()
    /// + hashmap, feed them into a fresh inbound Resource built from that
    /// segment's real advertisement, and return the inbound Resource AFTER a
    /// successful assemble() (which appends this segment's plaintext to the
    /// shared on-disk storagepath keyed by original_hash).
    @discardableResult
    private func roundTripSegment(_ outSeg: Resource, link: Link) async throws -> Resource {
        let segIndex = await outSeg.segmentIndex
        let adv = try await outSeg.getAdvertisement(segment: segIndex, linkMDU: LinkConstants.LINK_MDU)

        // The advertisement only carries the FIRST HMU chunk of the hashmap.
        // This test sizes segments under HASHMAP_MAX_LEN parts so the whole
        // hashmap fits in that first chunk (HMU is exercised elsewhere); assert
        // that precondition so the test fails loudly if it regresses.
        let numParts = await outSeg.numParts
        let maxLen = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
        XCTAssertLessThanOrEqual(numParts, maxLen,
            "test segment must fit in one HMU chunk (\(numParts) > \(maxLen)); raise partSize")

        let inSeg = Resource(advertisement: adv, link: link)
        // Identity decrypt — matches the identity linkEncrypt used on the
        // outbound side so the per-segment hash check round-trips.
        await inSeg.setDecryptCallback { $0 }

        // Drive to .transferring (what accept() does, minus the network send).
        await inSeg.transitionToTransferring()

        // Feed each real encrypted part through the real receive path.
        for i in 0..<numParts {
            let part = try await outSeg.getPart(at: i)
            try await inSeg.receivePart(part, at: i)
        }

        // All parts in → assemble (appends plaintext to storagepath).
        try await inSeg.transitionState(to: .assembling)
        _ = try await inSeg.assemble()
        return inSeg
    }

    /// Large multi-segment round-trip: a payload larger than MAX_EFFICIENT_SIZE
    /// is split into a chain, every segment is transferred via the real
    /// outbound→inbound part path, and the on-disk reassembled bytes equal the
    /// original. Asserts total_segments math and the o/i/l advertisement fields.
    func testLargeMultiSegmentRoundTrip() async throws {
        let link = makeLink()

        // ~2.5 MiB of non-uniform data so segment boundaries are meaningful and
        // compression is disabled (random-ish bytes don't shrink anyway).
        let totalSize = (5 * (1024 * 1024)) / 2  // 2_621_440 > 2*MAX_EFFICIENT_SIZE
        var original = Data(count: totalSize)
        for i in 0..<totalSize { original[i] = UInt8((i * 31 + 7) & 0xFF) }

        // partSize large enough that each ~1 MiB segment is few parts (< 74).
        let partSize = 256 * 1024

        // First segment.
        let seg1 = Resource(data: original, link: link, autoCompress: false)
        try await seg1.prepare(partSize: partSize, linkEncrypt: { $0 }, autoCompress: false)

        let totalSegments = await seg1.totalSegments
        let expectedSegments = ((totalSize - 1) / ResourceConstants.MAX_EFFICIENT_SIZE) + 1
        XCTAssertEqual(totalSegments, expectedSegments, "total_segments must match python ceil math")
        XCTAssertGreaterThan(totalSegments, 1, "payload should split into >1 segment")
        let split = await seg1.split
        XCTAssertTrue(split, "oversized payload must set split=true")

        let originalHash = await seg1.originalHash
        XCTAssertNotNil(originalHash)

        // Walk the whole chain: round-trip each segment, then prepare+advance.
        var current: Resource? = seg1
        var lastInbound: Resource?
        var segCount = 0
        while let outSeg = current {
            segCount += 1
            let idx = await outSeg.segmentIndex

            // Advertisement field checks (python :1286/:1292-1293/:1282).
            let adv = try await outSeg.getAdvertisement(segment: idx, linkMDU: LinkConstants.LINK_MDU)
            XCTAssertEqual(adv.segmentIndex, idx, "adv.i must be this segment index")
            XCTAssertEqual(adv.totalSegments, totalSegments, "adv.l constant across chain")
            XCTAssertEqual(adv.originalHash, originalHash, "adv.o = first-segment hash for every segment")
            XCTAssertEqual(adv.dataSize, totalSize, "adv.d = total chain plaintext size for every segment")
            XCTAssertTrue(adv.flags.isSplit, "adv split flag set on a chained resource")

            lastInbound = try await roundTripSegment(outSeg, link: link)

            // Prepare + advance to the next segment from the shared input file.
            let hasMore = await outSeg.hasMoreSegments
            if hasMore {
                let next = try await outSeg.prepareNextSegment(linkEncrypt: { $0 })
                XCTAssertNotNil(next, "prepareNextSegment must yield a segment when hasMoreSegments")
                await outSeg.transferInputFileOwnership(to: next!)
                current = next
            } else {
                current = nil
            }
        }
        XCTAssertEqual(segCount, totalSegments, "must transfer exactly total_segments segments")

        // The final inbound segment surfaces the FULLY reassembled resource read
        // back from the on-disk storagepath (python :737).
        let assembled = await lastInbound?.assembledData
        XCTAssertNotNil(assembled, "final segment must surface assembled data")
        XCTAssertEqual(assembled?.count, totalSize, "reassembled size == original size")
        XCTAssertEqual(assembled, original, "reassembled bytes == original bytes")

        // Forward hook is populated for the inbound side (python file handle, :737).
        let fileURL = await lastInbound?.assembledFileURL
        XCTAssertNotNil(fileURL, "assembledFileURL forward hook must be set")

        // Cleanup unlinks the storagepath (python os.unlink, :744).
        await lastInbound?.cleanup()
        if let url = fileURL {
            XCTAssertFalse(FileManager.default.fileExists(atPath: url.path),
                "storagepath must be unlinked after cleanup()")
        }
    }

    /// A payload <= MAX_EFFICIENT_SIZE stays a single in-RAM segment: no
    /// tempfile staging, total_segments == 1, split == false (python :285-290).
    func testSmallResourceIsSingleInRamSegment() async throws {
        let link = makeLink()

        // Comfortably under MAX_EFFICIENT_SIZE (1 MiB - 1), and small enough that its
        // parts fit a single HMU hashmap chunk so roundTripSegment's one-chunk contract
        // holds (64 KiB at LINK_MDU would span multiple HMU chunks — exercised elsewhere).
        let data = Data(repeating: 0x5A, count: 16 * 1024)
        let resource = Resource(data: data, link: link, autoCompress: false)
        try await resource.prepare(partSize: LinkConstants.LINK_MDU, linkEncrypt: { $0 }, autoCompress: false)

        let totalSegments = await resource.totalSegments
        let split = await resource.split
        XCTAssertEqual(totalSegments, 1, "small resource must be a single segment")
        XCTAssertFalse(split, "small resource must not be split")

        // Single-segment advertisement carries l=1, i=1, and the split flag clear.
        let adv = try await resource.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
        XCTAssertEqual(adv.totalSegments, 1)
        XCTAssertEqual(adv.segmentIndex, 1)
        XCTAssertFalse(adv.flags.isSplit, "single-segment advertisement must not set the split flag")
        XCTAssertEqual(adv.dataSize, data.count, "single-segment d == data size (no metadata)")

        // No next segment exists for a single-segment resource.
        let hasMore = await resource.hasMoreSegments
        XCTAssertFalse(hasMore)
        let next = try await resource.prepareNextSegment(linkEncrypt: { $0 })
        XCTAssertNil(next, "single-segment resource has no next segment")

        // It still round-trips through the real part path.
        let inbound = try await roundTripSegment(resource, link: link)
        let assembled = await inbound.assembledData
        XCTAssertEqual(assembled, data, "single-segment reassembly == original")
        await inbound.cleanup()
    }

    /// getPartHash must reject (return nil) an index beyond the loaded hashmap bytes
    /// rather than trapping — a part for an index whose HMU chunk hasn't arrived (or a
    /// malformed/out-of-order peer part) must be rejected, not crash the receiver. This
    /// pins the SIGTRAP fix (the slice was previously unguarded) and mirrors python's
    /// unfilled-hashmap-entry == None.
    func testGetPartHashRejectsOutOfRangeIndex() {
        let oneHash = Data([0x01, 0x02, 0x03, 0x04])  // exactly one 4-byte map hash
        XCTAssertEqual(ResourceHashmap.getPartHash(from: oneHash, at: 0), oneHash,
            "in-range index returns the hash bytes")
        XCTAssertNil(ResourceHashmap.getPartHash(from: oneHash, at: 1),
            "index one past the loaded hashmap returns nil, not a trap")
        XCTAssertNil(ResourceHashmap.getPartHash(from: oneHash, at: 99),
            "far out-of-range index returns nil")
        XCTAssertNil(ResourceHashmap.getPartHash(from: oneHash, at: -1),
            "negative index returns nil")
    }
}
