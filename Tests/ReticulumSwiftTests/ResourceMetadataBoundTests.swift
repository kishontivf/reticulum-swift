// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ResourceMetadataBoundTests.swift
//  ReticulumSwiftTests
//
//  Coverage for the resource METADATA-BOUND fix (PR #24, commit bf01893:
//  "reject metadata > MAX_EFFICIENT_SIZE"). Drives the real outbound
//  Resource(data:link:metadata:) packing path (Resource.swift:400-435) plus the
//  segment-plaintext layout that consumes `metadataSize`
//  (resolveSegmentPlaintext, :1101-1177) and the inbound metadata-recovery path
//  in assemble() (:2189-2213). No wire logic is reimplemented here: the framed
//  metadata size is checked against the SAME production `packMsgPack(.binary:)`
//  the initializer uses, real advertisements expose the `x` (has_metadata) flag,
//  and metadata bytes are recovered through the real receivePart()/assemble()
//  round-trip.
//
//  The clamp under test (Resource.swift:412-434): segment 1 reserves
//  `firstReadSize = MAX_EFFICIENT_SIZE - metadataSize` payload bytes, so framed
//  metadata larger than MAX_EFFICIENT_SIZE yields a NEGATIVE first-segment read
//  size that traps at runtime (`seek(toOffset: UInt64(negative))` on segment 2+).
//  METADATA_MAX_SIZE (16 MiB-1) alone is insufficient because it is LARGER than
//  MAX_EFFICIENT_SIZE (1 MiB-1); the fix adds the MAX_EFFICIENT_SIZE bound and
//  log-and-drops oversized metadata so construction can't produce a trapping
//  segment chain. testOversizedMetadataIsDroppedNotTrapped pins that regression.
//

import XCTest
@testable import ReticulumSwift

final class ResourceMetadataBoundTests: XCTestCase {

    private func makeLink() -> Link {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["resource"])
        return Link(destination: dest, identity: identity)
    }

    /// Pull every part of one prepared outbound segment via the real getPart()
    /// + hashmap, feed them into a fresh inbound Resource built from that
    /// segment's real advertisement, and return the inbound Resource AFTER a
    /// successful assemble(). Mirrors ResourceSegmentationTests.roundTripSegment
    /// so metadata recovery is exercised over the real receive path.
    @discardableResult
    private func roundTripSegment(_ outSeg: Resource, link: Link) async throws -> Resource {
        let segIndex = await outSeg.segmentIndex
        let adv = try await outSeg.getAdvertisement(segment: segIndex, linkMDU: LinkConstants.LINK_MDU)

        let numParts = await outSeg.numParts
        let maxLen = ResourceHashmap.hashmapMaxLength(linkMDU: LinkConstants.LINK_MDU)
        XCTAssertLessThanOrEqual(numParts, maxLen,
            "test segment must fit in one HMU chunk (\(numParts) > \(maxLen)); raise partSize")

        let inSeg = Resource(advertisement: adv, link: link)
        // Identity decrypt — matches the identity linkEncrypt used outbound so the
        // per-segment hash check round-trips.
        await inSeg.setDecryptCallback { $0 }
        await inSeg.transitionToTransferring()

        for i in 0..<numParts {
            let part = try await outSeg.getPart(at: i)
            try await inSeg.receivePart(part, at: i)
        }

        try await inSeg.transitionState(to: .assembling)
        _ = try await inSeg.assemble()
        return inSeg
    }

    // MARK: - 1. Small metadata is ATTACHED

    /// Modest metadata (framed <= MAX_EFFICIENT_SIZE) is attached by the
    /// initializer: `metadataSize` equals the production framed length (3-byte
    /// big-endian prefix + msgpack-binary body) and the prepared advertisement
    /// carries the `x` (has_metadata) flag with `d` = data + metadata size.
    func testSmallMetadataIsAttached() async throws {
        let link = makeLink()

        let metadata = Data("resource-metadata-header".utf8)  // 24 bytes
        let payload = Data(repeating: 0x5A, count: 16 * 1024)

        let resource = Resource(data: payload, link: link, metadata: metadata, autoCompress: false)

        // metadataSize == packed(msgpack-binary) length + 3-byte framing, computed
        // with the SAME production packer the initializer uses (no reimplementation).
        let expectedFramed = packMsgPack(.binary(metadata)).count + 3
        let metadataSize = await resource.metadataSize
        XCTAssertGreaterThan(metadataSize, 0, "modest metadata must be attached (hasMetadata)")
        XCTAssertEqual(metadataSize, expectedFramed,
            "metadataSize must equal the framed (3-byte prefix + packed) length")

        try await resource.prepare(partSize: LinkConstants.LINK_MDU, linkEncrypt: { $0 }, autoCompress: false)

        // The advertisement surfaces the metadata flag (python adv.x, Resource.py:1291)
        // and folds metadataSize into d (total plaintext size). Single segment: not split.
        let adv = try await resource.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
        XCTAssertTrue(adv.flags.hasMetadataFlag, "metadata-bearing resource must set the adv x flag")
        XCTAssertFalse(adv.flags.isSplit, "a small metadata resource stays a single segment")
        XCTAssertEqual(adv.dataSize, payload.count + metadataSize,
            "adv d = data + metadata size for a single metadata-bearing segment")

        let totalSegments = await resource.totalSegments
        XCTAssertEqual(totalSegments, 1, "small payload+metadata is one segment")
    }

    // MARK: - 2. Oversized metadata is DROPPED, not a trap (the regression)

    /// Metadata whose FRAMED size exceeds MAX_EFFICIENT_SIZE (but is still within
    /// METADATA_MAX_SIZE, so python's bound alone would NOT reject it) is dropped
    /// by the clamp: `metadataSize == 0` and `hasMetadataFlag == false`. Critically,
    /// construction + preparing a MULTI-segment chain (segment 1 read +
    /// prepareNextSegment's seek/read) must NOT trap. Before the fix the retained
    /// ~2 MiB metadata made `firstReadSize = MAX_EFFICIENT_SIZE - metadataSize`
    /// negative, trapping on `UInt64(negative)` seek.
    func testOversizedMetadataIsDroppedNotTrapped() async throws {
        let link = makeLink()

        // 2 MiB metadata: framed (> 2 MiB) exceeds MAX_EFFICIENT_SIZE (1 MiB-1) yet
        // packed stays under METADATA_MAX_SIZE (16 MiB-1) — isolates the NEW bound.
        let oversized = Data(repeating: 0xC3, count: 2 * 1024 * 1024)
        XCTAssertLessThanOrEqual(packMsgPack(.binary(oversized)).count, ResourceConstants.METADATA_MAX_SIZE,
            "precondition: packed metadata is within python's METADATA_MAX_SIZE")
        XCTAssertGreaterThan(packMsgPack(.binary(oversized)).count + 3, ResourceConstants.MAX_EFFICIENT_SIZE,
            "precondition: framed metadata exceeds MAX_EFFICIENT_SIZE (would underflow firstReadSize)")

        // Payload large enough to force a multi-segment chain on its own (so the
        // seek/read second-segment path actually runs). ~1.5 MiB.
        let totalSize = 3 * 512 * 1024  // 1_572_864 > MAX_EFFICIENT_SIZE
        var payload = Data(count: totalSize)
        for i in 0..<totalSize { payload[i] = UInt8((i * 31 + 7) & 0xFF) }

        // Non-throwing initializer: oversized metadata is log-and-dropped here.
        let resource = Resource(data: payload, link: link, metadata: oversized, autoCompress: false)

        let metadataSize = await resource.metadataSize
        XCTAssertEqual(metadataSize, 0, "framed metadata > MAX_EFFICIENT_SIZE must be DROPPED (clamp)")

        // First-segment prepare must not trap (firstReadSize = MAX_EFFICIENT_SIZE - 0).
        try await resource.prepare(partSize: 256 * 1024, linkEncrypt: { $0 }, autoCompress: false)

        let totalSegments = await resource.totalSegments
        XCTAssertGreaterThan(totalSegments, 1, "payload alone must still split into >1 segment")

        // Advertisement must NOT claim metadata (it was dropped).
        let adv = try await resource.getAdvertisement(segment: 1, linkMDU: 256 * 1024)
        XCTAssertFalse(adv.flags.hasMetadataFlag, "dropped metadata must clear the adv x flag")
        XCTAssertTrue(adv.flags.isSplit, "multi-segment payload sets the split flag")

        // Real part read on segment 1 (would index a negative-sized buffer if the
        // clamp were absent) must succeed.
        _ = try await resource.getPart(at: 0)

        // The seek/read second-segment path — the exact site of the pre-fix
        // `UInt64(negative)` seek trap — must produce a real next segment.
        let next = try await resource.prepareNextSegment(linkEncrypt: { $0 })
        XCTAssertNotNil(next, "prepareNextSegment must build segment 2 without trapping on a negative seek")
        let nextIndex = await next?.segmentIndex
        XCTAssertEqual(nextIndex, 2, "second segment carries index 2")
        let nextMetaSize = await next?.metadataSize
        XCTAssertEqual(nextMetaSize, 0, "later segments inherit metadataSize 0 (no negative firstReadSize)")
    }

    // MARK: - 3. Valid metadata survives a real single-segment round-trip

    /// A metadata-bearing single-segment resource transferred over the real
    /// outbound→inbound part path recovers the EXACT metadata bytes
    /// (`receivedMetadata`) and stores the metadata-STRIPPED payload as the
    /// assembled data (python Resource.py:696-704 / :730-731).
    func testValidMetadataRoundTripsSingleSegment() async throws {
        let link = makeLink()

        let metadata = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0xFE])
        let payload = Data(repeating: 0x37, count: 16 * 1024)

        let resource = Resource(data: payload, link: link, metadata: metadata, autoCompress: false)
        try await resource.prepare(partSize: LinkConstants.LINK_MDU, linkEncrypt: { $0 }, autoCompress: false)

        let inbound = try await roundTripSegment(resource, link: link)

        let recovered = await inbound.receivedMetadata
        XCTAssertEqual(recovered, metadata, "round-tripped metadata bytes must equal the original")

        let assembled = await inbound.assembledData
        XCTAssertEqual(assembled, payload,
            "assembled (delivered) data must be the metadata-stripped payload")

        await inbound.cleanup()
    }

    // MARK: - 4. Valid metadata survives a MULTI-segment round-trip (firstReadSize math)

    /// A metadata-bearing payload large enough to span multiple segments
    /// round-trips end to end: segment 1 reserves `MAX_EFFICIENT_SIZE -
    /// metadataSize` payload bytes and prepends the metadata prefix, later
    /// segments stream the remainder via seek/read. The segment-1 inbound recovers
    /// the metadata; the final inbound reassembles the full original payload. This
    /// pins the HAPPY-path firstReadSize arithmetic the clamp protects.
    func testValidMetadataRoundTripsMultiSegment() async throws {
        let link = makeLink()

        let metadata = Data([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
        let totalSize = 3 * 512 * 1024  // 1_572_864 > MAX_EFFICIENT_SIZE → splits
        var payload = Data(count: totalSize)
        for i in 0..<totalSize { payload[i] = UInt8((i * 17 + 3) & 0xFF) }

        let seg1 = Resource(data: payload, link: link, metadata: metadata, autoCompress: false)
        let metadataSize = await seg1.metadataSize
        XCTAssertGreaterThan(metadataSize, 0, "valid small metadata must be attached")

        let partSize = 256 * 1024  // few parts per ~1 MiB segment (fits one HMU chunk)
        try await seg1.prepare(partSize: partSize, linkEncrypt: { $0 }, autoCompress: false)

        let totalSegments = await seg1.totalSegments
        XCTAssertGreaterThan(totalSegments, 1, "metadata + payload must split into >1 segment")
        // total plaintext (d) folds in the metadata prefix.
        let adv1 = try await seg1.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
        XCTAssertTrue(adv1.flags.hasMetadataFlag, "segment 1 advertises metadata")
        XCTAssertEqual(adv1.dataSize, payload.count + metadataSize,
            "adv d = total payload + metadata size across the chain")

        // Walk the chain over the real part path.
        var current: Resource? = seg1
        var firstInbound: Resource?
        var lastInbound: Resource?
        while let outSeg = current {
            let inbound = try await roundTripSegment(outSeg, link: link)
            if firstInbound == nil { firstInbound = inbound }
            lastInbound = inbound

            if await outSeg.hasMoreSegments {
                let next = try await outSeg.prepareNextSegment(linkEncrypt: { $0 })
                XCTAssertNotNil(next, "prepareNextSegment must yield a segment while hasMoreSegments")
                await outSeg.transferInputFileOwnership(to: next!)
                current = next
            } else {
                current = nil
            }
        }

        // Metadata is recovered on the segment-1 inbound (python strips/unpacks on
        // segment_index == 1 only, Resource.py:696/730-731).
        let recovered = await firstInbound?.receivedMetadata
        XCTAssertEqual(recovered, metadata, "segment-1 inbound must recover the metadata bytes")

        // The final inbound surfaces the FULL reassembled, metadata-stripped payload.
        let assembled = await lastInbound?.assembledData
        XCTAssertEqual(assembled?.count, payload.count, "reassembled size == original payload size")
        XCTAssertEqual(assembled, payload, "reassembled bytes == original payload (metadata stripped)")

        await lastInbound?.cleanup()
    }
}
