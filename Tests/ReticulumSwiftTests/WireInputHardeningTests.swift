// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  WireInputHardeningTests.swift
//  ReticulumSwiftTests
//
//  Pins the security/concurrency hardening fixes landed in commit 60e3eb7
//  ("fix(security/concurrency): 7 bugs from a proactive bug-class sweep").
//
//  Each test drives the REAL production code and asserts the new graceful
//  behavior. Because an XCTest cannot catch a Swift fatalError/allocation
//  trap, the crash-fix tests assert that hostile peer input is now REJECTED
//  (throws a clean decode error) or DROPPED (returns false) and runs to
//  completion — a test that completes is itself the proof that the input no
//  longer traps the process.
//
//  Coverage:
//   a. MessagePack pre-allocation guard (MessagePack.decodeArray/decodeMap):
//      a tiny array32/map32 header with a multi-billion count must throw a
//      clean decode failure, not trap on an impossible reserveCapacity.
//   b. ResourceAdvertisement.unpack integer hardening: a hostile msgpack int
//      out of Int range, or flags > 255, must throw rather than narrowing-trap.
//   c. receiveResourceAdvertisement numParts drop: out-of-range numParts is
//      dropped (returns false) before Array(repeating:count:) can trap.
//   d. Resource.cancel() frees the named outbound staging tempfile (leak fix).
//   e. RequestReceipt: a response arriving before the timeout deadline is not
//      clobbered to .timeout and does not double-fire its callback.
//

import XCTest
import Foundation
@testable import ReticulumSwift

final class WireInputHardeningTests: XCTestCase {

    // MARK: - Helpers (all private/nested — no top-level symbols)

    /// Minimal non-active link, sufficient as a target for
    /// receiveResourceAdvertisement and as the owner of an outbound Resource.
    private func makeLink() -> Link {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["wire-hardening"])
        return Link(destination: dest, identity: identity)
    }

    /// Build a syntactically valid ResourceAdvertisement with a caller-chosen
    /// numParts (and flags). The public initializer does no count-based
    /// allocation, so a hostile numParts here is safe to construct — the trap
    /// the fix prevents only fires later, inside Resource(advertisement:).
    private func makeAdvertisement(
        numParts: Int,
        flags: ResourceFlags = ResourceFlags(encrypted: true),
        requestId: Data? = nil
    ) -> ResourceAdvertisement {
        ResourceAdvertisement(
            transferSize: 1024,
            dataSize: 2048,
            numParts: numParts,
            hash: Data(repeating: 0x11, count: 32),
            randomHash: Data(repeating: 0x22, count: ResourceConstants.RANDOM_HASH_SIZE),
            originalHash: Data(repeating: 0x11, count: 32),
            segmentIndex: 1,
            totalSegments: 1,
            requestId: requestId,
            flags: flags,
            hashmapChunk: Data(repeating: 0x33, count: ResourceConstants.MAPHASH_LEN)
        )
    }

    /// A well-formed msgpack map carrying every key ResourceAdvertisement.unpack
    /// requires, mirroring ResourceAdvertisement.pack(). Hostile cases start
    /// from this and replace exactly one field with an out-of-range int.
    private func validAdvMsgPackMap() -> [MessagePackValue: MessagePackValue] {
        [
            .string("t"): .int(1024),
            .string("d"): .int(2048),
            .string("n"): .int(4),
            .string("h"): .binary(Data(repeating: 0x11, count: 32)),
            .string("r"): .binary(Data(repeating: 0x22, count: ResourceConstants.RANDOM_HASH_SIZE)),
            .string("o"): .binary(Data(repeating: 0x11, count: 32)),
            .string("i"): .int(1),
            .string("l"): .int(1),
            .string("q"): .null,
            .string("f"): .uint(1),
            .string("m"): .binary(Data(repeating: 0x33, count: ResourceConstants.MAPHASH_LEN))
        ]
    }

    /// Snapshot the names of outbound resource staging tempfiles currently in
    /// NSTemporaryDirectory(). Used to isolate the file THIS test stages.
    private func stagingFileNames() -> Set<String> {
        let tmp = NSTemporaryDirectory()
        let names = (try? FileManager.default.contentsOfDirectory(atPath: tmp)) ?? []
        return Set(names.filter { $0.hasPrefix("rns_resource_out_") })
    }

    /// Async-safe invocation counter for callback assertions.
    private actor Counter {
        private(set) var value = 0
        func increment() { value += 1 }
    }

    // MARK: - (a) MessagePack pre-allocation guard

    /// A 5-byte map32 header declaring 2^32-1 entries must throw a clean decode
    /// failure, NOT trap on a multi-GB reserveCapacity. The fix bounds the
    /// reservation by remaining bytes (MessagePack.decodeMap), so decoding falls
    /// straight into the loop's "unexpected end of data" guard. Reaching the
    /// assertion at all proves the process didn't trap/abort.
    func testMsgPackMap32HugeCountThrowsInsteadOfTrapping() {
        let map32 = Data([0xdf, 0xff, 0xff, 0xff, 0xff])  // map32, count = 4294967295
        XCTAssertThrowsError(try unpackMsgPack(map32),
            "map32 with a multi-billion count must throw, not trap on pre-allocation") { error in
            XCTAssertTrue(error is MessagePackError,
                "expected a MessagePackError decode failure, got \(error)")
        }
    }

    /// As above for a 5-byte array32 header (count 2^32-1). The fix bounds
    /// decodeArray's reservation by remaining bytes.
    func testMsgPackArray32HugeCountThrowsInsteadOfTrapping() {
        let array32 = Data([0xdd, 0xff, 0xff, 0xff, 0xff])  // array32, count = 4294967295
        XCTAssertThrowsError(try unpackMsgPack(array32),
            "array32 with a multi-billion count must throw, not trap on pre-allocation") { error in
            XCTAssertTrue(error is MessagePackError,
                "expected a MessagePackError decode failure, got \(error)")
        }
    }

    /// Positive control: a small, well-formed map and array still decode
    /// correctly — the byte-bounded reservation must not break normal decoding.
    func testMsgPackSmallMapAndArrayStillDecode() throws {
        let packedMap = packMsgPack(.map([.string("k"): .uint(7)]))
        let decodedMap = try unpackMsgPack(packedMap)
        guard case .map(let m) = decodedMap else {
            return XCTFail("expected a map, got \(decodedMap)")
        }
        XCTAssertEqual(m[.string("k")], .uint(7), "small map round-trips intact")

        let packedArray = packMsgPack(.array([.uint(1), .uint(2), .uint(3)]))
        let decodedArray = try unpackMsgPack(packedArray)
        guard case .array(let a) = decodedArray else {
            return XCTFail("expected an array, got \(decodedArray)")
        }
        XCTAssertEqual(a, [.uint(1), .uint(2), .uint(3)], "small array round-trips intact")
    }

    // MARK: - (b) ResourceAdvertisement.unpack integer hardening

    /// A flags ("f") value outside a byte (256) must throw a clean decode
    /// failure. The fix uses UInt8(exactly:) instead of UInt8(_:), which would
    /// have been a narrowing trap on hostile peer input.
    func testAdvertisementUnpackRejectsOversizedFlags() {
        var map = validAdvMsgPackMap()
        map[.string("f")] = .uint(256)  // one past UInt8.max
        let packed = packMsgPack(.map(map))
        XCTAssertThrowsError(try ResourceAdvertisement.unpack(packed),
            "flags > 255 must throw, not narrowing-trap") { error in
            XCTAssertTrue(error is MessagePackError, "expected MessagePackError, got \(error)")
        }
    }

    /// A size field ("n") encoded as a uint64 > Int64.max (0xcf FF..FF) must
    /// throw a clean decode failure. The fix uses Int(exactly:) so an unbounded
    /// peer int can't narrowing-trap into Int.
    func testAdvertisementUnpackRejectsOutOfRangeUInt64Size() {
        var map = validAdvMsgPackMap()
        map[.string("n")] = .uint(UInt64.max)  // 0xcf FF FF FF FF FF FF FF FF
        let packed = packMsgPack(.map(map))
        XCTAssertThrowsError(try ResourceAdvertisement.unpack(packed),
            "a uint64 size > Int64.max must throw, not narrowing-trap") { error in
            XCTAssertTrue(error is MessagePackError, "expected MessagePackError, got \(error)")
        }
    }

    /// Positive control: a valid advertisement round-trips through pack -> unpack
    /// with every field intact — the hardening must not reject legitimate input.
    func testAdvertisementValidRoundTrip() throws {
        let original = makeAdvertisement(numParts: 4, flags: [.encrypted, .compressed])
        let packed = try original.pack()
        let decoded = try ResourceAdvertisement.unpack(packed)

        XCTAssertEqual(decoded.transferSize, original.transferSize)
        XCTAssertEqual(decoded.dataSize, original.dataSize)
        XCTAssertEqual(decoded.numParts, original.numParts)
        XCTAssertEqual(decoded.hash, original.hash)
        XCTAssertEqual(decoded.randomHash, original.randomHash)
        XCTAssertEqual(decoded.originalHash, original.originalHash)
        XCTAssertEqual(decoded.segmentIndex, original.segmentIndex)
        XCTAssertEqual(decoded.totalSegments, original.totalSegments)
        XCTAssertEqual(decoded.requestId, original.requestId)
        XCTAssertEqual(decoded.flags.rawValue, original.flags.rawValue)
        XCTAssertEqual(decoded.hashmapChunk, original.hashmapChunk)
    }

    // MARK: - (c) receiveResourceAdvertisement numParts drop

    /// A negative numParts must be dropped (returns false) BEFORE the Resource
    /// init's Array(repeating:count:) — a negative count is an uncatchable
    /// fatalError. Completing this test proves the guard fired instead.
    func testReceiveAdvertisementDropsNegativeNumParts() async {
        let link = makeLink()
        let accepted = await link.receiveResourceAdvertisement(makeAdvertisement(numParts: -1))
        XCTAssertFalse(accepted, "advertisement with negative numParts must be dropped, not accepted")
    }

    /// A multi-billion numParts (far beyond MAX_EFFICIENT_SIZE) must be dropped
    /// before Array(repeating:count:) attempts an impossible allocation.
    func testReceiveAdvertisementDropsHugeNumParts() async {
        let link = makeLink()
        let huge = await link.receiveResourceAdvertisement(makeAdvertisement(numParts: 4_000_000_000))
        XCTAssertFalse(huge, "advertisement with multi-billion numParts must be dropped")

        // One past the accepted bound is also rejected (boundary).
        let justOver = await link.receiveResourceAdvertisement(
            makeAdvertisement(numParts: ResourceConstants.MAX_EFFICIENT_SIZE + 1))
        XCTAssertFalse(justOver, "numParts == MAX_EFFICIENT_SIZE + 1 must be dropped")
    }

    /// Positive control: an advertisement with a sane numParts passes the guard
    /// and is accepted (returns true) under .acceptAll — the drop guard must not
    /// reject legitimate transfers.
    func testReceiveAdvertisementAcceptsSaneNumParts() async {
        let link = makeLink()
        await link.setResourceStrategy(.acceptAll)
        let accepted = await link.receiveResourceAdvertisement(makeAdvertisement(numParts: 1))
        XCTAssertTrue(accepted, "advertisement with sane numParts must be accepted under .acceptAll")
    }

    // MARK: - (d) Resource.cancel() frees the staging tempfile

    /// An outbound resource larger than MAX_EFFICIENT_SIZE stages its payload to
    /// a named tempfile (NSTemporaryDirectory()/rns_resource_out_<UUID>). cancel()
    /// is the terminal path that previously skipped cleanup() and orphaned that
    /// file; the fix calls cleanup(abandonChain:) so the staging file is unlinked.
    func testCancelFreesOutboundStagingFile() async throws {
        let link = makeLink()

        // > MAX_EFFICIENT_SIZE (1 MiB - 1); autoCompress off so it can't shrink
        // back under the staging threshold.
        let totalSize = 1_572_864  // 1.5 MiB
        var bigData = Data(count: totalSize)
        for i in 0..<totalSize { bigData[i] = UInt8((i * 31 + 7) & 0xFF) }

        let before = stagingFileNames()

        let resource = Resource(data: bigData, link: link, autoCompress: false)
        try await resource.prepare(partSize: 64 * 1024, linkEncrypt: { $0 }, autoCompress: false)

        // Isolate the file THIS prepare staged (serial test execution → exactly one).
        let newNames = stagingFileNames().subtracting(before)
        XCTAssertEqual(newNames.count, 1,
            "prepare() of an oversized resource must stage exactly one tempfile (got \(newNames.count))")
        guard let name = newNames.first else { return }
        let stagedURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(name)
        XCTAssertTrue(FileManager.default.fileExists(atPath: stagedURL.path),
            "staging tempfile must exist on disk after prepare()")

        await resource.cancel()

        XCTAssertFalse(FileManager.default.fileExists(atPath: stagedURL.path),
            "cancel() must unlink the outbound staging tempfile (leak fix); it still exists")
    }

    // MARK: - (e) RequestReceipt timeout race

    /// A response that arrives before the timeout deadline must keep the receipt
    /// in .responseReceived: the timeout monitor must NOT clobber it to .timeout
    /// (and must NOT fire the failure callback). The fix re-checks status
    /// atomically inside handleTimeout, so even when the timeout task races ahead
    /// of cancellation it observes the delivered response and returns.
    func testRequestReceiptResponseBeforeTimeoutIsNotClobbered() async throws {
        let responses = Counter()
        let failures = Counter()

        let receipt = RequestReceipt(
            requestId: Data(repeating: 0xAA, count: 16),
            pathHash: Data(repeating: 0xBB, count: 16),
            timeout: 0.3,
            responseCallback: { _ in await responses.increment() },
            failedCallback: { _ in await failures.increment() }
        )

        // Response lands immediately, well before the 0.3s deadline.
        await receipt.receiveResponse(Data("ok".utf8))

        let early = await receipt.status
        guard case .responseReceived = early else {
            return XCTFail("expected .responseReceived immediately after receiveResponse, got \(early)")
        }

        // Wait past the deadline so the timeout task has certainly run.
        try await Task.sleep(for: .milliseconds(600))

        let late = await receipt.status
        guard case .responseReceived = late else {
            return XCTFail("status clobbered to \(late) after the deadline — timeout gate regressed")
        }

        let responseCount = await responses.value
        let failureCount = await failures.value
        XCTAssertEqual(responseCount, 1, "response callback must fire exactly once")
        XCTAssertEqual(failureCount, 0,
            "failure/timeout callback must never fire when a response arrived before the deadline")
    }
}
