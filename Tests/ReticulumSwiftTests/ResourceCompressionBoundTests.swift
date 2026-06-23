// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ResourceCompressionBoundTests.swift
//  ReticulumSwiftTests
//
//  Coverage for the bz2 decompression bound (fix/resource-decompress-bound). Mirrors
//  python's max_decompressed_size = AUTO_COMPRESS_MAX_SIZE (Resource.py:687): the
//  decompressor caps its output buffer and rejects over-compressible ("bz2 bomb")
//  input instead of expanding memory unbounded. Previously decompress() had no
//  absolute size bound.
//

import XCTest
@testable import ReticulumSwift

final class ResourceCompressionBoundTests: XCTestCase {

    /// Normal round-trip with the advertised size as the buffer hint succeeds under the
    /// default 64 MB cap.
    func testRoundTripWithinCap() throws {
        let original = Data(repeating: 0xAB, count: 64 * 1024)  // highly compressible
        let compressed = try ResourceCompression.bz2Compress(original)
        XCTAssertLessThan(compressed.count, original.count, "compressible data should shrink")

        let decompressed = try ResourceCompression.bz2Decompress(compressed, expectedSize: original.count)
        XCTAssertEqual(decompressed, original)
    }

    /// Output that exceeds an explicit (tiny) cap throws the bomb/overflow signal rather
    /// than growing the buffer further.
    func testExceedingMaxDecompressedSizeThrows() throws {
        let original = Data(repeating: 0x00, count: 64 * 1024)  // ~64 KB decompressed
        let compressed = try ResourceCompression.bz2Compress(original)

        XCTAssertThrowsError(
            try ResourceCompression.bz2Decompress(compressed, maxDecompressedSize: 1024)
        ) { error in
            guard case BZ2Error.exceedsMaxDecompressedSize = error else {
                return XCTFail("expected BZ2Error.exceedsMaxDecompressedSize, got \(error)")
            }
        }
    }

    /// The high-level decompress() wrapper surfaces the overflow as ResourceError so the
    /// resource assembly path treats it like any other corruption (drop + conclude).
    func testDecompressWrapperSurfacesOverflowAsResourceError() throws {
        let original = Data(repeating: 0x00, count: 64 * 1024)
        let compressed = try ResourceCompression.bz2Compress(original)

        XCTAssertThrowsError(
            try ResourceCompression.decompress(compressed, maxDecompressedSize: 1024)
        ) { error in
            guard case ResourceError.decompressionFailed = error else {
                return XCTFail("expected ResourceError.decompressionFailed, got \(error)")
            }
        }
    }
}
