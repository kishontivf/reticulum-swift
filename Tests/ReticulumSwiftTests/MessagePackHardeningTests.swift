// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  MessagePackHardeningTests.swift
//  ReticulumSwiftTests
//
//  Untrusted-input hardening for the MessagePack decoder: a crafted header must NOT
//  trigger a huge eager allocation (width bomb) or unbounded recursion (depth bomb).
//  These paths are reachable pre-auth via announce app_data / resource metadata.
//

import XCTest
@testable import ReticulumSwift

final class MessagePackHardeningTests: XCTestCase {

    func testArrayWidthBombThrowsInsteadOfAllocating() {
        // array32 claiming ~4.29 billion elements, with no element bytes following.
        // Must throw (end-of-data), not trap on a multi-GB reserveCapacity.
        let bomb = Data([0xdd, 0xff, 0xff, 0xff, 0xff])
        XCTAssertThrowsError(try unpackMsgPack(bomb))
    }

    func testMapWidthBombThrowsInsteadOfAllocating() {
        let bomb = Data([0xdf, 0xff, 0xff, 0xff, 0xff]) // map32, ~4.29B entries
        XCTAssertThrowsError(try unpackMsgPack(bomb))
    }

    func testDeepNestingRejected() {
        // 200 nested 1-element arrays (0x91), innermost null — exceeds the depth cap,
        // so it must throw well before the native stack overflows (uncatchable in Swift).
        var deep = Data(repeating: 0x91, count: 200)
        deep.append(0xc0)
        XCTAssertThrowsError(try unpackMsgPack(deep))
    }

    func testShallowNestingAccepted() {
        // 8 nested arrays — comfortably within the cap; must decode without throwing.
        var ok = Data(repeating: 0x91, count: 8)
        ok.append(0xc0)
        XCTAssertNoThrow(try unpackMsgPack(ok))
    }
}
