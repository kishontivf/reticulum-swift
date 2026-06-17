// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  DiscoveryStamp.swift
//  ReticulumSwift
//
//  LXStamper proof-of-work primitives for interface-discovery announces.
//
//  FORCED DEVIATION: RNS imports these from `LXMF.LXStamper`
//  (`stamp_workblock` / `stamp_value` / `stamp_valid` / `generate_stamp`, used at
//  Discovery.py:172,235-237). reticulum-swift has NO LXMF dependency, so the PoW
//  is inlined here, built on the library's own HKDF (`KeyDerivation.deriveKey`),
//  SHA-256 (`Hashing.fullHash`) and MessagePack (`packMsgPack`). Documented in
//  port-deviations.md, citing LXMF/LXStamper.py.
//
//  Wire definition: the work-block is the concatenation of
//  WORKBLOCK_EXPAND_ROUNDS HKDF(256B) expansions of the material, each salted
//  with SHA-256(material || msgpack(round)); a stamp's value is the leading-zero
//  bit count of SHA-256(workblock||stamp); a stamp is valid iff
//  SHA-256(workblock||stamp) <= 2^(256-cost) as a 256-bit big-endian compare.
//

import Foundation

/// LXStamper proof-of-work primitives (LXMF LXStamper; Discovery.py:172,235-237).
public enum DiscoveryStamp {
    /// LXStamper.STAMP_SIZE — 32 bytes.
    public static let stampSize = DiscoveryConstants.STAMP_SIZE

    /// `stamp_workblock`: concat of `rounds` HKDF(256B) expansions of `material`,
    /// each salted with SHA-256(material || msgpack(round)). HKDF ==
    /// `KeyDerivation.deriveKey`; SHA-256 == `Hashing.fullHash`; msgpack(round) ==
    /// the positive-fixint/uint encoding of the round counter.
    public static func workblock(_ material: Data, rounds: Int = DiscoveryConstants.WORKBLOCK_EXPAND_ROUNDS) -> Data {
        var wb = Data()
        for n in 0..<rounds {
            let salt = Hashing.fullHash(material + packMsgPack(.uint(UInt64(n))))
            let derived = KeyDerivation.deriveKey(
                length: 256, inputKeyMaterial: material, salt: salt, context: nil)
            wb.append(derived)
        }
        return wb
    }

    /// `stamp_value`: leading zero bits of SHA-256(workblock||stamp).
    public static func value(workblock: Data, stamp: Data) -> Int {
        let digest = Hashing.fullHash(workblock + stamp)
        var value = 0
        for b in digest {
            if b == 0 { value += 8 } else { value += b.leadingZeroBitCount; break }
        }
        return value
    }

    /// `stamp_valid`: SHA-256(workblock||stamp) <= 2^(256-cost), as a 256-bit
    /// big-endian compare.
    public static func valid(_ stamp: Data, cost: Int, workblock: Data) -> Bool {
        let result = Array(Hashing.fullHash(workblock + stamp))   // 32 bytes, big-endian
        if cost <= 0 { return true }                              // target >= 2^256 >= result
        if cost > 256 { return result.allSatisfy { $0 == 0 } }    // target < 1 -> only zero passes
        // target = 2^(256-cost): a single set bit at position (256-cost) from the LSB.
        var target = [UInt8](repeating: 0, count: 32)
        let p = 256 - cost
        target[31 - (p / 8)] = UInt8(1 << (p % 8))
        for i in 0..<32 {
            if result[i] < target[i] { return true }
            if result[i] > target[i] { return false }
        }
        return true                                               // result == target -> valid
    }

    /// `generate_stamp` (LXStamper.job_simple): compute the work-block ONCE, then
    /// brute-force random STAMP_SIZE (32B) stamps until one clears `cost`. Only
    /// the 32-byte stamp is randomized per attempt — the expensive work-block is
    /// computed a single time per generate.
    public static func generate(_ material: Data, cost: Int, rounds: Int = DiscoveryConstants.WORKBLOCK_EXPAND_ROUNDS) -> (stamp: Data?, value: Int) {
        let wb = workblock(material, rounds: rounds)
        var stamp = randomBytes(stampSize)
        while !valid(stamp, cost: cost, workblock: wb) {
            stamp = randomBytes(stampSize)
        }
        return (stamp, value(workblock: wb, stamp: stamp))
    }

    private static func randomBytes(_ count: Int) -> Data {
        var d = Data(count: count)
        for i in 0..<count { d[i] = UInt8.random(in: 0...255) }
        return d
    }
}
