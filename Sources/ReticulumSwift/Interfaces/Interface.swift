// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Interface.swift
//  ReticulumSwift
//
//  Shared interface-level constants and pure helpers that mirror the
//  base `RNS/Interfaces/Interface.py` class plus the per-class MTU /
//  bitrate / IFAC machinery. reticulum-swift has no single base
//  `Interface` class (each concrete interface conforms to the
//  `NetworkInterface` protocol), so the bitrate→HW_MTU tier table,
//  the minimum-bitrate floor and the ifac_size bit→byte resolution
//  live here as static helpers the concrete interfaces and the
//  Reticulum config path call into. This keeps a single RNS-faithful
//  implementation of `optimise_mtu` rather than duplicating the tier
//  table at every call site.
//

import Foundation

/// Namespace mirroring `RNS/Interfaces/Interface.py` (the base `Interface`
/// class) for constants and the pure MTU/bitrate/IFAC helpers that RNS keeps
/// as class methods / Reticulum-config logic.
public enum Interface {

    // MARK: - Base-class defaults (Interface.py:89-90)

    /// `Interface.AUTOCONFIGURE_MTU` default on the *base* class (Interface.py:89).
    /// Concrete interface types override this (TCP sets it `True`).
    public static let AUTOCONFIGURE_MTU_DEFAULT: Bool = false

    /// `Interface.FIXED_MTU` default on the base class (Interface.py:90).
    public static let FIXED_MTU_DEFAULT: Bool = false

    // MARK: - TCP*Interface class constants (TCPInterface.py)

    /// `TCPInterface.HW_MTU` — the pre-autoconfigure hardware-MTU ceiling
    /// (TCPInterface.py:42). This is the value a TCP interface carries *before*
    /// `optimise_mtu()` runs; the live HW_MTU of a default (autoconfigured,
    /// 10 Mbps) TCP link is `optimiseMtu(10_000_000) == 8192`, NOT this ceiling.
    public static let tcpClassHwMtu: Int = 262144

    /// `TCPClientInterface.BITRATE_GUESS` / `TCPServerInterface.BITRATE_GUESS`
    /// (TCPInterface.py:76, :453) — the assumed bitrate (10 Mbps) a TCP
    /// interface uses to autoconfigure its MTU when no bitrate is configured.
    public static let tcpBitrateGuess: Int = 10_000_000

    /// `Reticulum.MINIMUM_BITRATE` (Reticulum.py:133) — a configured bitrate
    /// below this is ignored and the per-class BITRATE_GUESS is kept.
    public static let MINIMUM_BITRATE: Int = 5

    // MARK: - optimise_mtu (Interface.py:198-221)

    /// Mirror of `RNS.Interface.optimise_mtu` (Interface.py:198-221): map a
    /// link `bitrate` (bits/second) through the RNS tier table to a hardware
    /// MTU. Returns `nil` for the bottom branch (RNS sets `HW_MTU = None`
    /// for `bitrate <= 62_500`).
    ///
    /// The boundaries are strict `>` for every tier EXCEPT the top tier, which
    /// is `>=` — matching RNS byte-for-byte. A 10 Mbps TCP link
    /// (`10_000_000`) lands in the `8192` branch: it is not `> 10_000_000`
    /// but is `> 5_000_000`.
    ///
    /// This is the pure tier mapping only; the `AUTOCONFIGURE_MTU` gate (RNS
    /// only mutates `HW_MTU` when autoconfigure is on) is applied by the
    /// caller — see `deriveHwMtu(...)`.
    ///
    /// - Parameter bitrate: Link bitrate in bits/second.
    /// - Returns: The autoconfigured hardware MTU, or `nil` for `bitrate <= 62_500`.
    public static func optimiseMtu(bitrate: Int) -> Int? {
        // Reference: RNS/Interfaces/Interface.py:198-221
        if bitrate >= 1_000_000_000 {
            return 524288
        } else if bitrate > 750_000_000 {
            return 262144
        } else if bitrate > 400_000_000 {
            return 131072
        } else if bitrate > 200_000_000 {
            return 65536
        } else if bitrate > 100_000_000 {
            return 32768
        } else if bitrate > 10_000_000 {
            return 16384
        } else if bitrate > 5_000_000 {
            return 8192
        } else if bitrate > 2_000_000 {
            return 4096
        } else if bitrate > 1_000_000 {
            return 2048
        } else if bitrate > 62_500 {
            return 1024
        } else {
            return nil
        }
    }

    // MARK: - Effective bitrate (Reticulum.py:765-768)

    /// Apply the RNS minimum-bitrate floor (Reticulum.py:765-768): a configured
    /// bitrate `>= MINIMUM_BITRATE` (5) is applied; anything below (including
    /// the `0` "unset" sentinel reticulum-swift's `InterfaceConfig` uses) is
    /// ignored and the per-class `bitrateGuess` is kept. This is the bitrate
    /// that feeds `optimiseMtu`.
    ///
    /// - Parameters:
    ///   - configured: The configured bitrate (`InterfaceConfig.bitrate`); `0` means unset.
    ///   - guess: The per-class `BITRATE_GUESS` fallback (TCP == 10 Mbps).
    /// - Returns: The effective bitrate used for MTU autoconfiguration.
    public static func effectiveBitrate(configured: Int, guess: Int) -> Int {
        // Reference: RNS/Reticulum.py:765-768 (configured_bitrate floor)
        return configured >= MINIMUM_BITRATE ? configured : guess
    }

    // MARK: - Derived hardware MTU

    /// Resolve a concrete interface's live hardware MTU from its config, mirroring
    /// the RNS construction order:
    ///   - a configured `fixed_mtu` wins outright (FIXED_MTU true, AUTOCONFIGURE_MTU
    ///     false): `self.HW_MTU = fixed_mtu` (TCPInterface.py:116);
    ///   - otherwise, when `AUTOCONFIGURE_MTU` is on, the bitrate is mapped through
    ///     `optimise_mtu` over the minimum-bitrate floor (Interface.py:198-221 via
    ///     Reticulum.py interface_post_init :860 / :1047);
    ///   - otherwise the pre-autoconfigure class ceiling is kept.
    ///
    /// RNS's `optimise_mtu` can yield `None` (bitrate <= 62_500); reticulum-swift's
    /// `NetworkInterface.hwMtu` is a non-optional `Int`, so a `None` result is
    /// surfaced as the baseline `Reticulum.MTU` (500) — the same value link MTU
    /// signaling falls back to when no hardware MTU is advertised
    /// (`Link.init: hwMtu ?? 500`). For TCP this branch is unreachable because the
    /// effective bitrate is floored to the 10 Mbps guess (→ 8192).
    ///
    /// - Parameters:
    ///   - fixedMtu: `InterfaceConfig.fixedMtu` (FIXED_MTU value), or nil.
    ///   - autoconfigureMtu: `InterfaceConfig.autoconfigureMtu` (AUTOCONFIGURE_MTU).
    ///   - bitrate: `InterfaceConfig.bitrate` (configured, `0` == unset).
    ///   - bitrateGuess: Per-class `BITRATE_GUESS`.
    ///   - classHwMtu: Per-class pre-autoconfigure `HW_MTU` ceiling.
    /// - Returns: The live hardware MTU for link MTU signaling/negotiation.
    public static func deriveHwMtu(
        fixedMtu: Int?,
        autoconfigureMtu: Bool,
        bitrate: Int,
        bitrateGuess: Int,
        classHwMtu: Int
    ) -> Int {
        if let fixedMtu = fixedMtu {
            return fixedMtu
        }
        if autoconfigureMtu {
            let effective = effectiveBitrate(configured: bitrate, guess: bitrateGuess)
            return optimiseMtu(bitrate: effective) ?? MTU
        }
        return classHwMtu
    }

    // MARK: - ifac_size bit→byte resolution (Reticulum.py:719-723)

    /// Resolve a configured `ifac_size` given in BITS into the byte count RNS
    /// stores on the interface, mirroring Reticulum's config logic:
    ///   - if `bits >= IFAC_MIN_SIZE*8` (== 8) use `bits // 8` (16→2, 8→1);
    ///   - otherwise (including no value configured) fall back to
    ///     `DEFAULT_IFAC_SIZE` (16) — a sub-minimum value is NEVER passed
    ///     through as 0.
    ///
    /// Reference: RNS/Reticulum.py:719-723 (ifac_size bit divide) plus the
    /// `ifac_size != None ? ifac_size : interface.DEFAULT_IFAC_SIZE` fallback
    /// (Reticulum.py:860-862 / :1049-1050). `DEFAULT_IFAC_SIZE == 16`,
    /// `IFAC_MIN_SIZE == 1` (TCPInterface.py:77, Reticulum.py:148).
    ///
    /// - Parameter bits: Configured `ifac_size` in bits, or nil if unset.
    /// - Returns: The resolved IFAC signature size in BYTES.
    public static func resolveIfacSize(bits: Int?) -> Int {
        if let bits = bits, bits >= TransportConstants.IFAC_MIN_SIZE * 8 {
            return bits / 8
        }
        return TransportConstants.DEFAULT_IFAC_SIZE
    }
}
