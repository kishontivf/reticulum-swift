// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  DiscoveryAddress.swift
//  ReticulumSwift
//
//  Address + name validation grammar for interface discovery — a 1:1 port of
//  the module-level helpers in RNS/Discovery.py: `is_ip_address`, `is_ygg_ipv6`,
//  `is_hostname`, the `san_map` alnum set, and `InterfaceAnnouncer.sanitize`
//  (CR/LF strip). The per-label hostname grammar mirrors Python's
//  `(?!-)[a-z0-9-]{1,63}(?<!-)` regex.
//
//  Python reference: RNS/Discovery.py:769-790,89-94.
//

import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Interface-discovery address/name validation grammar (Discovery.py:769-790).
public enum DiscoveryAddress {

    // MARK: - IP / Yggdrasil detection (Discovery.py:769-777)

    /// `is_ip_address` (Discovery.py:769-773): `ipaddress.ip_address(s)` succeeds
    /// for a v4 or v6 literal. Implemented with `inet_pton` over both families.
    public static func isIPAddress(_ s: String) -> Bool {
        return isIPv4(s) || parseIPv6(s) != nil
    }

    private static func isIPv4(_ s: String) -> Bool {
        var addr = in_addr()
        var ok: Int32 = 0
        s.withCString { cs in ok = inet_pton(AF_INET, cs, &addr) }
        return ok == 1
    }

    private static func parseIPv6(_ s: String) -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: 16)
        var ok: Int32 = 0
        s.withCString { cs in
            bytes.withUnsafeMutableBytes { raw in
                ok = inet_pton(AF_INET6, cs, raw.baseAddress)
            }
        }
        return ok == 1 ? bytes : nil
    }

    /// `is_ygg_ipv6` (Discovery.py:775-777): membership in `IPv6Network("200::/7")`
    /// — the first byte masked by 0xFE equals 0x02.
    public static func isYggIPv6(_ s: String) -> Bool {
        guard let bytes = parseIPv6(s) else { return false }
        return (bytes[0] & 0xFE) == 0x02
    }

    // MARK: - Hostname grammar (Discovery.py:779-785)

    /// `is_hostname` (Discovery.py:779-785). Wrapped so any input that would raise
    /// in Python (notably the empty string, where `hostname[-1]` IndexErrors)
    /// reports false, matching the cmd's try/except.
    public static func isHostname(_ host0: String) -> Bool {
        var host = host0
        if host.isEmpty { return false }            // python hostname[-1] -> IndexError
        if host.hasSuffix(".") { host.removeLast() } // strip one trailing dot
        if host.utf8.count > 253 { return false }
        let components = host.components(separatedBy: ".")
        guard let last = components.last else { return false }
        // Numeric-TLD rejection: re.match(r"[0-9]+$", components[-1]).
        if !last.isEmpty && last.unicodeScalars.allSatisfy({ $0.value >= 48 && $0.value <= 57 }) {
            return false
        }
        // Each label: (?!-)[a-z0-9-]{1,63}(?<!-)$ (case-insensitive).
        for label in components where !labelValid(label) { return false }
        return true
    }

    private static func labelValid(_ label: String) -> Bool {
        let scalars = Array(label.unicodeScalars)
        if scalars.count < 1 || scalars.count > 63 { return false }
        for sc in scalars {
            let v = sc.value
            let ok = (v >= 48 && v <= 57) || (v >= 65 && v <= 90) ||
                     (v >= 97 && v <= 122) || v == 45  // '-'
            if !ok { return false }
        }
        if scalars.first?.value == 45 || scalars.last?.value == 45 { return false }
        return true
    }

    // MARK: - san_map (Discovery.py:787-790)

    /// True when `scalar` is in `san_map` — the ASCII alnum set RNS keys on when
    /// trimming interface names (Discovery.py:787-790: 0-9, A-Z, a-z).
    public static func isSanChar(_ scalar: Unicode.Scalar) -> Bool {
        let v = scalar.value
        return (v >= 48 && v <= 57) || (v >= 65 && v <= 90) || (v >= 97 && v <= 122)
    }

    // MARK: - sender sanitize (Discovery.py:89-94)

    /// `InterfaceAnnouncer.sanitize` (Discovery.py:89-94): strip CR and LF, then
    /// trim surrounding whitespace. Returns nil for a nil input.
    public static func sanitize(_ value: String?) -> String? {
        guard let value = value else { return nil }
        var r = value.replacingOccurrences(of: "\n", with: "")
        r = r.replacingOccurrences(of: "\r", with: "")
        return r.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
