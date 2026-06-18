// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  DiscoveryConstants.swift
//  ReticulumSwift
//
//  On-network interface-discovery constants — a 1:1 port of the module-level
//  literals in RNS/Discovery.py. The interface-discovery subsystem advertises a
//  `rnstransport.discovery.interface` destination whose announce app_data is a
//  self-describing msgpack record keyed by FIXED single-byte integer constants,
//  proven with an LXMF LXStamper proof-of-work and (optionally) network-encrypted.
//
//  Python reference: RNS/Discovery.py:12-38,189-190,365-377.
//

import Foundation

/// Fixed msgpack info-map field-key constants and protocol literals for the
/// interface-discovery wire format (Discovery.py:12-38,189-190).
public enum DiscoveryConstants {
    // MARK: - msgpack info-map field keys (Discovery.py:12-28)
    public static let NAME: UInt64            = 0xFF
    public static let TRANSPORT_ID: UInt64    = 0xFE
    public static let INTERFACE_TYPE: UInt64  = 0x00
    public static let TRANSPORT: UInt64       = 0x01
    public static let REACHABLE_ON: UInt64    = 0x02
    public static let LATITUDE: UInt64        = 0x03
    public static let LONGITUDE: UInt64       = 0x04
    public static let HEIGHT: UInt64          = 0x05
    public static let PORT: UInt64            = 0x06
    public static let IFAC_NETNAME: UInt64    = 0x07
    public static let IFAC_NETKEY: UInt64     = 0x08
    public static let FREQUENCY: UInt64       = 0x09
    public static let BANDWIDTH: UInt64       = 0x0A
    public static let SPREADINGFACTOR: UInt64 = 0x0B
    public static let CODINGRATE: UInt64      = 0x0C
    public static let MODULATION: UInt64      = 0x0D
    public static let CHANNEL: UInt64         = 0x0E

    /// Discovery app name (Discovery.py:30). The discovery Destination is
    /// `rnstransport.discovery.interface`.
    public static let APP_NAME = "rnstransport"

    // MARK: - announce flag bits (Discovery.py:189-190)
    /// FLAG_SIGNED is computed by the receiver but never acted on (tolerated).
    public static let FLAG_SIGNED: UInt8    = 0b00000001
    /// FLAG_ENCRYPTED selects the network_identity.encrypt payload (the only
    /// flag bit that changes the decode).
    public static let FLAG_ENCRYPTED: UInt8 = 0b00000010

    // MARK: - LXStamper proof-of-work constants (Discovery.py:34-35; LXStamper)
    /// Default sender stamp cost / receiver required-value (Discovery.py:34,192).
    public static let DEFAULT_STAMP_VALUE = 14
    /// HKDF expansion rounds for the stamp work-block (Discovery.py:35).
    public static let WORKBLOCK_EXPAND_ROUNDS = 20
    /// LXStamper.STAMP_SIZE = HASHLENGTH//8 = 32.
    public static let STAMP_SIZE = 32

    /// Identity.TRUNCATED_HASHLENGTH//8 — the expected TRANSPORT_ID byte length
    /// the receiver validates (Discovery.py:255).
    public static let TRANSPORT_ID_LENGTH = 16

    // MARK: - discovered-record staleness thresholds (Discovery.py:365-367)
    public static let THRESHOLD_UNKNOWN: TimeInterval = 24 * 60 * 60       // 86400
    public static let THRESHOLD_STALE: TimeInterval   = 3 * 24 * 60 * 60   // 259200
    public static let THRESHOLD_REMOVE: TimeInterval  = 7 * 24 * 60 * 60   // 604800

    // MARK: - status codes (Discovery.py:372-375)
    public static let STATUS_STALE     = 0
    public static let STATUS_UNKNOWN   = 100
    public static let STATUS_AVAILABLE = 1000
    /// status-string -> status-code (Discovery.py:375).
    public static let STATUS_CODE_MAP: [String: Int] = [
        "available": STATUS_AVAILABLE,
        "unknown":   STATUS_UNKNOWN,
        "stale":     STATUS_STALE,
    ]

    /// Sender/handler interface-type whitelist (Discovery.py:37-38) — SEVEN types
    /// and the only one of the two whitelists that includes TCPClientInterface.
    /// Distinct from `InterfaceDiscovery.DISCOVERABLE_TYPES` (the 6-type resolver
    /// STORE whitelist, which EXCLUDES TCPClientInterface).
    public static let DISCOVERABLE_INTERFACE_TYPES = [
        "BackboneInterface", "TCPServerInterface", "TCPClientInterface",
        "RNodeInterface", "WeaveInterface", "I2PInterface", "KISSInterface",
    ]
}

/// Opt-in interface-discovery feature gates.
///
/// FORCED DEVIATION: reticulum-swift models no Reticulum config object nor
/// per-Interface discovery feature flags, so RNS's live reads
/// (Interface.py:105-106 `discoverable`/`supports_discovery`;
/// Reticulum.py:259-260,1802-1807 `discover_interfaces` /
/// `should_autoconnect_discovered_interfaces()` /
/// `max_autoconnected_interfaces()`) are surfaced as their RNS spec-literal
/// defaults — every discovery feature defaults OFF (opt-in). Documented in
/// port-deviations.md.
public enum DiscoveryFeatureDefaults {
    public static let interfaceDiscoverable = false
    public static let interfaceSupportsDiscovery = false
    public static let discoverInterfaces = false
    public static let shouldAutoconnectDiscoveredInterfaces = false
    /// RNS's `max_autoconnected_interfaces()` returns the raw default bool False
    /// (Reticulum.py:260) for a freshly-initialised node.
    public static let maxAutoconnectedInterfaces = false
}
