// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  BLEMeshConstants.swift
//  ReticulumSwift
//
//  Constants for BLE mesh peer-to-peer networking.
//  Wire-compatible with Python ble-reticulum and Kotlin reticulum-kt.
//
//  SEPARATE from BLEConstants.swift (RNode/NUS for LoRa radio control).
//

import Foundation
#if canImport(CoreBluetooth)
import CoreBluetooth
#endif

// MARK: - BLE Mesh Constants

public enum BLEMeshConstants {

    // MARK: - GATT Service & Characteristics

    public static let serviceUUIDString = "37145b00-442d-4a94-917f-8f42c5da28e3"
    public static let txCharUUIDString = "37145b00-442d-4a94-917f-8f42c5da28e4"
    public static let rxCharUUIDString = "37145b00-442d-4a94-917f-8f42c5da28e5"
    public static let identityCharUUIDString = "37145b00-442d-4a94-917f-8f42c5da28e6"

    #if canImport(CoreBluetooth)
    public static let serviceUUID = CBUUID(string: serviceUUIDString)
    public static let txCharUUID = CBUUID(string: txCharUUIDString)
    public static let rxCharUUID = CBUUID(string: rxCharUUIDString)
    public static let identityCharUUID = CBUUID(string: identityCharUUIDString)
    #endif

    // MARK: - Fragment Header

    public static let headerSize = 5
    public static let fragmentStart: UInt8 = 0x01
    public static let fragmentContinue: UInt8 = 0x02
    public static let fragmentEnd: UInt8 = 0x03

    // MARK: - MTU

    public static let defaultMTU = 185
    public static let minMTU = 20
    public static let maxMTU = 517

    // MARK: - Keepalive

    public static let keepaliveByte: UInt8 = 0x00
    public static let keepaliveInterval: TimeInterval = 15.0

    // MARK: - Data-Path Liveness Probe (protocol v0.4.0)

    /// A keepalive proves the *link* is up; it does not prove *data* still flows
    /// (under RF degradation 1-byte writes succeed while larger fragments fail, and
    /// the link layer keeps an idle connection alive). The data-path probe is an
    /// active 2-byte PING/PONG round-trip over the real data path: a healthy link
    /// round-trips it (which keeps the link fresh, so idle links are never reaped),
    /// a data-dead link does not (so it is detected and reconnected). The 2-byte
    /// frames are shorter than the 5-byte fragment header, so peers that predate the
    /// probe reject them as "too short" and are unaffected.
    /// Wire-compatible with ble-reticulum python (BLE_PROTOCOL_v0.4.0.md).
    public static let probePingByte: UInt8 = 0x04
    public static let probePongByte: UInt8 = 0x05
    /// PING a link that has had no real data for this many seconds.
    public static let dataPathProbeInterval: TimeInterval = 15.0
    /// Reconnect a probe-capable peer whose data path has been silent this long.
    public static let dataPathTimeout: TimeInterval = 45.0
    /// How often the per-peer probe/detect loop runs.
    public static let dataPathProbePollInterval: TimeInterval = 10.0

    // MARK: - Timeouts

    public static let reassemblyTimeout: TimeInterval = 30.0
    public static let handshakeTimeout: TimeInterval = 30.0
    // A live peripheral connects in ~1-2s; a stale RPA (peer rotated its advertising
    // address) never completes. A short timeout lets the central abandon a stale
    // address fast and retry the live one — and (since the scan is paused during a
    // connect) keeps a stale attempt from blocking discovery for long.
    public static let connectionTimeout: TimeInterval = 8.0
    public static let zombieTimeout: TimeInterval = 45.0
    public static let zombieCheckInterval: TimeInterval = 15.0
    public static let zombieGracePeriod: TimeInterval = 5.0

    // MARK: - Blacklist / Backoff

    public static let blacklistBaseInterval: TimeInterval = 60.0
    public static let blacklistMaxMultiplier = 8

    // MARK: - Connection Limits

    public static let maxConnections = 7
    public static let minRSSI: Int = -85
    public static let evictionMargin: Double = 0.15

    // MARK: - RSSI Poll

    public static let rssiPollInterval: TimeInterval = 10.0

    // MARK: - MAC Rotation

    /// If a "connected" peer has no activity for this long, treat it as stale
    /// and allow replacement by a new connection with the same identity.
    /// Set to 2x keepalive interval.
    public static let staleConnectionThreshold: TimeInterval = 30.0

    /// Grace window between a peer's BLE connection dropping and tearing down its
    /// per-peer interface (unregistering it from the transport). A reconnect with
    /// the same identity during this window reuses the interface, so a transient
    /// drop (e.g. MAC rotation) does not cull the learned route.
    /// Mirrors ble-reticulum python `_pending_detach_grace_period = 2.0`
    /// (BLEInterface.py). iOS BLE reconnect latency may warrant tuning this up.
    public static let detachGracePeriod: TimeInterval = 2.0
}
