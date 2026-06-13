// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  BLEPeerInterface.swift
//  ReticulumSwift
//
//  Per-peer BLE mesh sub-interface registered with Transport.
//  Port of BLEPeerInterface.kt from reticulum-kt.
//
//  Each connected BLE mesh peer gets its own BLEPeerInterface actor
//  so Transport can route packets to specific peers via their interface ID.
//

import Foundation
import OSLog

// MARK: - BLE Peer Interface

/// A sub-interface representing a single connected BLE mesh peer.
///
/// BLEInterface spawns one of these for each peer that completes the
/// handshake. Each peer interface is registered with ReticulumTransport
/// independently, allowing the transport layer to route packets to
/// specific peers.
///
/// Handles fragmentation, reassembly, keepalive, and RSSI polling.
public actor BLEPeerInterface: @preconcurrency NetworkInterface {

    // MARK: - NetworkInterface Properties

    public let id: String
    public let config: InterfaceConfig
    public private(set) var state: InterfaceState = .connected

    // MARK: - Peer Properties

    /// Remote peer's identity hash (16 bytes hex string)
    public let peerIdentityHex: String

    /// Whether this is an outgoing (central) connection
    public private(set) var isOutgoing: Bool

    /// Latest RSSI reading
    public private(set) var rssi: Int = 0

    /// Last time we received any data (fragment or keepalive)
    public private(set) var lastActivity: Date = Date()

    /// Last time *real data* crossed the link — a data fragment or a data-path probe
    /// frame, but NOT a keepalive or handshake. Drives the data-path liveness probe.
    /// (`lastActivity` includes keepalives and so cannot distinguish an idle-but-healthy
    /// link from a keepalive-alive-but-data-dead one; this clock can.)
    /// Mirrors ble-reticulum python `_last_real_data` (BLEInterface.py).
    public private(set) var lastRealData: Date = Date()

    /// When this peer connection was established
    public private(set) var connectedAt: Date = Date()

    /// Total bytes sent to this peer
    public private(set) var bytesSent: Int = 0

    /// Total bytes received from this peer
    public private(set) var bytesReceived: Int = 0

    /// Total packets sent to this peer
    public private(set) var packetsSent: Int = 0

    /// Total packets received from this peer
    public private(set) var packetsReceived: Int = 0

    /// Hardware MTU — matches Python RNodeInterface.HW_MTU for BLE radio
    public var hwMtu: Int { 508 }

    /// Current MTU for this connection
    public var mtu: Int {
        connection.mtu
    }

    // MARK: - Internal

    private var connection: any BLEPeerConnection
    private var fragmenter: BLEFragmenter
    private let reassembler: BLEReassembler

    private var receiveTask: Task<Void, Never>?
    private var keepaliveTask: Task<Void, Never>?
    private var rssiTask: Task<Void, Never>?
    private var probeTask: Task<Void, Never>?

    /// Set once a PING/PONG has been seen from this peer (the peer speaks the
    /// data-path probe). Only probe-capable peers are reconnected on a dead path,
    /// so peers that predate the probe are never falsely reaped.
    /// Mirrors ble-reticulum python `_probe_capable` (BLEInterface.py).
    private var probeCapable: Bool = false

    private var delegateRef: WeakBLEPeerDelegate?
    /// Invoked when this peer detects its OWN connection dropped (receive stream
    /// ended or keepalive failed). The owner (`BLEInterface`) schedules a
    /// grace-period detach rather than removing the interface immediately.
    private var onConnectionLost: ((String) -> Void)?
    /// Invoked when this peer's data-path probe finds the link dead (connected but no
    /// real data flowing). The owner forces a real driver-level disconnect so the
    /// connection re-establishes — `connection.close()` alone only ends the receive
    /// stream, it does not cancel the BLE link. Mirrors ble-reticulum's probe calling
    /// `driver.disconnect(address)`.
    private var onDataPathDead: ((String) -> Void)?

    private let logger = Logger(subsystem: "net.reticulum", category: "BLEPeerInterface")

    // MARK: - Init

    /// Create a new BLE peer interface.
    ///
    /// - Parameters:
    ///   - parentId: Parent BLEInterface's ID
    ///   - peerIdentityHex: Remote peer's identity hash as hex string
    ///   - connection: Established BLE connection to this peer
    ///   - isOutgoing: True if we initiated the connection (central role)
    public init(
        parentId: String,
        peerIdentityHex: String,
        connection: any BLEPeerConnection,
        isOutgoing: Bool
    ) {
        self.id = "ble-\(parentId)-\(peerIdentityHex.prefix(8))"
        self.peerIdentityHex = peerIdentityHex
        self.connection = connection
        self.isOutgoing = isOutgoing
        self.fragmenter = BLEFragmenter(mtu: connection.mtu)
        self.reassembler = BLEReassembler()
        self.config = InterfaceConfig(
            id: "ble-\(parentId)-\(peerIdentityHex.prefix(8))",
            name: "BLEPeer[\(peerIdentityHex.prefix(8))]",
            type: .ble,
            enabled: true,
            mode: .full,
            host: peerIdentityHex,
            port: 0
        )
    }

    // MARK: - NetworkInterface Protocol

    public func connect() async throws {
        // Already connected at creation
    }

    public func disconnect() async {
        detach()
    }

    public func send(_ data: Data) async throws {
        guard state == .connected else {
            throw InterfaceError.notConnected
        }

        let fragments = fragmenter.fragment(data)
        for fragment in fragments {
            try await connection.sendFragment(fragment)
        }
        bytesSent += data.count
        packetsSent += 1
    }

    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegateRef = WeakBLEPeerDelegate(delegate)
    }

    // MARK: - Lifecycle

    /// Set the connection-lost callback (called when this peer detects its own
    /// connection dropped, so the owner can schedule a grace-period detach).
    public func setOnConnectionLost(_ callback: @escaping @Sendable (String) -> Void) {
        self.onConnectionLost = callback
    }

    /// Set the data-path-dead callback (called when the data-path probe finds the link
    /// dead, so the owner can force a real driver-level disconnect → reconnect).
    public func setOnDataPathDead(_ callback: @escaping @Sendable (String) -> Void) {
        self.onDataPathDead = callback
    }

    /// Start background loops: receive, keepalive, RSSI polling.
    public func startReceiving() {
        // Capture the stream while still on the actor
        let stream = connection.receivedFragments
        receiveTask = Task { [weak self] in
            for await fragment in stream {
                guard !Task.isCancelled else { break }
                guard let self = self else { break }
                await self.handleFragment(fragment)
            }
            // Stream ended — connection lost
            if !Task.isCancelled {
                await self?.handleConnectionLost()
            }
        }

        keepaliveTask = Task { [weak self] in
            var firstFailure = true
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(BLEMeshConstants.keepaliveInterval))
                } catch { break }

                guard let self = self else { break }
                do {
                    try await self.sendKeepalive()
                    firstFailure = true // Reset grace on success
                } catch {
                    if firstFailure {
                        // Grace period: one failure is OK
                        firstFailure = false
                        await self.logDebug("Keepalive failed (grace period)")
                    } else {
                        await self.logDebug("Keepalive failed twice — connection lost")
                        await self.handleConnectionLost()
                        break
                    }
                }
            }
        }

        // Data-path liveness probe: PING an idle link, reconnect a data-dead peer.
        probeTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(BLEMeshConstants.dataPathProbePollInterval))
                } catch { break }

                guard let self = self else { break }
                await self.runDataPathProbe()
            }
        }

        // Only poll RSSI on outgoing connections
        if isOutgoing {
            rssiTask = Task { [weak self] in
                while !Task.isCancelled {
                    do {
                        try await Task.sleep(for: .seconds(BLEMeshConstants.rssiPollInterval))
                    } catch { break }

                    guard let self = self else { break }
                    await self.pollRssi()
                }
            }
        }
    }

    /// Whether this peer's connection appears stale (no activity for staleConnectionThreshold).
    /// Used by BLEInterface to allow MAC-rotated peers to replace stale connections
    /// without waiting for the disconnect event.
    public var isStale: Bool {
        Date().timeIntervalSince(lastActivity) > BLEMeshConstants.staleConnectionThreshold
    }

    /// Update the underlying connection (e.g., after MAC rotation hot-swap).
    /// Resets stats and restarts background loops on the new connection.
    public func updateConnection(_ newConnection: any BLEPeerConnection, isOutgoing newIsOutgoing: Bool) {
        // Cancel existing loops
        receiveTask?.cancel()
        keepaliveTask?.cancel()
        rssiTask?.cancel()
        probeTask?.cancel()

        connection.close()
        connection = newConnection
        self.isOutgoing = newIsOutgoing
        fragmenter = BLEFragmenter(mtu: newConnection.mtu)
        reassembler.reset()
        lastActivity = Date()
        lastRealData = Date()
        probeCapable = false
        connectedAt = Date()
        bytesSent = 0
        bytesReceived = 0
        packetsSent = 0
        packetsReceived = 0
        state = .connected

        // Restart loops
        startReceiving()
    }

    /// Tear down this peer's BLE connection + background loops. Idempotent.
    ///
    /// This does NOT unregister the interface from the transport — that is owned by
    /// `BLEInterface.removePeer`, called either after the detach grace period expires
    /// or immediately for a deliberate removal (zombie / eviction / stop). Keeping
    /// teardown and transport-unregistration separate is what lets a transient drop
    /// hold the route alive during the grace window (ble-reticulum `_pending_detach`).
    public func detach() {
        guard state == .connected else { return }
        state = .disconnected

        receiveTask?.cancel()
        keepaliveTask?.cancel()
        rssiTask?.cancel()
        probeTask?.cancel()
        receiveTask = nil
        keepaliveTask = nil
        rssiTask = nil
        probeTask = nil

        connection.close()

        delegateRef?.delegate?.interface(id: id, didChangeState: .disconnected)

        logger.info("BLEPeerInterface[\(self.peerIdentityHex.prefix(8), privacy: .public)] connection torn down")
    }

    /// The peer detected its OWN connection dropped (receive stream ended, or
    /// keepalive failed twice). Tear the dead connection down, then ask the owning
    /// `BLEInterface` to schedule a grace-period detach instead of removing the
    /// interface immediately — a reconnect with the same identity during the grace
    /// window reuses it, so a transient drop does not cull the learned route.
    ///
    /// Mirrors ble-reticulum: the driver's disconnect callback
    /// (`_device_disconnected_callback`) schedules `_pending_detach` rather than
    /// detaching the peer interface inline.
    private func handleConnectionLost() {
        guard state == .connected else { return }
        detach()                            // teardown; sets state → .disconnected
        onConnectionLost?(peerIdentityHex)  // → BLEInterface.scheduleDetach (grace)
    }

    // MARK: - Fragment Handling

    private func handleFragment(_ fragment: Data) async {
        lastActivity = Date()
        bytesReceived += fragment.count

        // Keepalives (single 0x00 byte) prove the LINK, not the data path — ignore.
        if fragment.count == 1 && fragment[fragment.startIndex] == BLEMeshConstants.keepaliveByte {
            return
        }

        // Data-path liveness probe frames (2-byte PING/PONG).
        if await handleProbeFrame(fragment) {
            return
        }

        // Handshake data (exactly 16 bytes = identity) — not real data.
        if fragment.count == 16 {
            return
        }

        // Real data crossed the link — refresh the data-path liveness clock.
        lastRealData = Date()

        do {
            if let packet = try reassembler.receiveFragment(fragment, senderId: peerIdentityHex) {
                packetsReceived += 1
                delegateRef?.delegate?.interface(id: id, didReceivePacket: packet)
            }
        } catch {
            logger.warning("Reassembly error from \(self.peerIdentityHex.prefix(8), privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    private func sendKeepalive() async throws {
        let data = Data([BLEMeshConstants.keepaliveByte])
        try await connection.sendFragment(data)
    }

    // MARK: - Data-Path Liveness Probe

    /// Handle an inbound data-path liveness frame (2-byte PING/PONG). Returns true if
    /// `fragment` was a probe frame (and is now consumed). Receiving any probe frame
    /// proves the inbound data path is alive and that the peer speaks the probe, so the
    /// peer is marked probe-capable; a PING is echoed as a PONG.
    ///
    /// Port note: ble-reticulum `_handle_probe_frame` (BLEInterface.py) also normalizes a
    /// "dev:"-prefixed peripheral address to resolve the peer's identity; here the frame
    /// already arrives on this peer's own connection, so no address lookup is needed.
    private func handleProbeFrame(_ fragment: Data) async -> Bool {
        guard fragment.count == 2 else { return false }
        let type = fragment[fragment.startIndex]
        guard type == BLEMeshConstants.probePingByte || type == BLEMeshConstants.probePongByte else {
            return false
        }

        // Any probe frame proves the data path is alive and the peer speaks the probe.
        lastRealData = Date()
        probeCapable = true

        if type == BLEMeshConstants.probePingByte {
            let nonce = fragment[fragment.index(after: fragment.startIndex)]
            try? await sendProbe(BLEMeshConstants.probePongByte, nonce: nonce)
        }
        return true
    }

    /// Send a 2-byte data-path probe frame (PING/PONG) over the real data path.
    private func sendProbe(_ type: UInt8, nonce: UInt8) async throws {
        try await connection.sendFragment(Data([type, nonce]))
    }

    /// Periodic data-path liveness sweep for this peer.
    ///
    /// - If the link has had no real data for `dataPathProbeInterval`, send a PING; a
    ///   healthy peer echoes a PONG, which refreshes `lastRealData` — so the probe is
    ///   itself the traffic that keeps a genuinely idle-but-healthy link from ever
    ///   looking dead, and idle links are never reaped.
    /// - If a probe-capable peer's data path has been silent past `dataPathTimeout`, the
    ///   link is "connected but data-dead": tear it down so it re-establishes.
    ///
    /// Port note: ble-reticulum `_run_data_path_probes` (BLEInterface.py) runs one timer
    /// in the parent interface iterating all peers; this swift port runs the loop per-peer
    /// (alongside the existing keepalive/RSSI tasks) to fit the per-peer actor model. The
    /// reconnect is delegated to the owner via `onDataPathDead`, which forces a real
    /// `driver.disconnect(address)` (python parity) — `connection.close()` alone only ends
    /// the receive stream and would leave the (data-dead) BLE link up.
    private func runDataPathProbe() async {
        let idle = Date().timeIntervalSince(lastRealData)
        if idle > BLEMeshConstants.dataPathProbeInterval {
            try? await sendProbe(BLEMeshConstants.probePingByte,
                                 nonce: UInt8(truncatingIfNeeded: Int(Date().timeIntervalSince1970)))
        }
        // Re-read `lastRealData` after the await: this is an actor reentrancy
        // point, so the probe's PONG (or any real traffic) may have refreshed it
        // via `handleProbeFrame` while `sendProbe` was suspended. Deciding on the
        // stale pre-await `idle` here would force-disconnect a link that just
        // answered the PING — the spurious-reconnect-on-healthy-link bug.
        //
        // Also bail if `detach()` ran during the suspension: `handleConnectionLost`
        // flips `state` to `.disconnected` but leaves `probeCapable == true`, so
        // without this guard `onDataPathDead` fires on an already-dead peer — and if
        // a grace-window reconnect has meanwhile re-pointed `addressToIdentity`, the
        // resulting `driver.disconnect` lands on the NEW address and kills the
        // freshly-reconnected connection.
        guard state == .connected else { return }
        let currentIdle = Date().timeIntervalSince(lastRealData)
        if probeCapable && currentIdle > BLEMeshConstants.dataPathTimeout {
            logger.warning("data-path dead for \(self.peerIdentityHex.prefix(8), privacy: .public) — no real data for \(Int(currentIdle), privacy: .public)s, reconnecting")
            probeCapable = false
            onDataPathDead?(peerIdentityHex)
        }
    }

    private func pollRssi() {
        Task {
            do {
                let newRssi = try await connection.readRemoteRssi()
                self.rssi = newRssi
            } catch {
                // RSSI poll failure is not critical
            }
        }
    }

    private func logDebug(_ message: String) {
        logger.debug("\(message, privacy: .public)")
    }

    // MARK: - Testing

    /// Set lastActivity to an arbitrary date (for staleness testing).
    internal func setLastActivityForTesting(_ date: Date) {
        lastActivity = date
    }
}

// MARK: - Weak Delegate

private final class WeakBLEPeerDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension BLEPeerInterface: CustomStringConvertible {
    nonisolated public var description: String {
        "BLEPeerInterface<\(id)>"
    }
}
