// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  MPCInterface.swift
//  ReticulumSwift
//
//  Parent orchestrator for Apple Multipeer Connectivity transport.
//  Handles advertising, browsing, session management, and peer lifecycle.
//  Spawns MPCPeerInterface children for each connected peer.
//
//  MPC provides peer-to-peer WiFi between nearby Apple devices without
//  requiring shared WiFi infrastructure — filling the gap between
//  AutoInterface (shared LAN) and BLEInterface (Bluetooth only).
//

#if canImport(MultipeerConnectivity)
import Foundation
import MultipeerConnectivity
import OSLog

// MARK: - MPCInterface

/// Parent interface orchestrating Multipeer Connectivity discovery and sessions.
///
/// Architecture follows the same parent/child pattern as AutoInterface and BLEInterface:
/// - Parent handles discovery (advertise + browse), session management, peer lifecycle
/// - Children (MPCPeerInterface) handle send/receive for individual peers
///
/// Key limitations:
/// - No background operation — MPC disconnects when app is backgrounded
/// - 8-peer session limit (7 remote) — fine for typical Reticulum mesh
/// - No transport selection control — MPC picks BLE vs WiFi automatically
public actor MPCInterface: @preconcurrency NetworkInterface {

    // MARK: - Constants

    /// Default service type for Reticulum MPC discovery.
    /// Must be <=15 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphens.
    public static let defaultServiceType = "reticulum"

    // MARK: - Properties

    public let id: String
    public let config: InterfaceConfig
    public private(set) var state: InterfaceState = .disconnected

    /// Hardware MTU — same as AutoInterface (peer-to-peer WiFi, no practical constraint)
    public var hwMtu: Int { 1196 }

    /// MPC service type for advertising/browsing
    private let serviceType: String

    /// Our local peer identity
    private let localPeerID: MCPeerID

    /// Active session
    private var session: MCSession?

    /// Service advertiser
    private var advertiser: MCNearbyServiceAdvertiser?

    /// Service browser
    private var browser: MCNearbyServiceBrowser?

    /// Session delegate (bridging NSObject delegate to actor)
    private var sessionHandler: SessionHandler?

    /// Connected peer interfaces keyed by MCPeerID.displayName
    private var peers: [String: MPCPeerInterface] = [:]

    /// Peers the browser has discovered (keyed by displayName), kept so we can
    /// re-invite after an unexpected drop instead of waiting for the next
    /// `foundPeer` (which only fires on a fresh discovery, e.g. next app launch).
    private var discoveredPeers: [String: MCPeerID] = [:]

    /// Peer lifecycle callbacks
    private var onPeerAdded: (@Sendable (MPCPeerInterface) -> Void)?
    private var onPeerRemoved: (@Sendable (String) -> Void)?

    /// Delegate
    private var delegateRef: WeakMPCDelegate?

    private let logger = Logger(subsystem: "net.reticulum", category: "MPCInterface")

    // MARK: - Initialization

    /// Create a new MPCInterface.
    ///
    /// - Parameters:
    ///   - config: Interface configuration. `host` field can override service type.
    ///   - displayName: Local peer display name. Defaults to first 8 hex chars of transport identity.
    public init(config: InterfaceConfig, displayName: String? = nil) {
        self.id = config.id
        self.config = config

        // Use host field as service type if non-empty, otherwise default
        let svcType = config.host.isEmpty ? Self.defaultServiceType : config.host
        self.serviceType = svcType

        // Display name for MCPeerID
        let name = displayName ?? config.id
        self.localPeerID = MCPeerID(displayName: name)
    }

    // MARK: - NetworkInterface Protocol

    public func setDelegate(_ delegate: InterfaceDelegate) async {
        self.delegateRef = WeakMPCDelegate(delegate)
    }

    /// Set peer lifecycle callbacks for transport integration.
    ///
    /// - Parameters:
    ///   - onPeerAdded: Called when a new peer connects and its MPCPeerInterface is ready
    ///   - onPeerRemoved: Called with the peer interface ID when a peer disconnects
    public func setPeerCallbacks(
        onPeerAdded: @escaping @Sendable (MPCPeerInterface) -> Void,
        onPeerRemoved: @escaping @Sendable (String) -> Void
    ) {
        self.onPeerAdded = onPeerAdded
        self.onPeerRemoved = onPeerRemoved
    }

    /// Start advertising and browsing for nearby peers.
    public func connect() async throws {
        guard state == .disconnected else { return }

        logger.info("Starting MPC interface \(self.id, privacy: .public) with service type '\(self.serviceType, privacy: .public)'")

        // Create session with no encryption (Reticulum handles its own)
        let session = MCSession(
            peer: localPeerID,
            securityIdentity: nil,
            encryptionPreference: .none
        )
        self.session = session

        // Create and wire session handler
        let handler = SessionHandler(interface: self)
        session.delegate = handler
        self.sessionHandler = handler

        // Start advertising
        let adv = MCNearbyServiceAdvertiser(
            peer: localPeerID,
            discoveryInfo: nil,
            serviceType: serviceType
        )
        adv.delegate = handler
        adv.startAdvertisingPeer()
        self.advertiser = adv

        // Start browsing
        let brw = MCNearbyServiceBrowser(
            peer: localPeerID,
            serviceType: serviceType
        )
        brw.delegate = handler
        brw.startBrowsingForPeers()
        self.browser = brw

        state = .connected
        delegateRef?.delegate?.interface(id: id, didChangeState: .connected)
        logger.info("MPC interface \(self.id, privacy: .public) connected — advertising and browsing")
    }

    /// Stop advertising, browsing, and disconnect all peers.
    public func disconnect() async {
        logger.info("Disconnecting MPC interface \(self.id, privacy: .public)")

        advertiser?.stopAdvertisingPeer()
        advertiser = nil

        browser?.stopBrowsingForPeers()
        browser = nil

        // Remove all peer interfaces
        for (name, peer) in peers {
            await peer.disconnect()
            onPeerRemoved?(peer.id)
            logger.info("Removed MPC peer \(name, privacy: .public)")
        }
        peers.removeAll()

        session?.disconnect()
        session = nil
        sessionHandler = nil

        state = .disconnected
        delegateRef?.delegate?.interface(id: id, didChangeState: .disconnected)
    }

    /// Parent send is a broadcast to all connected peers.
    public func send(_ data: Data) async throws {
        guard state == .connected, let session = session else {
            throw InterfaceError.notConnected
        }
        let connectedPeers = session.connectedPeers
        guard !connectedPeers.isEmpty else { return }

        do {
            try session.send(data, toPeers: connectedPeers, with: .reliable)
        } catch {
            logger.error("MPC broadcast send failed: \(error.localizedDescription, privacy: .public)")
            throw InterfaceError.sendFailed(underlying: error.localizedDescription)
        }
    }

    // MARK: - Peer Management

    /// Called by SessionHandler when a peer connects.
    fileprivate func handlePeerConnected(_ peerID: MCPeerID) {
        let name = peerID.displayName
        // Remember the peer so we can re-invite after an unexpected drop even when the
        // link formed via our advertiser (peer invited us → our browser never fired
        // foundPeer for it, so discoveredPeers would otherwise be empty for this peer).
        discoveredPeers[name] = peerID
        guard peers[name] == nil, let session = session else { return }

        let peer = MPCPeerInterface(
            parentId: id,
            peerID: peerID,
            session: session
        )
        peers[name] = peer

        logger.info("MPC peer connected: \(name, privacy: .public)")
        onPeerAdded?(peer)
    }

    /// Called by SessionHandler when a peer disconnects.
    fileprivate func handlePeerDisconnected(_ peerID: MCPeerID) {
        let name = peerID.displayName
        guard let peer = peers.removeValue(forKey: name) else { return }

        logger.info("MPC peer disconnected: \(name, privacy: .public)")

        Task {
            await peer.disconnect()
        }
        onPeerRemoved?(peer.id)

        // Recover the link within this session instead of waiting for the next app
        // launch. A cold-start MPC session can flap once or twice before settling, and a
        // single re-invite often races the flap, so retry with a bounded, role-staggered
        // backoff until the peer reconnects (then onPeerAdded re-announces and the queued
        // first message flushes). Without this the first message stranded until next launch.
        scheduleReconnect(peerID)
    }

    /// Called by SessionHandler when the browser discovers a peer.
    fileprivate func handleFoundPeer(_ peerID: MCPeerID) {
        discoveredPeers[peerID.displayName] = peerID
        invitePeerIfNeeded(peerID)
    }

    /// Called by SessionHandler when the browser loses sight of a peer.
    fileprivate func handleLostPeer(_ peerID: MCPeerID) {
        discoveredPeers.removeValue(forKey: peerID.displayName)
    }

    /// Deterministic invite direction. Both devices advertise AND browse, so without
    /// this each side invites the other on discovery — two competing session-formation
    /// attempts that MCSession resolves by tearing one down ~2s after connecting (the
    /// cold-start flap). To avoid the race, only the peer with the lexicographically
    /// smaller display name invites; the other auto-accepts (and falls back to inviting
    /// if no connection forms, covering asymmetric discovery).
    private func shouldInitiateInvite(to peerID: MCPeerID) -> Bool {
        localPeerID.displayName < peerID.displayName
    }

    private func invitePeerIfNeeded(_ peerID: MCPeerID) {
        guard let session, let browser else { return }
        guard peers[peerID.displayName] == nil else { return }  // already connected

        if shouldInitiateInvite(to: peerID) {
            logger.info("Inviting MPC peer \(peerID.displayName, privacy: .public) (primary)")
            browser.invitePeer(peerID, to: session, withContext: nil, timeout: 15)
        } else {
            // We're the higher-named side: let the peer invite first to avoid the
            // simultaneous-invite race; fall back to inviting if nothing connects.
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                await self?.fallbackInvite(peerID)
            }
        }
    }

    private func fallbackInvite(_ peerID: MCPeerID) {
        guard peers[peerID.displayName] == nil else { return }            // already connected
        guard discoveredPeers[peerID.displayName] != nil else { return }  // peer went away
        guard let session, let browser else { return }
        logger.info("Fallback-inviting MPC peer \(peerID.displayName, privacy: .public) (no connection after delay)")
        browser.invitePeer(peerID, to: session, withContext: nil, timeout: 15)
    }

    /// Bounded, role-staggered reconnect retries after an unexpected peer drop. The two
    /// sides offset their invites (primary on whole seconds, secondary +500ms) so they
    /// never re-invite simultaneously — which would recreate the dual-session race — while
    /// both still drive recovery (the side that dropped may be the deterministic primary).
    private func scheduleReconnect(_ peerID: MCPeerID, attempt: Int = 1) {
        let maxAttempts = 6
        guard attempt <= maxAttempts else {
            logger.info("Gave up MPC reconnect to \(peerID.displayName, privacy: .public) after \(maxAttempts) attempts")
            return
        }
        // Attempt 1 fires immediately — the first message is the most latency-sensitive
        // and a fast re-invite is what triggers the peer's half-open session rebuild
        // (see prepareSessionForReinvitation). Later attempts back off by whole seconds.
        let base = UInt64(attempt - 1) * 1_000_000_000
        let offset: UInt64 = shouldInitiateInvite(to: peerID) ? 0 : 500_000_000
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: base + offset)
            await self?.attemptReconnect(peerID, attempt: attempt)
        }
    }

    private func attemptReconnect(_ peerID: MCPeerID, attempt: Int) {
        guard peers[peerID.displayName] == nil else { return }            // already reconnected
        guard discoveredPeers[peerID.displayName] != nil else { return }  // peer went away
        guard let session, let browser else { return }
        logger.info("MPC reconnect attempt \(attempt) → \(peerID.displayName, privacy: .public)")
        browser.invitePeer(peerID, to: session, withContext: nil, timeout: 10)
        scheduleReconnect(peerID, attempt: attempt + 1)
    }

    /// A peer we STILL consider connected is inviting us again. That only happens
    /// when our side of the link is half-open: the peer's MCSession dropped us (the
    /// cold-start flap, seen only from the side that got the `.notConnected`) while
    /// our MCSession never noticed and still lists the peer as connected. Returning
    /// that stale session makes MPC sit on its dead half until its own keepalive
    /// expires (~60s) before re-handshaking — long enough to strand the first
    /// message and fail the turn. Instead, rebuild the MCSession so the incoming
    /// invitation handshakes into a clean session immediately. Guarded on the peer
    /// already being present, so steady state (first-time invites) is untouched.
    func sessionForInvitation(from peerID: MCPeerID) -> MCSession? {
        guard peers[peerID.displayName] != nil else { return session }
        logger.info("Half-open MPC link to \(peerID.displayName, privacy: .public) — rebuilding session to accept re-invitation")
        return rebuildSession()
    }

    /// Tear down the current MCSession and its (now-stale) peer interfaces and stand
    /// up a fresh one wired to the same SessionHandler. Used only to heal a half-open
    /// link; advertiser/browser keep running so discovery is unaffected.
    private func rebuildSession() -> MCSession? {
        guard let handler = sessionHandler else { return session }
        for (name, peer) in peers {
            Task { await peer.disconnect() }
            onPeerRemoved?(peer.id)
            logger.info("Dropped stale MPC peer \(name, privacy: .public) during session rebuild")
        }
        peers.removeAll()

        session?.disconnect()
        let fresh = MCSession(
            peer: localPeerID,
            securityIdentity: nil,
            encryptionPreference: .none
        )
        fresh.delegate = handler
        self.session = fresh
        return fresh
    }

    /// Called by SessionHandler when data arrives from a peer.
    fileprivate func handleDataReceived(_ data: Data, from peerID: MCPeerID) {
        let name = peerID.displayName
        guard let peer = peers[name] else {
            logger.warning("Received data from unknown MPC peer: \(name, privacy: .public)")
            return
        }
        peer.processIncoming(data)
    }

    // MARK: - Status

    /// Number of currently connected peers.
    public var peerCount: Int { peers.count }

    /// Display names of connected peers.
    public var connectedPeerNames: [String] { Array(peers.keys) }

    // MARK: - Internal Accessors (for SessionHandler)

    /// Report an error through the delegate.
    func reportError(_ error: Error) {
        delegateRef?.delegate?.interface(id: id, didFailWithError: error)
    }

    /// Handle advertiser failure — transition to disconnected if not already browsing successfully.
    func handleAdvertiserFailed(_ error: Error) {
        logger.error("MPC advertiser failed, disconnecting: \(error.localizedDescription, privacy: .public)")
        delegateRef?.delegate?.interface(id: id, didFailWithError: error)
        // If browsing is also not working, go disconnected
        Task { await self.disconnect() }
    }

    /// Handle browser failure — transition to disconnected if not already advertising successfully.
    func handleBrowserFailed(_ error: Error) {
        logger.error("MPC browser failed, disconnecting: \(error.localizedDescription, privacy: .public)")
        delegateRef?.delegate?.interface(id: id, didFailWithError: error)
        Task { await self.disconnect() }
    }
}

// MARK: - SessionHandler

/// Bridges MCSession/MCNearbyServiceAdvertiser/MCNearbyServiceBrowser delegates
/// to the MPCInterface actor.
///
/// MCSession delegates must be NSObject subclasses and are called on arbitrary
/// dispatch queues. This handler dispatches events to the actor via Task.
private final class SessionHandler: NSObject,
    MCSessionDelegate,
    MCNearbyServiceAdvertiserDelegate,
    MCNearbyServiceBrowserDelegate,
    @unchecked Sendable
{
    private weak var interface: MPCInterface?
    private let logger = Logger(subsystem: "net.reticulum", category: "MPCSessionHandler")

    init(interface: MPCInterface) {
        self.interface = interface
    }

    // MARK: - MCSessionDelegate

    func session(
        _ session: MCSession,
        peer peerID: MCPeerID,
        didChange state: MCSessionState
    ) {
        guard let interface = interface else { return }

        switch state {
        case .connected:
            logger.info("MCSession peer connected: \(peerID.displayName, privacy: .public)")
            Task { await interface.handlePeerConnected(peerID) }

        case .notConnected:
            logger.info("MCSession peer disconnected: \(peerID.displayName, privacy: .public)")
            Task { await interface.handlePeerDisconnected(peerID) }

        case .connecting:
            logger.debug("MCSession peer connecting: \(peerID.displayName, privacy: .public)")

        @unknown default:
            logger.warning("MCSession unknown state for \(peerID.displayName, privacy: .public)")
        }
    }

    func session(
        _ session: MCSession,
        didReceive data: Data,
        fromPeer peerID: MCPeerID
    ) {
        guard let interface = interface else { return }
        Task { await interface.handleDataReceived(data, from: peerID) }
    }

    func session(
        _ session: MCSession,
        didReceive stream: InputStream,
        withName streamName: String,
        fromPeer peerID: MCPeerID
    ) {
        // Not used — Reticulum uses message-based transport
        stream.close()
    }

    func session(
        _ session: MCSession,
        didStartReceivingResourceWithName resourceName: String,
        fromPeer peerID: MCPeerID,
        with progress: Progress
    ) {
        // Not used
    }

    func session(
        _ session: MCSession,
        didFinishReceivingResourceWithName resourceName: String,
        fromPeer peerID: MCPeerID,
        at localURL: URL?,
        withError error: Error?
    ) {
        // Not used
    }

    // MARK: - MCNearbyServiceAdvertiserDelegate

    func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didReceiveInvitationFromPeer peerID: MCPeerID,
        withContext context: Data?,
        invitationHandler: @escaping (Bool, MCSession?) -> Void
    ) {
        // Auto-accept all invitations — IFAC provides Reticulum-layer auth if needed
        guard let interface = interface else {
            invitationHandler(false, nil)
            return
        }

        logger.info("Auto-accepting MPC invitation from \(peerID.displayName, privacy: .public)")
        Task {
            // Use a clean session if this is a half-open re-invitation (peer already
            // present), otherwise the current one. Heals the cold-start flap fast.
            let session = await interface.sessionForInvitation(from: peerID)
            invitationHandler(session != nil, session)
        }
    }

    func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didNotStartAdvertisingPeer error: Error
    ) {
        logger.error("MPC advertiser failed: \(error.localizedDescription, privacy: .public)")
        guard let interface = interface else { return }
        Task {
            await interface.handleAdvertiserFailed(error)
        }
    }

    // MARK: - MCNearbyServiceBrowserDelegate

    func browser(
        _ browser: MCNearbyServiceBrowser,
        foundPeer peerID: MCPeerID,
        withDiscoveryInfo info: [String: String]?
    ) {
        guard let interface = interface else { return }

        logger.info("MPC browser found peer: \(peerID.displayName, privacy: .public)")

        // Deterministic invite direction is decided inside the actor (see
        // invitePeerIfNeeded) to avoid the simultaneous-invite race.
        Task { await interface.handleFoundPeer(peerID) }
    }

    func browser(
        _ browser: MCNearbyServiceBrowser,
        lostPeer peerID: MCPeerID
    ) {
        logger.info("MPC browser lost peer: \(peerID.displayName, privacy: .public)")
        // MCSession state change handles actual disconnect
        guard let interface = interface else { return }
        Task { await interface.handleLostPeer(peerID) }
    }

    func browser(
        _ browser: MCNearbyServiceBrowser,
        didNotStartBrowsingForPeers error: Error
    ) {
        logger.error("MPC browser failed: \(error.localizedDescription, privacy: .public)")
        guard let interface = interface else { return }
        Task {
            await interface.handleBrowserFailed(error)
        }
    }
}

// MARK: - WeakMPCDelegate

private final class WeakMPCDelegate: @unchecked Sendable {
    weak var delegate: InterfaceDelegate?

    init(_ delegate: InterfaceDelegate) {
        self.delegate = delegate
    }
}

// MARK: - CustomStringConvertible

extension MPCInterface: CustomStringConvertible {
    nonisolated public var description: String {
        "MPCInterface<\(id)>"
    }
}

#endif
