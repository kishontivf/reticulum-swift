// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  TCPServerInterface.swift
//  ReticulumSwift
//
//  TCP listen-side interface. Binds NWListener to a loopback port and
//  spawns a `TCPSpawnedPeerInterface` per accepted client so each
//  physical connection is a separately-addressable NetworkInterface
//  the Transport can route to.
//
//  This mirrors Python RNS/Interfaces/TCPInterface.py's
//  TCPServerInterface + spawned child model and Kotlin's
//  TCPServerInterface. Primarily used by the conformance bridge's
//  wire_* commands where a real listen/connect pair is needed to
//  exercise the end-to-end transmit/receive pipeline.
//

import Foundation
import Network
import os.log

private let tcpServerLogger = Logger(subsystem: "net.reticulum", category: "TCPServerInterface")

// MARK: - Per-connection peer

/// NetworkInterface wrapping a single already-accepted inbound NWConnection.
///
/// Spawned by `TCPServerInterface` on each accepted connection. Each peer
/// holds its own FramedTransport so HDLC framing is applied per-connection,
/// matching the wire format every other TCP peer speaks.
///
/// Note: reuses the same `@unchecked Sendable` pattern as BehavioralMockInterface —
/// bridge commands serialize mutations, and NWConnection callbacks run on
/// a dedicated DispatchQueue that we guard with an NSLock.
public final class TCPSpawnedPeerInterface: NetworkInterface, @unchecked Sendable {
    public let id: String
    public let config: InterfaceConfig
    public var hwMtu: Int { 262144 }

    /// Name of the spawning parent, so tests that inspect interface names
    /// can tie a spawned child back to its server.
    public let parentName: String

    /// Runtime-mutable mode. `config.mode` is fixed at construction (the
    /// parent's mode at spawn time); `modeOverride` is what the Transport
    /// should read for AnnounceFilter decisions. When the bridge mutates
    /// the parent's mode via `wire_set_interface_mode`, it walks the
    /// spawned-peer list and sets this so existing connections observe
    /// the new mode too.
    public var modeOverride: InterfaceMode? {
        get { lock.lock(); defer { lock.unlock() }; return _modeOverride }
        set { lock.lock(); _modeOverride = newValue; lock.unlock() }
    }

    public var state: InterfaceState {
        lock.lock(); defer { lock.unlock() }
        return _state
    }

    /// Total bytes sent through this peer (for wire_tx_bytes aggregation).
    public var bytesSent: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return _bytesSent
    }

    /// Fired exactly once when this peer transitions to `.disconnected`.
    /// The parent server uses this to evict the peer from its
    /// `_spawnedPeers` map so the dictionary doesn't grow unbounded over
    /// the lifetime of the listener.
    var onDisconnect: ((String) -> Void)?

    // MARK: - Internal mutable state (lock-guarded)
    private let lock = NSLock()
    private var _state: InterfaceState = .disconnected
    private var _bytesSent: UInt64 = 0
    private var _modeOverride: InterfaceMode?
    private var _delegate: InterfaceDelegate?
    private var _firedDisconnect: Bool = false
    private let connection: NWConnection
    private let queue: DispatchQueue
    private var framed: FramedTransport?

    // MARK: - Init

    init(
        id: String,
        parentName: String,
        parentConfig: InterfaceConfig,
        connection: NWConnection,
        queue: DispatchQueue
    ) {
        self.id = id
        self.parentName = parentName
        self.connection = connection
        self.queue = queue
        // Derive our config from the parent's: same mode, same bitrate, same
        // IFAC settings. The id/name are per-peer so interface lookups in
        // the Transport layer stay unambiguous.
        self.config = InterfaceConfig(
            id: id,
            name: "Client on \(parentName)",
            type: .tcp,
            enabled: true,
            mode: parentConfig.mode,
            host: "127.0.0.1",
            port: 0,
            ifac: parentConfig.ifac,
            announceRateTarget: parentConfig.announceRateTarget,
            announceRateGrace: parentConfig.announceRateGrace,
            announceRatePenalty: parentConfig.announceRatePenalty,
            bitrate: parentConfig.bitrate,
            ifacSize: parentConfig.ifacSize,
            ifacKey: parentConfig.ifacKey
        )
    }

    // MARK: - NetworkInterface

    public func connect() async throws {
        // Spawned peers are born connected — the NWConnection was already
        // accepted by the listener before construction. Kick off the HDLC
        // transport wrap + receive loop here.
        start()
    }

    public func disconnect() async {
        lock.lock()
        let f = framed
        framed = nil
        _state = .disconnected
        lock.unlock()
        f?.disconnect()
    }

    public func send(_ data: Data) async throws {
        lock.lock()
        guard _state == .connected, let f = framed else {
            lock.unlock()
            throw InterfaceError.notConnected
        }
        lock.unlock()

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            f.send(data) { [weak self] error in
                guard let self else {
                    if let error { cont.resume(throwing: InterfaceError.sendFailed(underlying: error.localizedDescription)) }
                    else { cont.resume() }
                    return
                }
                if let error {
                    cont.resume(throwing: InterfaceError.sendFailed(underlying: error.localizedDescription))
                } else {
                    self.lock.lock()
                    self._bytesSent += UInt64(data.count)
                    self.lock.unlock()
                    cont.resume()
                }
            }
        }
    }

    public func setDelegate(_ delegate: InterfaceDelegate) async {
        lock.lock()
        _delegate = delegate
        lock.unlock()
    }

    // MARK: - Internals

    /// Wire the NWConnection into a FramedTransport. Called from the
    /// listener when this peer is born (already in .ready state).
    private func start() {
        let transport = NWInboundConnectionTransport(connection: connection, queue: queue)
        let f = FramedTransport(transport: transport)

        f.onStateChange = { [weak self] ts in
            guard let self else { return }
            switch ts {
            case .connected:
                self.setState(.connected)
            case .disconnected, .failed:
                self.setState(.disconnected)
            case .connecting:
                self.setState(.connecting)
            }
        }
        f.onDataReceived = { [weak self] data in
            guard let self else { return }
            let d: InterfaceDelegate?
            self.lock.lock()
            d = self._delegate
            self.lock.unlock()
            d?.interface(id: self.id, didReceivePacket: data)
        }

        lock.lock()
        framed = f
        lock.unlock()

        transport.start()
    }

    private func setState(_ new: InterfaceState) {
        let d: InterfaceDelegate?
        let disconnectCb: ((String) -> Void)?
        lock.lock()
        _state = new
        d = _delegate
        // Fire onDisconnect exactly once per peer lifetime so the parent
        // server can evict us from its _spawnedPeers map. Without this
        // eviction, disconnected peers accumulate indefinitely over the
        // server's lifetime — send() would silently try to deliver to
        // them on every subsequent broadcast and spawnedPeers iteration
        // (e.g. wire_set_interface_mode) would walk stale entries.
        if new == .disconnected, !_firedDisconnect {
            _firedDisconnect = true
            disconnectCb = onDisconnect
        } else {
            disconnectCb = nil
        }
        lock.unlock()
        d?.interface(id: id, didChangeState: new)
        disconnectCb?(id)
    }
}

// MARK: - Listen-side parent

/// TCP listen-side interface. Not an actor — uses NSLock for the same
/// reason BehavioralMockInterface does: NWListener callbacks run on a
/// dedicated DispatchQueue, and bridge commands serialize through
/// readLine, so contention is minimal and actor overhead is unnecessary.
///
/// Lifecycle:
///   1. init(config:) validates config.type == .tcp
///   2. start() (called via connect()) binds NWListener
///   3. For each accepted NWConnection, spawn a TCPSpawnedPeerInterface
///      and fire onClientConnected so the bridge can register it with
///      the ReticulumTransport via addInterface(_:)
///   4. The server itself has state=.connected while the listener is
///      bound; send() on the server broadcasts to all live spawned peers
///      (used when HEADER_1 announces need to reach all connected clients)
///   5. disconnect() tears down the listener and all peers
public final class TCPServerInterface: NetworkInterface, @unchecked Sendable {

    // MARK: - NetworkInterface properties

    public let id: String
    public let config: InterfaceConfig
    public var hwMtu: Int { 262144 }

    public var state: InterfaceState {
        lock.lock(); defer { lock.unlock() }
        return _state
    }

    /// Runtime-mutable mode. See `TCPSpawnedPeerInterface.modeOverride`
    /// for rationale. Setting this on the parent does NOT automatically
    /// propagate to spawned children — the conformance bridge mirrors
    /// Kotlin's behaviour and walks `spawnedPeers` on wire_set_interface_mode.
    public var modeOverride: InterfaceMode? {
        get { lock.lock(); defer { lock.unlock() }; return _modeOverride }
        set { lock.lock(); _modeOverride = newValue; lock.unlock() }
    }

    /// Snapshot of currently-live spawned peer interfaces.
    ///
    /// Returns a copy so callers can iterate without holding the lock,
    /// at the cost of potentially including a peer that just disconnected.
    /// For wire_tx_bytes / wire_set_interface_mode the race is harmless.
    public var spawnedPeers: [TCPSpawnedPeerInterface] {
        lock.lock(); defer { lock.unlock() }
        return Array(_spawnedPeers.values)
    }

    /// Aggregate tx-bytes across all spawned peers.
    ///
    /// The server's `send(_:)` fan-outs delegate to each peer's `send()`,
    /// and each peer increments its own `bytesSent` counter — so the per-peer
    /// sum is already the full server-side TX total. A parallel server-level
    /// counter would double-count every byte.
    public var totalBytesSent: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return _spawnedPeers.values.reduce(0) { $0 + $1.bytesSent }
    }

    // MARK: - Callbacks set by the bridge

    /// Fired when a new client connection is accepted. The bridge must
    /// call `transport.addInterface(spawned)` so the Transport-facing
    /// routing layer can find the peer and attach a delegate.
    ///
    /// Mirrors Kotlin's `TCPServerInterface.onClientConnected` — without
    /// it, path responses targeting `attachedInterface = <spawned child>`
    /// are silently dropped because the spawned interface isn't in
    /// `Transport.interfaces`.
    public var onClientConnected: ((TCPSpawnedPeerInterface) -> Void)?

    // MARK: - Private state

    private let lock = NSLock()
    private var _state: InterfaceState = .disconnected
    private var _modeOverride: InterfaceMode?
    private var _delegate: InterfaceDelegate?
    private var _spawnedPeers: [String: TCPSpawnedPeerInterface] = [:]
    private var listener: NWListener?
    private let queue: DispatchQueue

    // MARK: - Init

    public init(config: InterfaceConfig) throws {
        guard config.type == .tcp else {
            throw InterfaceError.invalidConfig(reason: "TCPServerInterface requires config type .tcp, got \(config.type)")
        }
        self.id = config.id
        self.config = config
        self.queue = DispatchQueue(label: "net.reticulum.tcpserver.\(config.id)", qos: .userInitiated)
    }

    // MARK: - NetworkInterface

    public func connect() async throws {
        try start()
    }

    public func disconnect() async {
        stop()
    }

    public func send(_ data: Data) async throws {
        let peers: [TCPSpawnedPeerInterface]
        lock.lock()
        peers = Array(_spawnedPeers.values)
        lock.unlock()
        guard !peers.isEmpty else {
            // With no connected clients we've nothing to send on; treat
            // it as a silent no-op rather than an error so broadcast
            // logic (HEADER_1 announces fan-out) doesn't throw during
            // a momentary disconnected window.
            return
        }
        for peer in peers {
            do { try await peer.send(data) }
            catch {
                tcpServerLogger.debug("Send to spawned peer \(peer.id, privacy: .public) failed: \(String(describing: error), privacy: .public)")
            }
        }
    }

    public func setDelegate(_ delegate: InterfaceDelegate) async {
        lock.lock()
        _delegate = delegate
        lock.unlock()
    }

    // MARK: - Lifecycle

    /// Bind the listener and enter .connected state.
    ///
    /// Separate from connect() so the bridge can call it synchronously
    /// during wire_start_tcp_server handling without blockingAsync overhead
    /// (connect() is async; start() isn't).
    public func start() throws {
        // Hold the lock across the entire "guard nil → create NWListener →
        // assign listener" critical region. Previously we released the lock
        // between the guard and the assignment, which let two concurrent
        // starters both pass the nil-guard, each build an NWListener, and
        // race on the same bind port (one would fail silently). Start is
        // only called from wire_start_tcp_server today, but the concurrency
        // hazard is cheap to close and removes a footgun for future callers.
        lock.lock()
        if listener != nil {
            lock.unlock()
            return
        }

        let port = NWEndpoint.Port(integerLiteral: config.port)
        let params = NWParameters.tcp
        // NWListener on `params, on: port` inherently binds on all
        // interfaces; we accept that here because the conformance bridge is
        // a short-lived loopback-only process. Cross-impl wire tests use
        // 127.0.0.1:port on the client side so off-box traffic doesn't
        // reach this listener anyway.
        let l: NWListener
        do {
            l = try NWListener(using: params, on: port)
        } catch {
            lock.unlock()
            throw InterfaceError.connectionFailed(underlying: "NWListener init: \(error.localizedDescription)")
        }
        l.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.setState(.connected)
            case .failed(let err):
                tcpServerLogger.error("Listener failed: \(err.localizedDescription, privacy: .public)")
                self.setState(.disconnected)
            case .cancelled:
                self.setState(.disconnected)
            default:
                break
            }
        }
        l.newConnectionHandler = { [weak self] conn in
            self?.accept(conn)
        }
        listener = l
        _state = .connecting
        lock.unlock()
        l.start(queue: queue)
    }

    /// Tear down the listener and all spawned peers.
    public func stop() {
        lock.lock()
        let l = listener
        let peers = Array(_spawnedPeers.values)
        listener = nil
        _spawnedPeers.removeAll()
        _state = .disconnected
        lock.unlock()
        l?.cancel()
        for p in peers {
            Task { await p.disconnect() }
        }
    }

    // MARK: - Private: accept loop

    private func accept(_ connection: NWConnection) {
        connection.stateUpdateHandler = { [weak self] ns in
            guard let self else { return }
            switch ns {
            case .ready:
                self.spawn(for: connection)
            case .failed(let err):
                tcpServerLogger.debug("Inbound connection failed: \(err.localizedDescription, privacy: .public)")
                connection.cancel()
            case .cancelled:
                break
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    private func spawn(for connection: NWConnection) {
        // Generate a unique spawned-peer id so the Transport-level
        // interface map keyed by `id` stays unique.
        let suffix = Data((0..<4).map { _ in UInt8.random(in: 0...255) })
            .map { String(format: "%02x", $0) }.joined()
        let spawnedId = "\(id)-peer-\(suffix)"
        let peer = TCPSpawnedPeerInterface(
            id: spawnedId,
            parentName: config.name,
            parentConfig: config,
            connection: connection,
            queue: queue
        )
        // Evict on disconnect so the _spawnedPeers map doesn't grow
        // unbounded over the listener's lifetime. Without this, every
        // broadcast send() would silently try to deliver to peers that
        // have long since gone away, and spawnedPeers iterators (e.g.
        // wire_set_interface_mode) would walk stale entries.
        peer.onDisconnect = { [weak self] id in
            guard let self else { return }
            self.lock.lock()
            self._spawnedPeers.removeValue(forKey: id)
            self.lock.unlock()
        }
        // Seed the child with the parent's modeOverride and insert it
        // into _spawnedPeers under a single lock acquisition. A
        // concurrent wire_set_interface_mode that snapshots peers
        // either runs entirely before this block (and we read its
        // newly-written _modeOverride here) or entirely after (and it
        // sees the new peer in its snapshot and applies the new mode
        // itself). Splitting the read of _modeOverride and the insert
        // would let a mode update slip between them and leave the new
        // peer with a stale mode until the next mode-set call.
        lock.lock()
        if let override = _modeOverride {
            peer.modeOverride = override
        }
        _spawnedPeers[spawnedId] = peer
        lock.unlock()

        // Notify the bridge so it can register the peer with the Transport.
        // The Transport's addInterface is responsible for both attaching a
        // delegate AND calling interface.connect() — which wires up the
        // spawned peer's FramedTransport and starts the receive loop.
        // We deliberately do NOT start the peer ourselves: doing so would
        // race against addInterface's connect() call and yield two
        // concurrent receive loops on the same NWConnection.
        onClientConnected?(peer)
    }

    private func setState(_ new: InterfaceState) {
        let d: InterfaceDelegate?
        lock.lock()
        _state = new
        d = _delegate
        lock.unlock()
        d?.interface(id: id, didChangeState: new)
    }
}

// MARK: - NWConnection-backed Transport

/// Transport wrapping an already-accepted inbound NWConnection.
///
/// Distinct from TCPTransport (which dials out) — here the NWConnection
/// is born from an NWListener and arrives in .ready state. We just need
/// to drive the receive loop and expose a send method so FramedTransport
/// can wrap us exactly like it wraps TCPTransport.
final class NWInboundConnectionTransport: Transport, @unchecked Sendable {
    // All mutations of `state` happen on `queue`. `disconnect()` from any
    // caller hops onto the queue before mutating, so it can never race the
    // receive-loop callback that also writes to `state` and is itself
    // dispatched onto the same queue. Reads from outside the queue are
    // benign (callers only inspect `state` for diagnostics) and the value
    // is a value type, so torn reads aren't a correctness issue here.
    var state: TransportState = .connected
    var onStateChange: ((TransportState) -> Void)?
    var onDataReceived: ((Data) -> Void)?

    private let connection: NWConnection
    private let queue: DispatchQueue

    init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    func connect() {
        // Already accepted + .ready by the time we get here; treat as no-op.
    }

    func start() {
        startReceiving()
        onStateChange?(.connected)
    }

    func send(_ data: Data, completion: ((Error?) -> Void)?) {
        connection.send(content: data, completion: .contentProcessed { err in
            completion?(err)
        })
    }

    func disconnect() {
        // Mutate state on the same queue that the receive-loop callback
        // runs on, so the two write paths can't race. Cancellation of the
        // NWConnection itself is thread-safe, but the `state =` and
        // `onStateChange?(...)` callout were not — Greptile flagged this
        // as a Thread-Sanitizer-visible data race on heavily-loaded CI
        // runners. Synchronizing through `queue` matches how
        // `startReceiving` already serializes its own state transitions.
        queue.async { [weak self] in
            guard let self else { return }
            self.connection.cancel()
            self.state = .disconnected
            self.onStateChange?(.disconnected)
        }
    }

    private func startReceiving() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.onDataReceived?(data)
            }
            if let error {
                self.state = .failed(error)
                self.onStateChange?(.failed(error))
                return
            }
            if !isComplete {
                self.startReceiving()
            } else {
                self.state = .disconnected
                self.onStateChange?(.disconnected)
            }
        }
    }
}
