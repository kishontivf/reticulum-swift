// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  TCPTransport.swift
//  ReticulumSwift
//
//  NWConnection-based TCP transport implementing the Transport protocol.
//

import Foundation
import Network
import OSLog

/// TCP transport using Network.framework NWConnection.
/// Handles connection lifecycle, state changes, data receive loop, and send operations.
public final class TCPTransport: Transport {

    /// Optional iOS Network Extension egress pin (default `false`). When a
    /// `NEPacketTunnelProvider` host sets this `true`, outbound TCP connections
    /// set `prohibitedInterfaceTypes = [.other]`, forcing a *physical* interface
    /// (wifi/cellular) instead of the provider's own packet-tunnel virtual
    /// interface (utun, which Network.framework types as `.other`).
    ///
    /// DEFENSIVE / REVERT-CANDIDATE — not a proven fix. This was added while
    /// chasing an on-device "announces not propagating" symptom on iPhone 14.
    /// The root cause turned out to be a *wedged relay daemon* on the LAN host,
    /// NOT egress: a stock `NWParameters.tcp` connection created inside the
    /// extension egresses fine (the "no SYN on the relay" observation that
    /// pointed here was a packet-capture filtered on the wrong device IP). It is
    /// retained only as cheap insurance in case a future iOS routing change ever
    /// did bind an NE-created connection to our own utun. `false` preserves
    /// stock behavior. Process-global; iOS-NE-specific, no Python-reference
    /// equivalent (see port-deviations.md).
    ///
    /// `nonisolated(unsafe)`: deliberately a set-once-before-any-transport global (the
    /// host flips it at startup); reads in `init` are safe by that contract. The
    /// annotation makes the unguarded-shared intent explicit and satisfies strict
    /// concurrency without a lock for a flag that is never mutated after init.
    nonisolated(unsafe) public static var bypassTunnelEgress = false

    // MARK: - Properties

    /// The underlying NWConnection instance.
    private var connection: NWConnection?

    /// Server hostname or IP address.
    private let host: String

    /// Server port number.
    private let port: UInt16

    /// Logger for TCP connection events.
    private let logger: Logger

    /// Queue for connection operations.
    private let connectionQueue = DispatchQueue(label: "com.columba.tcptransport", qos: .userInitiated)

    /// Guards `_state` so external callers (e.g. the reconnect loop) can read `state` from any
    /// thread while the connection callbacks mutate it on `connectionQueue`, without racing the
    /// retain/release of its associated `Error` payload (the cause of an `objc_retain`
    /// use-after-free crash under concurrent connect/disconnect + timeout).
    private let stateLock = NSLock()
    private var _state: TransportState = .disconnected

    /// Current connection state. Thread-safe.
    public var state: TransportState {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _state
    }

    /// Connection timeout work item (cancelled on success or disconnect).
    private var connectionTimeoutWork: DispatchWorkItem?

    /// Connection timeout in seconds.
    private let connectionTimeout: TimeInterval = 15.0

    /// Callback invoked when connection state changes.
    public var onStateChange: ((TransportState) -> Void)?

    /// Callback invoked when data is received from the server.
    public var onDataReceived: ((Data) -> Void)?

    // MARK: - Initialization

    /// Initialize a new TCP transport.
    /// - Parameters:
    ///   - host: Server hostname or IP address.
    ///   - port: Server port number.
    ///   - subsystem: Logger subsystem (default: "com.columba.core").
    public init(host: String, port: UInt16, subsystem: String = "com.columba.core") {
        self.host = host
        self.port = port
        self.logger = Logger(subsystem: subsystem, category: "TCPTransport")
        logger.info("TCPTransport initialized for \(host, privacy: .public):\(port, privacy: .public)")
    }

    // MARK: - Transport Protocol

    /// Establish TCP connection to the configured server.
    public func connect() {
        // All access to connection/state/timeout state is serialized on `connectionQueue` —
        // the same queue the NWConnection callbacks and timeout run on — so a caller-thread
        // connect can't race those callbacks.
        connectionQueue.async { [weak self] in self?.connectOnQueue() }
    }

    private func connectOnQueue() {
        guard state == .disconnected || state != .connecting else {
            logger.warning("Connect called but already connecting/connected")
            return
        }

        updateState(.connecting)
        logger.info("Connecting to \(self.host, privacy: .public):\(self.port, privacy: .public)...")

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: port)
        )

        let params = NWParameters.tcp
        if TCPTransport.bypassTunnelEgress {
            // iOS NE egress fix — see port-deviations.md. Prohibit the virtual
            // (.other = our own utun packet tunnel) interface so the connection
            // uses a physical interface (wifi/cellular) and actually egresses to
            // the LAN, instead of black-holing in our own tunnel.
            params.prohibitedInterfaceTypes = [.other]
        }
        connection = NWConnection(to: endpoint, using: params)

        connection?.stateUpdateHandler = { [weak self] nwState in
            guard let self = self else { return }
            self.handleNWState(nwState)
        }

        connection?.viabilityUpdateHandler = { [weak self] isViable in
            self?.logger.info("Connection viability: \(isViable, privacy: .public)")
        }

        connection?.betterPathUpdateHandler = { [weak self] betterPathAvailable in
            if betterPathAvailable {
                self?.logger.info("Better network path available")
            }
        }

        connection?.start(queue: connectionQueue)

        // Start connection timeout
        startConnectionTimeout()
    }

    /// Start a timeout that fires if connection isn't established in time.
    private func startConnectionTimeout() {
        connectionTimeoutWork?.cancel()

        let work = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            guard self.state == .connecting else { return }

            self.logger.error("Connection timed out after \(self.connectionTimeout)s to \(self.host, privacy: .public):\(self.port, privacy: .public)")
            self.connection?.cancel()
            self.connection = nil
            let error = TransportError.connectionTimedOut(host: self.host, port: self.port)
            self.updateState(.failed(error))
        }

        connectionTimeoutWork = work
        connectionQueue.asyncAfter(
            deadline: .now() + connectionTimeout,
            execute: work
        )
    }

    /// Send data to the server.
    /// - Parameters:
    ///   - data: Data to send.
    ///   - completion: Optional callback with nil on success, Error on failure.
    public func send(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        connectionQueue.async { [weak self] in self?.sendOnQueue(data, completion: completion) }
    }

    private func sendOnQueue(_ data: Data, completion: ((Error?) -> Void)? = nil) {
        guard state == .connected else {
            let error = TransportError.notConnected
            logger.error("Send failed: not connected")
            completion?(error)
            return
        }

        connection?.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.logger.error("Send failed: \(error.localizedDescription, privacy: .public)")
                completion?(error)
            } else {
                self?.logger.debug("Sent \(data.count, privacy: .public) bytes")
                completion?(nil)
            }
        })
    }

    /// Disconnect and clean up the connection.
    public func disconnect() {
        connectionQueue.async { [weak self] in self?.disconnectOnQueue() }
    }

    private func disconnectOnQueue() {
        logger.info("Disconnecting TCP connection")
        connectionTimeoutWork?.cancel()
        connectionTimeoutWork = nil
        connection?.cancel()
        connection = nil
        updateState(.disconnected)
    }

    // MARK: - Private Methods

    private func handleNWState(_ nwState: NWConnection.State) {
        logger.debug("NWConnection state: \(String(describing: nwState), privacy: .public)")

        switch nwState {
        case .ready:
            logger.info("TCP connection ready to \(self.host, privacy: .public):\(self.port, privacy: .public)")
            connectionTimeoutWork?.cancel()
            connectionTimeoutWork = nil
            updateState(.connected)
            startReceiving()

        case .waiting(let error):
            // Surface this as a failure so the UI gets feedback.
            // TCPInterface's reconnect loop will retry automatically.
            logger.warning("TCP connection waiting (unreachable): \(error.localizedDescription, privacy: .public)")
            connectionTimeoutWork?.cancel()
            connectionTimeoutWork = nil
            connection?.cancel()
            connection = nil
            let wrappedError = TransportError.connectionWaiting(
                host: host, port: port, reason: error.localizedDescription
            )
            updateState(.failed(wrappedError))

        case .failed(let error):
            logger.error("TCP connection failed: \(error.localizedDescription, privacy: .public)")
            connectionTimeoutWork?.cancel()
            connectionTimeoutWork = nil
            updateState(.failed(error))

        case .cancelled:
            logger.info("TCP connection cancelled")
            connectionTimeoutWork?.cancel()
            connectionTimeoutWork = nil
            updateState(.disconnected)

        case .preparing:
            logger.debug("TCP connection preparing...")

        case .setup:
            logger.debug("TCP connection setup...")

        @unknown default:
            logger.warning("Unknown connection state")
        }
    }

    private func updateState(_ newState: TransportState) {
        stateLock.lock()
        _state = newState
        stateLock.unlock()
        // Invoke the callback on our dedicated connection queue rather
        // than DispatchQueue.main. The UI-oriented original implementation
        // assumed a main run loop was live, but that breaks non-UI hosts
        // (daemons, CLI bridges) where the main thread is blocked on
        // stdin / other work and the main queue never drains — which
        // would leave this interface stuck in .connecting forever.
        connectionQueue.async { [weak self] in
            guard let self = self else { return }
            self.onStateChange?(newState)
        }
    }

    /// Start the receive loop to continuously read incoming data.
    private func startReceiving() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }

            if let data = data, !data.isEmpty {
                self.logger.debug("Received \(data.count, privacy: .public) bytes")
                self.onDataReceived?(data)
            }

            if let error = error {
                self.logger.error("Receive error: \(error.localizedDescription, privacy: .public)")
                return
            }

            // Continue receiving if connection is still open
            if !isComplete {
                self.startReceiving()
            } else {
                self.logger.info("Connection completed (isComplete=true)")
                self.updateState(.disconnected)
            }
        }
    }
}
