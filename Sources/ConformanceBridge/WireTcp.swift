// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  WireTcp.swift
//  ConformanceBridge
//
//  Implements the wire_* bridge commands used by
//  reticulum-conformance/tests/wire/*. Unlike the behavioral_* commands
//  (MockInterface, zero-wire), wire_* spins up real Network.framework
//  NWListener/NWConnection pairs so cross-impl tests exercise the full
//  transmit/receive pipeline end-to-end with IFAC applied on the wire.
//
//  Protocol reference: reticulum-conformance/reference/wire_tcp.py and
//  reticulum-kt/conformance-bridge/src/main/kotlin/WireTcp.kt
//
//  Process model: at most ONE wire instance per bridge process (server
//  OR client). The wire_peers pytest fixture spawns two bridges to pair
//  roles. resetWireState() is called at the top of every wire_start_*
//  to guarantee a clean slate.
//

import CryptoKit
import Foundation
import ReticulumSwift

// MARK: - Per-wire-handle state

/// State for a wire instance.
///
/// `role` is "server" or "client". Held by strong ref so the Transport
/// and interface stay alive for the duration of the test.
final class WireInstance: @unchecked Sendable {
    let transport: ReticulumTransport
    let identity: Identity
    let role: String
    let port: UInt16
    let serverInterface: TCPServerInterface?
    let clientInterface: TCPInterface?

    // Keep strong references to created destinations so they aren't GC'd
    // between wire_announce/wire_listen and downstream wire_poll_path.
    var destinations: [(Identity, Destination)] = []

    // Per-listener state, keyed by IN destination hash hex.
    var listeners: [String: WireListener] = [:]

    // Outbound links opened by wire_link_open, keyed by link_id hex.
    var outLinks: [String: Link] = [:]

    init(
        transport: ReticulumTransport,
        identity: Identity,
        role: String,
        port: UInt16,
        serverInterface: TCPServerInterface? = nil,
        clientInterface: TCPInterface? = nil
    ) {
        self.transport = transport
        self.identity = identity
        self.role = role
        self.port = port
        self.serverInterface = serverInterface
        self.clientInterface = clientInterface
    }
}

/// Per-destination receive buffer for incoming link data + completed resources.
final class WireListener: @unchecked Sendable {
    let destination: Destination
    let identity: Identity
    private let lock = NSLock()
    private var _recvBuffer: [Data] = []
    private var _resourceBuffer: [Data] = []
    // Per-link resource hash dedup, matching Kotlin's fix for the
    // double-fire of resourceConcluded. Swift doesn't currently exhibit
    // the same double-fire, but dedup is cheap and keeps behaviour
    // consistent should the upstream pattern change.
    private var _seenResourceHashes: Set<Data> = []

    init(destination: Destination, identity: Identity) {
        self.destination = destination
        self.identity = identity
    }

    func append(packetData: Data) {
        lock.lock(); defer { lock.unlock() }
        _recvBuffer.append(packetData)
    }

    func append(resource: Data, hash: Data?) {
        lock.lock(); defer { lock.unlock() }
        if let h = hash {
            if _seenResourceHashes.contains(h) { return }
            _seenResourceHashes.insert(h)
        }
        _resourceBuffer.append(resource)
    }

    func drainPackets() -> [Data] {
        lock.lock(); defer { lock.unlock() }
        let out = _recvBuffer
        _recvBuffer.removeAll()
        return out
    }

    func drainResources() -> [Data] {
        lock.lock(); defer { lock.unlock() }
        let out = _resourceBuffer
        _resourceBuffer.removeAll()
        return out
    }

    func hasAnyPackets() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !_recvBuffer.isEmpty
    }

    func hasAnyResources() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !_resourceBuffer.isEmpty
    }
}

// MARK: - Instance registry

private let wireLock = NSLock()
nonisolated(unsafe) private var wireInstances: [String: WireInstance] = [:]

/// Generate a fresh, unique handle for `wire_start_*`.
private func newHandle() -> String {
    Data((0..<8).map { _ in UInt8.random(in: 0...255) })
        .map { String(format: "%02x", $0) }.joined()
}

/// Tear down all wire state: detach interfaces, stop retransmission,
/// clear handle map. Called at the top of wire_start_* to guarantee
/// each test starts with a clean slate.
private func resetWireState() {
    wireLock.lock()
    let stale = Array(wireInstances.values)
    wireInstances.removeAll()
    wireLock.unlock()

    for inst in stale {
        inst.serverInterface?.stop()
        let clientIface = inst.clientInterface
        try? blockingAsync {
            if let c = clientIface { await c.disconnect() }
            await inst.transport.stopRetransmissionLoop()
        }
    }
}

// MARK: - IFAC key derivation

/// Fixed salt constant shared across all Reticulum implementations.
/// Python: RNS.Reticulum.IFAC_SALT (Reticulum.py:152).
///
/// `hexToBytes` is failable now (returns nil on malformed input). The
/// nil-coalesce to empty Data is purely a belt-and-braces against a typo
/// in this literal: a 32-byte mismatch surfaces as IFAC validation
/// failures in the conformance suite rather than a crash on bridge
/// startup. The literal is the canonical Reticulum salt and is verified
/// by the cross-impl IFAC interop tests, so empty data is unreachable
/// in practice.
private let ifacSalt: Data = hexToBytes(
    "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8"
) ?? Data()

/// Derive the 64-byte IFAC key from a network name and passphrase.
///
/// Matches Python RNS.Reticulum._add_interface (Reticulum.py:810-825):
/// ```
/// ifac_origin = b""
/// if netname: ifac_origin += full_hash(netname)
/// if passphrase: ifac_origin += full_hash(passphrase)
/// ifac_origin_hash = full_hash(ifac_origin)
/// ifac_key = HKDF(length=64, derive_from=ifac_origin_hash,
///                 salt=Reticulum.IFAC_SALT)
/// ```
///
/// Returns nil if both netname and passphrase are empty (no IFAC configured).
private func deriveIfacKey(networkName: String, passphrase: String) -> Data? {
    if networkName.isEmpty && passphrase.isEmpty { return nil }
    var ifacOrigin = Data()
    if !networkName.isEmpty {
        ifacOrigin.append(Data(SHA256.hash(data: Data(networkName.utf8))))
    }
    if !passphrase.isEmpty {
        ifacOrigin.append(Data(SHA256.hash(data: Data(passphrase.utf8))))
    }
    let ifacOriginHash = Data(SHA256.hash(data: ifacOrigin))
    return KeyDerivation.deriveKey(
        length: 64,
        inputKeyMaterial: ifacOriginHash,
        salt: ifacSalt
    )
}


// MARK: - Interface mode parsing

private func parseWireInterfaceMode(_ raw: String?) throws -> InterfaceMode {
    guard let raw, !raw.isEmpty else { return .full }
    switch raw.lowercased() {
    case "full": return .full
    case "gateway", "gw": return .gateway
    case "ap", "access_point", "accesspoint": return .accessPoint
    case "roaming": return .roaming
    case "boundary": return .boundary
    case "point_to_point", "pointtopoint", "p2p", "ptp": return .pointToPoint
    default:
        throw BridgeError.invalidData("Unknown interface mode: \(raw)")
    }
}

// MARK: - Free port allocation

/// Pre-allocate a free loopback port by binding then closing.
/// Tiny race window; acceptable for localhost conformance use.
private func allocateFreePort() -> UInt16 {
    let sock = socket(AF_INET, SOCK_STREAM, 0)
    guard sock >= 0 else { return 0 }
    defer { close(sock) }

    var reuse: Int32 = 1
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    addr.sin_port = 0
    let size = socklen_t(MemoryLayout<sockaddr_in>.size)

    let bindResult = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(sock, $0, size)
        }
    }
    guard bindResult == 0 else { return 0 }

    var boundAddr = sockaddr_in()
    var boundSize = size
    let nameResult = withUnsafeMutablePointer(to: &boundAddr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            getsockname(sock, $0, &boundSize)
        }
    }
    guard nameResult == 0 else { return 0 }

    return UInt16(bigEndian: boundAddr.sin_port)
}

// MARK: - Command dispatch

func handleWireCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result {
    switch command {

    // MARK: wire_start_tcp_server

    case "wire_start_tcp_server":
        resetWireState()

        let networkName = getStringOptional(p, "network_name") ?? ""
        let passphrase = getStringOptional(p, "passphrase") ?? ""
        let requestedPortInt = getIntOptional(p, "bind_port") ?? 0
        let requestedPort = UInt16(clamping: requestedPortInt)
        let bindPort = requestedPort == 0 ? allocateFreePort() : requestedPort
        guard bindPort != 0 else {
            throw BridgeError.invalidData("Failed to allocate free port")
        }
        let mode = try parseWireInterfaceMode(getStringOptional(p, "mode"))

        let ifacKey = deriveIfacKey(networkName: networkName, passphrase: passphrase)
        let ifacSize = ifacKey != nil ? 16 : 0

        let identity = Identity()
        let transport = ReticulumTransport(pathTable: PathTable())

        try blockingAsync {
            await transport.setTransportEnabled(true, identity: identity)
            await transport.startRetransmissionLoop()
            // Register the RNS `rnstransport.path.request` callback so
            // this peer answers incoming path requests with cached
            // announces and forwards unknown-destination PRs to other
            // interfaces. Without this, every wire test that asserts on
            // PR behaviour (test_roaming_loop_prevention_positive_companion,
            // test_discover_paths_for_mode_gating) fails because Swift's
            // `handlePathRequest` is never invoked. PipePeer already
            // does this at startup for the same reason.
            await transport.registerPathRequestHandler()
        }

        // Build the server's InterfaceConfig.
        let ifaceId = "wire-server-\(newHandle())"
        let config = InterfaceConfig(
            id: ifaceId,
            name: "Wire TCP Server",
            type: .tcp,
            enabled: true,
            mode: mode,
            host: "127.0.0.1",
            port: bindPort,
            ifacSize: ifacSize,
            ifacKey: ifacKey
        )

        let server: TCPServerInterface
        do {
            server = try TCPServerInterface(config: config)
        } catch {
            throw BridgeError.invalidData("TCPServerInterface init failed: \(error)")
        }

        // onClientConnected registers the spawned peer with the Transport
        // so path responses attached to that interface aren't silently
        // dropped. Mirrors Kotlin's WireTcp.kt:198-210.
        //
        // Register synchronously (via blockingAsync) rather than in a
        // fire-and-forget Task: the spawned peer's receive loop starts
        // inside addInterface (via interface.connect()), and any packet
        // arriving before the Transport knows about this interface would
        // be dropped at validateIFAC (interfaceId not in `interfaces` →
        // passthrough of still-masked IFAC bytes → packet parser chokes
        // on the header flag/offset). addInterface handles both
        // `setDelegate(TransportDelegateWrapper)` and `connect()`, so the
        // bridge has nothing else to do here.
        server.onClientConnected = { [weak transport] spawned in
            guard let transport else { return }
            do {
                try blockingAsync {
                    try await transport.addInterface(spawned)
                }
            } catch {
                FileHandle.standardError.write(
                    Data("[WireTcp] Failed to register spawned peer \(spawned.id): \(error)\n".utf8)
                )
            }
        }

        // Start the listener. We deliberately do NOT register the server
        // parent with the Transport — spawned peers are the actual
        // interfaces the Transport broadcasts over. Registering both
        // would double-deliver every HEADER_1 outbound (once via the
        // server's fan-out to peers, once per peer iterated by Transport)
        // and also double-apply IFAC using two different signing seeds,
        // which guarantees the receiving side rejects one of them.
        // Python and Kotlin take the same approach (spawned children are
        // the interfaces of record).
        do {
            try server.start()
        } catch {
            throw BridgeError.invalidData("TCPServerInterface.start failed: \(error)")
        }

        let handle = newHandle()
        let inst = WireInstance(
            transport: transport,
            identity: identity,
            role: "server",
            port: bindPort,
            serverInterface: server
        )
        wireLock.lock()
        wireInstances[handle] = inst
        wireLock.unlock()

        return [
            "handle": .string(handle),
            "port": .int(Int(bindPort)),
            "identity_hash": hex(identity.hash)
        ]

    // MARK: wire_start_tcp_client

    case "wire_start_tcp_client":
        resetWireState()

        let networkName = getStringOptional(p, "network_name") ?? ""
        let passphrase = getStringOptional(p, "passphrase") ?? ""
        let targetHost = try getString(p, "target_host")
        let targetPortInt = try getInt(p, "target_port")
        let targetPort = UInt16(clamping: targetPortInt)
        let mode = try parseWireInterfaceMode(getStringOptional(p, "mode"))

        let ifacKey = deriveIfacKey(networkName: networkName, passphrase: passphrase)
        let ifacSize = ifacKey != nil ? 16 : 0

        let identity = Identity()
        let transport = ReticulumTransport(pathTable: PathTable())

        try blockingAsync {
            await transport.setTransportEnabled(true, identity: identity)
            await transport.startRetransmissionLoop()
            // Register the RNS `rnstransport.path.request` callback so
            // this peer answers incoming path requests with cached
            // announces and forwards unknown-destination PRs to other
            // interfaces. Without this, every wire test that asserts on
            // PR behaviour (test_roaming_loop_prevention_positive_companion,
            // test_discover_paths_for_mode_gating) fails because Swift's
            // `handlePathRequest` is never invoked. PipePeer already
            // does this at startup for the same reason.
            await transport.registerPathRequestHandler()
        }

        let ifaceId = "wire-client-\(newHandle())"
        let config = InterfaceConfig(
            id: ifaceId,
            name: "Wire TCP Client",
            type: .tcp,
            enabled: true,
            mode: mode,
            host: targetHost,
            port: targetPort,
            ifacSize: ifacSize,
            ifacKey: ifacKey
        )

        let client: TCPInterface
        do {
            client = try TCPInterface(config: config)
        } catch {
            throw BridgeError.invalidData("TCPInterface init failed: \(error)")
        }

        // addInterface attaches a TransportDelegateWrapper (which forwards
        // inbound packets into handleReceivedData) and calls connect() in
        // one shot — no separate setDelegate / connect wiring needed.
        try blockingAsync {
            try await transport.addInterface(client)
        }

        // Wait for the NWConnection to actually finish its handshake before
        // we return. TCPInterface.connect() kicks off the connection
        // asynchronously and returns immediately, so without a wait the
        // very next wire_announce might send before the wire is up and
        // the bytes would be silently dropped. Poll on TCPInterface.state
        // with a capped deadline rather than sleeping a fixed interval:
        // fast hosts return quickly, slow/loaded CI hosts get the time
        // they need, and the cap prevents a stalled NWConnection from
        // hanging the bridge command loop.
        //
        // If the deadline passes without reaching .connected, throw a
        // clear connect-timeout error rather than returning a handle
        // that points at a broken interface — otherwise every downstream
        // `wire_announce` / `wire_poll_path` would fail opaquely with
        // "path not found" instead of surfacing the real cause.
        let connectDeadline = Date().addingTimeInterval(5.0)
        var clientConnected = false
        while Date() < connectDeadline {
            let ready: Bool = try blockingAsync { await client.state == .connected }
            if ready { clientConnected = true; break }
            Thread.sleep(forTimeInterval: 0.02)
        }
        guard clientConnected else {
            // Best-effort teardown so we don't leak a half-open interface.
            try? blockingAsync {
                let cid = await client.id
                await transport.removeInterface(id: cid)
                await client.disconnect()
            }
            throw BridgeError.invalidData(
                "TCPInterface did not connect to \(targetHost):\(targetPort) within 5s"
            )
        }

        let handle = newHandle()
        let inst = WireInstance(
            transport: transport,
            identity: identity,
            role: "client",
            port: targetPort,
            clientInterface: client
        )
        wireLock.lock()
        wireInstances[handle] = inst
        wireLock.unlock()

        return [
            "handle": .string(handle),
            "identity_hash": hex(identity.hash)
        ]

    // MARK: wire_stop

    case "wire_stop":
        let handle = try getString(p, "handle")
        wireLock.lock()
        let inst = wireInstances.removeValue(forKey: handle)
        wireLock.unlock()
        guard let inst else {
            return ["stopped": boolean(false)]
        }
        inst.serverInterface?.stop()
        let clientIface = inst.clientInterface
        try blockingAsync {
            if let c = clientIface { await c.disconnect() }
            await inst.transport.stopRetransmissionLoop()
        }
        return ["stopped": boolean(true)]

    // MARK: wire_announce

    case "wire_announce":
        let handle = try getString(p, "handle")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let appData = getHexOptional(p, "app_data")

        let inst = try requireInstance(handle)

        let identity = Identity()
        let destination = Destination(
            identity: identity,
            appName: appName,
            aspects: aspects,
            type: .single,
            direction: .in
        )
        if let ad = appData, !ad.isEmpty {
            destination.appData = ad
        }
        try blockingAsync {
            await inst.transport.registerDestination(destination)
        }

        let announce = Announce(destination: destination, appData: appData)
        let packet: Packet
        do {
            packet = try announce.buildPacket()
        } catch {
            throw BridgeError.invalidData("buildPacket failed: \(error)")
        }

        try blockingAsync {
            try await inst.transport.send(packet: packet)
        }

        inst.destinations.append((identity, destination))

        return [
            "destination_hash": hex(destination.hash),
            "identity_hash": hex(identity.hash)
        ]

    // MARK: wire_poll_path

    case "wire_poll_path":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 5000

        let inst = try requireInstance(handle)

        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while Date() < deadline {
            let found: Bool = try blockingAsync {
                await inst.transport.hasPath(for: destHash)
            }
            if found {
                let hops: Int = try blockingAsync {
                    Int(await inst.transport.hopsTo(destHash) ?? 0)
                }
                return ["found": boolean(true), "hops": .int(hops)]
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return ["found": boolean(false), "hops": .null]

    // MARK: wire_read_path_entry

    case "wire_read_path_entry":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")

        let inst = try requireInstance(handle)

        let entry: PathEntry? = try blockingAsync {
            await inst.transport.pathEntry(for: destHash)
        }
        guard let entry else {
            return ["found": boolean(false)]
        }

        // Map interfaceId back to the human-readable name the test asserts
        // on (e.g., "Wire TCP Server" / "Wire TCP Client"). TCPInterface is
        // an actor, so read its identity via blockingAsync.
        //
        // Server-role instances only register spawned peers with the
        // Transport (see wire_start_tcp_server above) — the parent
        // TCPServerInterface itself is never an interface of record, so
        // entry.interfaceId can only ever match a spawned peer here.
        let ifaceName: JSONValue
        if let server = inst.serverInterface {
            if let peer = server.spawnedPeers.first(where: { $0.id == entry.interfaceId }) {
                ifaceName = .string(peer.config.name)
            } else {
                ifaceName = .null
            }
        } else if let client = inst.clientInterface {
            let clientId: String = try blockingAsync { await client.id }
            let clientName: String = try blockingAsync { await client.config.name }
            ifaceName = (entry.interfaceId == clientId) ? .string(clientName) : .null
        } else {
            ifaceName = .null
        }

        return [
            "found": boolean(true),
            // Python reference bridge normalizes to ms-since-epoch; Kotlin does
            // the same. Match that so cross-impl expires - timestamp arithmetic
            // lines up in the tests.
            "timestamp": .int(Int(entry.timestamp.timeIntervalSince1970 * 1000)),
            "expires": .int(Int(entry.expires.timeIntervalSince1970 * 1000)),
            "hops": .int(Int(entry.hopCount)),
            "next_hop": hex(entry.nextHop ?? Data()),
            "receiving_interface_name": ifaceName
        ]

    // MARK: wire_has_discovery_path_request

    case "wire_has_discovery_path_request":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)
        let found: Bool = try blockingAsync {
            await inst.transport.hasDiscoveryPathRequest(for: destHash)
        }
        return ["found": boolean(found)]

    // MARK: wire_has_announce_table_entry

    case "wire_has_announce_table_entry":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)
        let found: Bool = try blockingAsync {
            await inst.transport.getAnnounceTable().contains(destHash)
        }
        return ["found": boolean(found)]

    // MARK: wire_read_announce_table_timestamp

    case "wire_read_announce_table_timestamp":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)
        let ts: Date? = try blockingAsync {
            await inst.transport.getAnnounceTable().entryTimestamp(destHash)
        }
        guard let ts else {
            return ["found": boolean(false)]
        }
        return [
            "found": boolean(true),
            "timestamp": .int(Int(ts.timeIntervalSince1970 * 1000))
        ]

    // MARK: wire_tx_bytes

    case "wire_tx_bytes":
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)
        var total: UInt64 = 0
        if let server = inst.serverInterface {
            total += server.totalBytesSent
        }
        if let client = inst.clientInterface {
            // TCPInterface.bytesSent is actor-isolated.
            total += try blockingAsync { await client.bytesSent }
        }
        // `Int(clamping:)` saturates at Int.max instead of trapping if a
        // 32-bit consumer ever sees a counter past 2³¹-1. macOS bridge
        // builds are always 64-bit so the saturation branch is
        // unreachable today, but the explicit clamp documents the
        // truncation semantics if `JSONValue.int` ever moves to a
        // narrower platform — and is the standard way to silence the
        // implicit-narrowing concern Greptile flagged.
        return ["tx_bytes": .int(Int(clamping: total))]

    // MARK: wire_read_path_random_hash

    case "wire_read_path_random_hash":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)

        let entry: PathEntry? = try blockingAsync {
            await inst.transport.pathEntry(for: destHash)
        }
        guard let entry else {
            return ["found": boolean(false)]
        }
        // Prefer the most recent random blob seen for this destination —
        // PathEntry stores a history bounded by MAX_RANDOM_BLOBS, and the
        // cached announce layout matches Python's (public_key[0:64] +
        // name_hash[64:74] + random_hash[74:84]).
        let blob = entry.randomBlob
        guard blob.count == 10 else {
            return ["found": boolean(false)]
        }
        return [
            "found": boolean(true),
            "random_hash": hex(blob)
        ]

    // MARK: wire_request_path

    case "wire_request_path":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let inst = try requireInstance(handle)
        try blockingAsync {
            await inst.transport.sendPathRequestUnconditional(for: destHash)
        }
        return ["sent": boolean(true)]

    // MARK: wire_set_interface_mode

    case "wire_set_interface_mode":
        let handle = try getString(p, "handle")
        let modeStr = try getString(p, "mode")
        let newMode = try parseWireInterfaceMode(modeStr)

        let inst = try requireInstance(handle)

        if let server = inst.serverInterface {
            server.modeOverride = newMode
            // Kotlin also propagates to spawned children so packets
            // arriving on existing connections observe the new mode
            // immediately, not just on future connections.
            for peer in server.spawnedPeers {
                peer.modeOverride = newMode
            }
        } else if inst.clientInterface != nil {
            // TCPInterface exposes mode via InterfaceConfig and the config
            // is let-bound (immutable). There's currently no runtime
            // override hook — the only way to change a client-side mode
            // is to reconnect with a new config. Surface this so a test
            // that expects runtime mutation fails loudly instead of
            // silently reading the old value.
            throw BridgeError.invalidData(
                "wire_set_interface_mode: TCPInterface mode is immutable; "
                + "the conformance suite only exercises this on server-side "
                + "interfaces. If a test needs client-side runtime mutation, "
                + "add a modeOverride hook to TCPInterface."
            )
        }
        return ["mode": .string(modeStr.lowercased())]

    // MARK: wire_listen

    case "wire_listen":
        let handle = try getString(p, "handle")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")

        let inst = try requireInstance(handle)

        let identity = Identity()
        let destination = Destination(
            identity: identity,
            appName: appName,
            aspects: aspects,
            type: .single,
            direction: .in
        )

        let listener = WireListener(destination: destination, identity: identity)

        // Register destination so inbound packets/link requests get routed
        // to it, and attach a link-established callback that wires up the
        // packet + resource callbacks onto each newly-accepted Link.
        try blockingAsync {
            await inst.transport.registerDestination(destination)
            await inst.transport.registerDestinationLinkCallback(for: destination.hash) { link in
                await link.setPacketCallback { data, _packet in
                    listener.append(packetData: data)
                }
                await link.setResourceStrategy(.acceptAll)
                // Set up resource concluded callback
                let callbacks = WireResourceCallbacks(listener: listener)
                await link.setResourceCallbacks(callbacks)
            }
        }

        // Announce so the sender peer can learn a path to this destination.
        let announce = Announce(destination: destination)
        let packet: Packet
        do {
            packet = try announce.buildPacket()
        } catch {
            throw BridgeError.invalidData("buildPacket for wire_listen announce failed: \(error)")
        }
        try blockingAsync {
            try await inst.transport.send(packet: packet)
        }

        inst.destinations.append((identity, destination))
        inst.listeners[destination.hash.map { String(format: "%02x", $0) }.joined()] = listener

        return [
            "destination_hash": hex(destination.hash),
            "identity_hash": hex(identity.hash)
        ]

    // MARK: wire_link_open

    case "wire_link_open":
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let appName = try getString(p, "app_name")
        let aspects = getStringArray(p, "aspects")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 10000

        let inst = try requireInstance(handle)

        // Identity comes from the previously-received announce, stashed in
        // the path entry's publicKeys. Swift has no Identity.recall global,
        // so we reconstruct public-key-only from the path table.
        let entry: PathEntry? = try blockingAsync {
            await inst.transport.pathEntry(for: destHash)
        }
        guard let entry, entry.publicKeys.count == 64 else {
            throw BridgeError.invalidData(
                "No path entry for \(destHash.map { String(format: "%02x", $0) }.joined()) "
                + "— ensure wire_listen (on the remote) and wire_poll_path "
                + "(here) completed before wire_link_open"
            )
        }
        let outIdentity: Identity
        do {
            outIdentity = try Identity(publicKeyBytes: entry.publicKeys)
        } catch {
            throw BridgeError.invalidData("Identity from publicKeys failed: \(error)")
        }
        let outDest = Destination(
            identity: outIdentity,
            appName: appName,
            aspects: aspects,
            type: .single,
            direction: .out
        )

        let link: Link = try blockingAsync {
            try await inst.transport.initiateLink(to: outDest, identity: inst.identity)
        }

        // Poll link state until active, bounded by timeoutMs.
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        var linkActive = false
        while Date() < deadline {
            let state: LinkState = try blockingAsync { await link.state }
            if case .active = state {
                linkActive = true
                break
            }
            if case .closed = state {
                throw BridgeError.invalidData(
                    "Link to \(destHash.map { String(format: "%02x", $0) }.joined()) closed before becoming active"
                )
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        guard linkActive else {
            throw BridgeError.invalidData(
                "Link to \(destHash.map { String(format: "%02x", $0) }.joined()) did not become active within \(timeoutMs)ms"
            )
        }

        let linkId: Data = try blockingAsync { await link.linkId }
        let linkIdHex = linkId.map { String(format: "%02x", $0) }.joined()
        inst.outLinks[linkIdHex] = link

        return ["link_id": .string(linkIdHex)]

    // MARK: wire_link_send

    case "wire_link_send":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let payload = try getHex(p, "data")

        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }
        // Link.send mirrors Python's link.send(): encrypts the plaintext
        // with the link's session key, frames a DATA packet addressed to
        // the linkId, and dispatches via the link's sendCallback.
        try blockingAsync {
            try await link.send(payload)
        }
        return ["sent": boolean(true)]

    // MARK: wire_link_poll

    case "wire_link_poll":
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 5000

        let inst = try requireInstance(handle)
        guard let listener = inst.listeners[destHashHex] else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHashHex)")
        }

        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while Date() < deadline, !listener.hasAnyPackets() {
            Thread.sleep(forTimeInterval: 0.05)
        }
        let out = listener.drainPackets().map { JSONValue.string(bytesToHex($0)) }
        return ["packets": .array(out)]

    // MARK: wire_resource_send

    case "wire_resource_send":
        let handle = try getString(p, "handle")
        let linkIdHex = try getString(p, "link_id")
        let payload = try getHex(p, "data")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 30000

        let inst = try requireInstance(handle)
        guard let link = inst.outLinks[linkIdHex] else {
            throw BridgeError.invalidData("Unknown link_id: \(linkIdHex)")
        }

        // sendResource returns once the advertisement is sent; we need to
        // wait until the transfer completes (or times out). Poll the
        // resource's state.
        let resource: Resource = try blockingAsync {
            try await link.sendResource(data: payload)
        }

        // Track the most-recent observed state separately from the
        // terminal state. If the poll times out while the resource is
        // still .transferring / .advertised, returning 0 (.none) in
        // `status` would hide the actual stage the transfer got stuck
        // in — report `lastSeen` instead so tests can distinguish
        // "never started" from "stalled mid-transfer".
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        var lastSeen: ResourceState = .none
        var terminalState: ResourceState?
        while Date() < deadline {
            let state: ResourceState = try blockingAsync { await resource.state }
            lastSeen = state
            if state == .complete || state == .failed {
                terminalState = state
                break
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        let timedOut = terminalState == nil
        let reportedState = terminalState ?? lastSeen
        let success = reportedState == .complete
        return [
            "success": boolean(success),
            "status": .int(reportedState.rawValueForBridge),
            "size": .int(payload.count),
            "timed_out": boolean(timedOut)
        ]

    // MARK: wire_resource_poll

    case "wire_resource_poll":
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 30000

        let inst = try requireInstance(handle)
        guard let listener = inst.listeners[destHashHex] else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHashHex)")
        }

        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        while Date() < deadline, !listener.hasAnyResources() {
            Thread.sleep(forTimeInterval: 0.1)
        }
        let out = listener.drainResources().map { JSONValue.string(bytesToHex($0)) }
        return ["resources": .array(out)]

    default:
        throw BridgeError.unknownCommand(command)
    }
}

// MARK: - Helpers

private func requireInstance(_ handle: String) throws -> WireInstance {
    wireLock.lock(); defer { wireLock.unlock() }
    guard let inst = wireInstances[handle] else {
        throw BridgeError.invalidData("Unknown handle: \(handle)")
    }
    return inst
}

/// Resource callbacks adapter for buffering completed resources into a
/// WireListener. Lives at module scope because ResourceCallbacks requires
/// AnyObject + Sendable conformance, which nested closures can't express
/// directly.
private final class WireResourceCallbacks: ResourceCallbacks, @unchecked Sendable {
    let listener: WireListener
    init(listener: WireListener) { self.listener = listener }

    func resourceConcluded(_ resource: Resource) async {
        let state = await resource.state
        guard state == .complete else { return }
        guard let data = await resource.assembledData else {
            FileHandle.standardError.write(
                Data("[WireTcp] wire_listen: COMPLETE resource has nil assembledData, dropping\n".utf8)
            )
            return
        }
        let hash = await resource.hash
        listener.append(resource: data, hash: hash)
    }
}

// MARK: - State → int helper

private extension ResourceState {
    /// Numeric value for the bridge protocol. Kotlin/Python report an int;
    /// mirror that by mapping enum cases to stable ints matching Python's
    /// RNS.Resource status codes (Resource.py constants).
    var rawValueForBridge: Int {
        switch self {
        case .none: return 0
        case .queued: return 1
        case .advertised: return 2
        case .transferring: return 3
        case .awaitingProof: return 4
        case .assembling: return 5
        case .complete: return 6
        case .failed: return 7
        case .rejected: return 8
        case .cancelled: return 9
        }
    }
}
