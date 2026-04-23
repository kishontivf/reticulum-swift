// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Behavioral.swift
//  ConformanceBridge
//
//  Implements the behavioral_* bridge commands used by
//  reticulum-conformance's tests/behavioral/* to drive ReticulumTransport
//  through mock interfaces, injecting raw bytes on the receive side and
//  draining raw bytes from the send side.
//
//  Protocol reference: reticulum-conformance/reference/behavioral_transport.py
//

import Foundation
import ReticulumSwift

// MARK: - Mock interface

/// NetworkInterface whose send() buffers packets and inject() fires the
/// delegate. No real I/O.
final class BehavioralMockInterface: NetworkInterface, @unchecked Sendable {
    let id: String
    let config: InterfaceConfig

    // Mode constrains AnnounceFilter decisions. Kept nonisolated(unsafe)
    // for the same reason other test mocks use it — bridge commands are
    // dispatched serially by the readLine loop.
    nonisolated(unsafe) var state: InterfaceState = .connected
    nonisolated(unsafe) private var _sent: [Data] = []
    nonisolated(unsafe) private var _delegate: InterfaceDelegate?
    private let lock = NSLock()

    init(id: String, name: String, mode: InterfaceMode, mtu: Int) {
        self.id = id
        self.config = InterfaceConfig(
            id: id,
            name: name,
            type: .tcp,
            enabled: true,
            mode: mode,
            host: "mock",
            port: 0,
            bitrate: max(mtu * 8, 0)
        )
    }

    // NetworkInterface

    func connect() async throws {}
    func disconnect() async {}

    func send(_ data: Data) async throws {
        lock.lock(); defer { lock.unlock() }
        _sent.append(data)
    }

    func setDelegate(_ delegate: InterfaceDelegate) async {
        lock.lock(); defer { lock.unlock() }
        _delegate = delegate
    }

    // Test harness hooks

    func inject(_ raw: Data) {
        let d: InterfaceDelegate?
        lock.lock()
        d = _delegate
        lock.unlock()
        d?.interface(id: id, didReceivePacket: raw)
    }

    func drainTx() -> [Data] {
        lock.lock(); defer { lock.unlock() }
        let out = _sent
        _sent = []
        return out
    }
}

// MARK: - Instance registry

/// State for a single behavioral_start handle.
final class BehavioralInstance: @unchecked Sendable {
    let transport: ReticulumTransport
    let identity: Identity
    var interfaces: [String: BehavioralMockInterface] = [:]

    init(transport: ReticulumTransport, identity: Identity) {
        self.transport = transport
        self.identity = identity
    }
}

/// Serialized access to the instance map. Bridge commands arrive serially
/// but behavioral_start spawns a background retransmission Task on the
/// transport, so the dictionary itself still needs locking.
private let behavioralLock = NSLock()
nonisolated(unsafe) private var behavioralInstances: [String: BehavioralInstance] = [:]

// MARK: - Helpers

private func parseInterfaceMode(_ raw: String) -> InterfaceMode {
    switch raw.uppercased() {
    case "FULL": return .full
    case "GATEWAY": return .gateway
    case "AP", "ACCESS_POINT", "ACCESSPOINT": return .accessPoint
    case "ROAMING": return .roaming
    case "BOUNDARY": return .boundary
    case "POINT_TO_POINT", "POINTTOPOINT", "P2P": return .pointToPoint
    default: return .full
    }
}

/// Run an async operation to completion from a synchronous context.
/// Bridge commands are dispatched synchronously by main.swift's readLine
/// loop, but ReticulumTransport is an actor — this is the bridge between
/// the two worlds. Only used on the bridge's I/O thread.
func blockingAsync<T>(_ op: @Sendable @escaping () async throws -> T) throws -> T {
    let sem = DispatchSemaphore(value: 0)
    let box = ResultBox<T>()
    Task {
        do {
            let value = try await op()
            box.set(.success(value))
        } catch {
            box.set(.failure(error))
        }
        sem.signal()
    }
    sem.wait()
    return try box.get()
}

private final class ResultBox<T>: @unchecked Sendable {
    private var value: Swift.Result<T, Error>?
    private let lock = NSLock()
    func set(_ v: Swift.Result<T, Error>) { lock.lock(); value = v; lock.unlock() }
    func get() throws -> T { lock.lock(); defer { lock.unlock() }; return try value!.get() }
}

// MARK: - Command dispatch

func handleBehavioralCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result {
    switch command {

    case "behavioral_start":
        // enable_transport defaults to true per the reference impl.
        let enableTransport = getBoolOptional(p, "enable_transport") ?? true
        let seedHex = getHexOptional(p, "identity_seed")

        let identity: Identity
        if let seed = seedHex {
            guard seed.count == 64 else {
                throw BridgeError.invalidData("identity_seed must be 64 bytes (32 enc + 32 sig)")
            }
            identity = try Identity(privateKeyBytes: seed)
        } else {
            identity = Identity()
        }

        let pathTable = PathTable()  // in-memory, no sqlite file
        let transport = ReticulumTransport(pathTable: pathTable)

        try blockingAsync {
            await transport.setTransportEnabled(enableTransport, identity: identity)
            await transport.startRetransmissionLoop()
        }

        let handle = Data((0..<8).map { _ in UInt8.random(in: 0...255) }).map { String(format: "%02x", $0) }.joined()
        let inst = BehavioralInstance(transport: transport, identity: identity)

        behavioralLock.lock()
        behavioralInstances[handle] = inst
        behavioralLock.unlock()

        return [
            "handle": .string(handle),
            "identity_hash": hex(identity.hash)
        ]

    case "behavioral_stop":
        let handle = try getString(p, "handle")
        behavioralLock.lock()
        let inst = behavioralInstances.removeValue(forKey: handle)
        behavioralLock.unlock()
        guard let inst else { return ["stopped": boolean(false)] }

        try blockingAsync {
            for ifaceId in inst.interfaces.keys {
                await inst.transport.removeInterface(id: ifaceId)
            }
            await inst.transport.stopRetransmissionLoop()
        }
        return ["stopped": boolean(true)]

    case "behavioral_attach_mock_interface":
        let handle = try getString(p, "handle")
        let name = try getString(p, "name")
        let modeRaw = getStringOptional(p, "mode") ?? "FULL"
        let mtu = getIntOptional(p, "mtu") ?? 500

        behavioralLock.lock()
        let inst = behavioralInstances[handle]
        behavioralLock.unlock()
        guard let inst else {
            throw BridgeError.invalidData("Unknown handle: \(handle)")
        }

        let ifaceId = Data((0..<6).map { _ in UInt8.random(in: 0...255) }).map { String(format: "%02x", $0) }.joined()
        let iface = BehavioralMockInterface(
            id: ifaceId,
            name: name,
            mode: parseInterfaceMode(modeRaw),
            mtu: mtu
        )

        try blockingAsync {
            try await inst.transport.addInterface(iface)
        }
        inst.interfaces[ifaceId] = iface

        return [
            "iface_id": .string(ifaceId),
            "interface_hash": hex(Data(SHA256.hash(data: Data(ifaceId.utf8))).prefix(16))
        ]

    case "behavioral_inject":
        let handle = try getString(p, "handle")
        let ifaceId = try getString(p, "iface_id")
        let raw = try getHex(p, "raw")

        behavioralLock.lock()
        let inst = behavioralInstances[handle]
        behavioralLock.unlock()
        guard let inst, let iface = inst.interfaces[ifaceId] else {
            throw BridgeError.invalidData("Unknown handle or iface_id")
        }

        iface.inject(raw)
        return [:]

    case "behavioral_drain_tx":
        let handle = try getString(p, "handle")
        let ifaceId = try getString(p, "iface_id")

        behavioralLock.lock()
        let inst = behavioralInstances[handle]
        behavioralLock.unlock()
        guard let inst, let iface = inst.interfaces[ifaceId] else {
            throw BridgeError.invalidData("Unknown handle or iface_id")
        }

        let packets = iface.drainTx()
        return ["packets": .array(packets.map { .string(bytesToHex($0)) })]

    default:
        throw BridgeError.unknownCommand(command)
    }
}

// Use CryptoKit's SHA256 for the interface_hash derivation. Kept minimal —
// the test harness only uses this for display/debug, not byte-level comparison.
import CryptoKit
