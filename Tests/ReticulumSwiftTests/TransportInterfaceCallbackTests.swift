// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  TransportInterfaceCallbackTests.swift
//  ReticulumSwift
//
//  Tests for the interface-lifecycle callbacks split out of the legacy
//  `onInterfaceAdded` hook: `onInterfaceConnected` (state-change-to-connected)
//  and `onInterfacePeerSpawned` (peer-add on AutoInterface / BLE / MPC), plus
//  the deprecated `setOnInterfaceAdded` shim that wires both.
//

import XCTest
@testable import ReticulumSwift

@available(macOS 14.0, iOS 17.0, *)
final class TransportInterfaceCallbackTests: XCTestCase {

    /// Tiny actor-isolated recorder so the @Sendable callback can mutate
    /// observable state without data-race warnings.
    private actor InvocationRecorder {
        private(set) var ids: [String] = []
        func record(_ id: String) { ids.append(id) }
        var count: Int { ids.count }
    }

    /// `setOnInterfaceConnected` should fire when an interface state-changes
    /// to `.connected`, and the callback receives the interface id.
    func testOnInterfaceConnectedFiresWithIdOnConnectedStateChange() async throws {
        let transport = ReticulumTransport(pathTable: PathTable())
        let recorder = InvocationRecorder()

        await transport.setOnInterfaceConnected { id in
            await recorder.record(id)
        }
        await transport.handleInterfaceStateChange(id: "iface-1", state: .connected)

        // The handler dispatches the callback to a Task; give it a beat.
        try await Task.sleep(for: .milliseconds(50))

        let ids = await recorder.ids
        XCTAssertEqual(ids, ["iface-1"], "callback must fire exactly once with the iface id")
    }

    /// Non-connected state transitions must NOT fire `onInterfaceConnected`.
    func testOnInterfaceConnectedDoesNotFireOnNonConnectedStates() async throws {
        let transport = ReticulumTransport(pathTable: PathTable())
        let recorder = InvocationRecorder()

        await transport.setOnInterfaceConnected { id in
            await recorder.record(id)
        }
        await transport.handleInterfaceStateChange(id: "iface-1", state: .disconnected)
        await transport.handleInterfaceStateChange(id: "iface-1", state: .connecting)

        try await Task.sleep(for: .milliseconds(50))

        let count = await recorder.count
        XCTAssertEqual(count, 0, "non-connected states must not fire the callback")
    }

    /// The deprecated `setOnInterfaceAdded` shim wires the same closure into
    /// both new hooks. The connected-fire path is observable here.
    func testDeprecatedSetOnInterfaceAddedShimFiresOnConnected() async throws {
        let transport = ReticulumTransport(pathTable: PathTable())
        let recorder = InvocationRecorder()

        // Suppress deprecation warning for the explicit shim test.
        @Sendable func setShim(_ t: ReticulumTransport, _ cb: @escaping @Sendable (String) async -> Void) async {
            await t.setOnInterfaceAdded(cb)
        }
        await setShim(transport) { id in await recorder.record(id) }

        await transport.handleInterfaceStateChange(id: "iface-shim", state: .connected)
        try await Task.sleep(for: .milliseconds(50))

        let ids = await recorder.ids
        XCTAssertEqual(ids, ["iface-shim"], "shim must wire onInterfaceConnected")
    }

    /// Setting `onInterfaceConnected` to nil must clear the callback.
    func testOnInterfaceConnectedNilClearsCallback() async throws {
        let transport = ReticulumTransport(pathTable: PathTable())
        let recorder = InvocationRecorder()

        await transport.setOnInterfaceConnected { id in
            await recorder.record(id)
        }
        await transport.setOnInterfaceConnected(nil)

        await transport.handleInterfaceStateChange(id: "iface-1", state: .connected)
        try await Task.sleep(for: .milliseconds(50))

        let count = await recorder.count
        XCTAssertEqual(count, 0, "nil callback should not fire")
    }

    /// `setOnInterfacePeerSpawned` accepts a closure. The fire path lives
    /// inside `addAutoInterface` / `addBLEInterface` / `addMPCInterface`'s
    /// `onPeerAdded` closure, which requires a real (or substantial mock)
    /// peer-spawning parent to exercise — out of scope for this unit test.
    /// This test covers the setter's one-line body.
    func testSetOnInterfacePeerSpawnedAcceptsCallback() async {
        let transport = ReticulumTransport(pathTable: PathTable())
        await transport.setOnInterfacePeerSpawned { _ in }
        await transport.setOnInterfacePeerSpawned(nil)
    }
}
