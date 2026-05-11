// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  TunnelModeIdempotencyTests.swift
//  ReticulumSwift
//
//  Pins the contract that `endTunnelMode()` is a no-op when the
//  interface was never put into tunnel mode via `beginTunnelMode(send:)`.
//
//  The bug this guards against: a downstream caller (e.g. Columba-iOS
//  `AppServices.applyTunnelModeToInterfaces`) firing `endTunnelMode()`
//  on every interface in response to a startup VPN status notification
//  (iOS emits an `.invalid` notification on every cold start regardless
//  of whether the user enabled the tunnel) would, prior to this fix,
//  tear down a working local transport that was never tunneled —
//  killing every TCP NWConnection seconds after the app's interface-
//  load loop brought it up.
//
//  See `port-deviations.md` under "TCPInterface.beginTunnelMode /
//  endTunnelMode" → "Sub-deviation (endTunnelMode() idempotency)".
//

import XCTest
@testable import ReticulumSwift

final class TunnelModeIdempotencyTests: XCTestCase {

    /// `endTunnelMode()` on a freshly-constructed TCPInterface that
    /// has never seen `beginTunnelMode(send:)` must not transition
    /// the interface's state. Prior to the idempotency fix, this
    /// would walk the state machine through `.disconnected →
    /// .connecting` and re-create the transport, killing whatever
    /// local connection was in flight.
    func testTCPInterfaceEndTunnelModeIsNoOpWhenNeverBegun() async throws {
        let config = InterfaceConfig(
            id: "test-idempotency",
            name: "test",
            type: .tcp,
            enabled: true,
            mode: .full,
            host: "127.0.0.1",
            port: 4242
        )
        let iface = try TCPInterface(config: config)

        // Brand-new interface, no beginTunnelMode call. State should
        // be the default `.disconnected` and the outbound hook nil.
        let stateBefore = await iface.state

        await iface.endTunnelMode()

        // The state must be unchanged — no `.connecting` transition,
        // no transport teardown / re-create. This is what protects
        // the downstream caller from clobbering a healthy interface.
        let stateAfter = await iface.state
        XCTAssertEqual(stateAfter, stateBefore,
            "endTunnelMode() on an interface that was never put into " +
            "tunnel mode must be a no-op — must not transition state " +
            "or re-create transport. (See port-deviations.md sub-" +
            "deviation under 'TCPInterface.beginTunnelMode'.)")
    }

    /// Same contract for AutoInterface — `endTunnelMode()` on a
    /// fresh interface must not flip state or spawn a reconnect task.
    /// AutoInterface's bug shape was slightly different from TCP's
    /// (it set `state = .disconnected` directly and spawned a
    /// reconnect Task), but the user-visible symptom is the same:
    /// surprise disconnect on a downstream caller's incorrectly-
    /// fired endTunnelMode.
    func testAutoInterfaceEndTunnelModeIsNoOpWhenNeverBegun() async throws {
        let config = InterfaceConfig(
            id: "test-auto-idempotency",
            name: "test-auto",
            type: .autoInterface,
            enabled: true,
            mode: .full,
            host: "",
            port: 0
        )
        let iface = AutoInterface(config: config)

        let stateBefore = await iface.state

        await iface.endTunnelMode()

        let stateAfter = await iface.state
        XCTAssertEqual(stateAfter, stateBefore,
            "AutoInterface.endTunnelMode() on a fresh interface must " +
            "be a no-op — must not flip state or spawn a reconnect " +
            "task. (See port-deviations.md sub-deviation under " +
            "'TCPInterface.beginTunnelMode'.)")
    }
}
