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

    /// Double-`endTunnelMode()` after a real `beginTunnelMode()` must
    /// also be a no-op on the second call. This is the path greptile
    /// flagged on PR #17: a VPN status observer could fire a second
    /// `.invalid` notification while the reconnect task from the
    /// FIRST `endTunnelMode()` is still in-flight. Without the guard,
    /// the second `endTunnelMode()` would run the full teardown
    /// again, racing the still-pending reconnect from the first call
    /// and producing two competing transports.
    ///
    /// Verification approach: behavioral contract. After repeated
    /// end calls, `beginTunnelMode()` must still work — the
    /// interface's internal state must not be corrupted. A
    /// guard-correct path leaves the interface in a clean
    /// post-end state that a fresh begin can transition out of;
    /// a destructive double-end would either crash, deadlock, or
    /// leave the interface in a state where re-begin doesn't
    /// produce the expected `.connected` transition.
    ///
    /// Why not count delegate-fired state transitions? Tried that —
    /// AutoInterface's first `end` spawns an async reconnect Task
    /// that fires its own state churn against the unreachable test
    /// host, racing the test's count sampling and making the
    /// assertion flaky. The behavioral assertion below sidesteps
    /// the timing problem entirely.
    func testTCPInterfaceEndTunnelModeIdempotentAfterBegin() async throws {
        let config = InterfaceConfig(
            id: "test-double-end",
            name: "test",
            type: .tcp,
            enabled: true,
            mode: .full,
            host: "127.0.0.1",
            port: 4242
        )
        let iface = try TCPInterface(config: config)

        // First cycle: begin + end. Establishes the post-end state.
        await iface.beginTunnelMode { _ in /* no-op */ }
        await iface.endTunnelMode()

        // Hot-fire 3 more ends. Without the guard, each one would
        // tear down whatever transport the previous end's
        // setupTransport() spawned and create yet another, producing
        // a cascade of competing reconnect attempts (the bug greptile
        // flagged on PR #17).
        await iface.endTunnelMode()
        await iface.endTunnelMode()
        await iface.endTunnelMode()

        // Behavioral assertion: the interface must still be functional.
        // `beginTunnelMode` sets `state = .connected` synchronously, so
        // a guard-correct interface lands at `.connected` immediately
        // after this call. A corrupted-by-double-end interface would
        // fail this — either the state set wouldn't take (some racing
        // async work overwrites it), or beginTunnelMode would itself
        // crash on a stale resource.
        await iface.beginTunnelMode { _ in /* no-op */ }
        let stateAfterReBegin = await iface.state
        XCTAssertEqual(stateAfterReBegin, .connected,
            "After begin + 4×end + begin, the interface must still " +
            "transition to .connected. A future regression of the " +
            "`outboundHook != nil` guard would race competing reconnect " +
            "tasks from each hot-fired end and likely leave the " +
            "interface unable to re-enter tunnel mode cleanly. " +
            "Got \(stateAfterReBegin).")
    }

    /// Same double-end behavioral contract for AutoInterface.
    /// AutoInterface's destructive path was slightly different from
    /// TCPInterface's (it sets `state = .disconnected` directly and
    /// spawns a reconnect Task via `connect()`); without the guard,
    /// repeated end calls would cascade competing connect() tasks.
    func testAutoInterfaceEndTunnelModeIdempotentAfterBegin() async throws {
        let config = InterfaceConfig(
            id: "test-auto-double-end",
            name: "test-auto",
            type: .autoInterface,
            enabled: true,
            mode: .full,
            host: "",
            port: 0
        )
        let iface = AutoInterface(config: config)

        await iface.beginTunnelMode { _ in /* no-op */ }
        await iface.endTunnelMode()

        // Hot-fire 3 more ends.
        await iface.endTunnelMode()
        await iface.endTunnelMode()
        await iface.endTunnelMode()

        // Same behavioral assertion as TCP. AutoInterface's
        // beginTunnelMode also sets `state = .connected` synchronously
        // (the closing lines of its `beginTunnelMode` mirror TCP's).
        await iface.beginTunnelMode { _ in /* no-op */ }
        let stateAfterReBegin = await iface.state
        XCTAssertEqual(stateAfterReBegin, .connected,
            "AutoInterface after begin + 4×end + begin must still " +
            "transition to .connected. Without the guard, the cascade " +
            "of competing pendingReconnectTask spawns from each end " +
            "would likely leave the interface in an inconsistent " +
            "state. Got \(stateAfterReBegin).")
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

