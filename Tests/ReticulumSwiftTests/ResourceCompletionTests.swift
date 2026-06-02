// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ResourceCompletionTests.swift
//  ReticulumSwiftTests
//
//  Coverage for the resource failure / cleanup contract (fix/resource-completion-cleanup).
//  Link.handleResourceData's corrupt-assembly path and Link.close()'s teardown both move
//  an in-flight resource to the terminal .failed state (mirroring python Resource.py
//  :715/721 → :723 and Link.link_closed :724-726), drop it from the link's tracking, run
//  cleanup(), and fire resourceConcluded (which the LXMF handler ignores for a non-.complete
//  resource). These tests pin the state-transition contract those paths rely on and that
//  cleanup() is a safe no-op. Full Link/Resource integration is covered by the suite at large.
//

import XCTest
@testable import ReticulumSwift

final class ResourceCompletionTests: XCTestCase {

    /// Build an outbound resource driven to `.transferring` — the active state the link's
    /// corrupt-assembly and close()-teardown paths operate on. `prepare()` sets the hash
    /// and moves the resource to `.queued`; the link only satisfies the initializer.
    private func makeTransferringResource() async throws -> Resource {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["resource"])
        let link = Link(destination: dest, identity: identity)
        let resource = Resource(data: Data(repeating: 0xAB, count: 4096), link: link)
        try await resource.prepare(partSize: 200, linkEncrypt: { $0 }, autoCompress: false)
        try await resource.transitionState(to: .advertised)
        await resource.transitionToTransferring()
        let state = await resource.state
        XCTAssertEqual(state, .transferring, "resource should be transferring after setup")
        return resource
    }

    /// The corrupt-assembly path and close() teardown both transition an in-flight resource
    /// to terminal `.failed`. Verify that transition is legal from the active states they
    /// encounter — `.transferring` (close teardown) and `.assembling` (inbound assemble
    /// failure) — so `try? transitionState(to: .failed)` in those paths actually takes effect.
    func testActiveResourceTransitionsToFailed() async throws {
        let r1 = try await makeTransferringResource()
        try await r1.transitionState(to: .failed)
        let s1 = await r1.state
        XCTAssertEqual(s1, .failed, ".transferring -> .failed (close teardown) must be legal")
        XCTAssertTrue(s1.isTerminal)

        // .transferring -> .assembling -> .failed : the inbound corrupt-assembly sequence.
        let r2 = try await makeTransferringResource()
        try await r2.transitionState(to: .assembling)
        try await r2.transitionState(to: .failed)
        let s2 = await r2.state
        XCTAssertEqual(s2, .failed, ".assembling -> .failed (corrupt assemble) must be legal")
        XCTAssertTrue(s2.isTerminal)
    }

    /// Only `.complete` is deliverable — the corrupt/teardown paths leave the resource in a
    /// non-`.complete` terminal state precisely so the LXMF resourceConcluded handler (gated
    /// on `.complete`) drops it without delivery. Pin that `.failed` is not `.complete`.
    func testFailedResourceIsNotComplete() async throws {
        let resource = try await makeTransferringResource()
        try await resource.transitionState(to: .failed)
        let state = await resource.state
        XCTAssertNotEqual(state, .complete)
        XCTAssertFalse(state.isComplete)
    }

    /// cleanup() is a safe, idempotent no-op today (the disk-streaming work fills it in) and
    /// must not, by itself, change resource state.
    func testCleanupIsSafeNoOp() async throws {
        let resource = try await makeTransferringResource()
        await resource.cleanup()
        await resource.cleanup()
        let state = await resource.state
        XCTAssertEqual(state, .transferring, "cleanup() alone must not change state")
    }
}
