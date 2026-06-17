// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  ResourceWindowHMUTests.swift
//  ReticulumSwiftTests
//
//  Coverage for resource surface NOT exercised by ResourceWindowTests /
//  ResourceSegmentationTests / ResourceCompletionTests / ResourceCompressionBound:
//
//   - ResourceWindow seed/reset arithmetic (setInitialWindow clamp + window_min
//     re-derive, resetOutstanding) — RNS/Resource.py:216-219 / :937.
//   - ResourceState predicates (isTerminal / isActive / isComplete), the
//     canTransition() state machine (cancel/fail-from-any-non-terminal, the
//     corrupt receive-only rule, terminal lockout, the explicit valid edges) and
//     CustomStringConvertible — RNS/Resource.py state model.
//   - ResourceFlags advertisement bit packing (x/u/p/s/c/encrypted) and decode
//     helpers — RNS/Resource.py:1286-1307.
//   - Resource.getPartHash(at:) bounds + no-hashmap error path (distinct from the
//     static ResourceHashmap.getPartHash covered elsewhere).
//   - HMU receive path: hashmapUpdate(segment:hashmap:) duplicate/grow branches,
//     hashmapUpdatesReceived counter, hashmapHeight coverage, appendHashmapSegment
//     alias, terminal late-packet guard — RNS/Resource.py:493-503.
//   - getProgress() non-split sender/receiver fraction — RNS/Resource.py:1126-1181.
//
//  Every assertion drives REAL production code (no reimplementation): ResourceWindow
//  arithmetic, the ResourceState enum, ResourceFlags OptionSet, and a real inbound
//  Resource built from a real outbound advertisement + fed real encrypted parts.
//

import XCTest
@testable import ReticulumSwift

final class ResourceWindowHMUTests: XCTestCase {

    // MARK: - Construction Helpers (private; no global collisions)

    private func makeLink() -> Link {
        let identity = Identity()
        let dest = Destination(identity: identity, appName: "test", aspects: ["resource"])
        return Link(destination: dest, identity: identity)
    }

    /// Non-uniform bytes so prepare() with autoCompress:false stays uncompressed
    /// and part boundaries are meaningful.
    private func varietyData(_ count: Int) -> Data {
        var d = Data(count: count)
        for i in 0..<count { d[i] = UInt8((i &* 37 &+ 11) & 0xFF) }
        return d
    }

    private func makePreparedOutbound(byteCount: Int, partSize: Int, link: Link) async throws -> Resource {
        let r = Resource(data: varietyData(byteCount), link: link, autoCompress: false)
        try await r.prepare(partSize: partSize, linkEncrypt: { $0 }, autoCompress: false)
        return r
    }

    /// Build a fresh inbound Resource from a prepared outbound's segment-1
    /// advertisement (the same construction roundTripSegment uses).
    private func makeInbound(from outbound: Resource, link: Link) async throws -> Resource {
        let adv = try await outbound.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
        return Resource(advertisement: adv, link: link)
    }

    // MARK: - ResourceWindow: setInitialWindow (RNS/Resource.py:216-219)

    /// setInitialWindow clamps to at least 1 and re-derives window_min =
    /// max(WINDOW_MIN, window - WINDOW_FLEXIBILITY). A seed of 0 / negative must
    /// floor at 1 (never zero / negative — that would stall request batching).
    func testSetInitialWindowClampsToOne() {
        let w = ResourceWindow()
        w.setInitialWindow(0)
        XCTAssertEqual(w.currentWindow, 1, "seed 0 floors to 1")
        XCTAssertEqual(w.windowMin, ResourceConstants.WINDOW_MIN,
                       "window_min re-derives to floor WINDOW_MIN when window-flex < WINDOW_MIN")

        let w2 = ResourceWindow()
        w2.setInitialWindow(-9)
        XCTAssertEqual(w2.currentWindow, 1, "negative seed floors to 1")
    }

    /// A large inherited window seeds the current window verbatim and lifts
    /// window_min by WINDOW_FLEXIBILITY (skips slow-start on an established link).
    func testSetInitialWindowSeedsLargeAndLiftsMin() {
        let w = ResourceWindow()
        w.setInitialWindow(20)
        XCTAssertEqual(w.currentWindow, 20, "established seed is taken verbatim")
        XCTAssertEqual(w.windowMin, 20 - ResourceConstants.WINDOW_FLEXIBILITY,
                       "window_min = window - WINDOW_FLEXIBILITY when above WINDOW_MIN")
        XCTAssertEqual(w.windowMin, 16)
    }

    // MARK: - ResourceWindow: resetOutstanding (RNS/Resource.py:937)

    /// resetOutstanding zeroes the in-flight count so each request_next rebuilds
    /// from scratch and never drifts across batches.
    func testResetOutstandingZeroesCounter() {
        let w = ResourceWindow()
        w.markRequested(count: 7)
        XCTAssertEqual(w.outstanding, 7)
        w.resetOutstanding()
        XCTAssertEqual(w.outstanding, 0, "resetOutstanding clears the batch in-flight count")
        // Re-add for the next batch — the documented request_next pattern.
        w.markRequested(count: 2)
        XCTAssertEqual(w.outstanding, 2)
    }

    // MARK: - ResourceState: predicates over the full enum

    private let allStates: [ResourceState] = [
        .none, .queued, .advertised, .transferring, .awaitingProof,
        .assembling, .complete, .failed, .corrupt, .rejected, .cancelled
    ]

    func testIsTerminalForEveryState() {
        let terminal: Set<String> = ["complete", "failed", "rejected", "cancelled", "corrupt"]
        for s in allStates {
            XCTAssertEqual(s.isTerminal, terminal.contains(s.description),
                           "isTerminal wrong for \(s)")
        }
    }

    func testIsActiveForEveryState() {
        let active: Set<String> = ["transferring", "awaitingProof", "assembling"]
        for s in allStates {
            XCTAssertEqual(s.isActive, active.contains(s.description),
                           "isActive wrong for \(s)")
        }
    }

    func testIsCompleteOnlyForComplete() {
        for s in allStates {
            XCTAssertEqual(s.isComplete, s == .complete, "isComplete wrong for \(s)")
        }
    }

    /// A terminal state must be neither active nor complete-unless-complete, and
    /// must report terminal — cross-checks the three predicates agree.
    func testTerminalStatesAreNotActive() {
        for s in allStates where s.isTerminal {
            XCTAssertFalse(s.isActive, "\(s) is terminal so must not be active")
        }
    }

    // MARK: - ResourceState: CustomStringConvertible (all 11 branches)

    func testDescriptionForEveryState() {
        XCTAssertEqual(ResourceState.none.description, "none")
        XCTAssertEqual(ResourceState.queued.description, "queued")
        XCTAssertEqual(ResourceState.advertised.description, "advertised")
        XCTAssertEqual(ResourceState.transferring.description, "transferring")
        XCTAssertEqual(ResourceState.awaitingProof.description, "awaitingProof")
        XCTAssertEqual(ResourceState.assembling.description, "assembling")
        XCTAssertEqual(ResourceState.complete.description, "complete")
        XCTAssertEqual(ResourceState.failed.description, "failed")
        XCTAssertEqual(ResourceState.corrupt.description, "corrupt")
        XCTAssertEqual(ResourceState.rejected.description, "rejected")
        XCTAssertEqual(ResourceState.cancelled.description, "cancelled")
    }

    // MARK: - ResourceState: canTransition state machine

    /// The explicit non-fail/non-cancel valid edges of the machine.
    func testCanTransitionValidEdges() {
        let valid: [(ResourceState, ResourceState)] = [
            (.none, .queued),
            (.queued, .advertised),
            (.advertised, .transferring),
            (.advertised, .rejected),
            (.transferring, .awaitingProof),
            (.transferring, .assembling),
            (.awaitingProof, .complete),
            (.assembling, .complete),
        ]
        for (from, to) in valid {
            XCTAssertTrue(ResourceState.canTransition(from: from, to: to),
                          "\(from) -> \(to) must be valid")
        }
    }

    /// cancel() is reachable from EVERY non-terminal state (python sets FAILED for
    /// any status < COMPLETE; cancelled is the explicit any-state escape).
    func testCanTransitionCancelFromAnyNonTerminal() {
        for s in allStates {
            XCTAssertEqual(ResourceState.canTransition(from: s, to: .cancelled),
                           !s.isTerminal,
                           "cancel reachable iff \(s) non-terminal")
        }
    }

    /// FAILED is reachable from every non-terminal state (RNS/Resource.py:1086-1087).
    func testCanTransitionFailFromAnyNonTerminal() {
        for s in allStates {
            XCTAssertEqual(ResourceState.canTransition(from: s, to: .failed),
                           !s.isTerminal,
                           "fail reachable iff \(s) non-terminal")
        }
    }

    /// CORRUPT is the receiver-assemble outcome — reachable ONLY from the active
    /// receive states (.transferring, .assembling), never from queued/advertised/
    /// awaitingProof (RNS/Resource.py:715/:689).
    func testCanTransitionCorruptOnlyFromActiveReceive() {
        for s in allStates {
            let expected = (s == .transferring || s == .assembling)
            XCTAssertEqual(ResourceState.canTransition(from: s, to: .corrupt),
                           expected,
                           "corrupt reachable iff \(s) is an active receive state")
        }
    }

    /// No transition is legal out of a terminal state — the machine is locked.
    func testCanTransitionFromTerminalAlwaysFalse() {
        for from in allStates where from.isTerminal {
            for to in allStates {
                XCTAssertFalse(ResourceState.canTransition(from: from, to: to),
                               "terminal \(from) must not transition to \(to)")
            }
        }
    }

    /// A spread of edges that are NOT in the machine must be rejected.
    func testCanTransitionRejectsInvalidEdges() {
        let invalid: [(ResourceState, ResourceState)] = [
            (.none, .advertised),
            (.none, .transferring),
            (.queued, .complete),
            (.queued, .transferring),
            (.advertised, .complete),
            (.advertised, .awaitingProof),
            (.transferring, .rejected),
            (.awaitingProof, .assembling),
            (.assembling, .awaitingProof),
            (.transferring, .none),   // .none is never a valid target
            (.queued, .none),
        ]
        for (from, to) in invalid {
            XCTAssertFalse(ResourceState.canTransition(from: from, to: to),
                           "\(from) -> \(to) must be invalid")
        }
    }

    // MARK: - ResourceFlags: advertisement bit packing (x/u/p/s/c)

    func testFlagPackingIndividualBits() {
        XCTAssertEqual(ResourceFlags(encrypted: true).rawValue, 0x01)
        XCTAssertEqual(ResourceFlags(encrypted: false, compressed: true).rawValue, 0x02)
        XCTAssertEqual(ResourceFlags(encrypted: false, split: true).rawValue, 0x04)
        XCTAssertEqual(ResourceFlags(encrypted: false, isRequest: true).rawValue, 0x08)
        XCTAssertEqual(ResourceFlags(encrypted: false, isResponse: true).rawValue, 0x10)
        XCTAssertEqual(ResourceFlags(encrypted: false, hasMetadata: true).rawValue, 0x20)
    }

    func testFlagPackingAllBitsSet() {
        let all = ResourceFlags(
            encrypted: true, compressed: true, split: true,
            isRequest: true, isResponse: true, hasMetadata: true
        )
        XCTAssertEqual(all.rawValue, 0x3F, "all six flag bits packed")
    }

    /// Decode helpers read the exact bit they name and ignore the others.
    func testFlagDecodeHelpers() {
        // 0x2A = 0b0010_1010 -> compressed(1), isRequest(3), hasMetadata(5).
        let f = ResourceFlags(rawValue: 0x2A)
        XCTAssertFalse(f.isEncrypted)
        XCTAssertTrue(f.isCompressed)
        XCTAssertFalse(f.isSplit)
        XCTAssertTrue(f.isRequestFlag)
        XCTAssertFalse(f.isResponseFlag)
        XCTAssertTrue(f.hasMetadataFlag)

        // 0x15 = 0b0001_0101 -> encrypted(0), split(2), isResponse(4).
        let g = ResourceFlags(rawValue: 0x15)
        XCTAssertTrue(g.isEncrypted)
        XCTAssertFalse(g.isCompressed)
        XCTAssertTrue(g.isSplit)
        XCTAssertFalse(g.isRequestFlag)
        XCTAssertTrue(g.isResponseFlag)
        XCTAssertFalse(g.hasMetadataFlag)
    }

    /// The split advertisement bit travels through getAdvertisement on a real
    /// single-segment outbound: split=false, encrypted=true, no request/response.
    func testSingleSegmentAdvertisementFlags() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 800, partSize: 100, link: link)
        let adv = try await out.getAdvertisement(segment: 1, linkMDU: LinkConstants.LINK_MDU)
        XCTAssertTrue(adv.flags.isEncrypted, "link resources always encrypted")
        XCTAssertFalse(adv.flags.isSplit, "small resource is not split")
        XCTAssertFalse(adv.flags.isRequestFlag, "no request_id -> u bit clear")
        XCTAssertFalse(adv.flags.isResponseFlag, "no request_id -> p bit clear")
    }

    // MARK: - Resource.getPartHash(at:) (instance accessor, bounds + no-hashmap)

    /// In range: returns exactly one MAPHASH_LEN slice equal to the hashmap's
    /// leading entry (cross-checked against the static decoder).
    func testGetPartHashInRange() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 800, partSize: 100, link: link)
        let h0 = try await out.getPartHash(at: 0)
        XCTAssertEqual(h0.count, ResourceConstants.MAPHASH_LEN, "part hash is MAPHASH_LEN bytes")

        let map = await out.hashmap
        XCTAssertNotNil(map)
        XCTAssertEqual(h0, ResourceHashmap.getPartHash(from: map!, at: 0),
                       "instance getPartHash matches the static hashmap decoder")
    }

    func testGetPartHashThrowsOutOfRange() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 800, partSize: 100, link: link)
        let n = await out.numParts
        await XCTAssertThrowsErrorAsync(try await out.getPartHash(at: -1),
                                        "negative index must throw")
        await XCTAssertThrowsErrorAsync(try await out.getPartHash(at: n),
                                        "index == numParts must throw (past the end)")
        await XCTAssertThrowsErrorAsync(try await out.getPartHash(at: n + 50),
                                        "far out-of-range index must throw")
    }

    /// Before prepare() there is no hashmap; getPartHash surfaces the invalidState
    /// error rather than trapping.
    func testGetPartHashThrowsWhenNoHashmap() async throws {
        let link = makeLink()
        let r = Resource(data: varietyData(64), link: link, autoCompress: false)
        await XCTAssertThrowsErrorAsync(try await r.getPartHash(at: 0),
                                        "no hashmap before prepare() must throw")
    }

    // MARK: - HMU receive path (hashmapUpdate / hashmapHeight / counters)

    /// A single-chunk inbound already covers all parts in its advertisement chunk:
    /// hashmapHeight == numParts and the counter starts at zero.
    func testInboundHashmapHeightFromAdvertisementChunk() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 1000, partSize: 100, link: link)
        let inbound = try await makeInbound(from: out, link: link)

        let n = await inbound.numParts
        let height = await inbound.hashmapHeight
        XCTAssertEqual(height, n, "single-chunk advertisement covers every part")
        let received = await inbound.hashmapUpdatesReceived
        XCTAssertEqual(received, 0, "no HMU applied yet")
    }

    /// A duplicate HMU (segment already covered) is idempotent: returns false,
    /// coverage unchanged — but it still self-heals ADVERTISED->TRANSFERRING,
    /// counts the receipt, and clears the HMU wait flag (RNS/Resource.py:493-503).
    func testHashmapUpdateDuplicateIsIdempotent() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 1000, partSize: 100, link: link)
        let inbound = try await makeInbound(from: out, link: link)
        let before = await inbound.hashmapHeight

        // segment 0 starts at part 0, already within coverage -> duplicate branch.
        let grew = await inbound.hashmapUpdate(segment: 0, hashmap: Data([0xDE, 0xAD, 0xBE, 0xEF]))
        XCTAssertFalse(grew, "duplicate HMU does not grow coverage")

        let after = await inbound.hashmapHeight
        XCTAssertEqual(after, before, "coverage unchanged by a duplicate")
        let received = await inbound.hashmapUpdatesReceived
        XCTAssertEqual(received, 1, "duplicate still counts as a received HMU")
        let state = await inbound.state
        XCTAssertEqual(state, .transferring, "HMU self-heals advertised -> transferring")
        let waiting = await inbound.waitingForHMU
        XCTAssertFalse(waiting, "HMU clears the wait flag")
    }

    /// An HMU that extends coverage grows hashmapHeight by the chunk's entry count
    /// and reports grew==true (the append branch, RNS/Resource.py:867-873).
    func testHashmapUpdateGrowsCoverage() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 1000, partSize: 100, link: link)
        let inbound = try await makeInbound(from: out, link: link)
        let before = await inbound.hashmapHeight

        // segment 1 begins past the single-chunk coverage -> append + grow.
        let chunk = Data([0x01, 0x02, 0x03, 0x04])  // one 4-byte map hash
        let grew = await inbound.hashmapUpdate(segment: 1, hashmap: chunk)
        XCTAssertTrue(grew, "extending HMU grows coverage")

        let after = await inbound.hashmapHeight
        XCTAssertEqual(after, before + 1, "coverage grew by exactly one map-hash entry")
        let received = await inbound.hashmapUpdatesReceived
        XCTAssertEqual(received, 1)
    }

    /// appendHashmapSegment is a thin alias forwarding to hashmapUpdate — same
    /// observable effect (counter increments, coverage grows).
    func testAppendHashmapSegmentAliasForwards() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 1000, partSize: 100, link: link)
        let inbound = try await makeInbound(from: out, link: link)
        let before = await inbound.hashmapHeight

        let grew = await inbound.appendHashmapSegment(Data([0x09, 0x08, 0x07, 0x06]), wireSegment: 1)
        XCTAssertTrue(grew, "alias forwards the grow result")
        let after = await inbound.hashmapHeight
        XCTAssertEqual(after, before + 1)
        let received = await inbound.hashmapUpdatesReceived
        XCTAssertEqual(received, 1, "alias increments the same HMU counter")
    }

    /// A terminal resource ignores a late HMU entirely (no count, no coverage
    /// change) — the FAILED/terminal late-packet guard (RNS/Resource.py:493).
    func testHashmapUpdateTerminalGuardIgnores() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 1000, partSize: 100, link: link)
        let inbound = try await makeInbound(from: out, link: link)
        // advertised -> failed is a legal any-non-terminal -> failed transition.
        try await inbound.transitionState(to: .failed)
        let before = await inbound.hashmapHeight

        let grew = await inbound.hashmapUpdate(segment: 1, hashmap: Data([0x11, 0x22, 0x33, 0x44]))
        XCTAssertFalse(grew, "terminal resource rejects the HMU")
        let after = await inbound.hashmapHeight
        XCTAssertEqual(after, before, "terminal HMU does not change coverage")
        let received = await inbound.hashmapUpdatesReceived
        XCTAssertEqual(received, 0, "terminal HMU is not counted (guard returns before increment)")
    }

    // MARK: - getProgress() non-split (RNS/Resource.py:1126-1181)

    /// A freshly prepared outbound has sent nothing -> progress 0.0 (sender path
    /// uses sentPartCount/numParts).
    func testGetProgressZeroOnFreshOutbound() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 1000, partSize: 100, link: link)
        let p = await out.getProgress()
        XCTAssertEqual(p, 0.0, accuracy: 1e-9, "no parts sent -> 0.0 progress")
    }

    /// Receiver progress tracks received fraction: feed parts in order through the
    /// REAL receive path and watch getProgress climb from a partial fraction to 1.0.
    func testGetProgressReceiverReflectsReceivedFraction() async throws {
        let link = makeLink()
        let out = try await makePreparedOutbound(byteCount: 1200, partSize: 100, link: link)
        let n = await out.numParts
        XCTAssertGreaterThan(n, 3, "need several parts to see partial progress")

        let inbound = try await makeInbound(from: out, link: link)
        await inbound.setDecryptCallback { $0 }
        await inbound.transitionToTransferring()

        let half = n / 2
        for i in 0..<half {
            let part = try await out.getPart(at: i)
            let ok = try await inbound.receivePart(part, at: i)
            XCTAssertTrue(ok, "in-order, in-window part \(i) must be accepted")
        }
        let received = await inbound.receivedCount
        XCTAssertEqual(received, half, "received count matches fed parts")
        let pHalf = await inbound.getProgress()
        XCTAssertEqual(pHalf, Double(half) / Double(n), accuracy: 1e-9,
                       "receiver progress == received/total")

        for i in half..<n {
            let part = try await out.getPart(at: i)
            _ = try await inbound.receivePart(part, at: i)
        }
        let pFull = await inbound.getProgress()
        XCTAssertEqual(pFull, 1.0, accuracy: 1e-9, "all parts received -> 1.0")
    }

    // MARK: - async throwing assert helper

    private func XCTAssertThrowsErrorAsync<T>(
        _ expression: @autoclosure () async throws -> T,
        _ message: String = "",
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await expression()
            XCTFail(message.isEmpty ? "expected an error to be thrown" : message,
                    file: file, line: line)
        } catch {
            // expected
        }
    }
}
