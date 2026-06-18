// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  LinkRequestReceiptTests.swift
//  ReticulumSwiftTests
//
//  Coverage for the Link request/response/identify surface that the
//  existing Link suites don't touch:
//
//    * RequestReceipt (actor) — the full status state machine:
//      pending -> delivered -> responseReceived / failed / timeout, the
//      completed-state guards, response + metadata storage, the
//      response/failure/progress callbacks, the timeout monitor and its
//      cancellation, and the statusUpdates AsyncStream.
//      (Sources/ReticulumSwift/Request/RequestReceipt.swift)
//
//    * Link.request() / Link.respond() — the `.notActive` guards, the
//      sub-MDU REQUEST DATA wire format ([timestamp, pathHash, data]
//      msgpack, REQUEST context, link destination), receipt creation +
//      markDelivered, and the inbound response delivery paths
//      handleRequestResponse() / handleResponsePacket() (including the
//      raw-bytes-not-double-framed and structured-value re-pack branches).
//      (Sources/ReticulumSwift/Link/Link+Request.swift, Link.swift)
//
//    * Link.identify() / handleIdentifyPacket() — the silent no-op guards
//      (non-initiator, non-ACTIVE), the responder-side proof validation
//      (size, signature, identity reconstruction, remoteIdentity storage,
//      IdentifyCallbacks notification) and a full encrypted round trip.
//      (Sources/ReticulumSwift/Link/Link+Identify.swift, Link.swift)
//
//  The encrypted-send tests stand up a real in-memory Link PAIR via the
//  genuine handshake (getLinkRequestPacket -> createProofPacket ->
//  processProof -> processLRRTT) so request()/respond()/identify() run
//  their true encrypt() paths against a peer that can decrypt — no mocks
//  of the crypto. Everything asserts real observable state, so a
//  regression in any of the above would turn one of these red.
//

import XCTest
import CryptoKit
@testable import ReticulumSwift

// `_setStateForTesting` is wrapped in `#if DEBUG` on the implementation
// side, so wrap the suite the same way (mirrors LinkProveTests.swift).
#if DEBUG
final class LinkRequestReceiptTests: XCTestCase {

    // MARK: - Nested test helpers (private — no integration-time collision)

    /// Concurrency-safe sink for sendCallback-captured packet bytes.
    private actor SendRecorder {
        private var packets: [Data] = []
        func append(_ data: Data) { packets.append(data) }
        func drain() -> [Data] { let copy = packets; packets = []; return copy }
        var count: Int { packets.count }
    }

    /// Counts how many times a RequestReceipt callback fired.
    private actor CallbackCounter {
        private(set) var count = 0
        func bump() { count += 1 }
    }

    /// Records identities surfaced through IdentifyCallbacks.
    private actor IdentityRecorder {
        private(set) var identities: [Identity] = []
        func record(_ identity: Identity) { identities.append(identity) }
    }

    /// IdentifyCallbacks delegate that forwards into an IdentityRecorder.
    private final class CapturingIdentifyCallbacks: IdentifyCallbacks {
        let recorder: IdentityRecorder
        init(_ recorder: IdentityRecorder) { self.recorder = recorder }
        func remoteIdentified(_ identity: Identity) async {
            await recorder.record(identity)
        }
    }

    /// Human-readable name for a RequestReceipt.Status (it has an
    /// associated value so it isn't Equatable — switch to a name instead).
    private func statusName(_ status: RequestReceipt.Status) -> String {
        switch status {
        case .pending: return "pending"
        case .delivered: return "delivered"
        case .responseReceived: return "responseReceived"
        case .failed(let reason): return "failed(\(reason))"
        case .timeout: return "timeout"
        }
    }

    /// Build a responder-shaped Link from a synthesized LINKREQUEST.
    /// Mirrors the fixture in LinkProveTests / LinkDataSendTests but lets
    /// the caller pick the forced state. Returns an `initiator == false`
    /// link with a stable linkId.
    private func makeResponderLink(state: LinkState? = nil) async throws -> Link {
        let identity = Identity()
        let dest = Destination(
            identity: identity, appName: "test", aspects: ["link-request-receipt"]
        )

        let encKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let sigKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let signaling = IncomingLinkRequest.encodeSignaling(
            mtu: 500, mode: LinkConstants.MODE_DEFAULT
        )
        var requestData = Data()
        requestData.append(encKey)
        requestData.append(sigKey)
        requestData.append(signaling)
        let header = PacketHeader(
            headerType: .header1,
            hasContext: false,
            transportType: .broadcast,
            destinationType: .single,
            packetType: .linkRequest,
            hopCount: 0
        )
        let lrPacket = Packet(
            header: header,
            destination: dest.hash,
            context: 0x00,
            data: requestData
        )
        let incoming = try IncomingLinkRequest(data: requestData, packet: lrPacket)
        let link = Link(incomingRequest: incoming, destination: dest, identity: identity)
        if let state {
            await link._setStateForTesting(state)
        }
        return link
    }

    /// 128-byte LINKIDENTIFY proof (publicKeys(64) || signature(64)) for
    /// `identity` over `linkId`, exactly as Link.identify() builds it.
    private func makeIdentifyProof(linkId: Data, presenting identity: Identity) throws -> Data {
        let publicKeys = identity.publicKeys
        var signedData = linkId
        signedData.append(publicKeys)
        let signature = try identity.sign(signedData)
        var proof = publicKeys
        proof.append(signature)
        return proof
    }

    /// Stand up a fully-established, mutually-decryptable Link pair via the
    /// real handshake. After this returns BOTH links are `.active` and hold
    /// a derived token, so request()/respond()/identify() run their genuine
    /// encrypt paths and the opposite side can decrypt() the result.
    private func establishLinkPair() async throws
        -> (initiator: Link, responder: Link, initiatorSends: SendRecorder, responderSends: SendRecorder) {

        let initiatorIdentity = Identity()
        let responderIdentity = Identity()
        let responderDest = Destination(
            identity: responderIdentity, appName: "test", aspects: ["linkreq-pair"]
        )

        // Initiator side: build link + LINKREQUEST, start handshake.
        let initiator = Link(destination: responderDest, identity: initiatorIdentity)
        let initiatorSends = SendRecorder()
        await initiator.setSendCallback { await initiatorSends.append($0) }
        let lrPacket = try await initiator.getLinkRequestPacket()
        await initiator.markRequestSent()

        // Responder side: parse the LINKREQUEST, build link, create PROOF.
        let incoming = try IncomingLinkRequest(data: lrPacket.data, packet: lrPacket)
        let responder = Link(
            incomingRequest: incoming, destination: responderDest, identity: responderIdentity
        )
        let responderSends = SendRecorder()
        await responder.setSendCallback { await responderSends.append($0) }
        let proofPacket = try await responder.createProofPacket()

        // Initiator validates PROOF -> derives key -> active -> emits LRRTT.
        try await initiator.processProof(proofPacket.data)

        // Responder derives its key and completes via the emitted LRRTT.
        try await responder.deriveResponderKeys()
        let initiatorOutbound = await initiatorSends.drain()
        let lrrttRaw = try XCTUnwrap(
            initiatorOutbound.last,
            "processProof must emit an LRRTT packet to complete the handshake"
        )
        let lrrttPacket = try Packet(from: lrrttRaw)
        let lrrttPlain = try await responder.decrypt(lrrttPacket.data)
        try await responder.processLRRTT(lrrttPlain)

        return (initiator, responder, initiatorSends, responderSends)
    }

    private func makeReceipt(
        requestId: Data = Data(repeating: 0xA1, count: 16),
        pathHash: Data = Data(repeating: 0xB2, count: 16),
        timeout: TimeInterval = 100,
        responseCallback: ((RequestReceipt) async -> Void)? = nil,
        failedCallback: ((RequestReceipt) async -> Void)? = nil,
        progressCallback: ((RequestReceipt) async -> Void)? = nil
    ) -> RequestReceipt {
        RequestReceipt(
            requestId: requestId,
            pathHash: pathHash,
            timeout: timeout,
            responseCallback: responseCallback,
            failedCallback: failedCallback,
            progressCallback: progressCallback
        )
    }

    // MARK: - RequestReceipt: construction + accessors

    func testReceiptStartsPendingWithIdentityPreserved() async throws {
        let rid = Data(repeating: 0x11, count: 16)
        let ph = Data(repeating: 0x22, count: 16)
        let receipt = makeReceipt(requestId: rid, pathHash: ph)

        let status = statusName(await receipt.status)
        let gotId = await receipt.requestId
        let gotPath = await receipt.pathHash
        let body = await receipt.responseData
        let meta = await receipt.metadata
        let resource = await receipt.responseResource

        XCTAssertEqual(status, "pending",
            "A freshly created RequestReceipt must start in .pending")
        XCTAssertEqual(gotId, rid,
            "requestId accessor must echo the id passed at init")
        XCTAssertEqual(gotPath, ph,
            "pathHash accessor must echo the path hash passed at init")
        XCTAssertNil(body, "responseData must be nil before any response is received")
        XCTAssertNil(meta, "metadata must be nil before any response is received")
        XCTAssertNil(resource, "responseResource must be nil before any resource response")
    }

    func testTimeoutIntervalAccessorReflectsInit() async throws {
        let receipt = makeReceipt(timeout: 42.5)
        let interval = await receipt.timeoutInterval
        XCTAssertEqual(interval, 42.5, accuracy: 0.0001,
            "timeoutInterval must expose the exact timeout passed at init — " +
            "the bridge reads this rather than reconstructing rtt*6 + grace")
    }

    // MARK: - RequestReceipt: state transitions

    func testMarkDeliveredTransitionsPendingToDelivered() async throws {
        let receipt = makeReceipt()
        await receipt.markDelivered()
        let status = statusName(await receipt.status)
        XCTAssertEqual(status, "delivered",
            "markDelivered must move .pending -> .delivered")
    }

    func testMarkDeliveredIsNoOpFromNonPending() async throws {
        // After a response, status is .responseReceived; markDelivered guards
        // on `case .pending` and must NOT clobber the completed state.
        let receipt = makeReceipt()
        await receipt.receiveResponse(Data("done".utf8))
        await receipt.markDelivered()
        let status = statusName(await receipt.status)
        XCTAssertEqual(status, "responseReceived",
            "markDelivered after completion must be a no-op (guard on .pending)")
    }

    func testReceiveResponseDeliversDataAndFiresResponseCallback() async throws {
        let counter = CallbackCounter()
        let receipt = makeReceipt(responseCallback: { _ in await counter.bump() })
        await receipt.markDelivered()

        let payload = Data("hello-response".utf8)
        await receipt.receiveResponse(payload)

        let status = statusName(await receipt.status)
        let body = await receipt.responseData
        let fired = await counter.count
        XCTAssertEqual(status, "responseReceived",
            "receiveResponse must transition to .responseReceived")
        XCTAssertEqual(body, payload,
            "receiveResponse must store the delivered bytes verbatim")
        XCTAssertEqual(fired, 1,
            "receiveResponse must invoke the response callback exactly once")
    }

    func testReceiveResponseStoresMetadata() async throws {
        let receipt = makeReceipt()
        let meta = Data("file-metadata".utf8)
        await receipt.receiveResponse(Data("body".utf8), metadata: meta)

        let gotMeta = await receipt.metadata
        let body = await receipt.responseData
        XCTAssertEqual(gotMeta, meta,
            "receiveResponse(_:metadata:) must store metadata for file responses")
        XCTAssertEqual(body, Data("body".utf8),
            "metadata path must still deliver the response body")
    }

    func testReceiveResponseIgnoredAfterResponseReceived() async throws {
        let receipt = makeReceipt()
        await receipt.receiveResponse(Data("first".utf8))
        // Second response must be dropped — status is already terminal.
        await receipt.receiveResponse(Data("second".utf8))

        let body = await receipt.responseData
        XCTAssertEqual(body, Data("first".utf8),
            "A second receiveResponse after completion must NOT overwrite the " +
            "stored response (switch default returns)")
    }

    func testMarkFailedSetsReasonAndFiresFailedCallback() async throws {
        let counter = CallbackCounter()
        let receipt = makeReceipt(failedCallback: { _ in await counter.bump() })
        await receipt.markDelivered()

        await receipt.markFailed(reason: "boom")

        let status = statusName(await receipt.status)
        let fired = await counter.count
        XCTAssertEqual(status, "failed(boom)",
            "markFailed must set .failed with the supplied reason")
        XCTAssertEqual(fired, 1,
            "markFailed must invoke the failed callback exactly once")
    }

    func testMarkFailedDoesNotOverwriteResponseReceived() async throws {
        let failed = CallbackCounter()
        let receipt = makeReceipt(failedCallback: { _ in await failed.bump() })
        await receipt.receiveResponse(Data("ok".utf8))

        await receipt.markFailed(reason: "late failure")

        let status = statusName(await receipt.status)
        let fired = await failed.count
        XCTAssertEqual(status, "responseReceived",
            "markFailed must not overwrite a completed .responseReceived state")
        XCTAssertEqual(fired, 0,
            "failed callback must not fire when the receipt already succeeded")
    }

    func testReceiveResponseIgnoredAfterFailed() async throws {
        let receipt = makeReceipt()
        await receipt.markFailed(reason: "dead")
        await receipt.receiveResponse(Data("too late".utf8))

        let status = statusName(await receipt.status)
        let body = await receipt.responseData
        XCTAssertEqual(status, "failed(dead)",
            "receiveResponse after .failed must be dropped (only .pending/.delivered accept)")
        XCTAssertNil(body, "a dropped response must not populate responseData")
    }

    func testReportProgressFiresProgressCallback() async throws {
        let counter = CallbackCounter()
        let receipt = makeReceipt(progressCallback: { _ in await counter.bump() })

        await receipt.reportProgress()
        await receipt.reportProgress()

        let fired = await counter.count
        XCTAssertEqual(fired, 2,
            "reportProgress must invoke the progress callback on each call")
    }

    // MARK: - RequestReceipt: timeout monitor

    func testTimeoutTransitionsToTimeoutAndFiresFailedCallback() async throws {
        let counter = CallbackCounter()
        // Tiny timeout so the monitor fires within the test window.
        let receipt = makeReceipt(timeout: 0.15, failedCallback: { _ in await counter.bump() })
        await receipt.markDelivered()

        try await Task.sleep(for: .seconds(0.6))

        let status = statusName(await receipt.status)
        let fired = await counter.count
        XCTAssertEqual(status, "timeout",
            "A receipt still awaiting after its timeout must transition to .timeout")
        XCTAssertEqual(fired, 1,
            "the timeout monitor must invoke the failed callback once on expiry")
    }

    func testResponseBeforeTimeoutCancelsTimeoutMonitor() async throws {
        let failed = CallbackCounter()
        let receipt = makeReceipt(timeout: 0.2, failedCallback: { _ in await failed.bump() })
        await receipt.markDelivered()

        // Respond promptly; this must cancel the pending timeout task.
        await receipt.receiveResponse(Data("quick".utf8))
        // Wait well past the original timeout to prove it doesn't fire.
        try await Task.sleep(for: .seconds(0.5))

        let status = statusName(await receipt.status)
        let fired = await failed.count
        XCTAssertEqual(status, "responseReceived",
            "a response before the timeout must cancel the monitor — status " +
            "must stay .responseReceived, not flip to .timeout")
        XCTAssertEqual(fired, 0,
            "the failed callback must not fire after a successful response")
    }

    func testMarkFailedDoesNotOverwriteTimeout() async throws {
        let receipt = makeReceipt(timeout: 0.12)
        await receipt.markDelivered()
        try await Task.sleep(for: .seconds(0.5))
        // Now in .timeout; a later markFailed must be ignored.
        await receipt.markFailed(reason: "redundant")

        let status = statusName(await receipt.status)
        XCTAssertEqual(status, "timeout",
            "markFailed must not overwrite a terminal .timeout state")
    }

    func testStatusUpdatesStreamYieldsCurrentAndFinalStatus() async throws {
        let receipt = makeReceipt(timeout: 100)
        await receipt.markDelivered()

        // statusUpdates yields the current status immediately, then each
        // change; receiveResponse finishes the stream.
        let stream = await receipt.statusUpdates
        let collector = Task { () -> [String] in
            var names: [String] = []
            for await status in stream {
                switch status {
                case .pending: names.append("pending")
                case .delivered: names.append("delivered")
                case .responseReceived: names.append("responseReceived")
                case .failed: names.append("failed")
                case .timeout: names.append("timeout")
                }
            }
            return names
        }

        await receipt.receiveResponse(Data("x".utf8))
        let names = await collector.value

        XCTAssertEqual(names.first, "delivered",
            "statusUpdates must yield the current status (.delivered) on subscribe")
        XCTAssertEqual(names.last, "responseReceived",
            "statusUpdates must yield the terminal .responseReceived before finishing")
    }

    // MARK: - Link.request() / respond(): notActive guards

    func testRequestThrowsNotActiveOnPendingLink() async throws {
        // A default initiator link is .pending (not established).
        let link = Link(
            destination: Destination(identity: Identity(), appName: "t", aspects: ["req-guard"]),
            identity: Identity()
        )
        do {
            _ = try await link.request(path: "/x")
            XCTFail("request() on a non-established link must throw .notActive")
        } catch let error as LinkError {
            guard case .notActive = error else {
                return XCTFail("request() guard threw the wrong LinkError: \(error)")
            }
        }
    }

    func testRespondThrowsNotActiveOnPendingLink() async throws {
        let link = Link(
            destination: Destination(identity: Identity(), appName: "t", aspects: ["resp-guard"]),
            identity: Identity()
        )
        do {
            try await link.respond(to: Data(repeating: 1, count: 16), with: Data("r".utf8))
            XCTFail("respond(to:with:) on a non-established link must throw .notActive")
        } catch let error as LinkError {
            guard case .notActive = error else {
                return XCTFail("respond() guard threw the wrong LinkError: \(error)")
            }
        }
    }

    func testRespondFileThrowsNotActiveOnPendingLink() async throws {
        let link = Link(
            destination: Destination(identity: Identity(), appName: "t", aspects: ["respfile-guard"]),
            identity: Identity()
        )
        do {
            try await link.respond(to: Data(repeating: 1, count: 16), file: Data("f".utf8), metadata: nil)
            XCTFail("respond(to:file:metadata:) on a non-established link must throw .notActive")
        } catch let error as LinkError {
            guard case .notActive = error else {
                return XCTFail("respond(file:) guard threw the wrong LinkError: \(error)")
            }
        }
    }

    // MARK: - Link.handleRequestResponse(): receipt matching

    func testHandleRequestResponseDeliversToMatchingReceiptAndDropsIt() async throws {
        let link = try await makeResponderLink(state: .active)
        let rid = Data(repeating: 0x5A, count: 16)
        let receipt = makeReceipt(requestId: rid)
        await link.addPendingRequest(receipt)

        let payload = Data("the-response".utf8)
        await link.handleRequestResponse(requestId: rid, data: payload)

        let status = statusName(await receipt.status)
        let body = await receipt.responseData
        let pendingEmpty = await link.pendingRequests.isEmpty
        XCTAssertEqual(status, "responseReceived",
            "handleRequestResponse must deliver to the receipt whose requestId matches")
        XCTAssertEqual(body, payload,
            "the matched receipt must carry the delivered bytes")
        XCTAssertTrue(pendingEmpty,
            "a delivered request must be removed from the pending list")
    }

    func testHandleRequestResponseIgnoresUnknownRequestId() async throws {
        let link = try await makeResponderLink(state: .active)
        let receipt = makeReceipt(requestId: Data(repeating: 0x01, count: 16))
        await link.addPendingRequest(receipt)

        // Deliver to a DIFFERENT id — nothing should match.
        await link.handleRequestResponse(requestId: Data(repeating: 0x99, count: 16), data: Data("nope".utf8))

        let status = statusName(await receipt.status)
        let pendingCount = await link.pendingRequests.count
        XCTAssertEqual(status, "pending",
            "an unmatched response id must leave the receipt untouched")
        XCTAssertEqual(pendingCount, 1,
            "an unmatched response must NOT remove anything from the pending list")
    }

    func testHandleRequestResponsePropagatesMetadata() async throws {
        let link = try await makeResponderLink(state: .active)
        let rid = Data(repeating: 0x3C, count: 16)
        let receipt = makeReceipt(requestId: rid)
        await link.addPendingRequest(receipt)

        let meta = Data("x-metadata".utf8)
        await link.handleRequestResponse(requestId: rid, data: Data("file-bytes".utf8), metadata: meta)

        let gotMeta = await receipt.metadata
        XCTAssertEqual(gotMeta, meta,
            "handleRequestResponse must forward (file, metadata) metadata to the receipt")
    }

    // MARK: - Link.handleResponsePacket(): msgpack unpack + double-frame fix

    func testHandleResponsePacketDeliversRawBytesWithoutDoubleFraming() async throws {
        let link = try await makeResponderLink(state: .active)
        let rid = Data(repeating: 0x7B, count: 16)
        let receipt = makeReceipt(requestId: rid)
        await link.addPendingRequest(receipt)

        // Wire form produced by respond(to:with:): umsgpack([request_id, data]).
        let raw = Data("raw-response-payload".utf8)
        let packed = packMsgPack(.array([.binary(rid), .binary(raw)]))
        await link.handleResponsePacket(packed)

        let body = await receipt.responseData
        XCTAssertEqual(body, raw,
            "handleResponsePacket must extract the .binary payload RAW — re-packing " +
            "it would re-add an msgpack bin frame (the double-frame regression)")
    }

    func testHandleResponsePacketRepacksStructuredResponse() async throws {
        let link = try await makeResponderLink(state: .active)
        let rid = Data(repeating: 0x2D, count: 16)
        let receipt = makeReceipt(requestId: rid)
        await link.addPendingRequest(receipt)

        // A non-bytes (structured) response value has no raw byte form, so the
        // receipt must hold its re-encoded msgpack blob.
        let structured = MessagePackValue.int(4242)
        let packed = packMsgPack(.array([.binary(rid), structured]))
        await link.handleResponsePacket(packed)

        let body = await receipt.responseData
        XCTAssertEqual(body, packMsgPack(structured),
            "a structured (non-.binary) response value must be re-packed into the receipt")
    }

    func testHandleResponsePacketIgnoresMalformedPayload() async throws {
        let link = try await makeResponderLink(state: .active)
        let rid = Data(repeating: 0x4E, count: 16)
        let receipt = makeReceipt(requestId: rid)
        await link.addPendingRequest(receipt)

        // Not a msgpack [request_id, response] array at all.
        await link.handleResponsePacket(Data([0x00, 0x01, 0x02, 0x03]))

        let status = statusName(await receipt.status)
        let pendingCount = await link.pendingRequests.count
        XCTAssertEqual(status, "pending",
            "a malformed RESPONSE payload must not deliver to any receipt")
        XCTAssertEqual(pendingCount, 1,
            "a malformed RESPONSE payload must leave the pending list intact")
    }

    // MARK: - Link.identify(): silent no-op guards

    func testIdentifyOnResponderLinkIsSilentNoOp() async throws {
        // A responder link (initiator == false) must NOT emit a LINKIDENTIFY
        // packet — identify() guards `initiator && state == .active`.
        let link = try await makeResponderLink(state: .active)
        let sends = SendRecorder()
        await link.setSendCallback { await sends.append($0) }

        try await link.identify(identity: Identity())

        let count = await sends.count
        XCTAssertEqual(count, 0,
            "identify() on a responder link must be a silent no-op (no packet emitted)")
    }

    func testIdentifyOnPendingInitiatorLinkIsSilentNoOp() async throws {
        // Initiator but state == .pending (not .active) -> silent no-op.
        let link = Link(
            destination: Destination(identity: Identity(), appName: "t", aspects: ["id-pending"]),
            identity: Identity()
        )
        let sends = SendRecorder()
        await link.setSendCallback { await sends.append($0) }

        try await link.identify(identity: Identity())

        let count = await sends.count
        XCTAssertEqual(count, 0,
            "identify() on a non-ACTIVE initiator link must be a silent no-op")
    }

    // MARK: - Link.handleIdentifyPacket(): responder-side validation

    func testHandleIdentifyPacketStoresValidatedRemoteIdentity() async throws {
        let link = try await makeResponderLink(state: .active)
        let recorder = IdentityRecorder()
        await link.setIdentifyCallbacks(CapturingIdentifyCallbacks(recorder))

        let presented = Identity()
        let linkId = await link.linkId
        let proof = try makeIdentifyProof(linkId: linkId, presenting: presented)

        try await link.handleIdentifyPacket(proof)

        let identified = await link.isRemoteIdentified
        let getHash = await link.getRemoteIdentity()?.hash
        let propHash = await link.remoteIdentity?.hash
        let firedHash = await recorder.identities.first?.hash
        XCTAssertTrue(identified,
            "a valid LINKIDENTIFY proof must flip isRemoteIdentified to true")
        XCTAssertEqual(getHash, presented.hash,
            "the stored remoteIdentity must be the presented identity")
        XCTAssertEqual(propHash, presented.hash,
            "remoteIdentity accessor must agree with getRemoteIdentity()")
        XCTAssertEqual(firedHash, presented.hash,
            "IdentifyCallbacks.remoteIdentified must fire with the verified identity")
    }

    func testHandleIdentifyPacketRejectsWrongSize() async throws {
        let link = try await makeResponderLink(state: .active)
        do {
            // 100 bytes != 128 -> size guard.
            try await link.handleIdentifyPacket(Data(repeating: 0, count: 100))
            XCTFail("handleIdentifyPacket must reject a non-128-byte proof")
        } catch let error as LinkError {
            guard case .invalidState(let expected, _) = error else {
                return XCTFail("expected .invalidState for a wrong-size proof, got \(error)")
            }
            XCTAssertEqual(expected, "128 bytes",
                "the size guard must report the expected 128-byte length")
        }
        let identified = await link.isRemoteIdentified
        XCTAssertFalse(identified,
            "a rejected proof must not populate remoteIdentity")
    }

    func testHandleIdentifyPacketRejectsInvalidSignature() async throws {
        let link = try await makeResponderLink(state: .active)
        let presented = Identity()

        // Valid-length proof, but signature is over the WRONG message so
        // verification against (linkId + publicKeys) fails.
        var proof = presented.publicKeys
        let badSig = try presented.sign(Data("not-the-link-binding".utf8))
        proof.append(badSig)
        XCTAssertEqual(proof.count, 128, "precondition: proof must be 128 bytes")

        do {
            try await link.handleIdentifyPacket(proof)
            XCTFail("handleIdentifyPacket must reject a proof whose signature doesn't verify")
        } catch let error as LinkError {
            guard case .invalidState(let expected, _) = error else {
                return XCTFail("expected .invalidState for a bad signature, got \(error)")
            }
            XCTAssertEqual(expected, "valid signature",
                "the signature guard must report 'valid signature' as expected")
        }
        let identified = await link.isRemoteIdentified
        XCTAssertFalse(identified,
            "a signature failure must leave remoteIdentity unset")
    }

    func testHandleIdentifyPacketIsNoOpOnInitiatorLink() async throws {
        // Only responders accept identification; an initiator silently returns.
        let link = Link(
            destination: Destination(identity: Identity(), appName: "t", aspects: ["id-init"]),
            identity: Identity()
        )
        await link._setStateForTesting(.active)
        let linkId = await link.linkId
        let proof = try makeIdentifyProof(linkId: linkId, presenting: Identity())

        // Must not throw and must not store anything.
        try await link.handleIdentifyPacket(proof)

        let identified = await link.isRemoteIdentified
        XCTAssertFalse(identified,
            "handleIdentifyPacket on an initiator link must be a silent no-op")
    }

    func testHandleIdentifyPacketThrowsNotActiveOnUnestablishedLink() async throws {
        // Default responder link is .handshake (isEstablished == false).
        let link = try await makeResponderLink()
        let linkId = await link.linkId
        let proof = try makeIdentifyProof(linkId: linkId, presenting: Identity())

        do {
            try await link.handleIdentifyPacket(proof)
            XCTFail("handleIdentifyPacket on a non-established responder must throw .notActive")
        } catch let error as LinkError {
            guard case .notActive = error else {
                return XCTFail("expected .notActive for an unestablished link, got \(error)")
            }
        }
    }

    // MARK: - Full encrypted round trips over a real Link pair

    func testRequestEmitsEncryptedRequestPacketAndMarksDelivered() async throws {
        let (initiator, responder, initiatorSends, _) = try await establishLinkPair()
        _ = await initiatorSends.drain() // clear handshake traffic

        let receipt = try await initiator.request(path: "/echo", data: .string("hello"))

        // request() marks the receipt delivered once the packet is sent.
        let status = statusName(await receipt.status)
        XCTAssertEqual(status, "delivered",
            "after a successful send, request() must mark the receipt .delivered")

        // Find the REQUEST DATA packet on the wire.
        let outbound = await initiatorSends.drain()
        let requestPacket = try XCTUnwrap(
            outbound.compactMap { try? Packet(from: $0) }
                .first { $0.context == RequestPacketContext.request },
            "request() must emit a link DATA packet with REQUEST context"
        )
        let linkId = await initiator.linkId
        XCTAssertEqual(requestPacket.header.destinationType, .link,
            "a link request packet must address destinationType=LINK")
        XCTAssertEqual(requestPacket.destination, linkId,
            "the request packet must be addressed to the link id")

        // The peer can decrypt it; the plaintext is umsgpack([ts, pathHash, data]).
        let plain = try await responder.decrypt(requestPacket.data)
        let unpacked = try unpackMsgPack(plain)
        guard case .array(let fields) = unpacked, fields.count == 3 else {
            return XCTFail("request payload must unpack to a 3-element array [ts, pathHash, data]")
        }
        guard case .binary(let pathHash) = fields[1] else {
            return XCTFail("request payload field[1] must be the binary path hash")
        }
        XCTAssertEqual(pathHash, Hashing.truncatedHash(Data("/echo".utf8)),
            "the request path hash must be truncatedHash(utf8(path))")
        guard case .string(let body) = fields[2] else {
            return XCTFail("request payload field[2] must carry the native msgpack data value")
        }
        XCTAssertEqual(body, "hello",
            "the request data must be packed as its native msgpack type, not binary")

        // request_id is the sent packet's truncated hash (Python parity).
        let rid = await receipt.requestId
        XCTAssertEqual(rid, requestPacket.getTruncatedHash(),
            "the receipt's requestId must equal the sent packet's truncated hash")

        await initiator.close()
        await responder.close()
    }

    func testRequestResponseRoundTripDeliversToReceipt() async throws {
        let (initiator, responder, _, responderSends) = try await establishLinkPair()

        // Initiator sends a request; capture its receipt + id.
        let receipt = try await initiator.request(path: "/lookup", data: .binary(Data([0x01, 0x02])))
        let requestId = await receipt.requestId
        _ = await responderSends.drain() // ignore anything emitted so far

        // Responder answers; respond() packs umsgpack([request_id, data]) and
        // sends it as a RESPONSE DATA packet.
        let responsePayload = Data("server-says-hi".utf8)
        try await responder.respond(to: requestId, with: responsePayload)

        let responderOutbound = await responderSends.drain()
        let responseRaw = try XCTUnwrap(
            responderOutbound
                .compactMap { try? Packet(from: $0) }
                .first { $0.context == RequestPacketContext.response },
            "respond(to:with:) must emit a link DATA packet with RESPONSE context"
        )

        // Decrypt on the initiator side and feed the inbound RESPONSE handler.
        let plain = try await initiator.decrypt(responseRaw.data)
        await initiator.handleResponsePacket(plain)

        let status = statusName(await receipt.status)
        let body = await receipt.responseData
        let pendingEmpty = await initiator.pendingRequests.isEmpty
        XCTAssertEqual(status, "responseReceived",
            "the round-trip response must drive the pending receipt to .responseReceived")
        XCTAssertEqual(body, responsePayload,
            "the receipt must carry the exact bytes the responder sent")
        XCTAssertTrue(pendingEmpty,
            "a fulfilled request must be removed from the initiator's pending list")

        await initiator.close()
        await responder.close()
    }

    func testIdentifyRoundTripRevealsIdentityToResponder() async throws {
        let (initiator, responder, initiatorSends, _) = try await establishLinkPair()
        _ = await initiatorSends.drain()

        let recorder = IdentityRecorder()
        await responder.setIdentifyCallbacks(CapturingIdentifyCallbacks(recorder))

        // The initiator may reveal an ARBITRARY identity (RNS parity).
        let presented = Identity()
        try await initiator.identify(identity: presented)

        let identifyOutbound = await initiatorSends.drain()
        let identifyRaw = try XCTUnwrap(
            identifyOutbound
                .compactMap { try? Packet(from: $0) }
                .first { $0.context == LinkConstants.CONTEXT_LINKIDENTIFY },
            "identify() on an active initiator must emit a LINKIDENTIFY packet"
        )

        // Responder decrypts the proof and validates it.
        let proof = try await responder.decrypt(identifyRaw.data)
        try await responder.handleIdentifyPacket(proof)

        let identified = await responder.isRemoteIdentified
        let getHash = await responder.getRemoteIdentity()?.hash
        let firedHash = await recorder.identities.first?.hash
        XCTAssertTrue(identified,
            "the responder must mark the link as remote-identified after a valid proof")
        XCTAssertEqual(getHash, presented.hash,
            "the responder must recover exactly the identity the initiator presented")
        XCTAssertEqual(firedHash, presented.hash,
            "the responder's IdentifyCallbacks must fire with the presented identity")

        await initiator.close()
        await responder.close()
    }
}
#endif
