// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  RequestReceipt.swift
//  ReticulumSwift
//
//  Tracks a request sent over a Link.
//  Provides status, response data, and timeout handling.
//
//  Matches Python RNS Link.py request/response semantics.
//

import Foundation

// MARK: - Request Packet Context

/// Packet context for request/response.
///
/// These context bytes identify request and response packets
/// within the link data stream.
public enum RequestPacketContext {
    /// Request packet context byte (matches Python RNS Packet.REQUEST = 0x09)
    public static let request: UInt8 = 0x09

    /// Response packet context byte (matches Python RNS Packet.RESPONSE = 0x0A)
    public static let response: UInt8 = 0x0A
}

// MARK: - RequestReceipt

/// Tracks a request sent over a Link.
///
/// RequestReceipt provides:
/// - Status tracking (pending, delivered, responseReceived, failed, timeout)
/// - Response data storage
/// - Timeout handling with automatic failure notification
/// - AsyncStream for observing status changes
/// - Callbacks for response/failure/progress
///
/// Example usage:
/// ```swift
/// let receipt = try await link.request(path: "/api/data")
/// for await status in await receipt.statusUpdates {
///     switch status {
///     case .responseReceived:
///         let data = await receipt.responseData
///         // Process response
///     case .failed(let reason):
///         print("Request failed: \(reason)")
///     case .timeout:
///         print("Request timed out")
///     default:
///         break
///     }
/// }
/// ```
public actor RequestReceipt {

    // MARK: - Identity

    /// Unique request ID (truncated hash of packed request)
    public let requestId: Data

    /// Request path hash
    public let pathHash: Data

    // MARK: - State

    /// Request status
    public enum Status: Sendable {
        /// Request created but not yet sent
        case pending
        /// Request sent, awaiting response
        case delivered
        /// Response received successfully
        case responseReceived
        /// Request failed with reason
        case failed(reason: String)
        /// Request timed out
        case timeout
    }

    /// Current status
    public private(set) var status: Status = .pending

    /// Response data (after responseReceived)
    public private(set) var responseData: Data?

    /// Response metadata. Set only for a (file, metadata) response, where RNS
    /// passes `resource.metadata` to `response_received(response, metadata)`
    /// (RNS Link.py:1369/:1461). nil for plain bytes / structured responses.
    public private(set) var metadata: Data?

    /// Response resource (for large responses)
    public private(set) var responseResource: Resource?

    // MARK: - Timing

    /// Request send time
    private let sentAt: Date

    /// Timeout duration
    private let timeout: TimeInterval

    /// Public read-back of the request's computed timeout (seconds). Mirrors
    /// RNS `RequestReceipt.timeout` (Link.py:1377), which is a plain attribute;
    /// Swift's actor encapsulation needs an explicit accessor so the bridge can
    /// observe the real `rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME *
    /// 1.125` value instead of reconstructing it.
    public var timeoutInterval: TimeInterval { timeout }

    /// Timeout task
    private var timeoutTask: Task<Void, Never>?

    // MARK: - Callbacks

    /// Response callback
    private var responseCallback: ((RequestReceipt) async -> Void)?

    /// Failure callback
    private var failedCallback: ((RequestReceipt) async -> Void)?

    /// Progress callback (for resource-based requests)
    private var progressCallback: ((RequestReceipt) async -> Void)?

    // MARK: - Status Observation

    /// Continuation for status updates
    private var statusContinuation: AsyncStream<Status>.Continuation?

    /// AsyncStream for observing status changes.
    ///
    /// Yields the current status immediately upon subscription, then yields
    /// each subsequent status change. The stream finishes when the request
    /// completes (success, failure, or timeout).
    public var statusUpdates: AsyncStream<Status> {
        AsyncStream { continuation in
            self.statusContinuation = continuation
            continuation.yield(self.status)
        }
    }

    // MARK: - Initialization

    /// Create request receipt.
    ///
    /// - Parameters:
    ///   - requestId: Unique request identifier
    ///   - pathHash: Request path hash
    ///   - timeout: Timeout duration
    ///   - responseCallback: Called on successful response
    ///   - failedCallback: Called on failure/timeout
    ///   - progressCallback: Called on progress (resource transfers)
    public init(
        requestId: Data,
        pathHash: Data,
        timeout: TimeInterval,
        responseCallback: ((RequestReceipt) async -> Void)? = nil,
        failedCallback: ((RequestReceipt) async -> Void)? = nil,
        progressCallback: ((RequestReceipt) async -> Void)? = nil
    ) {
        self.requestId = requestId
        self.pathHash = pathHash
        self.timeout = timeout
        self.sentAt = Date()
        self.responseCallback = responseCallback
        self.failedCallback = failedCallback
        self.progressCallback = progressCallback

        Task { [self] in await startTimeoutMonitor() }
    }

    // MARK: - Response Handling

    /// Mark as delivered (request sent successfully).
    ///
    /// Updates status to delivered, indicating the request has been
    /// transmitted and is awaiting a response.
    public func markDelivered() {
        guard case .pending = status else { return }
        status = .delivered
        statusContinuation?.yield(status)
    }

    /// Receive response data.
    ///
    /// Called when a response packet is received for this request.
    /// Updates status to responseReceived and invokes the response callback.
    ///
    /// - Parameters:
    ///   - data: Response data
    ///   - metadata: Optional response metadata. RNS `response_received(response,
    ///     metadata=None)` stores `self.metadata = metadata` (Link.py:1457-1461);
    ///     it is non-nil only for a (file, metadata) response. Defaults to nil so
    ///     existing call sites (plain bytes / structured responses) are unchanged.
    public func receiveResponse(_ data: Data, metadata: Data? = nil) async {
        // Allow receiving response in pending or delivered state
        switch status {
        case .pending, .delivered:
            break
        default:
            return
        }

        cancelTimeout()
        responseData = data
        self.metadata = metadata
        status = .responseReceived
        statusContinuation?.yield(status)
        statusContinuation?.finish()

        await responseCallback?(self)
    }

    /// Receive response as resource.
    ///
    /// Called when the response is too large for a single packet and
    /// arrives as a Resource transfer.
    ///
    /// - Parameter resource: Response resource
    public func receiveResourceResponse(_ resource: Resource) async {
        responseResource = resource
        // Resource will notify when complete via its own callbacks
    }

    /// Mark as failed.
    ///
    /// Called when the request fails for any reason other than timeout.
    ///
    /// - Parameter reason: Failure reason description
    public func markFailed(reason: String) async {
        // Don't overwrite completed states
        switch status {
        case .responseReceived, .failed, .timeout:
            return
        default:
            break
        }

        cancelTimeout()
        status = .failed(reason: reason)
        statusContinuation?.yield(status)
        statusContinuation?.finish()

        await failedCallback?(self)
    }

    /// Report progress.
    ///
    /// Called during resource-based transfers to notify the caller
    /// of transfer progress.
    public func reportProgress() async {
        await progressCallback?(self)
    }

    // MARK: - Timeout Handling

    /// Start the timeout monitor task.
    ///
    /// Creates a task that sleeps for the timeout duration, then
    /// marks the request as timed out if still pending/delivered.
    private func startTimeoutMonitor() {
        timeoutTask = Task { [weak self] in
            guard let self = self else { return }

            let timeoutValue = self.timeout
            try? await Task.sleep(for: .seconds(timeoutValue))

            guard !Task.isCancelled else { return }

            // handleTimeout re-checks status atomically inside the actor — the response
            // can arrive between this point and handleTimeout running, so the gate must
            // be there, not here (this pre-read would already be stale).
            await self.handleTimeout()
        }
    }

    /// Handle timeout expiration.
    ///
    /// Updates status to timeout and invokes the failure callback.
    private func handleTimeout() async {
        // Re-check status atomically here (no await before this guard, so no actor
        // message can interleave between the read and the transition). Between the
        // timeout monitor firing and this call, the RESPONSE may have arrived —
        // response_received transitions status to .ready and cancels the timeout — so
        // only time out if still waiting. Otherwise overwriting to .timeout would clobber
        // a delivered/ready request AND double-fire its callback. Mirrors RNS
        // request_timed_out's status gate.
        switch status {
        case .pending, .delivered:
            break
        default:
            return
        }
        status = .timeout
        statusContinuation?.yield(status)
        statusContinuation?.finish()

        await failedCallback?(self)
    }

    /// Cancel the timeout task.
    ///
    /// Called when a response is received or the request fails
    /// before the timeout expires.
    private func cancelTimeout() {
        timeoutTask?.cancel()
        timeoutTask = nil
    }
}
