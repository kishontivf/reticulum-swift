//
//  AnnounceTrafficEvent.swift
//  ReticulumSwift
//

import Foundation

/// One announce this node heard or put on the wire, with the interface it crossed and what the
/// node did with it. Emitted through `ReticulumTransport.setOnAnnounceTraffic` so a host app can
/// tally announce traffic without parsing diagnostic strings.
///
/// ⚠️ LOCAL DIVERGENCE from upstream reticulum-swift — re-apply after an upstream refresh. The
/// hook is a plain optional closure, so a host that never sets it pays one nil check per announce.
public struct AnnounceTrafficEvent: Sendable, Equatable {
    /// What happened to an announce this node heard.
    public enum Disposition: String, Sendable {
        /// Recorded a path and stopped here — this node did not carry it onward.
        case kept
        /// Accepted for onward carriage: queued for retransmission, or answered as a path
        /// response. This node is relaying it for the network.
        case relayed
    }

    /// Whose announce this node just transmitted.
    public enum Origin: String, Sendable {
        /// This node's own announce.
        case own
        /// Another node's announce, retransmitted while acting as a transport node.
        case relayed
    }

    public enum Direction: Sendable, Equatable {
        case received(Disposition)
        case sent(Origin)
    }

    public let direction: Direction
    /// Ingress interface for `.received`, egress interface for `.sent`.
    public let interfaceId: String
    public let destinationHash: Data

    public init(direction: Direction, interfaceId: String, destinationHash: Data) {
        self.direction = direction
        self.interfaceId = interfaceId
        self.destinationHash = destinationHash
    }
}
