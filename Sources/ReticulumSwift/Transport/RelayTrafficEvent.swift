//
//  RelayTrafficEvent.swift
//  ReticulumSwift
//

import Foundation

/// One packet this node carried for someone else while acting as a transport node — it was
/// neither sender nor recipient, but the hop in the middle. Emitted through
/// `ReticulumTransport.setOnRelayTraffic` so a host app can tally what its relaying actually
/// costs without parsing diagnostic strings.
///
/// Announce retransmissions are NOT reported here — they have their own
/// ``AnnounceTrafficEvent``, and counting them twice would make the two totals disagree.
///
/// ⚠️ LOCAL DIVERGENCE from upstream reticulum-swift — re-apply after an upstream refresh.
public struct RelayTrafficEvent: Sendable, Equatable {
    /// Which forwarded-packet flavour this was. `linkData` is the one that carries an actual
    /// message body in transit; the rest are the link setup and the proofs around it.
    public enum Kind: String, Sendable {
        case linkRequest
        case linkProof
        case linkData
        case dataPacket
        case dataProof
    }

    public let kind: Kind
    /// The interface the packet arrived on.
    public let ingressInterfaceId: String
    /// The interface it was sent back out on.
    public let egressInterfaceId: String
    /// Size of the forwarded packet as written to the egress interface.
    public let bytes: Int

    public init(kind: Kind, ingressInterfaceId: String, egressInterfaceId: String, bytes: Int) {
        self.kind = kind
        self.ingressInterfaceId = ingressInterfaceId
        self.egressInterfaceId = egressInterfaceId
        self.bytes = bytes
    }
}
