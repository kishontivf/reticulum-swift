// Ext+Dispatch.swift — central sub-handler chains for the conformance bridge.
//
// The bridge dispatch (handleCommand in main.swift, handleWireCommand in
// WireTcp.swift) was refactored so adding a command never requires editing a
// shared switch. Instead, each cluster of commands lives in its own file with a
// `handle…Command(command, params) -> Result?` function that returns nil for any
// command it doesn't own. These two chains try each cluster in turn.
//
// This lets the (large) conformance command surface be ported in parallel:
// one file per cluster, zero shared-file contention. Only THIS file lists the
// clusters, and it changes only when a whole new cluster is added.
import Foundation

/// Non-wire / non-behavioral commands (ports from reference/bridge_server.py).
/// Called from handleCommand's default case in main.swift.
func handleExtensionCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    if let r = try handleCryptoExtCommand(command, p) { return r }
    if let r = try handleIdentityExtCommand(command, p) { return r }
    if let r = try handlePacketExtCommand(command, p) { return r }
    if let r = try handleAnnounceExtCommand(command, p) { return r }
    if let r = try handleDestinationExtCommand(command, p) { return r }
    if let r = try handleDiscoveryExtCommand(command, p) { return r }
    if let r = try handleNamingExtCommand(command, p) { return r }
    if let r = try handleInterfaceExtCommand(command, p) { return r }
    if let r = try handleFramingExtCommand(command, p) { return r }
    return nil
}

/// Live-TCP wire commands not matched by the core handleWireCommand switch
/// (ports from reference/wire_tcp.py). Called from that switch's default case.
func handleWireExtensionCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    if let r = try handleWireLinkCommand(command, p) { return r }
    if let r = try handleWireResourceCommand(command, p) { return r }
    if let r = try handleWireChannelCommand(command, p) { return r }
    if let r = try handleWireInjectCommand(command, p) { return r }
    if let r = try handleWireSendCommand(command, p) { return r }
    if let r = try handleWireIdentityCommand(command, p) { return r }
    if let r = try handleWireIfaceCommand(command, p) { return r }
    return nil
}

/// Behavioral (mock-transport black-box) commands not matched by the core
/// handleBehavioralCommand switch (ports from reference/behavioral_transport.py).
/// Called from that switch's default case.
func handleBehavioralExtensionCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    if let r = try handleBehavioralBlackholeCommand(command, p) { return r }
    if let r = try handleBehavioralPathCommand(command, p) { return r }
    if let r = try handleBehavioralAnnounceCommand(command, p) { return r }
    if let r = try handleBehavioralTablesCommand(command, p) { return r }
    return nil
}
