// Ext+Naming.swift — conformance bridge extension cluster: M-NAMING
//   app_and_aspects_from_name — split a dotted full name into (app_name, [aspects...])
//   auto_discovery_token      — AutoInterface peer-auth token = full_hash(group_id || addr.utf8)
//
// Ports from reticulum-conformance reference/bridge_server.py
// (cmd_app_and_aspects_from_name :2686, cmd_auto_discovery_token :1622).
// Returns nil for any command it does not own (dispatch chain: Ext+Dispatch.swift).
import Foundation
import ReticulumSwift

func handleNamingExtCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // RNS.Destination.app_and_aspects_from_name (Destination.py:131):
    //   components = full_name.split("."); return (components[0], components[1:])
    // The first dotted component is the app name; the rest are aspects.
    // NOTE: use components(separatedBy:) — NOT String.split(separator:) — so that
    // empty components are preserved exactly as python's str.split(".") does
    // (e.g. "a..b" -> ["a", "", "b"]; String.split would drop the empty subseq).
    case "app_and_aspects_from_name":
        let fullName = try getString(p, "full_name")
        let components = fullName.components(separatedBy: ".")
        let appName = components[0]
        let aspects = Array(components.dropFirst())
        return [
            "app_name": str(appName),
            "aspects": .array(aspects.map { str($0) })
        ]

    // RNS.Destination.hash_from_name_and_identity (Destination.py:141):
    //   app_name, aspects = app_and_aspects_from_name(full_name)
    //   return Destination.hash(identity_hash, app_name, *aspects)
    // i.e. truncated_hash(name_hash(app,aspects) || identity_hash) — identical
    // to the `destination_hash` command but taking a dotted full_name + the raw
    // 16-byte identity hash. (This command takes an identity HASH, not a key.)
    case "hash_from_name_and_identity":
        let fullName = try getString(p, "full_name")
        let identityHash = try getHex(p, "identity_hash")
        let components = fullName.components(separatedBy: ".")
        let appName = components[0]
        let aspects = Array(components.dropFirst())
        let nameHash = Hashing.destinationNameHash(appName: appName, aspects: aspects)
        var combined = Data()
        combined.append(nameHash)
        combined.append(identityHash)
        return ["destination_hash": hex(Hashing.truncatedHash(combined))]

    // AutoInterface.discovery_handler peer-auth token (AutoInterface.py:365):
    //   RNS.Identity.full_hash(group_id + ipv6_src.encode("utf-8"))
    // full_hash is SHA-256 (32 bytes). The dedicated library helper
    // AutoInterfaceConstants.discoveryToken computes exactly this (groupId ||
    // addr.utf8 -> Hashing.fullHash), mirroring python's delegation.
    case "auto_discovery_token":
        let groupId = try getHex(p, "group_id")
        let addr = try getString(p, "link_local_addr")
        let token = AutoInterfaceConstants.discoveryToken(groupId: groupId, address: addr)
        return ["token": hex(token)]

    default:
        return nil
    }
}
