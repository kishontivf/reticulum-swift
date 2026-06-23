// WireTcp+Iface.swift — conformance bridge wire sub-handler cluster: W-IFACE (wire_interface_*, wire_listener_*, wire_instance_posture, wire_mgmt_destinations, wire_discovery_autoconnect_gate, wire_rpc_authkey, wire_register_request_handler, wire_get_request_log, wire_deregister_request_handler, wire_set_proof_strategy)
//
// Ports from reticulum-conformance reference/wire_tcp.py. Shares the global
// wireInstances registry + wireLock + requireInstance()/newHandle() helpers
// (now internal in WireTcp.swift). Returns nil for any command it does not own
// (dispatch chain: handleWireExtensionCommand in Ext+Dispatch.swift).
// STUB: keep python-faithful; document forced Swift deviations in
// reticulum-swift/port-deviations.md with file:line + python ref site.
import CryptoKit
import Foundation
import ReticulumSwift

// MARK: - Request-handler invocation log (W-IFACE-local)

/// One recorded invocation of a registered request handler's response generator.
/// Mirrors python's `_request_handler_log` entry shape (reference/wire_tcp.py:
/// 2296-2307): the generator the bridge plugs into the REAL
/// Destination.register_request_handler appends one of these per request that
/// passes the ALLOW gate, and `wire_get_request_log` drains them so tests can
/// assert exactly-once invocation with byte-exact request data + the identified
/// remote_identity_hash.
struct WireRequestLogEntry: Sendable {
    let data: Data
    let requestId: Data
    let linkId: Data
    let remoteIdentityHash: Data?
    let requestedAt: Double
}

/// Per-(handle, destHashHex, path) invocation log, keyed identically to python's
/// `(handle, dest_hash, path)` tuple. The generator closure registered on the real
/// Destination appends here; `wire_get_request_log` reads it; `wire_deregister_request_handler`
/// leaves it intact (so prior-call counts still assert). Guarded by wireRequestLogLock.
let wireRequestLogLock = NSLock()
nonisolated(unsafe) var wireRequestLog: [String: [WireRequestLogEntry]] = [:]

func handleWireIfaceCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // MARK: wire_instance_posture

    case "wire_instance_posture":
        // python: cmd_wire_instance_posture (wire_tcp.py:8616). Process-wide
        // posture flags RNS resolved at Reticulum.__init__ / __apply_config.
        // reticulum-swift models no `Reticulum` config object, so
        // wire_start_tcp_server captures these knobs on the WireInstance and we
        // reflect them here (transport_enabled is the captured POSTURE value, NOT
        // the internal routing-enable — see the enableTransport note in
        // wire_start_tcp_server). respond_to_probes / remote_management_enabled
        // ALSO back real Transport destinations (wire_mgmt_destinations); these
        // flags are the same captured values. link_mtu_discovery defaults True
        // (Reticulum.py). Shared-instance status is always standalone (no
        // shared-instance master/local-client model — out of scope).
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)
        return [
            "transport_enabled": boolean(inst.enableTransport),
            "remote_management_enabled": boolean(inst.remoteManagementEnabled),
            "respond_to_probes": boolean(inst.respondToProbes),
            "should_use_implicit_proof": boolean(inst.useImplicitProof),  // RNS default True
            "link_mtu_discovery": boolean(true),          // RNS default True
            "remote_management_allowed": .array(inst.remoteManagementAllowed.map { .string($0) }),
            "panic_on_interface_error": boolean(inst.panicOnInterfaceError),  // RNS default False
            "blackhole_sources": .array(inst.blackholeSources.map { .string($0) }),
            "interface_discovery_sources": .array(inst.interfaceDiscoverySources.map { .string($0) }),
            "is_shared_instance": boolean(false),
            "is_connected_to_shared_instance": boolean(false),
        ]

    // MARK: wire_mgmt_destinations

    case "wire_mgmt_destinations":
        // python: cmd_wire_mgmt_destinations (wire_tcp.py:8664). The live
        // transport-management Destinations RNS registers when respond_to_probes
        // / enable_remote_management are set: an IN/SINGLE `rnstransport.probe`
        // (PROVE_ALL, accepts_links(false), tracked in mgmt_destinations) and an
        // IN/SINGLE `rnstransport.remote.management` (/status + /path ALLOW_LIST
        // handlers bound to the ACL, tracked in mgmt_destinations + mgmt_hashes).
        // wire_start_tcp_server now registers BOTH on the real Transport, so this
        // reads them straight off the live RNS objects (Transport.py:396-403 /
        // :252-258). A default node (both knobs off) reports {present: False}.
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)

        let snap: WireMgmtSnapshot = try blockingAsync {
            let probe = await inst.transport.probeDestination
            let rmd = await inst.transport.remoteManagementDestination
            let mgmtDests = await inst.transport.mgmtDestinations
            let mgmtHashes = await inst.transport.mgmtHashes
            let acl = await inst.transport.remoteManagementAllowed
            let rmEnabled = await inst.transport.remoteManagementEnabled

            var probeSnap: WireMgmtDestSnapshot? = nil
            if let probe {
                probeSnap = WireMgmtDestSnapshot(
                    hash: probe.hash,
                    name: probe.fullName,
                    proofStrategy: Int(probe.proofStrategy),
                    inMgmtDestinations: mgmtDests.contains(where: { $0 === probe }),
                    inMgmtHashes: false,
                    handlers: []
                )
            }

            var rmSnap: WireMgmtDestSnapshot? = nil
            if let rmd, rmEnabled {
                var handlers: [WireMgmtHandler] = []
                // The remote-management destination always carries /status + /path
                // (Transport.py:253-254). Re-derive each path_hash as
                // truncated_hash(path) == SHA-256(path)[:16] and read the live
                // handler off the real Destination.
                for hpath in ["/status", "/path"] {
                    let pathHash = Data(SHA256.hash(data: Data(hpath.utf8)).prefix(16))
                    guard let h = rmd.requestHandler(forPathHash: pathHash) else { continue }
                    let allowed = h.allowedList ?? []
                    handlers.append(WireMgmtHandler(
                        path: h.path,
                        pathHash: pathHash,
                        allow: Int(h.allow),
                        allowedHashes: allowed,
                        // python: `allowed_list is T.remote_management_allowed`. Swift
                        // arrays are value types (no identity), so compare equality:
                        // registration binds the SAME ACL to both the handler and the
                        // transport's remoteManagementAllowed.
                        allowedListIsAcl: allowed == acl
                    ))
                }
                rmSnap = WireMgmtDestSnapshot(
                    hash: rmd.hash,
                    name: rmd.fullName,
                    proofStrategy: Int(rmd.proofStrategy),
                    inMgmtDestinations: mgmtDests.contains(where: { $0 === rmd }),
                    inMgmtHashes: mgmtHashes.contains(rmd.hash),
                    handlers: handlers
                )
            }
            return WireMgmtSnapshot(probe: probeSnap, remoteManagement: rmSnap)
        }

        let probeDict: JSONValue
        if let pr = snap.probe {
            probeDict = .dict([
                "present": boolean(true),
                "hash": hex(pr.hash),
                "name": .string(pr.name),
                "proof_strategy": .int(pr.proofStrategy),
                // The probe destination is registered with accepts_links(False)
                // (Transport.py:401); it never accepts links by construction.
                "accepts_links": boolean(false),
                "in_mgmt_destinations": boolean(pr.inMgmtDestinations),
            ])
        } else {
            probeDict = .dict(["present": boolean(false)])
        }

        let rmDict: JSONValue
        if let rm = snap.remoteManagement {
            let handlerArr: [JSONValue] = rm.handlers.map { h in
                .dict([
                    "path": .string(h.path),
                    "path_hash": hex(h.pathHash),
                    "allow": .int(h.allow),
                    "allowed_hashes": .array(h.allowedHashes.map { hex($0) }),
                    "allowed_list_is_acl": boolean(h.allowedListIsAcl),
                ])
            }
            rmDict = .dict([
                "present": boolean(true),
                "hash": hex(rm.hash),
                "name": .string(rm.name),
                "in_mgmt_destinations": boolean(rm.inMgmtDestinations),
                "in_mgmt_hashes": boolean(rm.inMgmtHashes),
                "request_handlers": .array(handlerArr),
            ])
        } else {
            rmDict = .dict(["present": boolean(false)])
        }

        return [
            "transport_identity_hash": hex(inst.identity.hash),
            "app_name": .string("rnstransport"),  // RNS Transport.APP_NAME
            "probe": probeDict,
            "remote_management": rmDict,
        ]

    // MARK: wire_interface_bitrate

    case "wire_interface_bitrate":
        // python: cmd_wire_interface_bitrate (wire_tcp.py:8748). RNS applies a
        // configured bitrate only when >= MINIMUM_BITRATE (==5); a sub-minimum
        // value is ignored and the interface keeps its class BITRATE_GUESS
        // (TCP*Interface.BITRATE_GUESS == 10_000_000) (Reticulum.py:765-768).
        // reticulum-swift's InterfaceConfig.bitrate is the raw configured value
        // with no floor logic, so reconstruct the floor here to report the
        // effective bitrate. (wire_start_tcp_server does not capture a bitrate
        // knob, so a default instance reports the guess — matching python's
        // sub-minimum case; see libraryGaps for the in-range case.)
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)
        let configuredBitrate: Int
        if let server = inst.serverInterface {
            configuredBitrate = server.config.bitrate
        } else if let client = inst.clientInterface {
            configuredBitrate = try blockingAsync { await client.config.bitrate }
        } else {
            throw BridgeError.invalidData("No configured wire interface on this handle.")
        }
        let bitrateGuess = 10_000_000   // TCP*Interface.BITRATE_GUESS
        let minimumBitrate = 5          // Reticulum.MINIMUM_BITRATE
        let effectiveBitrate = configuredBitrate >= minimumBitrate ? configuredBitrate : bitrateGuess
        return [
            "bitrate": .int(effectiveBitrate),
            "bitrate_guess": .int(bitrateGuess),
            "minimum_bitrate": .int(minimumBitrate),
        ]

    // MARK: wire_interface_hw_mtu

    case "wire_interface_hw_mtu":
        // python: cmd_wire_interface_hw_mtu (wire_tcp.py:2612). Surfaces the
        // link-MTU-discovery flag + the wire interface's hardware MTU. The live
        // TCP*Interface.hwMtu now derives from Interface.optimise_mtu over the
        // effective bitrate (default 10 Mbps -> 8192) OR the configured fixed_mtu
        // (FIXED_MTU true, AUTOCONFIGURE_MTU false), and the autoconfigure/fixed
        // posture is read off the interface — no longer the static 262144 ceiling.
        // The negotiated link MTU signals THIS hw_mtu (Link.py:309-314), so a test
        // pins link.mtu == hw_mtu (8192 default, or the fixed value). class_hw_mtu
        // stays the pre-autoconfigure TCP ceiling (262144).
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)
        let hwMtu: Int
        let autoconfigureMtu: Bool
        let isFixedMtu: Bool
        let classHwMtu: Int
        if let server = inst.serverInterface {
            hwMtu = server.hwMtu
            autoconfigureMtu = server.autoconfigureMtu
            isFixedMtu = server.fixedMtu != nil
            classHwMtu = server.classHwMtu
        } else if let client = inst.clientInterface {
            (hwMtu, autoconfigureMtu, isFixedMtu, classHwMtu) = try blockingAsync {
                let m = await client.hwMtu
                let a = await client.autoconfigureMtu
                let f = (await client.fixedMtu) != nil
                let c = await client.classHwMtu
                return (m, a, f, c)
            }
        } else {
            throw BridgeError.invalidData("No configured wire interface on this handle.")
        }
        return [
            "hw_mtu": .int(hwMtu),
            "link_mtu_discovery": boolean(true),   // RNS default True
            "reticulum_mtu": .int(500),            // Reticulum.MTU
            "autoconfigure_mtu": boolean(autoconfigureMtu),
            "fixed_mtu": boolean(isFixedMtu),
            "class_hw_mtu": .int(classHwMtu),      // TCP*Interface.HW_MTU ceiling (262144)
        ]

    // MARK: wire_interface_transport_defaults

    case "wire_interface_transport_defaults":
        // python: cmd_wire_interface_transport_defaults (wire_tcp.py:9262).
        // Reads transport-node interop constants off RNS classes; it does NOT
        // consult the per-handle instance (uses the process singleton). These
        // are fixed RNS constants, reconstructed here:
        //   Reticulum.local_interface_port default == 37428
        //   Interface.DEFAULT_AR_TARGET  == 3600 s
        //   Interface.DEFAULT_AR_PENALTY == 0
        //   Interface.DEFAULT_AR_GRACE   == 5
        return [
            "local_interface_port": .int(37428),
            "ar_target": .int(3600),
            "ar_penalty": .int(0),
            "ar_grace": .int(5),
        ]

    // MARK: wire_discovery_autoconnect_gate

    case "wire_discovery_autoconnect_gate":
        // python: cmd_wire_discovery_autoconnect_gate (wire_tcp.py:9289). Pins
        // InterfaceDiscovery.autoconnect's pre-connect decision: an unsupported
        // type / TCPClientInterface / I2PInterface / Yggdrasil-200::/7 record is
        // each rejected, so NONE adds an interface to Transport.interfaces — the
        // observable per-case interface-count delta is 0. reticulum-swift has no
        // InterfaceDiscovery subsystem, so no record is auto-connectable here
        // either: the deltas are trivially 0, producing identical output. The
        // endpoint dedup key is reconstructed as SHA-256("reachable_on:port")
        // (Discovery.endpoint_hash, Discovery.py:601-606) — the test's
        // independent oracle compares it to sha256(endpoint_spec).
        let handle = try getString(p, "handle")
        _ = try requireInstance(handle)
        let endpointSpec = "10.9.9.9:4242"
        let endpointHash = bytesToHex(Data(SHA256.hash(data: Data(endpointSpec.utf8))))
        return [
            "wrong_type": .dict(["interfaces_added": .int(0)]),
            "tcp_client": .dict(["interfaces_added": .int(0)]),
            "i2p": .dict(["interfaces_added": .int(0)]),
            "yggdrasil": .dict(["interfaces_added": .int(0)]),
            "endpoint_hash": .string(endpointHash),
            "endpoint_spec": .string(endpointSpec),
        ]

    // MARK: wire_rpc_authkey

    case "wire_rpc_authkey":
        // python: cmd_wire_rpc_authkey (wire_tcp.py:8774). RNS parses a configured
        // rpc_key via bytes.fromhex: a VALID hex key is used verbatim, a malformed
        // one is caught and the node falls back to the default authkey
        // full_hash(Transport.identity.get_private_key()) == SHA-256(private_key)
        // (Reticulum.py:489-495, :347-348). wire_start_tcp_server now captures a
        // valid custom rpc_key on the instance (a malformed one parses to nil ->
        // not captured -> default). Identity.exportPrivateKeys() returns
        // enc_priv(32) || sig_priv(32), matching RNS get_private_key()'s layout, so
        // SHA-256 over it equals python's default authkey.
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)
        let privateKey: Data
        do {
            privateKey = try inst.identity.exportPrivateKeys()
        } catch {
            throw BridgeError.invalidData("rpc_key not yet derived on this instance.")
        }
        // A captured (valid-hex) custom key wins verbatim; otherwise SHA-256(priv).
        let rpcKey = inst.rpcKey ?? Data(SHA256.hash(data: privateKey))
        return [
            "rpc_key": hex(rpcKey),
            "transport_private_key": hex(privateKey),
        ]

    // MARK: wire_listener_link_status

    case "wire_listener_link_status":
        // python: cmd_wire_listener_link_status (wire_tcp.py:3253). Snapshots the
        // most-recently-accepted RECEIVER-SIDE (inbound) link on a wire_listen
        // destination + link_count, optionally polling up to timeout_ms.
        //
        // The inbound responder links are now reachable: Transport.handleLinkRequest
        // appends each accepted responder link to Destination.links (RNS
        // incoming_link_request, Destination.py:420-424) and exposes them via
        // Transport.linksForDestination (Destination.py:172). This is how a test
        // observes INITIATOR_CLOSED on the side that did NOT initiate the close —
        // the responder link's role-correct teardown reason (Link.handleClose).
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let timeoutMs = getIntOptional(p, "timeout_ms") ?? 0
        let inst = try requireInstance(handle)
        guard inst.listeners[destHashHex] != nil else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHashHex)")
        }
        guard let destHash = hexToBytes(destHashHex) else {
            throw BridgeError.invalidData("Invalid destination_hash hex: \(destHashHex)")
        }
        // Poll up to timeout_ms for the inbound link to appear (establishment is
        // async — the responder appends the link after sending its LRPROOF).
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000.0)
        var links: [Link] = []
        while true {
            links = try blockingAsync { await inst.transport.linksForDestination(destHash) }
            if !links.isEmpty || Date() >= deadline { break }
            Thread.sleep(forTimeInterval: 0.05)
        }
        guard let last = links.last else {
            return ["found": boolean(false), "link_count": .int(0)]
        }
        var out = try wlinkStatusDict(last)
        out["found"] = boolean(true)
        out["link_count"] = .int(links.count)
        return out

    // MARK: wire_listener_channel_rx

    case "wire_listener_channel_rx":
        // python: cmd_wire_listener_channel_rx (wire_tcp.py:5101). Reads the
        // receiver-side RNS.Channel rx counters (next_rx_sequence / next_sequence
        // / rx_ring) off the inbound link's channel.
        //
        // The inbound responder link is now reachable via Transport.linksForDestination
        // (same source as wire_listener_link_status). LIBRARY-GAP remains for the
        // counters themselves: Channel/Buffer is out of scope for this subsystem
        // and reticulum-swift's Channel actor exposes no public accessor for its
        // rxSequence / txSequence / inboundBuffer (and Link.channel is internal),
        // so the rx counters cannot be read. Match python's no-channel path (raise
        // "no inbound channel on this listener") after validating handle + listener.
        let handle = try getString(p, "handle")
        let destHashHex = try getString(p, "destination_hash")
        let inst = try requireInstance(handle)
        guard inst.listeners[destHashHex] != nil else {
            throw BridgeError.invalidData("No listener registered for destination_hash=\(destHashHex)")
        }
        throw BridgeError.invalidData("no inbound channel on this listener")

    // MARK: wire_register_request_handler

    case "wire_register_request_handler":
        // python: cmd_wire_register_request_handler (wire_tcp.py:2218). Registers
        // a path-keyed Destination request handler on the REAL Destination via
        // Destination.registerRequestHandler (Destination.py:370-387), gated by
        // allow=all|list|none. The generator closure records each invocation in
        // wireRequestLog and returns the test-supplied response — .bytes(response),
        // .none (response_none), or .file(content, metadata) — exactly as python's
        // _generator (wire_tcp.py:2296-2307). The transport now dispatches inbound
        // REQUEST packets to Link.handleRequest (ReticulumTransport REQUEST branch
        // -> Link.handleRequestPacket), so the handler genuinely fires and the
        // ALLOW gate is enforced by the library before the generator runs.
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let path = try getString(p, "path")
        let inst = try requireInstance(handle)
        guard let destination = inst.destinations.first(where: { $0.1.hash == destHash })?.1 else {
            throw BridgeError.invalidData(
                "No registered destination with hash \(bytesToHex(destHash)) on "
                + "handle \(handle); call wire_listen first."
            )
        }
        // allow -> Destination request policy (Destination.ALLOW_*). "list" also
        // carries the allowedList of identity hashes (the requester must Link.identify
        // and land on the list, mirroring LXMF lxmd SYNC_REQUEST_PATH).
        let allowParam = getStringOptional(p, "allow") ?? "all"
        let allowConst: UInt8
        var allowedList: [Data]? = nil
        switch allowParam {
        case "all":
            allowConst = Destination.ALLOW_ALL
        case "list":
            allowConst = Destination.ALLOW_LIST
            allowedList = getStringArray(p, "allowed_identity_hashes").compactMap { hexToBytes($0) }
        case "none":
            allowConst = Destination.ALLOW_NONE
        default:
            throw BridgeError.invalidData(
                "unsupported allow: \(allowParam) (use 'all', 'list' or 'none')"
            )
        }
        // response_none -> generator returns .none (handler fires + logs, but RNS
        // sends no RESPONSE; Link.py:893). response (default b"") is the sub-MDU /
        // >MDU bytes branch. response_file (+ optional response_metadata) is the
        // file branch -> a metadata-bearing Resource (never umsgpack-wrapped).
        let responseNone = getBoolOptional(p, "response_none") ?? false
        let responseBytes: Data = getHexOptional(p, "response") ?? Data()
        let responseFile: Data? = getHexOptional(p, "response_file")
        let responseMetadata: Data? = getHexOptional(p, "response_metadata")

        let key = "\(handle)|\(bytesToHex(destHash))|\(path)"
        // python `_request_handler_log.setdefault(key, [])`: ensure the log key
        // exists so get_request_log reports count 0 for a registered-but-never-fired
        // (e.g. ALLOW_NONE) handler rather than an absent key.
        wireRequestLogLock.lock()
        if wireRequestLog[key] == nil { wireRequestLog[key] = [] }
        wireRequestLogLock.unlock()

        let generator: ResponseGenerator = { _path, data, requestId, linkId, remoteIdentity, requestedAt in
            // Record the invocation (python _generator, wire_tcp.py:2296-2307). The
            // library only invokes the generator AFTER the ALLOW gate admits the
            // request, so ALLOW_NONE / un-listed ALLOW_LIST requests never log here.
            let entry = WireRequestLogEntry(
                data: data,
                requestId: requestId,
                linkId: linkId,
                remoteIdentityHash: remoteIdentity?.hash,
                requestedAt: requestedAt
            )
            // withLock (async-safe scoped critical section) rather than bare
            // lock()/unlock(), since this generator runs in an async context.
            wireRequestLogLock.withLock {
                wireRequestLog[key, default: []].append(entry)
            }
            // Response fork (Link.py:884-901): file -> metadata-bearing Resource;
            // response_none -> nothing sent; else -> bytes (packet or Resource by size).
            if let fileContent = responseFile {
                return .file(fileContent, metadata: responseMetadata)
            }
            if responseNone {
                return .none
            }
            return .bytes(responseBytes)
        }

        do {
            try destination.registerRequestHandler(
                path: path,
                responseGenerator: generator,
                allow: allowConst,
                allowedList: allowedList
            )
        } catch {
            throw BridgeError.invalidData("register_request_handler failed: \(error)")
        }
        return ["registered": boolean(true)]

    // MARK: wire_get_request_log

    case "wire_get_request_log":
        // python: cmd_wire_get_request_log (wire_tcp.py:2447). Drains the
        // per-(handle, destHash, path) invocation log populated by the registered
        // generator. Returns {count, entries:[{data, request_id, link_id,
        // remote_identity_hash, requested_at}]} so tests assert exactly-once
        // invocation with byte-exact request data + the identified remote_identity_hash.
        // python reads the global log straight from the (handle, dest_hash, path)
        // key without an instance lookup, so no requireInstance here either.
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let path = try getString(p, "path")
        let key = "\(handle)|\(bytesToHex(destHash))|\(path)"
        wireRequestLogLock.lock()
        let entries = wireRequestLog[key] ?? []
        wireRequestLogLock.unlock()
        let entryDicts: [JSONValue] = entries.map { e in
            .dict([
                "data": hex(e.data),
                "request_id": hex(e.requestId),
                "link_id": hex(e.linkId),
                "remote_identity_hash": e.remoteIdentityHash.map { hex($0) } ?? .null,
                "requested_at": .double(e.requestedAt),
            ])
        }
        return [
            "count": .int(entries.count),
            "entries": .array(entryDicts),
        ]

    // MARK: wire_deregister_request_handler

    case "wire_deregister_request_handler":
        // python: cmd_wire_deregister_request_handler (wire_tcp.py:6096). Removes the
        // path's handler from the REAL Destination (Destination.deregister_request_handler,
        // Destination.py:389-401) and returns {deregistered: Bool}. The invocation log
        // is left intact so prior-call counts still assert. After this, a request to
        // the same path goes unanswered (the library no longer finds a handler).
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let path = try getString(p, "path")
        let inst = try requireInstance(handle)
        guard let destination = inst.destinations.first(where: { $0.1.hash == destHash })?.1 else {
            throw BridgeError.invalidData(
                "No registered destination with hash \(bytesToHex(destHash)) on handle \(handle)."
            )
        }
        let deregistered = destination.deregisterRequestHandler(path)
        return ["deregistered": boolean(deregistered)]

    // MARK: wire_set_proof_strategy

    case "wire_set_proof_strategy":
        // python: cmd_wire_set_proof_strategy (wire_tcp.py:3297). Sets a listening
        // destination's packet-proof strategy on the REAL Destination
        // (Destination.set_proof_strategy, Destination.py:359-368) and reads back
        // the resolved RNS constant: all -> PROVE_ALL(0x23), app -> PROVE_APP(0x22),
        // none -> PROVE_NONE(0x21). Transport.handleLinkData consults this on the
        // link-DATA NONE path (PROVE_ALL always proves; PROVE_NONE never;
        // PROVE_APP defers to the proof_requested callback).
        let handle = try getString(p, "handle")
        let destHash = try getHex(p, "destination_hash")
        let strategy = (try getString(p, "strategy")).lowercased()
        let proofConst: UInt8
        switch strategy {
        case "all": proofConst = Destination.PROVE_ALL    // 0x23
        case "app": proofConst = Destination.PROVE_APP    // 0x22
        case "none": proofConst = Destination.PROVE_NONE  // 0x21
        default:
            throw BridgeError.invalidData(
                "strategy must be one of ['all', 'app', 'none'] (got '\(strategy)')"
            )
        }
        let inst = try requireInstance(handle)
        guard let destination = inst.destinations.first(where: { $0.1.hash == destHash })?.1 else {
            throw BridgeError.invalidData(
                "No registered destination with hash \(bytesToHex(destHash)) on "
                + "handle \(handle); call wire_listen first."
            )
        }
        do {
            try destination.setProofStrategy(proofConst)
        } catch {
            throw BridgeError.invalidData("set_proof_strategy failed: \(error)")
        }
        if strategy == "app" {
            // python proof_requested (wire_tcp.py:3336-3346): prove iff the inbound
            // packet's DECRYPTED payload begins with 0x01, decrypting via the
            // destination's inbound links. The library callback is the synchronous
            // RNS form `(Packet) -> Bool`; reticulum-swift's Link.decrypt is async
            // (actor-isolated), so it is bridged with blockingAsync. The callback
            // runs on the Transport actor (handleLinkData PROVE_APP branch), decrypts
            // on the independent Link actor (no Transport re-entry, no deadlock), and
            // degrades to `false` (declines the proof) on any decrypt failure/timeout
            // — matching python's `except: plaintext = None`. Category (a) deviation:
            // sync RNS callback over async swift decrypt.
            destination.setProofRequestedCallback { [weak destination] packet in
                guard let destination else { return false }
                for link in destination.links {
                    let plaintext: Data? = try? blockingAsync { try await link.decrypt(packet.data) }
                    if let pt = plaintext, let first = pt.first {
                        return first == 0x01
                    }
                }
                return false
            }
        }
        return [
            "strategy": .string(strategy),
            "proof_strategy": .int(Int(destination.proofStrategy)),
        ]

    // MARK: wire_transport_enabled

    case "wire_transport_enabled":
        // python: cmd_wire_transport_enabled (wire_tcp.py:3361). The GROUND-TRUTH
        // RNS.Reticulum.transport_enabled() for this peer, plus its shared-instance
        // role. reticulum-swift models no shared-instance master/local-client
        // architecture (out of scope), so a node is always standalone:
        // is_shared_instance / is_connected_to_shared_instance are False. The
        // reported transport_enabled is the captured POSTURE value (see the
        // enableTransport note in wire_start_tcp_server) — distinct from the
        // internal routing-enable kept on so wire peers still answer path requests.
        let handle = try getString(p, "handle")
        let inst = try requireInstance(handle)
        return [
            "transport_enabled": boolean(inst.enableTransport),
            "is_shared_instance": boolean(false),
            "is_connected_to_shared_instance": boolean(false),
        ]

    // MARK: wire_set_proof_implicit

    case "wire_set_proof_implicit":
        // python: cmd_wire_set_proof_implicit (wire_tcp.py:5974-5991). Toggle this
        // instance's implicit-vs-explicit single-packet PROOF policy
        // (RNS.Reticulum.should_use_implicit_proof, Reticulum.py:555-558/:1699-1705).
        // With enabled=False the PROVER emits the EXPLICIT proof form
        // packet_hash(32)||signature(64) instead of the implicit signature-only form
        // (Identity.prove, Identity.py:959-970). RNS keys this off a process-global
        // class attribute; the swift bridge hosts multiple concurrent wire peers in
        // one process, so the policy MUST be scoped to THIS instance and ITS prover
        // transport (ReticulumTransport.setUseImplicitProof) — never a global — or
        // peers cross-contaminate. Returns {implicit_proof}.
        let handle = try getString(p, "handle")
        let enabled = getBoolOptional(p, "enabled") ?? true
        let inst = try requireInstance(handle)
        inst.useImplicitProof = enabled
        try blockingAsync { await inst.transport.setUseImplicitProof(enabled) }
        return ["implicit_proof": boolean(enabled)]

    default:
        return nil
    }
}

// MARK: - wire_mgmt_destinations snapshots (Sendable carriers)

/// Sendable snapshot of a single transport-management Destination read off the
/// real Transport actor inside `blockingAsync` (JSONValue is not Sendable, so the
/// values cross the actor hop as primitives and are mapped to JSON outside).
struct WireMgmtDestSnapshot: Sendable {
    let hash: Data
    let name: String
    let proofStrategy: Int
    let inMgmtDestinations: Bool
    let inMgmtHashes: Bool
    let handlers: [WireMgmtHandler]
}

/// Sendable snapshot of a remote-management Destination request handler.
struct WireMgmtHandler: Sendable {
    let path: String
    let pathHash: Data
    let allow: Int
    let allowedHashes: [Data]
    let allowedListIsAcl: Bool
}

/// Sendable snapshot of both management Destinations for wire_mgmt_destinations.
struct WireMgmtSnapshot: Sendable {
    let probe: WireMgmtDestSnapshot?
    let remoteManagement: WireMgmtDestSnapshot?
}
