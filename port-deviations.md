# reticulum-swift port deviations

All logic in this swift port mirrors `../Reticulum/RNS/` (python reference).
Any deviation from the python reference must be documented here with the
file:line, the python reference site, and the reason.

## Active deviations

### `ReticulumTransport.onInterfacePeerSpawned` / `onInterfaceConnected` (new feature)

**Sites:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` —
`onInterfacePeerSpawned`, `onInterfaceConnected`, and their setters
`setOnInterfacePeerSpawned` / `setOnInterfaceConnected`.

**Python reference:** No equivalent. Python `RNS.Transport` has no app-layer
hook for "an interface was added" or "an interface reached connected." The
upstream pattern is for app code to inspect `RNS.Transport.interfaces`
directly or to register destinations and let the transport layer handle
discovery. Swift needs these hooks because the iOS app (Columba) has
lifecycle-driven UI state and per-interface announce policy that depends
on knowing precisely *when* an interface flips, distinguished by the
*kind* of trigger (peer-spawn on AutoInterface/BLE/MPC vs. state-change
on TCP/RNode/static).

**Reason:** Category (b) — new feature for the swift app surface. The
older single `onInterfaceAdded` callback (now wired as a deprecated shim)
fired from both kinds of trigger indistinguishably; the iOS app needs to
gate them independently behind separate user-facing settings
(`auto_announce_on_peer_spawned` vs `auto_announce_on_tcp_reconnect`).

### `TCPInterface.beginTunnelMode(send:)` / `endTunnelMode()` — VPN-extension hook (new feature)

**Sites:** `Sources/ReticulumSwift/Interfaces/TCPInterface.swift` —
`beginTunnelMode`, `endTunnelMode`, and the matching pair on
`Sources/ReticulumSwift/Interfaces/Auto/AutoInterface.swift`.

**Python reference:** No equivalent. Python's
`RNS.Interfaces.TCPInterface` owns its socket directly with no notion of
an outbound-write hook. The swift port needs this hook because iOS app
extensions (`NEPacketTunnelProvider`) run in a separate process and own
the authoritative network socket while the main app is suspended /
backgrounded. When the extension is active, the main-process
TCPInterface must tear down its own NWConnection and route outbound
bytes through the extension's IPC instead. Python doesn't have an
analogous process-split constraint — its Transport runs in one process
and that process keeps running.

**Reason:** Category (b) — new feature for the iOS port to support
background-mode delivery via Network Extension. No python-side analog
is meaningful.

**Sub-deviation (`endTunnelMode()` idempotency, fix/end-tunnel-mode-idempotent
2026-05-11):** `endTunnelMode()` now early-returns when `outboundHook ==
nil` instead of unconditionally tearing down and re-creating the
transport. The previous unconditional path was destructive when called
on an interface that was never in tunnel mode (e.g. the iOS VPN status
machinery emits a `.invalid` notification on every cold start regardless
of whether the user has enabled the tunnel; the downstream caller —
Columba-iOS `AppServices.applyTunnelModeToInterfaces` — would observe
this `.invalid` and fire `endTunnelMode()` on every TCPInterface,
killing every live NWConnection seconds after the Step 7 loop brought
them up). The downstream `isTunnelModeActive` workaround in Columba-iOS
exists specifically because this method wasn't idempotent; pinning the
contract here is the correct fix and lets the workaround be deleted on
the next Columba-iOS deps bump.

### Resource corrupt-assembly handling — `.failed` mapping + deferred bz2-overflow teardown (fix/resource-completion-cleanup 2026-06-02)

**Sites:** `Sources/ReticulumSwift/Link/Link.swift` — `handleResourceData`
assembly catch + `close()` resource teardown; `Sources/ReticulumSwift/Resource/Resource.swift`
— `cleanup()`.

**Python reference:** `RNS/Resource.py` `assemble()` (`:672-749`) + `cancel()`
(`:1071-1104`); `RNS/Link.py` `link_closed()` (`:724-726`).

**Behavior (faithful):** an inbound assembly that hits a hash-mismatch (`:715`),
decrypt error, or any exception (`:721`) leaves the resource non-COMPLETE and falls
through to `link.resource_concluded(self)` (`:723`) — the swift port drops it from
`inboundResources` and fires `resourceConcluded` (which the LXMF handler ignores for a
non-`.complete` resource, matching `LXMRouter.py:1878`). No packet is sent and the link
is NOT torn down. `Link.close()` cancels in-flight resources (mirrors `link_closed`
`:724-726`) without emitting `RESOURCE_ICL`, because the link is no longer ACTIVE
(`Resource.py:1088-1092` gates the cancel packet on `link.status == ACTIVE`). The prior
swift `catch` only logged, leaking the resource in `.assembling` with the callback never
fired — that leak is what this fixes.

**Two structural notes (not behavioral divergences from the common corrupt path):**
1. `ResourceState` has no `CORRUPT` case (pre-existing); the corrupt-assembly path maps
   to the terminal `.failed`. Observably identical: non-COMPLETE ⇒ not delivered,
   concluded, removed.
2. **Deferred:** python's bz2 *max-decompressed-size overflow* sub-path
   (`Resource.py:688-692`) sets CORRUPT and calls `cancel()` → `reject()` (RESOURCE_RCL)
   + `link.teardown()`. The swift `ResourceCompression.decompress` does not enforce /
   surface a max-decompressed-size, so that decompression-bomb guard is not yet ported;
   such input currently takes the ordinary corrupt path (drop + conclude, no teardown).
   Tracked with the transport memory-caps work (decompression-bomb / max-size guard).

## Resolved deviations

### `ReticulumTransport.sendLinkData` — incorrectly converted link DATA to HEADER_2 (resolved 2026-05-10)

**Site:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` —
`sendLinkData(packet:)` (was `sendLinkData(packet:destinationHash:)`
prior to this fix; the `destinationHash` parameter was the input the
buggy path-table lookup consumed and was dropped to prevent
regressions).

**Python reference:** `RNS/Transport.py:1034-1130` — `Transport.outbound`.
The path-table lookup at `:1063` keys on `packet.destination_hash`. For
link DATA packets, `destination_hash == link_id`, and link_ids are
NEVER inserted into `Transport.path_table`. The lookup therefore always
misses, and execution falls through to the broadcast loop at `:1122`.
The LINK destination guard at `:1128-1130` (`if interface !=
packet.destination.attached_interface: should_transmit = False`) then
restricts transmission to the link's `attached_interface` only, as
HEADER_1.

**Bug:** the prior swift implementation looked up the path by the
peer's destination hash (passed as a separate `destinationHash`
parameter, since the packet's destination is `linkId` for links) and
performed HEADER_2 conversion when `hopCount > 1`. This produced
HEADER_2 packets with `destination_hash = linkId`, which downstream
transport nodes (rnsd) interpret as transport-routed packets but
cannot route — link_ids aren't routable destinations — and silently
drop. Symptom on iOS smoke pipeline `direct_echo`: phone hits
`state=SENT`, rnsd validates the LRPROOF, link DATA disappears
without forwarding, echo bot's `on_delivery` never fires.

**Fix:** `sendLinkData` now sends the unmodified HEADER_1 packet to
the link's `attachedInterfaceId` (set during `handleLinkProof` /
`handleLinkRequest`). The `destinationHash` parameter was removed;
the public signature is now `sendLinkData(packet:)`. Any caller
using the old `sendLinkData(packet:destinationHash:)` form will
get a compile error and must be updated.
Mirrors python `Transport.outbound:1122-1130`.

**Why this needs a deviation entry even though it's a fix:** The
prior buggy implementation was itself an undocumented divergence
(the python upstream has no path-table lookup for link DATA). This
entry records the bug for future re-syncers and codifies the
correct semantic so the divergence doesn't reappear.
