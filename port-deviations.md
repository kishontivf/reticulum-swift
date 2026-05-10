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
