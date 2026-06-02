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
2. python's bz2 *max-decompressed-size* bound (`Resource.py:687`,
   `max_length = max_decompressed_size = AUTO_COMPRESS_MAX_SIZE`) is now enforced:
   `ResourceCompression.decompress` / `bz2Decompress` cap the output buffer at
   `AUTO_COMPRESS_MAX_SIZE` (64 MB) and throw `BZ2Error.exceedsMaxDecompressedSize`
   on overflow, so an over-compressible ("bz2 bomb") payload can't exhaust memory
   (`assemble()` passes the advertised size as the buffer hint). **Deferred:** python's
   overflow *response* additionally `reject()`s (RESOURCE_RCL) and tears the link down
   (the CORRUPT branch of `cancel()`, `Resource.py:1081-1084`); the swift overflow throw
   currently takes the ordinary corrupt path (drop + conclude, no reject/teardown — the
   same deferral as the rest of the corrupt-assembly handling above).

### Resource SEGMENTATION — disk-streaming port (perf/resource-disk-streaming 2026-06-02)

**Sites:** `Sources/ReticulumSwift/Resource/Resource.swift` — segmentation
members, outbound segment init, `prepare()` + `resolveSegmentPlaintext()`,
`stageInputFile()`/`openInputHandle()`, `getAdvertisement()`,
`prepareNextSegment()` / `transferInputFileOwnership()` / `adoptInputFile()`,
`assemble()` + `appendToStorage()`/`storageURL()`, `cleanup(abandonChain:)`;
`Sources/ReticulumSwift/Resource/ResourceAdvertisement.swift` —
`create(... originalHash: ...)`; `Sources/ReticulumSwift/Link/Link.swift` —
`handleResourceProof` + `advertiseNextSegment`, `handleResourceData`
segment-aware completion, cancel/reject/close cleanup calls.

**Python reference:** `RNS/Resource.py` `__init__` staging (`:273-314`),
`total_segments`/seek/read (`:285-313`), bytes→tempfile copy (`:274-279`),
metadata prefix (`:266`, prepend `:331-333`), `assemble` (`:672-749`, append to
storagepath `:708-710`, per-segment hash check `:694-695`, metadata strip
`:696-704`, final-segment surface+unlink `:725-747`), `prove` (`:752-763`),
`__prepare_next_segment` (`:765-780`) + its `advertise()` trigger (`:516-518`),
`validate_proof` segment continuation (`:782-821`), `ResourceAdvertisement`
fields (`:1281-1307`, `pack(segment=0)` `:1333-1339`), storagepath naming
(`:199`).

**Behavior (faithful):** data with `metadata_size + len(data) >
MAX_EFFICIENT_SIZE` (1 MiB-1) is staged to a tempfile and split into a chain of
`ceil(total_size / MAX_EFFICIENT_SIZE)` segments, each an independent `Resource`
reading its plaintext chunk via seek/read from the shared input file (segment 1
reads `MAX_EFFICIENT_SIZE - metadata_size`, later segments read
`MAX_EFFICIENT_SIZE` from `first_read_size + (seek_index-1)*MAX_EFFICIENT_SIZE`).
Each segment independently compresses/encrypts/hashes its chunk; the
advertisement carries `i`=segment_index, `l`=total_segments, `o`=first-segment
hash, `d`=total chain plaintext size, `s`/`x` flags. After a segment's proof
validates, the next segment is prepared and advertised (re-keyed in
`outboundResources` by its own hash). Inbound: each segment decrypts, validates
`full_hash(plaintext+random_hash)==hash`, strips the metadata prefix on segment
1, and APPENDS plaintext to a per-resource storagepath; the chain concludes
(delivery + callback + unlink) only when `segment_index == total_segments`.
Data <= MAX_EFFICIENT_SIZE keeps the single in-RAM segment path
(`total_segments=1`, no tempfile) — no behavior change for small resources.

**Deviations (category a — runtime/structural — and the noted new feature):**
1. **Temp-file location.** Python uses `tempfile.TemporaryFile()` for the
   outbound stage (`:277`) and `RNS.Reticulum.resourcepath + "/" +
   original_hash.hex()` for the inbound storagepath (`:199`). This port has no
   `resourcepath`; both live under `NSTemporaryDirectory()` (per-extension
   private, sandbox-valid — already the pattern at `Link.swift:27`). OUTBOUND
   staging is named `rns_resource_out_<uuid>` (a single Resource owns it; the
   resource hash isn't known until after hashing). INBOUND storagepath is named
   `rns_resource_in_<original_hash hex>` — DETERMINISTIC, no uuid, because each
   inbound segment is a fresh `Resource` (one accepted advertisement per
   segment) and they must all `open(...,"ab")`-append to the SAME file; a
   per-instance uuid would break cross-segment append. This matches python's
   hash-keyed storagepath exactly.
2. **Staging deferred to `prepare()`.** Python decides staging in `__init__`
   (`:273-314`). This port defers it to `prepare()` because staging needs the
   part size + metadata size, which the swift port resolves at prepare-time, and
   because the public `Resource(data:link:)` init is non-throwing/sync. Observable
   wire output is identical.
3. **Async next-segment preparation.** Python prepares the next segment on a
   daemon thread (`__prepare_next_segment` via `threading.Thread`, `:517/768`)
   and `validate_proof` busy-waits `while self.next_segment == None`
   (`:811`). This port prepares it in an `async` call inside
   `advertiseNextSegment` (actor-model equivalent); the next segment is never
   advertised before its preparation completes, same as python.
4. **`linkEncryptClosure` capture.** Python segments call
   `self.link.encrypt(...)` directly (`:427`). The swift `Resource` doesn't reach
   into `Link` for the token, so `prepare()` captures the `linkEncrypt` closure
   and threads it to child segments via the segment initializer. No behavioral
   change.
5. **`assembledFileURL` (category b — new feature).** Python surfaces the
   assembled resource as a file handle (`self.data = open(storagepath,"rb")`,
   `:737`). This port preserves the existing in-RAM `assembledData: Data`
   contract (reads the file back) AND adds `assembledFileURL: URL?` as a forward
   hook so callers can stream large assembled resources from disk. NOTE: the URL
   currently points at the storagepath which `cleanup()` unlinks on conclusion —
   callers wanting the on-disk file must copy it out before the resource
   concludes. A future change can defer the unlink when a file-consuming callback
   is registered (mirroring python's `meta_storagepath`/callback split).
6. **Inbound metadata parsed-and-dropped.** Python writes segment-1 metadata to
   `meta_storagepath` and decodes it for the assembled callback (`:700-702`,
   `:727-735`). This port has no metadata-consuming resource API yet, so the
   receive path parses the 3-byte length + metadata bytes off segment 1 (so the
   stored data stream matches python's `data = self.data[3+metadata_size:]`,
   `:704`) but DROPS the metadata rather than persisting a sidecar. Outbound:
   this port's callers attach no metadata (`metadata` stays empty,
   `metadataSize=0`), so `total_size == data_size` and the `x` flag is unset —
   identical wire output to python invoked without metadata. The receive-side
   parsing exists purely for interop with a metadata-bearing python sender.
7. **`cleanup(abandonChain:)` parameter.** Python unlinks the inbound storagepath
   only after the final-segment callback (`:744`). This port adds an
   `abandonChain` flag so abnormal teardown (corrupt segment, cancel, reject,
   link close) unlinks a PARTIAL storagepath unconditionally to avoid leaking it;
   normal per-segment conclusion still unlinks only on the final segment. No
   wire/behavioral divergence — purely a temp-file lifecycle guard.
8. **Per-segment size guard replaces whole-resource size check.** The prior swift
   `assemble()` asserted `finalData.count == originalSize`. With segmentation,
   `originalSize`/`d` is the WHOLE chain plaintext size, not a single segment's,
   so that check is replaced by python's per-segment integrity check
   (`full_hash(plaintext+random_hash)==hash`, `:694-695`) — strictly more
   faithful. The encrypted-side `assembled.count == transferSize` check is
   retained (transferSize is per-segment `t`).

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

### L4 transport memory caps — audited, NOT ported (python-faithful); NE bound deferred to GATE

**Sites:** none changed. Audit covered `Transport/FramedTransport.swift`
(`receiveBuffer`), `Transport/ReticulumTransport.swift` (`pendingPackets`,
`discoveryPathRequests`, `discoveryPrTags`), `Routing/PathTable.swift`, and
`Link/Link.swift` (resource strategy).

**Python reference:** `../Reticulum/RNS/Interfaces/TCPInterface.py:380-398`
(HDLC read loop); `../Reticulum/RNS/Transport.py:121-128` (`path_requests` /
`discovery_path_requests` dicts; `pending_discovery_prs = deque(maxlen=32)`);
`Transport.py:788-799` (expiry culling).

**Finding:** A planned hardening task ("L4") proposed bounding the HDLC
`receiveBuffer`, an LRU cap on the pending-destination count, a hard entry
ceiling on the path table, and a per-link concurrent-resource cap. Checked
against the reference: python bounds NONE of these. The python HDLC read loop
(`TCPInterface.py:382` `frame_buffer += data_in`) appends unconditionally and
only trims when a complete `FLAG…FLAG` frame is found — the `HW_MTU` guard at
`:362` lives in the KISS branch only, which `FramedTransport` (HDLC) does not
mirror. The path table and `discovery_path_requests` are expiry-managed dicts
with no count ceiling. `pending_discovery_prs` (the only count-capped structure,
`deque(maxlen=32)`) is a work queue feeding a python worker thread; the swift
port forwards path requests inline via async with no equivalent handoff queue to
bound. Swift's existing `pendingPackets` per-destination cap (10) and
`discoveryPrTags` cap already match-or-exceed python's bounding.

**Decision (2026-06-02):** add NONE of the proposed caps — each would be a
divergence from a reference that is itself unbounded / expiry-only. This entry
exists so a future re-syncer does NOT "helpfully" re-add them believing they are
missing: they are faithfully absent.

**Deferred NE-hardening note:** the unbounded `receiveBuffer` is a genuine risk
for the memory-constrained iOS Network Extension (~60 MB budget) that python's
desktop reference never faced — a malicious relay streaming an unterminated HDLC
frame could grow it without limit and trigger jetsam. Per owner decision this is
NOT pre-emptively bounded (a speculative divergence); it is revisited at GATE
Phase 1b (under-load NE memory measurement). If the NE actually OOMs on this
path, an `HW_MTU`-style bound is added THEN as a measured, explicitly documented
category-(a) divergence (a runtime constraint the python pattern cannot express
in the NE sandbox), and this entry is updated to record it.
