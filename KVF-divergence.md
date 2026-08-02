# KVF divergence from upstream `reticulum-swift`

Divergence of `kishontivf/reticulum-swift` (`origin/master`) from `torlando-tech/reticulum-swift`
(`upstream/main`).

| | |
|---|---|
| Fork HEAD | `36b9d20` — *Crash fix* |
| Upstream base | `52e2a9a` — *Merge pull request #25 from torlando-tech/feat/rnode-ble-uuid-identity* |
| Relationship | **Fast-forward ahead.** 16 commits ahead, **0 behind** — the fork contains all of `upstream/main`, no upstream work is missing and no divergent history exists |
| Net diff | 14 files changed, 1021 insertions(+), 46 deletions(-) |
| Date range | 2026-05-30 → 2026-07-14 |

Reproduce with:

```sh
git fetch upstream
git rev-list --left-right --count upstream/main...HEAD   # → 0  16
git diff 52e2a9a..HEAD
```

## Contents

1. [Divergence at a glance](#1-divergence-at-a-glance)
2. [Schema & domain changes](#2-schema--domain-changes) ← every change that introduced domain or storage state
3. [Implementation-logic changes](#3-implementation-logic-changes)
4. [Commit index](#4-commit-index)
5. [Wire-protocol & interop impact](#5-wire-protocol--interop-impact)
6. [Risks and open items](#6-risks-and-open-items)

---

## 1. Divergence at a glance

| File | ± | Theme |
|---|---|---|
| `Sources/ReticulumSwift/Routing/PathTable.swift` | +272 | Fallback-interface routing model (new domain state) |
| `Sources/ReticulumSwift/Interfaces/MPC/MPCInterface.swift` | +139/−10 | Deterministic invite direction, reconnect, half-open session healing |
| `Sources/ReticulumSwift/Logging/NetworkLog.swift` | +135 (new file) | New opt-in routing diagnostic log |
| `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` | +93 | Dual-dispatch send, link establishment watchdog, connected-interface push |
| `Sources/ReticulumSwift/Routing/AnnounceHandler.swift` | +85/−4 | Known-key collision guard, null next-hop fix, throttled snapshots |
| `Sources/ReticulumSwift/Protocol/AnnounceValidator.swift` | +51 | Destination-hash binding (announce spoofing fix) |
| `Sources/ReticulumSwift/Crypto/Identity.swift` | +33/−12 | Keychain accessibility + non-destructive write |
| `Sources/ReticulumSwift/Transport/TCPTransport.swift` | +31/−3 | Lock-guarded state, queue-serialized API (crash fix) |
| `Sources/ReticulumSwift/Protocol/MessagePack.swift` | +24/−14 | Decoder depth cap |
| `Sources/ReticulumSwift/Crypto/RatchetManager.swift` | +10/−2 | Ratchet file protection + backup exclusion |
| `Sources/ReticulumSwift/Interfaces/TCPInterface.swift` | +7/−1 | Reconnect backoff cap |
| `Tests/…/AnnounceBindingTests.swift` | +91 (new) | Announce binding tests |
| `Tests/…/MessagePackHardeningTests.swift` | +47 (new) | Width/depth bomb tests |
| `.gitignore` | +3 | Ignore `Derived/`, `*.xcodeproj`, `*.xcworkspace` |

Untouched relative to upstream: `README.md`, `port-deviations.md`, `Package.swift`, `codecov.yml`,
CI workflows, `Sources/ConformanceBridge/`, and every other source file.

---

## 2. Schema & domain changes

This chapter covers every fork change that introduced **new domain state, domain objects, public
domain API, or persisted-storage change** — as opposed to changes that only altered implementation
logic. Changes that are purely logic live in [chapter 3](#3-implementation-logic-changes).

### 2.0 Headline: no relational schema change

**No SQLite table, column, or index was created, altered, or dropped by the fork.** The `paths`
table DDL in `PathTable.swift` (`CREATE TABLE … paths`, the `announce_data` `ALTER TABLE`
migration) is byte-identical to upstream. There is **no database migration to run** and an existing
persisted path database opens unchanged in both directions.

What *did* change at the database level is **row lifecycle** — which rows get written, updated, or
withheld. See [2.4](#24-row-lifecycle-changes-in-the-paths-table).

### 2.1 New domain objects

#### `NetworkLog` — new public type

`Sources/ReticulumSwift/Logging/NetworkLog.swift` (new file, new `Logging/` directory).

A public, opt-in, file-backed diagnostic log dedicated to *following routing decisions*, kept
separate from the `os.Logger` firehose.

| Member | Kind | Notes |
|---|---|---|
| `configure(directory:fileName:)` | `public static func` | Enables the log; default file `reticulum-network.log` |
| `disable()` | `public static func` | Back to no-op |
| `isEnabled` | `public static var` (get) | Cheap guard for expensive snapshot building |
| `debugScaffolding` | `public static var` | **Defaults to `true`**; master switch for the temporary `[MSG]`/`[ROUTE]`/`[ANNDROP]`/`[RECORD]`/`[FALLBACK]` markers |
| `log(_:)` / `debug(_:)` | `public static func` | `@autoclosure`; `debug` additionally gated on `debugScaffolding` |
| `describe(_ entry: PathEntry)` | `public static func` | One-line path-entry summary |
| `hex8(_:)`, `hasZeroNextHop(_:)` | `public static func` | Formatting / null-next-hop predicate |

Storage side effects (new persisted artifacts on disk):

- Creates `<directory>/reticulum-network.log`.
- Rolls one generation aside to `<directory>/reticulum-network.prev.log` on each `configure`.
- Written on a private serial `DispatchQueue`; `fileURL` and `debugScaffolding` are
  `nonisolated(unsafe)` statics.
- **No file-protection class or backup exclusion is set on these files**, unlike the ratchet store
  ([2.5](#25-persisted-storage-attribute-changes)). Log content includes destination hashes (first
  8 bytes), interface IDs, hop counts, and node display names (control characters stripped).

### 2.2 New domain properties

#### `PathTable` — the fallback-interface / liveness model

`Sources/ReticulumSwift/Routing/PathTable.swift`. This is the largest domain addition in the fork:
a whole new routing concept — a *fallback (carrier) interface* that is deliberately deprioritized
against normal interfaces regardless of hop count, plus the liveness bookkeeping needed to decide
when the carrier may take a route over.

New instance state (all **in-memory only — none of it is persisted to SQLite**):

| Property | Type | Line | Meaning |
|---|---|---|---|
| `fallbackInterfaceIds` | `Set<String>` | 73 | Interfaces the embedder marked low-priority fallback/carrier |
| `fallbackPinnedDestinations` | `Set<Data>` | 97 | Destinations pinned to the carrier; announces from normal interfaces are rejected while pinned |
| `lastHeardByInterface` | `[Data: [String: Date]]` | 103 | Per-destination, per-interface wall-clock last-announce time — the liveness signal |
| `connectedInterfaces` | `Set<String>` | 117 | Interfaces whose transport link is `.connected`, pushed by the transport |

New static configuration (public, mutable, process-wide):

| Property | Type | Default | Line | Meaning |
|---|---|---|---|---|
| `fallbackTakeoverGraceSeconds` | `UInt64` | `75` | 83 | How long a destination's normal interface may go announce-silent before the carrier may take over |
| `fallbackPromoteMaxLagSeconds` | `UInt64` | `90` | 90 | **Deprecated / dead** — kept for source stability, no longer consulted. Promotion is now unconditional for unpinned destinations |

New public methods on the `PathTable` actor:

| Method | Line | Purpose |
|---|---|---|
| `setFallbackInterface(_:isFallback:)` | 307 | Register/unregister an interface as fallback |
| `setConnectedInterfaces(_:)` | 319 | Transport pushes the live-connection set |
| `fallbackInterfaceIdsList() -> [String]` | 325 | Carrier IDs, for the dual-dispatch send path |
| `wasHeardOnInterface(_:interfaceId:within:) -> Bool` | 332 | Is the peer currently reachable on that specific interface |
| `isBestPathFallback(_:) -> Bool` | 340 | Does the current best path already route over a carrier |
| `setDestinationPinnedToFallback(_:_:) -> Void` | 346 | Pin/unpin a peer to the carrier (embedder sets this from an out-of-band "peer lost internet" signal) |

New private helper: `normalInterfaceHeardRecently(_:within:)` (line 357).

**Lifecycle wiring:** `lastHeardByInterface` is pruned everywhere `paths` is pruned —
`remove(destinationHash:)`, the conditional remove, `removeAll()`, and both expiry sweeps in
`cleanup(activeInterfaceIds:)`. `fallbackInterfaceIds`, `fallbackPinnedDestinations`, and
`connectedInterfaces` are never pruned (they are small, embedder-controlled sets).

**Restart semantics (important):** because none of this state is persisted, after a process
restart the fallback registry must be re-declared by the embedder, all pins are lost, and
`lastHeardByInterface` is empty — the takeover decision then falls back to the incumbent entry's
own `timestamp` as its startup liveness proxy (`PathTable.swift:350`).

#### `ReticulumTransport`

| Member | Kind | Line | Notes |
|---|---|---|---|
| `sendFallbackCopy(packet:heardWithin:)` | **new `public func`** | 1893 | Dual-dispatch: sends a second copy of a packet over any nearby carrier interface in addition to its normal route. Default `heardWithin` = 120 s |
| `lastConnectedInterfaceSet` | new `private var Set<String>` | 3292 | Change-detection so the connected set is only pushed/logged on change |
| `refreshConnectedInterfaces()` | new `private func` | 3298 | Recomputes and pushes the connected set to `PathTable` |
| `closeIfUnestablished(linkId:)` | new `private func` | 3255 | Closes a responder link stuck in `.handshake` past the establishment timeout |

#### `MPCInterface`

| Member | Kind | Line | Notes |
|---|---|---|---|
| `discoveredPeers` | new `private var [String: MCPeerID]` | 78 | Peers seen by the browser *or* connected via our advertiser, retained so a dropped link can be re-invited within the session |
| `sessionForInvitation(from:)` | new internal method | 340 | Replaces `getSession()`; returns a rebuilt session when the link is half-open |
| `getSession()` | **removed** | — | Was internal (not `public`), so this is not a public API break |
| `handleFoundPeer` / `handleLostPeer` / `invitePeerIfNeeded` / `fallbackInvite` / `shouldInitiateInvite` / `scheduleReconnect` / `attemptReconnect` / `rebuildSession` | new methods | 256–349 | See [3.3](#33-multipeer-connectivity-mpcinterface) |

#### `AnnounceHandler`

| Member | Kind | Line | Notes |
|---|---|---|---|
| `snapshotEvery` | new `private static let Int = 25` | 160 | Throttle divisor for the expensive path-table snapshot |
| `snapshotThrottleCounter` | new `private var Int` | 161 | Per-actor counter |

#### `TCPTransport` — stored-to-computed property change

`Sources/ReticulumSwift/Transport/TCPTransport.swift:66-74`.

```diff
-public private(set) var state: TransportState = .disconnected
+private let stateLock = NSLock()
+private var _state: TransportState = .disconnected
+public var state: TransportState { stateLock.lock(); defer { stateLock.unlock() }; return _state }
```

The public name, type, and read semantics are unchanged; the backing storage moved behind a lock.
Source-compatible for readers. (This is a domain/storage-shape change; the reason for it is the
crash fix described in [3.4](#34-concurrency-and-crash-fixes).)

### 2.3 New public API surface (behavioral, no new state)

| Symbol | File:line | Notes |
|---|---|---|
| `AnnounceValidator.validateDestinationBinding(parsed:)` | `AnnounceValidator.swift:263` | New `public static func`. Also now called from inside `validate(parsed:)`, so *existing* callers get the stricter check automatically |

No public symbol was removed or renamed anywhere in the fork.

### 2.4 Row-lifecycle changes in the `paths` table

Schema unchanged, but the fork adds and changes decision branches inside `PathTable.record(entry:)`
that determine whether a row is written at all. Behavioural delta versus upstream:

| Branch | New/changed | Effect on persisted rows |
|---|---|---|
| Pinned-destination rejection (`PathTable.swift:379`) | new | An announce on a **non-fallback** interface for a pinned destination is rejected outright — the existing row is **not** updated (upstream would have updated it) |
| Carrier takeover (`:417-469`) | new | A fallback-interface announce replaces the incumbent row **only** when the normal path is silent past `fallbackTakeoverGraceSeconds`, its interface is disconnected, or the path is marked unresponsive |
| Normal-over-fallback promotion (`:470-495`) | new | A normal-interface announce **unconditionally** replaces a fallback incumbent (unpinned destinations), writes the row, and resets `pathState` to `PATH_STATE_UNKNOWN` |
| Shorter-hop upgrade, "Path 2b" (`:515-529`) | new | A strictly-shorter-hop copy of an **already-held** announce (same random blob) now upgrades the row, preserving the existing `randomBlobs`/timebase. Upstream ignored this case and kept the worse, often dead-next-hop route |
| `lastHeardByInterface` write (`:388`) | new | Recorded **before** any early return, so duplicate-blob arrivals still refresh liveness (in-memory only) |

Net effect: for a single-interface deployment the persisted rows are identical to upstream except
for the Path 2b shorter-hop upgrade. For a deployment that registers a fallback interface, row
ownership (`interface_id`, `hop_count`, `next_hop`) can differ substantially from upstream.

### 2.5 Persisted-storage attribute changes

These change how existing records are stored on device. No schema, but real migration semantics.

#### Keychain identity item — `Identity.saveToKeychain(service:account:)`

`Sources/ReticulumSwift/Crypto/Identity.swift:701-748`.

| Aspect | Upstream | Fork |
|---|---|---|
| Accessibility class | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** |
| Write strategy | `SecItemDelete` then `SecItemAdd` | `SecItemUpdate`, falling back to `SecItemAdd` **only** on `errSecItemNotFound` |
| Error handling | Delete result ignored; add failure throws | Any non-`errSecItemNotFound` update error throws instead of silently proceeding |

Both changes are stated in-code as protecting the identity key, which is unrecoverable if lost:

- The accessibility relaxation lets a background relaunch (BLE/location wake-up) with the device
  locked read the key, instead of concluding it is missing and regenerating a new identity.
- The update-or-add removes a window where a locked device could successfully delete the real key
  and then fail to add the replacement, destroying the only copy.

**Migration:** `SecItemUpdate` carries `kSecAttrAccessible` in its attribute dictionary, so the next
save of an existing identity migrates that item in place from `WhenUnlocked…` to
`AfterFirstUnlock…`. There is no explicit migration step and no rollback — an item already migrated
stays readable-while-locked even if the code is reverted.

**Security trade-off, stated plainly:** `AfterFirstUnlockThisDeviceOnly` is a strictly weaker
at-rest posture than `WhenUnlockedThisDeviceOnly` — the identity private key is readable by the
process while the screen is locked, once the device has been unlocked since boot. It remains
non-exportable off-device (`ThisDeviceOnly`). This is a deliberate availability-over-confidentiality
choice for background operation.

#### Ratchet key file — `RatchetManager`

`Sources/ReticulumSwift/Crypto/RatchetManager.swift:345-356`.

| Aspect | Upstream | Fork |
|---|---|---|
| Write options | `.atomic` | `[.atomic, .completeFileProtectionUntilFirstUserAuthentication]` |
| Backup | included in device backups | `URLResourceValues.isExcludedFromBackup = true` (best-effort, `try?`) |

Rationale in-code: the file holds forward-secrecy **private** keys and its existing signature only
authenticates it, it does not protect confidentiality. Protection class matches the identity/DB
stores; backup exclusion keeps keys whose purpose is to bound the blast radius of an identity
compromise out of unencrypted backups.

**Migration:** the protection class is applied on the next write; a file written by an older build
keeps its old class until then. Backup exclusion is likewise applied on next write, and failures
are swallowed (`try?`) — it is not guaranteed. Practical consequence: ratchets no longer survive a
device restore, which is acceptable for ephemeral forward-secrecy state but is a behavioural change.

### 2.6 Decoder acceptance-envelope change

`Sources/ReticulumSwift/Protocol/MessagePack.swift:240`. A new module-private constant
`messagePackMaxDepth = 64` and a `depth` parameter threaded through `decodeValue` / `decodeArray` /
`decodeMap`.

This is not new state, but it does narrow the set of payloads the library will accept: any
MessagePack value nested deeper than 64 container levels now throws
`MessagePackError.decodingFailed` where upstream would recurse (and, past a few thousand levels,
overflow the native stack — an uncatchable crash in Swift, not a throw). RNS/LXMF structures nest
only a few levels, so no legitimate payload is affected. Python's `umsgpack` is bounded by the
interpreter recursion limit, so this restores parity rather than departing from it.

### 2.7 Summary table — changes with domain/storage impact

| # | Change | Kind | Persisted? | Migration needed |
|---|---|---|---|---|
| 1 | `NetworkLog` type + log files | New public type, new on-disk artifacts | Yes (log files) | No |
| 2 | `PathTable` fallback/liveness model (4 properties, 2 statics, 6 public methods) | New domain state + API | **No** — in-memory only | No; embedder must re-register on each launch |
| 3 | `ReticulumTransport.sendFallbackCopy` + connected-set state | New public API + private state | No | No |
| 4 | `MPCInterface.discoveredPeers` + session-rebuild API | New domain state | No | No |
| 5 | `TCPTransport.state` stored → lock-guarded computed | Storage-shape change | No | No (source-compatible) |
| 6 | `AnnounceValidator.validateDestinationBinding` | New public API | No | No |
| 7 | `AnnounceHandler` snapshot throttle counters | New private state | No | No |
| 8 | Keychain accessibility + update-or-add | **Persisted record attribute** | Yes | Implicit, on next save; not reversible |
| 9 | Ratchet file protection + backup exclusion | **Persisted file attribute** | Yes | Implicit, on next write |
| 10 | `paths` row-lifecycle branches | Row semantics, not schema | Yes (existing table) | No |
| 11 | MessagePack depth cap | Acceptance envelope | No | No |
| — | **SQLite tables / columns / indexes** | **unchanged** | — | **none** |

---

## 3. Implementation-logic changes

Changes below alter behaviour only — no new domain or storage state.

### 3.1 Security hardening

Commit `c2cdf92` *Fable security fixes*, plus parts of `d989b02`.

**Announce destination-hash binding** — `AnnounceValidator.swift:226-275`, `AnnounceHandler.swift:219-250`.

Upstream verified the Ed25519 signature on an announce but never checked that the announced public
keys actually *own* the destination hash in the header. A valid signature only proves the announcer
holds the private key for the keys carried in the payload. An attacker could therefore announce any
victim's destination hash with their own keypair and a self-valid signature, installing a path for
the victim pointing at themselves and overwriting the cached public key — so senders resolving that
destination would encrypt to the attacker. Identity/route hijack, pre-auth.

The fork restores the RNS check (`Identity.validate_announce`, Identity.py:585-599):

```
expected = truncated_hash(name_hash || truncated_hash(public_key))
reject if destination_hash != expected
```

called from inside `validate(parsed:)`, so `parseAndValidate` is now the full RNS
`validate_announce`. PLAIN announces carry no keys and skip the check.

**Known-key collision guard** — `AnnounceHandler.swift:247-258`. Mirrors RNS Identity.py:588-596:
even with a valid signature *and* a correct binding, refuse to overwrite a destination's already
known public key with a different one. Only reachable via a truncated-hash collision, but RNS
rejects rather than permit a key swap.

**Announce error classification** — `AnnounceHandler.swift:222-233`. `error as!
AnnounceValidationError` (a forced cast that would trap on any other error type) became a
non-trapping `as?` + `switch`, with `.hashMismatch` classified as an authenticity failure
(`.invalidSignature`) rather than a format error.

**MessagePack width and depth bombs** — `MessagePack.swift`. The depth cap is described in
[2.6](#26-decoder-acceptance-envelope-change). The width-bomb reservation bounds
(`reserveCapacity(min(count, remaining))`) were already upstream; the fork adds regression tests for
them. Both paths are reachable pre-auth via announce `app_data` and resource metadata.

**Half-open link watchdog** — `ReticulumTransport.swift:2252-2264`, `3255-3268`. A responder link
waits in `.handshake` for the initiator's LRRTT. If that never arrived, the per-link stale watchdog
(which only starts on activation) never ran, `cleanupLinks` skipped it (`.handshake` is not
terminal), and the link was pinned in `activeLinks` and `destination._links` forever — an
unauthenticated LINKREQUEST flood could exhaust memory/CPU. The fork arms a
`ESTABLISHMENT_TIMEOUT_PER_HOP * 5` timer that closes any still-unestablished link, making it
terminal so the existing sweep reclaims it.

### 3.2 Routing: fallback interfaces and message delivery

Commits `5695d00` *Asymmetric transports*, `c154af3` *Fallback interface support*, `bc483ec` *Keeping
up multiple active interfaces*, `2e11b59` *Improving message sending*. The domain state these
introduce is in [2.2](#22-new-domain-properties); the decision logic is here.

The problem: a fallback carrier (e.g. an app's virtual BLE link) is physically adjacent and
therefore always low-hop, so on pure hop-count it beats any real route; and it re-announces far more
often than a periodic relayed announce, so on pure freshness it also always looks newer. Either
metric alone lets the carrier capture and hold every route.

Resolution as implemented:

- **Carrier may take over** only when the normal path is genuinely dead — silent on every
  non-fallback interface for `fallbackTakeoverGraceSeconds` (`PathTable.swift:417-469`; 75 s ≈ 2.5× a 30 s announce interval,
  chosen after 45 s flapped on a single late announce), **or** its interface is not in the connected
  set, **or** the path is marked unresponsive by delivery failures.
- **Delivery-awareness** (`PathTable.swift:447`) is the decisive signal, not connectivity. Keying
  purely on "incumbent interface is connected" was too aggressive: a peer on 5G behind carrier NAT
  has a TCP path that resolves but never delivers, and holding it blocked the only working link.
  `isPathUnresponsive` (fed by `LXMRouter.markPathUnresponsive`) overrides the connectivity check —
  and doing so also un-blocks the existing demotion failover, which this branch would otherwise
  short-circuit with an early `return false`.
- **Normal reclaims unconditionally** (`PathTable.swift:470-495`) on the first normal-interface
  announce for an unpinned destination. Any freshness gate here let the direct carrier — which wins
  every arrival race — hold the route indefinitely (a ~140 s BLE→TCP return was observed). The
  authoritative holds are the pin and the 75 s anti-flap window, so an unconditional promote is both
  safe and the point of a "fallback".
- **Pinning** (`PathTable.swift:379`) is the authoritative offline trigger: while a peer is pinned,
  normal-interface announces are rejected, so a transport node still relaying that peer's dead TCP
  path cannot refresh liveness and starve the carrier.
- **Dual dispatch** (`ReticulumTransport.swift:1893`) sends a carrier copy alongside the normal
  route for opportunistic LXMF delivery, so a message reaches an undeliverable-but-nearby peer
  without waiting for demotion. Gated on: best path is not already the carrier, carrier interface is
  `.connected`, and the peer was heard on that carrier within `heardWithin` (120 s default). The
  receiver dedups by packet hash, so the duplicate is harmless.
- **Connected-set refresh** (`ReticulumTransport.swift:2900`, `3318`) is called from the *inbound
  announce path* as well as `periodicTableCleanup`, because the latter's retransmission loop is
  stopped when relay mode is off — which left `connectedInterfaces` permanently empty in ENDPOINT
  mode and made the whole liveness check inert.

**Null next-hop fix** — `AnnounceHandler.swift:293-305`. A HEADER_2 announce carrying an all-zero
transport address now falls back to the destination hash as next hop (matching Python's
`received_from = destination_hash`) instead of recording a dead all-zero next hop that can never
route.

**Shorter-hop upgrade** — see Path 2b in [2.4](#24-row-lifecycle-changes-in-the-paths-table).
Prevents a destination flickering in and out of reachability when a relayed copy wins the arrival
race against the direct copy.

### 3.3 Multipeer Connectivity (`MPCInterface`)

Commit `d7dcc67` *MPCInterface discovery fix*.

- **Deterministic invite direction** (`:272`). Both devices advertise *and* browse, so upstream had
  each side inviting the other on discovery — two competing session-formation attempts that MCSession
  resolves by tearing one down ~2 s after connecting (the cold-start flap). Now only the
  lexicographically smaller display name invites; the higher-named side auto-accepts and
  fallback-invites after 4 s if nothing formed (covering asymmetric discovery).
- **Bounded reconnect** (`:305`). Up to 6 attempts, first immediate then 1 s steps, role-staggered
  (+500 ms for the secondary) so the two sides never re-invite simultaneously. Upstream waited for
  the next `foundPeer`, which only fires on fresh discovery — in practice the next app launch, which
  stranded the first message.
- **Half-open session healing** (`:340`, `:349`). A peer we still consider connected re-inviting us
  means our half of the link is dead while MCSession hasn't noticed; returning the stale session made
  MPC sit on it until its ~60 s keepalive expired. The fork rebuilds the MCSession so the incoming
  invitation handshakes into a clean one immediately. Guarded on the peer already being present, so
  first-time invites are untouched.
- `invitationHandler(session != nil, session)` replaces an unconditional `true`, so a nil session is
  now declined rather than accepted.
- `browser(_:lostPeer:)` now clears `discoveredPeers`; invite timeouts dropped 30 s → 15 s (10 s for
  reconnects).

### 3.4 Concurrency and crash fixes

Commit `36b9d20` *Crash fix* — `TCPTransport.swift`.

An `objc_retain` use-after-free under concurrent connect/disconnect plus timeout: `state` is a
`TransportState` whose payload can carry an `Error`, mutated on `connectionQueue` by NWConnection
callbacks while external callers (the reconnect loop) read it from other threads, racing the
retain/release of that payload.

Fix: `_state` behind an `NSLock` with a thread-safe computed `state`, and `connect()`, `send(_:completion:)`,
`disconnect()` all now hop to `connectionQueue` (`connectOnQueue` / `sendOnQueue` / `disconnectOnQueue`),
so every access to connection, state, and timeout work items is serialized on the same queue the
callbacks run on.

**Note:** the pre-existing guard `state == .disconnected || state != .connecting` in `connectOnQueue`
was carried over verbatim; it is tautologically true for every state except `.connecting`, and was
not touched by the fork.

### 3.5 Interface tuning

`TCPInterface.swift:170-177` — reconnect backoff capped at 10 s instead of the 300 s default
(`ExponentialBackoff(baseDelay: 1.0, maxDelay: 10.0)`). A device that loses and regains connectivity
accrues failed attempts while offline, so the default scheduled the next retry 32–64 s after
internet returned. Trade-off accepted in-code: more frequent retries against a genuinely dead
endpoint, in exchange for ≤10 s recovery.

### 3.6 Diagnostics

Commit `ebda44b` *Logs and improvements* plus markers added throughout later commits.
`NetworkLog` itself is documented in [2.1](#21-new-domain-objects). Call sites:

| Marker | Where | Content |
|---|---|---|
| `ANNOUNCE recorded=` | `AnnounceHandler.swift:353` | Per-announce: dest, hops, header type, computed next hop, interface |
| `PATHTABLE` | `AnnounceHandler.swift:360-377` | Throttled snapshot: totals for zero-next-hop / direct / routed / responsive, plus up to 30 *routable* entries |
| `[ANNDROP]` | `AnnounceHandler.swift` | Hop-limit, parse/validate failure, known-key mismatch |
| `[RECORD]` | `PathTable.swift` | Accept/ignore reason on every `record()` branch, emitted only when a fallback interface is involved |
| `[FALLBACK]` | `PathTable.swift`, `ReticulumTransport.swift` | register / REJECT / ACCEPT / PROMOTE, and the connected-interface set |
| `ROUTE` | `ReticulumTransport.swift:1455-1486`, `1853-1856` | HEADER_2 routed vs HEADER_1 direct vs no-path broadcast, and send failures |
| `[DUAL]` | `ReticulumTransport.swift:1893` | Dual-dispatch carrier copy sent / skipped / failed |

**Performance note captured in-code:** running the full path-table snapshot per announce serialized
on the `AnnounceHandler` actor throttled announce processing to ~0.5/s under a reconnect flood,
stalling a contact's TCP announce ~115 s behind the mesh backlog. Hence `snapshotEvery = 25` and the
`if NetworkLog.isEnabled` guard around snapshot construction.

The in-code comments mark the `[MSG]`/`[ROUTE]`/`[ANNDROP]`/`[RECORD]`/`[FALLBACK] register`
markers, `NetworkLog.debugScaffolding`, and the `refreshConnectedInterfaces` log line as
**temporary scaffolding slated for removal** once the offline/return behaviour is signed off.

### 3.7 Tests

| File | Coverage |
|---|---|
| `Tests/ReticulumSwiftTests/AnnounceBindingTests.swift` | 4 tests: correctly-bound announce passes; spoofed announce rejected with `.hashMismatch`; wrong name hash rejected; PLAIN announce skips binding |
| `Tests/ReticulumSwiftTests/MessagePackHardeningTests.swift` | 4 tests: array32 and map32 width bombs throw instead of allocating; 200-deep nesting rejected; 8-deep nesting accepted |

Both files carry the upstream MPL-2.0 header and `Copyright (c) 2026 Torlando Tech LLC`.

**Coverage gap:** the entire `PathTable` fallback/liveness model, `sendFallbackCopy`, the
`MPCInterface` invite/reconnect logic, the link establishment watchdog, and the `TCPTransport`
locking have **no unit tests** in the fork. Their correctness rationale is recorded only as in-code
comments referencing field sessions ("session-3", "session-4", "session-13", "session-37").

### 3.8 Build and repo hygiene

Commit `c25b95e`. `.gitignore` gains `Derived/*`, `*.xcodeproj`, `*.xcworkspace`. Consequence: the
`ReticulumSwift.xcodeproj` and `Derived/` present in the working tree are untracked — the package is
consumed via SwiftPM and the Xcode project is a local artifact. No tracked file was removed.

---

## 4. Commit index

| Commit | Date | Subject | Chapters |
|---|---|---|---|
| `c25b95e` | 2026-05-30 | Improvements and locks | [3.8](#38-build-and-repo-hygiene) |
| `ebda44b` | 2026-06-26 | Logs and improvements | [2.1](#21-new-domain-objects), [3.6](#36-diagnostics) |
| `d7dcc67` | 2026-06-30 | MPCInterface discovery fix | [2.2](#22-new-domain-properties), [3.3](#33-multipeer-connectivity-mpcinterface) |
| `5695d00` | 2026-07-02 | Asymmetric transports | [2.2](#22-new-domain-properties), [2.4](#24-row-lifecycle-changes-in-the-paths-table), [3.2](#32-routing-fallback-interfaces-and-message-delivery) |
| `c154af3` | 2026-07-03 | Fallback interface support | [2.2](#22-new-domain-properties), [2.4](#24-row-lifecycle-changes-in-the-paths-table), [3.2](#32-routing-fallback-interfaces-and-message-delivery), [3.5](#35-interface-tuning) |
| `c2cdf92` | 2026-07-05 | Fable security fixes | [2.3](#23-new-public-api-surface-behavioral-no-new-state), [2.6](#26-decoder-acceptance-envelope-change), [3.1](#31-security-hardening), [3.7](#37-tests) |
| `d989b02` | 2026-07-12 | Fable review, fixes. Identity fix if app running without unlock | [2.5](#25-persisted-storage-attribute-changes), [3.1](#31-security-hardening) |
| `bc483ec` | 2026-07-13 | Keeping up multiple active interfaces | [2.2](#22-new-domain-properties), [3.2](#32-routing-fallback-interfaces-and-message-delivery) |
| `2e11b59` | 2026-07-13 | Improving message sending | [2.2](#22-new-domain-properties), [2.4](#24-row-lifecycle-changes-in-the-paths-table), [3.2](#32-routing-fallback-interfaces-and-message-delivery) |
| `36b9d20` | 2026-07-14 | Crash fix | [2.2](#22-new-domain-properties), [3.4](#34-concurrency-and-crash-fixes) |

Merge commits `318a0fb` (#5), `15232eb` (#6), `aa5f0b6` (#4), `49cc82e` (#3), `b3e5b64` (#2),
`7e68ab6` (upstream merge) carry no changes of their own.

---

## 5. Wire-protocol & interop impact

| Aspect | Impact |
|---|---|
| Packet / announce wire format | **None.** No encoding, header, or field change |
| Announce validation strictness | **Increased, toward RNS parity.** The fork now rejects announces the Python reference also rejects (unbound destination hash, known-key mismatch). No conformant announce is newly rejected |
| MessagePack acceptance | Narrowed to ≤64 nesting levels — inside Python's own recursion bound, so no conformant payload is affected |
| Routing decisions | Diverge from upstream **only** when the embedder registers a fallback interface via `setFallbackInterface`. With no fallback registered, the only routing delta is the Path 2b shorter-hop upgrade |
| Dual dispatch | Emits a duplicate packet over the carrier link; peers dedup by packet hash, so this is transparent to a conformant receiver |
| Conformance suite | Not modified; `Sources/ConformanceBridge/` untouched |

Interoperability with the Python RNS reference is unaffected or improved by every change in the fork.

---

## 6. Risks and open items

1. **Keychain accessibility relaxation is a one-way, silent migration.** `AfterFirstUnlockThisDeviceOnly`
   is weaker than upstream's `WhenUnlockedThisDeviceOnly`, it migrates existing items on the next
   save, and reverting the code does not revert already-migrated items. Deliberate; see
   [2.5](#25-persisted-storage-attribute-changes).
2. **Ratchet files are excluded from backup on a best-effort basis** (`try?`). Ratchets no longer
   survive a device restore. Acceptable for ephemeral forward-secrecy state, but it is a
   behavioural change.
3. **`NetworkLog.debugScaffolding` defaults to `true`.** Once `configure(directory:)` is called, the
   temporary scaffolding markers write destination hashes, interface IDs, and peer display names to
   an unprotected, non-backup-excluded file. The log is a no-op until configured, so release builds
   that never configure it are unaffected — but any build that does configure it gets the full
   scaffolding by default.
4. **Fallback routing state is entirely non-persistent.** After a restart the embedder must
   re-register fallback interfaces and re-apply pins, and liveness history is empty. Nothing in the
   library enforces or reminds; a host that registers once at first launch will silently lose the
   behaviour on relaunch.
5. **`PathTable.fallbackPromoteMaxLagSeconds` is public, mutable, and dead.** It is documented as no
   longer consulted but still settable, so an embedder tuning it gets no effect and no warning.
6. **Two process-wide mutable statics** (`fallbackTakeoverGraceSeconds`,
   `NetworkLog.debugScaffolding`, the latter `nonisolated(unsafe)`) are global configuration, not
   per-instance — a concern for multi-instance hosts and for tests running in parallel.
7. **No test coverage for the largest divergence.** The fallback/liveness routing model, dual
   dispatch, MPC reconnect, link watchdog, and `TCPTransport` locking are untested; their
   justification lives in in-code comments referencing field sessions that are not reproducible from
   this repository.
8. **Scaffolding marked for removal is still present.** The in-code comments commit to removing the
   `[MSG]`/`[ROUTE]`/`[ANNDROP]`/`[RECORD]`/`[FALLBACK] register` markers and the
   `refreshConnectedInterfaces` diagnostic once the offline/return behaviour is signed off; that
   cleanup has not happened.
9. **Upstream merge risk is concentrated in `PathTable.record()`.** The fork inserts several
   decision branches into the middle of a function upstream actively maintains; any upstream change
   to path-selection ordering will conflict there first.

---

*Generated 2026-08-02 against `36b9d20` vs `upstream/main` @ `52e2a9a`.*
