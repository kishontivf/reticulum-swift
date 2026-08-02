# KVF divergence from upstream reticulum-swift

Living record of every change this fork (`kishontivf/reticulum-swift`) carries on top of
upstream (`torlando-tech/reticulum-swift`). **Keep this file current: any commit that adds,
changes, or drops a divergence must update the matching section — and its commit list —
in the same commit.**

These are our own product requirements — there is no intent to upstream them. The point of
this file is to know exactly what to re-apply and what to watch for when pulling upstream
work *in*.

Scope note: this file tracks *fork vs. upstream*. `port-deviations.md` tracks *Swift port
vs. python RNS* and is upstream's document — the fork has added no entries to it. If we
ever do, that entry is itself a divergence and must be listed here.

Downstream note: `kishontivf/LXMF-swift` depends on this fork and consumes two of these
divergences directly — see [Downstream coupling](#downstream).

- **Upstream base:** `52e2a9a` (`Merge pull request #25 … feat/rnode-ble-uuid-identity`)
- **Fork HEAD at last update:** `36b9d20` (Crash fix)
- **Upstream commits not in this fork:** none — the fork is strictly ahead (16 / 0).
- **Net diff:** 14 files, +1021 / −46
- **Last reviewed:** 2026-08-02

## Summary

| ID | Area | Change | Commits | Depends on |
|----|------|--------|---------|------------|
| [D1](#d1) | Routing (PathTable) | Fallback/carrier interface model — deprioritise a carrier against normal interfaces regardless of hop count | `5695d00`, `c154af3`, `bc483ec`, `2e11b59` | — |
| [D2](#d2) | Transport (outbound) | Dual dispatch — `sendFallbackCopy` emits a carrier copy alongside the normal route | `2e11b59` | D1 |
| [D3](#d3) | Routing (announce) | Path-recording fixes: null next-hop fallback, shorter-hop upgrade | `c154af3`, `2e11b59` | — |
| [D4](#d4) | Protocol (announce) | Destination-hash binding + known-key collision guard | `c2cdf92` | — |
| [D5](#d5) | Protocol (MessagePack) | Decoder depth cap | `c2cdf92` | — |
| [D6](#d6) | Transport (link) | Half-open link establishment watchdog | `d989b02` | — |
| [D7](#d7) | Crypto (Identity) | Keychain accessibility + non-destructive write | `d989b02` | — |
| [D8](#d8) | Crypto (RatchetManager) | Ratchet file protection class + backup exclusion | `d989b02` | — |
| [D9](#d9) | Interfaces (MPC) | Deterministic invite direction, bounded reconnect, half-open session healing | `d7dcc67` | — |
| [D10](#d10) | Transport (TCP) | `TCPTransport` thread-safety — lock-guarded state, queue-serialised API | `36b9d20` | — |
| [D11](#d11) | Interfaces (TCP) | Reconnect backoff capped at 10 s | `c154af3` | — |
| [D12](#d12) | Logging | `NetworkLog` — opt-in routing diagnostic log | `ebda44b`, `c154af3` | — |
| [D13](#d13) | Repo hygiene | `.gitignore` additions | `c25b95e` | — |

### Commit ledger

Every fork commit since the upstream base, oldest first. Merge commits (`b3e5b64`,
`49cc82e`, `aa5f0b6`, `15232eb`, `318a0fb` — the PR merges for `feature/offline-improvements`,
`feature/bluetooth`, `feature/fable-security-fixes`, `review/fable-fixes`,
`feature/improvements` — and `7e68ab6`, the upstream merge) carry no changes of their own
and are omitted.

| Commit | Date | Subject | Divergence |
|--------|------|---------|------------|
| `c25b95e` | 2026-05-30 | Improvements and locks | [D13](#d13) |
| `ebda44b` | 2026-06-26 | Logs and improvements | [D12](#d12) |
| `d7dcc67` | 2026-06-30 | MPCInterface discovery fix | [D9](#d9) |
| `5695d00` | 2026-07-02 | Asymmetric transports | [D1](#d1) (initial fallback model) |
| `c154af3` | 2026-07-03 | Fallback interface support | [D1](#d1), [D3](#d3), [D11](#d11), [D12](#d12) |
| `c2cdf92` | 2026-07-05 | Fable security fixes | [D4](#d4), [D5](#d5) |
| `d989b02` | 2026-07-12 | Fable review, fixes. Identity fix if app running without unlock | [D6](#d6), [D7](#d7), [D8](#d8) |
| `bc483ec` | 2026-07-13 | Keeping up multiple active interfaces | [D1](#d1) (connected-interface set) |
| `2e11b59` | 2026-07-13 | Improving message sending | [D1](#d1), [D2](#d2), [D3](#d3) |
| `36b9d20` | 2026-07-14 | Crash fix | [D10](#d10) |

The D-sections below cover **logic/behaviour** divergence. Anything that changes the
*shape* of the stored data — DB schema, persisted record attributes, or domain model — is
tracked separately in [Schema & domain changes](#schema) and must be logged there too.

---

## Schema & domain changes {#schema}

Standing register for structural changes: new/renamed/dropped **tables**, **columns**,
**indexes**, and new/changed **persisted properties** on domain types. Logic-only changes
do not belong here — this chapter answers "did the stored data shape change, and can an
older or newer build still read it?"

**Current state: no SQLite divergence, two persisted-attribute divergences.**

The `paths` table and both migrations are upstream's, byte-identical. There is no database
migration to run, and a persisted path database opens unchanged in either direction:

| Structure | Origin |
|-----------|--------|
| `paths` base DDL — `CREATE TABLE IF NOT EXISTS paths (…)`, 11 columns | upstream |
| `migrateRandomBlobColumn()` — `random_blob` BLOB → `random_blobs` TEXT, via table rebuild | upstream |
| `migrateAnnounceDataColumn()` — `ALTER TABLE paths ADD COLUMN announce_data BLOB` | upstream |

Unlike LXMF-swift there is **no version counter**: reticulum's migrations are idempotent
functions that self-detect via `PRAGMA table_info(paths)` and return early if already
applied. This changes the collision failure mode — see [rule 2](#rules) below.

Two fork changes *do* alter how existing records are stored, without touching shape. Both
are implicit, applied on next write, and one-way:

### Ledger

Append one row per structural change. Keep it even after upstream adopts the same idea —
the point is to be able to reconstruct what our stored data looks like at any commit.

| ID | Commit | Date | Migration | Structure changed | Domain property | Reason |
|----|--------|------|-----------|-------------------|-----------------|--------|
| S1 | `d989b02` | 2026-07-12 | none — implicit, on next `saveToKeychain` | Keychain identity item: `kSecAttrAccessible` `WhenUnlockedThisDeviceOnly` → `AfterFirstUnlockThisDeviceOnly` | — (attribute of the stored item, not a Swift property) | Background relaunch with the device locked could not read the key, concluded it was missing, and regenerated a new identity — see [D7](#d7) |
| S2 | `d989b02` | 2026-07-12 | none — implicit, on next ratchet write | Ratchet key file: protection class → `completeFileProtectionUntilFirstUserAuthentication`; `isExcludedFromBackup = true` | — | File holds forward-secrecy private keys; its signature authenticates but does not protect confidentiality — see [D8](#d8) |

**Not in this ledger, deliberately:**

- **The fallback/liveness domain model** ([D1](#d1)) adds four instance properties, two
  public statics and six public methods to `PathTable`, but **none of it is persisted** —
  it is in-memory only, so it changes no stored shape. Its restart semantics are a real
  operational hazard and are documented in D1 instead.
- **Row-lifecycle changes** in the `paths` table ([D1](#d1), [D3](#d3)) change *which* rows
  get written and *which* interface owns a route, not the columns. Same schema, different
  contents.
- **`TCPTransport.state`** ([D10](#d10)) moved from a stored property to a lock-guarded
  computed one. Storage shape in memory only; nothing persisted, and the public name, type
  and read semantics are unchanged.

### Rules for adding one {#rules}

1. **Append, never edit.** A migration that has shipped has already run on user devices —
   changing its body is silently a no-op there. Add a new migration function instead.
2. **There is no counter to collide on — the risk is the column name.** Upstream will keep
   adding self-detecting `migrate<Thing>Column()` functions guarded by
   `PRAGMA table_info(paths)`. If we add a column upstream later adds under the same name,
   both guards see it present and neither runs, and the two builds silently disagree about
   what the column *means*. Prefix ours `kvf_<what>` so a re-sync produces a visible
   conflict at the migration list instead of two different semantics sharing one column.
3. **Log the domain side too.** If the column backs a new property on `PathEntry` or
   another domain type, name it in the ledger — that property is part of the public API
   surface consumers compile against.
4. **Check every reader.** `PathTable` opens the database with plain `sqlite3_open`
   (read/write, create) and there is no read-only mode. Any second process opening the same
   file gets a writable handle and will run its own migrations, so a column added by a newer
   binary must tolerate being read by an older one still running against the same file.
5. **Every migration must apply to a database written before it existed.** Make no
   assumptions about pre-existing rows, and make the guard idempotent in both directions —
   the `announce_data` migration is the model to copy: probe `table_info`, return early if
   present, otherwise a single `ALTER TABLE … ADD COLUMN`. Prefer `ADD COLUMN` over the
   table-rebuild pattern in `migrateRandomBlobColumn()`, which drops and recreates.
6. **Update the summary table** with an `S<n>` row and this chapter's entry in the same commit.

---

## D1 — Fallback (carrier) interface routing model {#d1}

**Commits:** `5695d00` (initial model), `c154af3` (takeover/promotion rules, pinning),
`bc483ec` (connected-interface set), `2e11b59` (delivery-awareness, unconditional promote)

**Files:** `Sources/ReticulumSwift/Routing/PathTable.swift`,
`Sources/ReticulumSwift/Transport/ReticulumTransport.swift`

The largest divergence in the fork: a whole routing concept upstream does not have. A
*fallback (carrier) interface* is deliberately deprioritised against normal interfaces
**regardless of hop count**, plus the liveness bookkeeping needed to decide when the
carrier may take a route over.

The problem it solves: a carrier (e.g. an app's virtual BLE link) is physically adjacent
and therefore always low-hop, so on pure hop-count it beats any real route; and it
re-announces far more often than a periodic relayed announce, so on pure freshness it also
always looks newer. Either metric alone lets the carrier capture and hold every route.

New instance state on the `PathTable` actor — **all in-memory, none persisted**:

| Property | Type | Meaning |
|----------|------|---------|
| `fallbackInterfaceIds` | `Set<String>` | Interfaces the embedder marked low-priority carrier |
| `fallbackPinnedDestinations` | `Set<Data>` | Destinations pinned to the carrier; normal-interface announces are rejected while pinned |
| `lastHeardByInterface` | `[Data: [String: Date]]` | Per-destination, per-interface last-announce time — the liveness signal |
| `connectedInterfaces` | `Set<String>` | Interfaces whose transport link is `.connected`, pushed by the transport |

New public statics: `fallbackTakeoverGraceSeconds` (`UInt64`, 75) and
`fallbackPromoteMaxLagSeconds` (`UInt64`, 90 — **dead, see the known gap below**).

New public methods: `setFallbackInterface(_:isFallback:)`, `setConnectedInterfaces(_:)`,
`fallbackInterfaceIdsList()`, `wasHeardOnInterface(_:interfaceId:within:)`,
`isBestPathFallback(_:)`, `setDestinationPinnedToFallback(_:_:)`. On the transport side:
`lastConnectedInterfaceSet`, `refreshConnectedInterfaces()`.

Decision rules as implemented, inside `PathTable.record(entry:)`:

- **Carrier may take over** only when the normal path is genuinely dead — silent on every
  non-fallback interface for `fallbackTakeoverGraceSeconds` (75 s ≈ 2.5× a 30 s announce
  interval; 45 s flapped on a single late announce), **or** its interface is not in the
  connected set, **or** the path is marked unresponsive by delivery failures.
- **Delivery-awareness is the decisive signal, not connectivity.** Keying purely on
  "incumbent interface is connected" was too aggressive: a peer on 5G behind carrier NAT
  has a TCP path that resolves but never delivers, and holding it blocked the only working
  link. `isPathUnresponsive` (upstream API, fed by `LXMRouter.markPathUnresponsive`)
  overrides the connectivity check — which also un-blocks the existing demotion failover
  that this branch would otherwise short-circuit with an early `return false`.
- **Normal reclaims unconditionally** on the first normal-interface announce for an
  unpinned destination. Any freshness gate here let the direct carrier — which wins every
  arrival race — hold the route indefinitely (a ~140 s BLE→TCP return was observed). The
  authoritative holds are the pin and the 75 s anti-flap window.
- **Pinning is the authoritative offline trigger.** While a peer is pinned, normal-interface
  announces are rejected outright, so a transport node still relaying that peer's dead TCP
  path cannot refresh liveness and starve the carrier.
- **Connected-set refresh** is called from the *inbound announce path* as well as
  `periodicTableCleanup`, because the latter's retransmission loop is stopped when relay
  mode is off — which left `connectedInterfaces` permanently empty in ENDPOINT mode and made
  the whole liveness check inert.

`lastHeardByInterface` is pruned everywhere `paths` is pruned. The other three sets are
never pruned (small, embedder-controlled).

**Why it matters:** with no fallback interface registered, routing is upstream's except for
the shorter-hop upgrade in [D3](#d3). Every behaviour above is dormant until the embedder
calls `setFallbackInterface`.

**Known gap — restart semantics.** None of this state is persisted. After a process restart
the fallback registry must be re-declared by the embedder, all pins are lost, and
`lastHeardByInterface` is empty — the takeover decision then falls back to the incumbent
entry's own `timestamp` as a startup liveness proxy. Nothing in the library enforces or
reminds; a host that registers once at first launch silently loses the behaviour on relaunch.

**Known gap — `fallbackPromoteMaxLagSeconds` is public, mutable and dead.** It survives only
for source stability; the unconditional-promote change removed its last reader. An embedder
tuning it gets no effect and no warning.

**Known gap — process-wide mutable statics.** `fallbackTakeoverGraceSeconds` is global
configuration, not per-instance: a concern for multi-instance hosts and for tests running in
parallel.

**Known gap — no test coverage.** The entire model is untested; its correctness rationale
lives in in-code comments referencing field sessions ("session-3", "session-13",
"session-37") that are not reproducible from this repository.

## D2 — Dual dispatch (carrier copy) {#d2}

**Commits:** `2e11b59`

**Files:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift`

New `public func sendFallbackCopy(packet:heardWithin:)` (default `heardWithin` = 120 s).
Sends a second copy of a packet over a nearby carrier interface *in addition to* its normal
route, so a message reaches an undeliverable-but-nearby peer without waiting for demotion.

Gated on three conditions: the best path is not already the carrier, the carrier interface
is `.connected`, and the peer was heard on that carrier within `heardWithin`. The receiver
dedups by packet hash, so the loser is a no-op and the duplicate is transparent to a
conformant peer.

**Why it matters:** this is the API `kishontivf/LXMF-swift` D5 calls from `sendOpportunistic`
— removing or renaming it breaks the downstream fork. See [Downstream coupling](#downstream).

**Known gap:** untested, and it has no `sendDirect` (link-based) equivalent — it applies to
the opportunistic path only.

## D3 — Announce path-recording fixes {#d3}

**Commits:** `c154af3` (null next-hop), `2e11b59` (shorter-hop upgrade)

**Files:** `Sources/ReticulumSwift/Routing/AnnounceHandler.swift`,
`Sources/ReticulumSwift/Routing/PathTable.swift`

Two independent correctness fixes in how an announce becomes a path row. Both apply with no
fallback interface registered, so these are the *only* routing changes a plain deployment sees.

- **Null next-hop fallback.** A HEADER_2 announce carrying an all-zero transport address now
  falls back to the destination hash as next hop, matching python's
  `received_from = destination_hash`. Upstream recorded a dead all-zero next hop that could
  never route.
- **Shorter-hop upgrade ("Path 2b").** A strictly-shorter-hop copy of an *already-held*
  announce (same random blob) now upgrades the row, preserving the existing
  `randomBlobs`/timebase. Upstream ignored this case and kept the worse, often
  dead-next-hop route — which made a destination flicker in and out of reachability when a
  relayed copy won the arrival race against the direct copy.

Also here: `error as! AnnounceValidationError` — a forced cast that would trap on any other
error type — became a non-trapping `as?` + `switch`.

## D4 — Announce destination-hash binding + known-key collision guard {#d4}

**Commits:** `c2cdf92`

**Files:** `Sources/ReticulumSwift/Protocol/AnnounceValidator.swift`,
`Sources/ReticulumSwift/Routing/AnnounceHandler.swift`,
`Tests/ReticulumSwiftTests/AnnounceBindingTests.swift`

Upstream verified the Ed25519 signature on an announce but never checked that the announced
public keys actually *own* the destination hash in the header. A valid signature only proves
the announcer holds the private key for the keys carried in the payload — so an attacker
could announce any victim's destination hash with their own keypair and a self-valid
signature, installing a path for the victim pointing at themselves and overwriting the
cached public key. Senders resolving that destination would then encrypt to the attacker.
Identity/route hijack, pre-auth.

- New `public static func validateDestinationBinding(parsed:)` restores the RNS check
  (`Identity.validate_announce`): reject unless
  `destination_hash == truncated_hash(name_hash ‖ truncated_hash(public_key))`.
- It is called from inside `validate(parsed:)`, so *existing* callers get the stricter check
  automatically and `parseAndValidate` is now the full RNS `validate_announce`.
- PLAIN announces carry no keys and skip the check.
- **Known-key collision guard** in `AnnounceHandler`: even with a valid signature *and* a
  correct binding, refuse to overwrite a destination's already-known public key with a
  different one. Only reachable via a truncated-hash collision, but RNS rejects rather than
  permit a key swap.
- `.hashMismatch` is classified as an authenticity failure (`.invalidSignature`), not a
  format error.

Four tests: correctly-bound announce passes, spoofed announce rejected, wrong name hash
rejected, PLAIN announce skips binding.

**Why it matters:** this makes the fork *stricter* than upstream but no stricter than python
RNS — it rejects exactly what the reference rejects. No conformant announce is newly refused.

## D5 — MessagePack decoder hardening {#d5}

**Commits:** `c2cdf92`

**Files:** `Sources/ReticulumSwift/Protocol/MessagePack.swift`,
`Tests/ReticulumSwiftTests/MessagePackHardeningTests.swift`

The decoder runs on raw inbound bytes before any signature check — reachable pre-auth via
announce `app_data` and resource metadata.

- **Depth bomb:** new module-private `messagePackMaxDepth = 64`, with a `depth` parameter
  threaded through `decodeValue` / `decodeArray` / `decodeMap`, throwing
  `MessagePackError.decodingFailed` past the cap. Unbounded recursion overflows the native
  stack, which is an uncatchable crash in Swift, not a throw.
- **Width bomb:** the bounded `reserveCapacity(min(count, remaining))` guards were *already*
  upstream; the fork adds regression tests for them.

Four tests: array32 and map32 width bombs, 200-deep nesting rejected, 8-deep accepted.

**Why it matters:** this narrows the accepted payload set. RNS/LXMF structures nest only a
few levels and python's `umsgpack` is bounded by the interpreter recursion limit, so the cap
restores parity rather than departing from it.

## D6 — Half-open link establishment watchdog {#d6}

**Commits:** `d989b02`

**Files:** `Sources/ReticulumSwift/Transport/ReticulumTransport.swift`

A responder link waits in `.handshake` for the initiator's LRRTT. If that never arrived the
per-link stale watchdog never ran (it only starts on activation), `cleanupLinks` skipped it
(`.handshake` is not terminal), and the link was pinned in `activeLinks` and
`destination._links` forever — an unauthenticated LINKREQUEST flood could exhaust memory
and CPU.

New `closeIfUnestablished(linkId:)` arms an `ESTABLISHMENT_TIMEOUT_PER_HOP * 5` timer that
closes any still-unestablished link, making it terminal so the existing sweep reclaims it.

**Known gap:** untested.

## D7 — Keychain identity persistence hardening {#d7}

**Commits:** `d989b02` — **schema ledger [S1](#schema)**

**Files:** `Sources/ReticulumSwift/Crypto/Identity.swift` (`saveToKeychain(service:account:)`)

| Aspect | Upstream | Fork |
|--------|----------|------|
| Accessibility class | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` |
| Write strategy | `SecItemDelete` then `SecItemAdd` | `SecItemUpdate`, falling back to `SecItemAdd` only on `errSecItemNotFound` |
| Error handling | Delete result ignored; add failure throws | Any non-`errSecItemNotFound` update error throws instead of silently proceeding |

Both changes protect the identity key, which is unrecoverable if lost. The accessibility
relaxation lets a background relaunch (BLE/location wake-up) with the device locked read the
key, instead of concluding it is missing and regenerating a new identity. The update-or-add
removes a window where a locked device could successfully delete the real key and then fail
to add the replacement, destroying the only copy.

**Migration:** `SecItemUpdate` carries `kSecAttrAccessible` in its attribute dictionary, so
the next save of an existing identity migrates the item in place. No explicit step, and **no
rollback** — an item already migrated stays readable-while-locked even if the code is reverted.

**Known gap — deliberate security trade-off.** `AfterFirstUnlockThisDeviceOnly` is a strictly
weaker at-rest posture than upstream's `WhenUnlockedThisDeviceOnly`: the identity private key
is readable by the process while the screen is locked, once the device has been unlocked
since boot. It remains non-exportable off-device (`ThisDeviceOnly`). This is availability
over confidentiality, chosen for background operation.

## D8 — Ratchet key file protection {#d8}

**Commits:** `d989b02` — **schema ledger [S2](#schema)**

**Files:** `Sources/ReticulumSwift/Crypto/RatchetManager.swift`

| Aspect | Upstream | Fork |
|--------|----------|------|
| Write options | `.atomic` | `[.atomic, .completeFileProtectionUntilFirstUserAuthentication]` |
| Backup | included in device backups | `URLResourceValues.isExcludedFromBackup = true` (best-effort, `try?`) |

The file holds forward-secrecy **private** keys and its existing signature only authenticates
it — it does not protect confidentiality. The protection class now matches the identity and
database stores; backup exclusion keeps keys whose whole purpose is to bound the blast radius
of an identity compromise out of unencrypted backups.

**Migration:** applied on next write. A file written by an older build keeps its old class
until then.

**Known gap:** backup exclusion is best-effort (`try?`) and failures are swallowed, so it is
not guaranteed. Practical consequence: ratchets no longer survive a device restore. Acceptable
for ephemeral forward-secrecy state, but it is a behavioural change.

## D9 — Multipeer Connectivity discovery & reconnect {#d9}

**Commits:** `d7dcc67`

**Files:** `Sources/ReticulumSwift/Interfaces/MPC/MPCInterface.swift`

New `discoveredPeers: [String: MCPeerID]` retains peers seen by the browser *or* connected
via our advertiser, so a dropped link can be re-invited within the session.
`sessionForInvitation(from:)` replaces the internal `getSession()` (not `public`, so no API
break).

- **Deterministic invite direction.** Both devices advertise *and* browse, so upstream had
  each side inviting the other on discovery — two competing session-formation attempts that
  MCSession resolves by tearing one down ~2 s after connecting (the cold-start flap). Now
  only the lexicographically smaller display name invites; the higher-named side auto-accepts
  and fallback-invites after 4 s if nothing formed, covering asymmetric discovery.
- **Bounded reconnect.** Up to 6 attempts, first immediate then 1 s steps, role-staggered
  (+500 ms for the secondary) so the two sides never re-invite simultaneously. Upstream
  waited for the next `foundPeer`, which only fires on fresh discovery — in practice the next
  app launch, which stranded the first message.
- **Half-open session healing.** A peer we still consider connected re-inviting us means our
  half of the link is dead while MCSession has not noticed; returning the stale session made
  MPC sit on it until its ~60 s keepalive expired. The fork rebuilds the MCSession so the
  incoming invitation handshakes into a clean one immediately. Guarded on the peer already
  being present, so first-time invites are untouched.
- `invitationHandler(session != nil, session)` replaces an unconditional `true`, so a nil
  session is declined rather than accepted.
- `browser(_:lostPeer:)` now clears `discoveredPeers`; invite timeouts dropped 30 s → 15 s
  (10 s for reconnects).

**Known gap:** untested.

## D10 — `TCPTransport` thread-safety {#d10}

**Commits:** `36b9d20`

**Files:** `Sources/ReticulumSwift/Transport/TCPTransport.swift`

An `objc_retain` use-after-free under concurrent connect/disconnect plus timeout. `state` is
a `TransportState` whose payload can carry an `Error`, mutated on `connectionQueue` by
NWConnection callbacks while external callers (the reconnect loop) read it from other
threads, racing the retain/release of that payload.

```diff
-public private(set) var state: TransportState = .disconnected
+private let stateLock = NSLock()
+private var _state: TransportState = .disconnected
+public var state: TransportState { stateLock.lock(); defer { stateLock.unlock() }; return _state }
```

`connect()`, `send(_:completion:)` and `disconnect()` now all hop to `connectionQueue`
(`connectOnQueue` / `sendOnQueue` / `disconnectOnQueue`), so every access to connection,
state and timeout work items is serialised on the same queue the callbacks run on. The
public name, type and read semantics are unchanged — source-compatible for readers.

**Known gap:** the pre-existing guard `state == .disconnected || state != .connecting` in
`connectOnQueue` was carried over verbatim. It is tautologically true for every state except
`.connecting`, and was not touched by the fork.

## D11 — TCP reconnect backoff cap {#d11}

**Commits:** `c154af3`

**Files:** `Sources/ReticulumSwift/Interfaces/TCPInterface.swift`

`ExponentialBackoff(baseDelay: 1.0, maxDelay: 10.0)` — reconnect backoff capped at 10 s
instead of the 300 s default. A device that loses and regains connectivity accrues failed
attempts while offline, so the default scheduled the next retry 32–64 s after internet
returned. Trade-off accepted in-code: more frequent retries against a genuinely dead endpoint,
in exchange for ≤10 s recovery.

## D12 — `NetworkLog` routing diagnostics {#d12}

**Commits:** `ebda44b` (the type and first markers), `c154af3` (fallback markers); further
markers added throughout the D1/D2 commits

**Files:** `Sources/ReticulumSwift/Logging/NetworkLog.swift` (new file, new `Logging/`
directory), call sites in `AnnounceHandler.swift`, `PathTable.swift`,
`ReticulumTransport.swift`

A public, opt-in, file-backed diagnostic log dedicated to *following routing decisions*, kept
separate from the `os.Logger` firehose. It is a no-op until `configure(directory:)` is called.
Markers: `ANNOUNCE recorded=`, `PATHTABLE` (throttled snapshot), `[ANNDROP]`, `[RECORD]`,
`[FALLBACK]`, `ROUTE`, `[DUAL]`.

**Performance note captured in-code:** running the full path-table snapshot per announce,
serialised on the `AnnounceHandler` actor, throttled announce processing to ~0.5/s under a
reconnect flood, stalling a contact's TCP announce ~115 s behind the mesh backlog. Hence
`snapshotEvery = 25`, `snapshotThrottleCounter`, and the `if NetworkLog.isEnabled` guard
around snapshot construction.

**Known gap — the log records identifiers.** Destination hashes (first 8 bytes), interface
IDs, hop counts and node display names (control characters stripped) are written to an
unprotected, non-backup-excluded file. `NetworkLog.debugScaffolding` defaults to `true`, so
any build that configures the log gets the full scaffolding. Release builds that never
configure it are unaffected.

**Known gap — scaffolding marked for removal is still present.** The in-code comments commit
to removing the `[MSG]`/`[ROUTE]`/`[ANNDROP]`/`[RECORD]`/`[FALLBACK] register` markers,
`NetworkLog.debugScaffolding` and the `refreshConnectedInterfaces` log line once the
offline/return behaviour is signed off. That cleanup has not happened.

## D13 — Repo hygiene {#d13}

**Commits:** `c25b95e`

**Files:** `.gitignore`

Adds `Derived/*`, `*.xcodeproj`, `*.xcworkspace`. Nothing previously tracked became ignored —
`ReticulumSwift.xcodeproj` and `Derived/` are untracked locally.

---

## Downstream coupling {#downstream}

`kishontivf/LXMF-swift` depends on this fork (its D1 pins
`https://github.com/kishontivf/reticulum-swift.git`, `from: "0.4.1"`) and calls into two
APIs across the boundary:

| LXMF-swift | Calls | Provenance | Risk |
|------------|-------|------------|------|
| D5 — dual dispatch | `ReticulumTransport.sendFallbackCopy(packet:)` | **fork-only** ([D2](#d2)) | Renaming or removing it breaks the downstream build outright |
| D4 — `PATH_DEMOTE_ATTEMPTS` | `PathTable.markPathUnresponsive(_:)` | **upstream API** | The symbol is upstream's and safe; but what an unresponsive path *does* — release the route to a carrier — is fork behaviour from [D1](#d1). Dropping D1 silently makes LXMF-swift's failover assist a no-op |

The second row is the subtle one: a re-sync that keeps the symbol but drops the fallback
model leaves LXMF-swift compiling and quietly ineffective. Re-sync the two forks in lockstep.

---

## Re-sync checklist

When pulling new upstream work:

1. `git fetch upstream && git log --oneline HEAD..upstream/main`
2. Conflict-prone files, in order of likelihood:
   `Sources/ReticulumSwift/Routing/PathTable.swift` (D1, D3 — **by far the most likely**;
   the fork inserts several decision branches into the middle of `record()`, a function
   upstream actively maintains, so any upstream change to path-selection ordering conflicts
   here first),
   `Sources/ReticulumSwift/Routing/AnnounceHandler.swift` (D3, D4, D12),
   `Sources/ReticulumSwift/Transport/ReticulumTransport.swift` (D1, D2, D6),
   `Sources/ReticulumSwift/Interfaces/MPC/MPCInterface.swift` (D9),
   `Sources/ReticulumSwift/Crypto/Identity.swift` (D7),
   `Sources/ReticulumSwift/Protocol/MessagePack.swift` (D5).
3. Diff the migration functions in `PathTable` against
   [Schema & domain changes](#schema). The failure mode to look for is upstream adding a
   column under a name we already use with different semantics — both `PRAGMA table_info`
   guards see it present, neither runs, and the builds silently disagree. Resolve by renaming
   ours to `kvf_…`, never by editing an already-shipped migration.
4. Check upstream has not renamed or removed `markPathUnresponsive` / `isPathUnresponsive`
   (D1 depends on the latter) or the `PATH_STATE_*` constants.
5. Re-sync `kishontivf/LXMF-swift` in lockstep — see [Downstream coupling](#downstream).
6. `swift build && swift test`.
7. Update the base/HEAD/net-diff/last-reviewed lines at the top of this file, refresh
   [Status at generation](#status), and append any new fork commits to the
   [commit ledger](#summary).

---

## Status at generation {#status}

**Generated:** 2026-08-02 (all figures below measured on that date, against
`upstream` = `git@github.com:torlando-tech/reticulum-swift.git` after `git fetch upstream`).

| Metric | Value |
|--------|-------|
| Fork HEAD | `36b9d20` — 2026-07-14 (19 days old) |
| Upstream base we sit on | `52e2a9a` — 2026-06-23 (**40 days old**) |
| Upstream `main` tip | `52e2a9a` — identical to our base |
| Upstream commits we are missing | **0** — `upstream/main` has not moved since we branched |
| Our commits ahead of upstream | **16** (10 content commits + 6 merges) |

So the fork is strictly ahead: nothing to pull, 16 commits to carry. The "40 days old"
figure is the age of upstream's newest work on `main`, not a backlog — upstream `main`
itself has been idle since 2026-06-23.

**Unmerged upstream branches** (not on `main`, so not counted above, but they are where the
next re-sync conflict will come from):

| Branch | Ahead of `main` | Tip | Relevance |
|--------|-----------------|-----|-----------|
| `fix/conformance-failures` | 27 | `c2f335c` — 2026-06-24 | **The one to watch.** 31 files, and it touches `AnnounceHandler.swift` and `ReticulumTransport.swift` — direct overlap with [D1](#d1), [D2](#d2), [D3](#d3), [D4](#d4), [D6](#d6) and [D12](#d12). It also splits the transport into `ReticulumTransport+Transport.swift` / `+Tunnels.swift`, so our transport changes would need re-homing, not just merging |
| `fix/ios-rnode-session-restoration` | 2 | `604a82f` — 2026-07-31 | Newest upstream work anywhere. Touches `BLETransport.swift` and `RNodeBLEIdentityTests.swift` only — no overlap with our D-sections |
| `docs/add-implementation-status` | 1 | `5d7ebe6` — 2026-03-27 | `ReticulumSwift.swift` only; documentation/status. No overlap |

Four further upstream branches (`cleanup/remove-unused-module-entry`,
`fix/invalidate-stale-path-interface`, `fix/link-data-no-header2-conversion`,
`fix/pathtable-ne-safe-h4`) are 0 ahead of `main` — already contained in our base, nothing
to re-apply.

**Ledger date note:** the commit ledger shows **author** dates, and author and committer
dates agree throughout — nothing in this fork was rebased. `c25b95e` (2026-05-30) reads as
older than the base it sits on because the fork branched from an earlier upstream point and
later took `upstream/main` in as a merge (`7e68ab6`) rather than rebasing onto it. Two
commits have a committer date one day after their author date (`c2cdf92`, `d989b02`) — PR
merge timing, no history rewrite.

## Document changelog {#doc-changelog}

Revisions to *this file*, newest first. One row per edit; the "Covers" column is the fork
HEAD the file described at that point.

| Date | Covers | Change |
|------|--------|--------|
| 2026-08-02 | `36b9d20` | Added [Status at generation](#status) and this changelog. |
| 2026-08-02 | `36b9d20` | Restructured to match `kishontivf/LXMF-swift`'s format: [D1](#d1)–[D13](#d13) numbered divergence sections with `{#dN}` anchors, summary table with `Depends on`, commit ledger, [Schema & domain changes](#schema) as a standing register with ledger rows [S1/S2](#schema) and rules, per-section `Known gap` callouts, new [Downstream coupling](#downstream) chapter, and a re-sync checklist. Dropped source line-number citations. |
| 2026-08-02 | `36b9d20` | Corrected seven per-file diff counts in the summary table that had used git's total-lines-changed column as the insertion count; the table now sums to the verified +1021 / −46. |
| 2026-08-02 | `36b9d20` | Initial version — chapter-based layout (schema vs. implementation logic), commit index, wire/interop impact, risks and open items. |
