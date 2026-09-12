# Pairing UX — field test notes from a real self-hosted setup

> **Status:** Field notes (2026-08-15 through 2026-08-20). C0 (pairing invents
> a drive) is superseded — both sides derive. M6 (opening an HTTP drive moves
> the home server) is closed. Open: M4 (pre-0.40 DID auth), M8 (desktop
> “saved locally” toast), M12 (presence over Iroh), extra-workspace inventory.
> Companion to [`device-pairing.md`](../device-pairing.md), which owns the
> pairing/onboarding UX; anything adopted from here belongs there.
>
> **Outcome (revised 2026-08-20):** C0 below is a pre-derivation finding.
> The personal-drive DID is derived from the Agent key
> ([`deterministic-personal-drive.md`](../deterministic-personal-drive.md)), so
> two devices with the same secret name the same home. They cannot invent
> disjoint personal-drive subjects. Pairing + live sync between desktop and
> the HA node was verified 2026-08-17. The 2026-08-15 header ("a blank node
> still cannot pull a peer's drives") described looking up the
> `personalDrive` pointer and minting when it was absent — that path is gone.
>
> **This note has been wrong in both directions in one day.** The first draft
> called it a bootstrap deadlock; the second declared it fixed after a
> rebuild, on the strength of an `INDEXING title="My drive"` log line that was
> a local creation rather than an import. Read "What this cost, and why" at
> the end before trusting any single signal here.
>
> **Evening session (2026-08-15).** Six commits on
> [PR 1272](https://github.com/ontola/atomic-server/pull/1272) took a real
> pre-DID account (drives on atomicdata.dev) from "migration never runs" to
> "drives adopted, but unreadable". See "Migrating a pre-DID account" below
> for what works, what is left, and the build trap that made most of the
> evening measure the wrong binary.
>
> **Setup:** atomic-server as a Home Assistant add-on behind a Cloudflare
> tunnel (`atomic.ontola.io`, GHCR `develop`), plus the macOS Tauri desktop
> app. Findings below are split by whether they reproduce on a **current
> build** or were only ever seen on **0.41.0-beta.2 (Jul 25)**.

## What works, and what only looks like it

Transport is fine. Iroh reaches the add-on through the public relay — both
nodes settle on `euw1-1.relay.iroh.network` within a second of boot — and the
Cloudflare tunnel is not involved in sync at all (it carries HTTPS only).
Pairing itself completes: the peer is dialed and recorded.

**What does not happen is drive transfer.** Verified by asking each node for
the other's drives:

| drive | server | desktop |
| --- | --- | --- |
| `bkvN8DuZ…` (desktop's) | not found locally | present (private) |
| `kZR5Rbwu…` (server's) | present (private) | not found locally |

Disjoint. See C0 for why.

## Confirmed on a current build

### C0 — A blank node invents a drive instead of pulling the peer's (superseded)

**Historical (2026-08-15).** The agent resource for one DID existed in two
divergent copies, and the home was still a `personalDrive` pointer:

| | desktop | server |
| --- | --- | --- |
| `personalDrive` | `did:ad:ZLrn1clJ…` | **absent** |
| `name` | joep.io | Joep Meindertsma |
| `publicKey` | `Qmfp…rcQ` | `Qmfp…rcQ=` |

Sequence then: sign in on the desktop → `fetchPersonalDriveSubject` asked a
server for the agent's `personalDrive` → the server's copy had none →
`adoptLegacyDriveList` provisioned a fresh private drive locally → pairing
resolved *that* drive and reported "Your workspace is here". The two nodes
held disjoint drive sets (`bkvN8DuZ…` vs `kZR5Rbwu…`). Nothing asked the peer
what it held.

**Why this cannot happen for the personal drive anymore.**
`fetchPersonalDriveSubject` (`helpers/personalDrive.ts`) derives the subject
from the Agent key (`agent.personalDriveSubject()`). The pointer is not
identity. `createDrive({ personal: true })` pins that same DID; a repeat
genesis merges. Two devices with the same secret therefore *name* the same
home before any network round-trip. M23 then stopped *materializing* that
subject before `deviceHasDriveData`, so an empty local shell is no longer
read as "you already have your workspace".

What is still true, and is not C0: pairing syncs the named drive (and
whatever the peer pushes for it). Extra workspaces the agent holds elsewhere
arrive by being listed on that shared home, or by an explicit pull — there is
still no "ask the peer which drives you have" inventory. That is a sync-scope
question, not an identity one.

### C1 — The pairing input rejects a server address

The one thing that still reliably stops someone. There are two near-identical
inputs with different contracts:

| Screen | Accepts | Placeholder |
| --- | --- | --- |
| Sync page (`SyncRoute.tsx:1582`) | a **server address** | `localhost:9883 or your-server.example` |
| Getting-started `ConnectDeviceStep` | an **`atomic:pair` code** or bare node DID | — |

Typing `atomic.ontola.io` — the obvious thing, and valid one screen over —
fails with *"Not a pairing code: expected an atomic:pair link."* Observed
twice on the current build, by someone who knew exactly what they were doing.

Two contributing details:

- **The error names one of two accepted formats.** `decodePairingEnvelope`
  (`browser/lib/src/pairing.ts:175`) takes an `atomic:pair?…` URI **or** a
  bare `did:ad:node:…`; the message (`pairing.ts:185`) mentions only the
  first. Someone holding a node DID — which the Sync page shows with a copy
  button — is told it is invalid.
- **The resolution already exists, and is switched off here.**
  `ConnectDeviceStep` imports `fetchManagedInfo` and `normalizeServerUrl`,
  and at line 225 turns an address into a node DID — gated
  `if (isNode || !baseURL) return`. So the app resolves `atomic.ontola.io`
  in a browser tab and refuses to on the desktop, the only device that can
  act on it.

**Fix:** when the pasted text isn't a valid envelope, run it through
`normalizeServerUrl` + `fetchManagedInfo(url).nodeId` before erroring, and
reword the message to name both accepted forms. Both helpers are already
imported in that file.

### C2 — Drives created after boot are undiscoverable until a restart

`announce_drives_pkarr` is called once, inside Iroh transport startup
(`server/src/serve.rs:298`). Nothing re-announces on drive creation.
Observed on the `develop` image:

| time | event | drives announced |
| --- | --- | --- |
| 12:17 | add-on boots, empty store | `announced 0 drives` |
| 13:43 | three drives created from the browser | still 0 |
| ~13:48 | pairing attempted → fails | still 0 |
| 13:50 | add-on restarted | `announced 3 drives` |

For a long-running server this is the normal case: create a drive, and
discovery cannot see it until the next restart. Two related notes:

- The log line prints when the loop **finishes**, not at startup — 0.4 s for
  3 drives, ~3.5 min for 1,671. It is a completion marker, not a boot marker.
- Pkarr records carry a TTL, so a server running for weeks goes stale even
  with no new drives.

Re-announce on drive creation, and periodically.

### C3 — A second launch opens a window with a dead server

No longer panics (it did in July). It now logs
`[node] the embedded server stopped: Failed to create redb … Database
already open. Cannot acquire lock.` — but the app still opens a second
window whose embedded server is dead. Should focus the running instance
instead.

### C4 — The app reads `.env` from its working directory

`read_opts` calls `dotenv()` (`server/src/config.rs`), so launched from a
terminal the desktop app parses the cwd's `.env`. Configuration silently
depends on where it was started from — invisible from Finder, confusing
otherwise.

### C5 — Startup announce is O(drives) on the path to being reachable

A store that had accumulated 4.0 GB / 4,339 drives from past dev work took
~3.5 min to become reachable versus ~2 s fresh. A dev artifact here, but the
shape is real for any large store, and it sits directly on the onboarding
path.

### Adjacent — the app does not run at all over plain HTTP

Not pairing, but it blocks the same journey and cost the first hour.
`crypto.randomUUID` is secure-context-only; over plain HTTP on a
non-localhost origin (`http://homeassistant.local:9883` — how essentially
everyone first opens a Home Assistant add-on) it is absent, and
`presence.ts:82` calls it while loading any drive, so the first paint is the
"Error loading resource" screen rather than a degraded app. OPFS and Web
Locks are withheld too, so ClientDb caching and offline are off — that part
is inherent to plain HTTP and cannot be polyfilled.

Fixed by a `crypto.randomUUID` polyfill beside the existing
`crypto.subtle.digest` one in `browser/data-browser/src/index.tsx`, which
covers the ~10 other `randomUUID` call sites too. Verified present in the
current bundle.

## Migrating a pre-DID account (evening session, 2026-08-15)

Tested against a real account: agent at
`https://atomicdata.dev/agents/<publicKey>`, ~53 drives listed on it,
atomicdata.dev running a pre-0.40 server with no DID support. Client was the
desktop app built from PR 1272.

### Where the chain reaches now

| step | state |
| --- | --- |
| Migration runs at all | fixed — see M1 |
| Legacy Agent fetched from atomicdata.dev | works (that resource is public) |
| Legacy `drives` list adopted onto the derived drive | fixed — see M2 |
| Reading those drives | **blocked** — see M4 |
| One stable personal drive | **broken** — see M5 |

### M1 — Builds were silently stale, so nothing measured what it claimed

The most expensive finding, and not about pairing at all.

`vite` consumes `@tomic/lib` from its built `dist/`, not from source. `dist`
is gitignored, built by tsup, and nothing rebuilt it: `tauri.conf.json` calls
`pnpm -C browser/data-browser build:tauri`, which went straight to
`vite build`. The root `browser` script orders this correctly
(`--filter "@tomic/lib" run build` first); the Tauri path bypassed it.

So editing `lib/src` and building the app produced an app **without the
edit**. Nothing failed: source correct, `vitest` green (it runs `src`), bundle
builds fine — only the running app was stale. Three rounds of "still broken"
were all measuring the PR's original code.

**CI cannot catch this.** It builds every package from scratch in dependency
order on a clean checkout, so `dist` is always fresh there. The failure exists
only where artifacts survive between runs — a developer machine.

Fixed in `f03360f3`: `build:tauri` and `dev:tauri` build their workspace deps
first. Still worth adding: a preflight that **fails loudly** when `lib/dist`
is older than the newest file in `lib/src`. That catches the next variant
rather than this one, including paths that bypass the scripts.

General rule this is an instance of: *a build artifact that is an input to
another build needs its freshness enforced or asserted — a comment is not a
contract.*

### M2 — The legacy drive list is adopted (fixed)

`isAdoptableDriveSubject` kept only subjects matching the current
`serverUrl`. A pre-DID account keeps its drives on the server it is migrating
**away** from, while the client already points at the new home, so every drive
was filtered out and `adoptLegacyDriveList` returned on an empty list.

`92c8479f` also accepts the legacy Agent's own origin — the account being
migrated from, which the user authenticated against. Confirmed working: the
app now fetches every drive from the legacy list.

Deliberately unchanged: a stale entry naming `http://localhost:9883` is still
dropped, which is the case `legacy-drive-adoption.test.ts` exists for (it once
made a hosted app issue requests at the signed-in user's own machine). A first
attempt relaxed this to "any http(s) origin" and broke those specs — the tests
caught it.

Known limit: only the legacy Agent's *exact* origin is adopted, so
`staging.atomicdata.dev` drives on an `atomicdata.dev` account are still
dropped. Extending this needs an origin *set*, not a single origin.

### M3 — Migration inputs did not survive a restart (fixed)

`legacySubject` and `initialDrive` exist only on the secret, which is read
once, at sign-in. `agentStorage` persisted the keypair and subject and dropped
both, so every later launch rehydrated an Agent with
`legacySubject === undefined` and `adoptLegacyAgentIdentity` returned on its
first line. Fire-and-forget, so no error surfaced.

`6721b7ce` stores and restores them on both the non-extractable and readable
paths. `c640a686` additionally treats `initialDrive` as a second source of the
old home.

Migration consequence worth documenting for users: once the keypair is stored
non-extractably the secret is deliberately unreadable, so nothing can
back-fill these fields. **Everyone upgrading past this has to re-enter their
secret once.**

### M4 — No authentication against a pre-0.40 server (open)

Adopted drives all return `401 — not publicly readable`. The client logs:

```text
[atomic-lib] Skipping DID authentication request to 'https://atomicdata.dev':
             server version unknown (assuming <0.40).
```

`shouldSkipDidAuthForLegacyServer` (`serverCapabilities.ts`) suppresses DID
auth for an origin that sends no `X-Atomic-Server-Version` header — and
nothing takes its place, so the requests go out anonymous.

What is missing is a legacy fallback: against a pre-0.40 origin, sign as
`agent.legacySubject` rather than the DID. Same key, same scheme the old
server already accepts; only the identifier differs, and the secret carries
it.

This is required whether migration *links* the old drives or eventually
*copies* them — either way they must be readable first. Until it exists, a
migrated account gets a list of drives it cannot open, which is arguably worse
than an empty list because it looks like it worked.

### M5 — WebCrypto signatures are not reproducible, so every lookup minted a new drive (root cause found, fixed)

The symptom grew as the session went on: three `"My drive"` resources in 25
seconds, then — after a clean store reset — **411 distinct personal drives in
about 30 seconds**, 47 MB of store.

Settled by exporting the polluted store (`atomic-server export`) and reading
the resources instead of the logs:

```
total resources:        2346
resources isA Drive:     411      ← every one named "My drive"
distinct subjects:       411
distinct genesis certs:    1      ← byte-identical
```

All 411 carry **one byte-identical genesis certificate**: the personal-drive
nonce, `createdAt: 0`, empty parent, the same signer pubkey. The subject IS
the Ed25519 signature over those bytes, so all 411 were checked against that
single cert and key:

```
signatures that VERIFY: 411 | invalid: 0
distinct signature bytes: 411
```

411 different, all-valid signatures over the same message with the same key.
Ed25519 is deterministic per RFC 8032, but that is a property of an
*implementation*: WebCrypto promises nothing, and the WKWebView provider the
desktop app uses randomizes the nonce. So `personalDriveSubject()` returned a
different DID on every call, the reuse check in `Store.createDrive` searched
for a subject that had never existed, and each miss minted another drive.
Every downstream symptom — the "Server error" drive, the empty "My drives",
"DID Resource not found locally" — follows from that.

The runaway rate is the same bug feeding itself: the app looks up the personal
drive, derives a fresh DID, doesn't find it, creates it, and the next lookup
derives another one.

**Why the earlier "ruled out: the crypto" was wrong.** `d7d06322` added
coverage under `SubtleCryptoProvider` — the right provider, in an environment
where it cannot fail. Node's WebCrypto Ed25519 *is* deterministic (checked:
`true`). The test asserted exactly the right property somewhere it could only
ever pass, and reading it green is what sent the next several hours after the
server's merge path instead. A test that exercises a real provider cannot
catch this; reproducing it needs a signer that randomizes on purpose.

**The fix.** Derive the personal-drive subject once, from the raw private key,
with noble's deterministic implementation — matching `ed25519_dalek` on the
server — and cache it on the Agent. It cannot be recomputed later because the
stored keypair is non-extractable, so it is persisted beside the agent in
IndexedDB, exactly as `legacySubject` and `initialDrive` already are.
`createDrive` pins the new drive to that subject rather than re-signing, which
was a second instance of the same bug: even a correct derivation was discarded
because `newResource` minted the drive's subject through the same
non-deterministic signer.

When neither a cached subject nor a deterministic signer is available, the
Agent now **throws instead of signing**. An unreproducible subject is worse
than none: minting under it is precisely what produced 411 drives with no
signal that anything was wrong.

**Carry-over:** an already-signed-in session has no cached subject and no way
to recompute one, so it must sign in with the secret once more. Sessions
created after the fix persist it at sign-in.

**Wider lesson:** `repeat_genesis_is_mergeable` in `lib/src/commit.rs` is
built on "every device mints the same cert, so the same DID". That assumption
was load-bearing and unenforced on the client. Deriving identity from a
signature requires the signer to be deterministic — a requirement worth
stating wherever it is relied upon.

### M6 — Adopting a drive hands the whole session to the old server (fixed, 2026-08-20)

The migration working is what used to break the app.

`AppSettings.setDrive` used to repoint the entire app at *any* HTTP drive's origin:

```ts
if (newDrive.startsWith('http://') || newDrive.startsWith('https://')) {
  setBaseURL(new URL(newDrive).origin);
  serverURLStorage.set(url.origin);
}
```

Migration restores drives that live on `atomicdata.dev`. Opening one moved the
session to that pre-0.40 server — which cannot do DID auth and does not speak
the v2 websocket — so authentication timed out after 30s, the socket retried
forever, and every local `did:ad:` resource 404ed because the client was asking
the wrong machine.

Measured on a run with the app's own server captured: **0 requests from the
webview reached `localhost:9883`** (the 153 in the log were an unrelated
headless Chrome), while the console looped:

```
WebSocket connection to 'wss://atomicdata.dev/ws' failed
Auth error: Timed out waiting 30000ms for WS tag 2
[Store] Server disconnected / [Store] Server connected   (repeating)
```

The embedded server was healthy throughout — HTTP root in 0.9ms, correct
default agent, 100ms durable-flush tick running.

This was the parent of most of that evening's symptoms: "Server error" on every
drive, the private drive not resolving, the migration fetch timing out (`curl`
gets that same resource in 120ms), and the lost edits.

**Decision, not a blanket ban on HTTP origins.** A bare origin
(`https://host`, no path) is still a server switch — that *is* what "open this
URL" means when the URL is the machine. An HTTP subject *with a path* is a
drive. `Store.setDrive` / `AppSettings.setDrive` set it as the current
workspace and leave `serverUrl` alone. Fetch goes to the subject's own origin;
live SUB / SYNC_VV / presence stay on the home websocket (`isLiveSyncedDrive`).
A drive adopted from a server you are migrating *away from* cannot take the
session with it.

Pinned by `browser/lib/src/store.set-drive.test.ts`. Reading those drives
still needs M4 (legacy auth against a pre-0.40 origin); this fix only stops
the session move.

### M7 — A foreign origin's websocket took the whole app offline (fixed)

`WSClient` called `store.setServerConnected(false)` from its error and close
handlers with no check that the socket belonged to the current server. A client
holds one socket per origin, and adopted drives add origins the app does not
depend on — old, unreachable, or gone. Each failure marked the entire store
disconnected, so the app showed "Working offline" and queued writes while its
own server answered in under a millisecond.

Fixed by gating every global connection-state change on "this socket is the
app's server". The regression test was checked to FAIL without the gate, not
merely to pass with it — the lesson from M5, where a test asserted the right
property in the one environment where it could not fail.

### M8 — "Your changes are saved locally" is false on desktop (open)

Offline edits mark subjects dirty in the outbox, but the *content* lives in the
Loro doc, which is persisted by the ClientDb: "On reload the Loro doc rehydrates
from clientDb" (`local-outbox.ts`). The desktop app runs with the ClientDb off
by design — the embedded server is meant to be the local store — so while
offline, edits exist only in memory and a restart loses them, under a toast
promising the opposite.

Server-side durability is not the problem: `serve.rs` runs a 100ms durable-flush
tick, and the desktop goes through that same path.

Either the outbox must persist content without the ClientDb on this platform, or
the app must not claim local safety it does not have.

### M14 — Cursors crossed the peer link but the text did not (fixed)

Remote carets never appeared between the desktop and the HA node, and the
receiving browser logged `The container does not exist in the doc` on every
keystroke the other side typed.

The transport was not the problem, which is what made this take a while. Frames
were measured going both ways (190–200 bytes out, 371–531 in), HA rejected
nothing, and the payload survives the trip intact — it is base64, so the
`as_bytes()` / `from_utf8_lossy()` round-trip in the relay is lossless.

The gap was that only *half* of a collaborative edit was crossing. Two separate
client channels carry an edit, and they are easy to mistake for one:

| client call | carries | crossed the link? |
| --- | --- | --- |
| `broadcastLoroEphemeralUpdate` | `CursorEphemeralStore` bytes — cursor positions | yes |
| `broadcastLoroSyncUpdate` | `LoroDoc` ops — the actual characters | **no** |

`broadcast_ephemeral` had exactly two callers, `Handler<LoroEphemeralUpdate>`
and `Handler<PresenceUpdate>`. `Handler<LoroSyncUpdate>` fanned out to local
websocket subscribers and stopped there. A caret pointing into text the
receiving document has never heard of is exactly what Loro refuses to place.

**Fixed** by relaying document ops too, as a third `ephemeral_kind` (`DOC`) on
the existing frame rather than a new frame type. Two things differ from presence
and are switched on the kind byte:

- **Admission is on write, not read.** Presence discloses who is looking at
  what and authors nothing, so read is enough. Uncommitted ops are somebody
  else's characters appearing in a document; a peer with read access has no
  business putting text in front of an editor as though it belonged there.
- **A looser size ceiling** (1 MB vs 64 KB). A keystroke is tens of bytes but a
  paste is one op, and the presence ceiling would drop exactly the edits most
  worth relaying.

Nothing is written to the store on receipt: relayed ops go to open editors and
become durable only if a local user saves, which produces a signed commit under
that user's own identity. Worth stating plainly, because it means a paired peer
can put text in a document you have open, and your save signs it.

### M14a — what the A/B actually showed, and what the first write-up got wrong

The first version of this note said committed state "does cross on save", which
implied a save would make an edit appear for the other user. It does not. A/B on
one variable, same page instance on both sides, only the `DOC` relay toggled:

| | relay on | relay off |
| --- | --- | --- |
| text in the peer's **store** | yes | **yes** (`imported update`, 190ms) |
| text in the peer's **open editor** | yes, ~2.5s | **never** (still absent at 12s) |
| caret renders | yes | yes |

So a save puts the edit on the other node's disk and no further. The open page
does not re-render — `ExternalChange` carries a Loro snapshot to subscribers,
but it does not reach a live editor. Only a reload shows it. That the caret
still rendered in the control run is what rules out a dropped websocket: the
channel was up, and content specifically was not travelling it.

This is a better fit for the reported symptoms than the original story. It is
not a narrow race — live collaboration between two nodes did not work in an open
window at all, in either direction. It is worth re-testing "table rows do not
sync" against this: same shape (content on disk, not in the open page), so it
may be the same root cause rather than an unrelated bug.

### M14b — a client that misses one delta stops updating, silently (fixed)

Found while confirming the fix, and not fixed by it. The live channel is
deltas with no gap recovery. A client that misses one op — link down, or the
control run above — queues every subsequent delta as pending, because their
dependencies never arrive. The editor then silently stops updating: no error,
no indicator, just a document that quietly stops being live.

Measured: after the control run left the HA page one op behind, the next two
relayed edits did not appear. A reload pulled a fresh snapshot and showed all of
them, and live updates resumed immediately.

So the earlier claim that "a dropped frame costs a moment of divergence, not the
edit — the sender's next save pushes a full snapshot" is wrong for an editor
that is already open. The snapshot reaches the store; the open editor stays
stuck until someone reloads.

**Reproduced on a real document, 2026-08-16.** Two clients on the paired nodes,
same document open. One had typed a line the other never received:

| | line 3 of the document |
| --- | --- |
| receiving editor, open | `awd` |
| same editor, after reload | `awdawdawad oawdinawiodawoi dn` |

The full text was on the server throughout — the reload fetched it immediately.
The open editor had diverged and stayed diverged, with no error and no
indicator, while the other client's cursor kept rendering in it the whole time.

That last detail is why this reads to a user as "presence works but content does
not": presence is stateless, so it cannot get stuck, while content is a delta
stream that can. Both channels are up; only one of them can silently fall behind.

**Fixed and verified in the running app (2026-08-16).** An unappliable delta
injected at a live resource on the receiving device:

| check | result |
| --- | --- |
| `applyIncoming` outcome | `invalid`, not `applied` |
| recovery | `[Store] incomplete Loro import … fetching a full snapshot to catch up` |
| claimed the unapplied commit | no |
| document blanked or failed | no — content intact, no error |

Not stamping `lastCommit` is what makes it work: the echo-dedup at the top of
`applyIncoming` drops updates matching the cached commit, so claiming a commit
we never applied would have discarded the very fetch issued to repair the gap.
The fix would have looked right and done nothing.

The original design note follows, since it still describes what is needed if the
delta stream is ever made to detect gaps itself rather than inferring them from
a failed import:

Fixing it needs the receiver to notice a version gap and ask for a snapshot,
rather than assuming deltas always arrive in order. The `SYNC_VV` handshake
already does exactly this at connect time — it is the reconnect/gap case that
has no equivalent.

### M15 — A peer's new row arrives without its contents (fixed)

Tested because "adding things to a table does not sync" had the same shape as
the document bug fixed above. It is a real bug, but a narrower one than the
first version of this note claimed.

**The first measurement was invalid, and the correction is the interesting
part.** Row added on the desktop, table open on both nodes: the peer's page
received *nothing at all* — zero websocket frames, verified with a hook on the
live socket and a positive control (a document edit on the same page and socket
captured two frames). That looked conclusive.

It was an artefact of the test account. The client subscribes drive-wide via
`subscribeToDrive()` → `encodeSub(store.getDrive())`, and this session's drive
was `https://atomic.ontola.io` — the server root — rather than the DID drive,
because the account was created through an invite and never had a drive set. So
`Handler<ExternalChange>`'s `owner.is_within_drive(...)` check correctly refused
to fan out, and "zero frames" was the server behaving properly on a wrongly
subscribed connection. The giveaway was in view the whole time: the sidebar
showed `/` rather than the drive name, and `/search?parents=https://atomic.ontola.io`
was returning 500.

With the drive set correctly, the same test gives a different and much more
specific result:

| | desktop | HA, page open | HA, after reload |
| --- | --- | --- | --- |
| row exists | yes | **yes** — row 3 renders, footer count 2 → 3 | yes |
| row's `name` | `RowGamma-5514` | **empty** | `RowGamma-5514` |

So membership propagates live and content does not. The peer's page learns a
third row exists, renders it, and leaves the cell blank until a reload.

That rules out the drive-fanout path being dead, which is what the first version
of this note asserted. What it does not yet explain is why the `UPDATE` frame
that carries the row — `Handler<ExternalChange>` encodes a full Loro snapshot
plus `commit_id` — leaves the client with a resource that has no `name`. Two
candidates worth separating: the frame for the row subject is never sent (only
the parent table's own change is, which alone would move the count), or it is
sent and the client stores it in a way the table's cell does not read.

### M15a — corrected again: the data arrives, the table does not re-render

The version above said "membership propagates live and content does not". Also
wrong. Content propagates. Read directly out of the live store on the receiving
page, while those same cells rendered blank:

| subject | `name` | `isA` | `loading` | `error` |
| --- | --- | --- | --- | --- |
| `ZkDx6E0iQs6…` | `RowEta-FLAGS-7791` | set | false | none |
| `f3R9qMqKjOc…` | `RowTheta-CONSOLE-6203` | set | false | none |

Complete, class set, not loading, no error. So the row crosses the peer link,
imports cleanly, and is in the store with its name — and the table shows an empty
cell. **This is a render bug, not a sync bug.** Everything below the UI is
working.

Supporting detail from a frame capture on the receiving socket: each new row
arrives as one `SNAPSHOT|PUSH` frame followed by several `HAS_COMMIT_ID|PUSH`
deltas from the commit path, and nothing calls `failResource` — consistent with
imports reporting `complete`, which the store contents confirm.

**Two dead ends recorded so the next person does not repeat them.** Both looked
compelling and both were aimed at the wrong layer:

1. *The server mislabels the frame.* `Handler<ExternalChange>` sent a payload read
   from `Tree::LoroSnapshots` without `flags::SNAPSHOT`, unlike the normal push
   path. Fixed, verified on the wire (`flags: 5`), symptom unchanged. The fix is
   kept because labelling a snapshot as a snapshot is correct on its own terms,
   not because it fixes anything here.
2. *The client ignores `SNAPSHOT` on the push branch.* Real — `applyIncoming` is
   called without `replaceLoroDocsFromRemote` there, only on the pending-GET
   branch. But imports complete and resources are correct without it, so it is
   not implicated in this symptom.

**Fixed and verified end-to-end (2026-08-16).** A row created on the paired node
appeared on the other device with its name, live, no reload — `aria-setsize`
9 → 10, footer count 8 → 9.

The cause was not the cell at all. `memberCount` is frozen at the count the
collection had when it first became ready, deliberately, so a materialising
session row never remounts and drops keystrokes. Rows below that index render as
collection members; rows above come from `newRowSubjects`. A row from a peer is
neither — it grows the collection but not the baseline, and it is not one of this
session's drafts, so nothing draws it. `totalMembers` 8 against `aria-setsize` 5.
The baseline now accounts for what this session contributed and lets anything
beyond that raise it.

Worth recording that the earlier reading here — "the cell is empty" — was itself
wrong. Five named rows, one empty row and a footer count of eight meant the three
new rows were not being rendered at all; the single empty row was the trailing
placeholder. Reading "empty cell" instead of "missing row" sent the next two
hours at the wrong layer.
Prime suspect is the React Compiler memoisation pitfall this repo has hit before
— reading `resource.get(...)` into a variable during render memoises on the proxy
identity, and internal mutation does not invalidate it. A reload rebuilds the
component tree, which is exactly why reloading "fixes" it.

Cheapest harness for the next attempt: two atomic-server instances on one
machine rather than deploying to the Pi — `cargo build` instead of an 11-minute
cross-build. One constraint: do not start a second vite dev server, as two
wuchale extractors race on `src/locales/*.po` and corrupt the catalog; have the
second instance serve built assets.

Related to M14b: both are a peer's changes reaching an open page only partly.

### M16 — A connect that never opened pins the auth flag forever (fixed)

The desktop app and its embedded server start together, and the webview is ready
first. Any fetch issued in that window fails, and the app settles on:

> Could not reach the server
> `Offline: resource not available locally. Reconnect to fetch.`

It then stays there. Measured: the server bound at 16:23:40 and answered `HTTP
200 in 1.2ms`, while the webview still reported the error screen two minutes
later. Nothing re-fetches; the only way out is the Retry button.

Surfaced constantly during this session because `cargo tauri dev` watches
`desktop/`, `server/` **and** `lib/`, so every Rust edit rebuilds and restarts
the app — but the packaged app has the same shape, and a cold start on a slow
machine lands a user on a dead-end error for a resource that is about to be
available.

The wording compounds it. "Offline" and "Reconnect to fetch" describe a network
that is gone. The machine is fine, the server is fine, and the resource is on
disk — it simply was not listening yet at the instant the page asked. Someone
reading this checks their wifi.

**Two thirds of the first write-up here was wrong, and the correction is the
finding.** It said the reconnect never runs. It does: backoff 2/4/8/16/30s,
indefinitely, and a socket killed *after* opening reconnects within a minute.
One of the runs that seemed to prove otherwise was C3 in disguise — three app
instances alive at once, the oldest holding the redb lock
(`Failed to create redb … Database already open`), so there was no server to
reach and the retries were correctly failing.

**The real mechanism.** `openPromise` only ever resolved:

```js
this.openPromise = new Promise(resolve => {
  ws.addEventListener('open', () => { … resolve(); });
});
```

A socket that dies before opening leaves it pending forever. `authenticate()`
awaits it while holding `isAuthenticating`, and the `finally` that clears that
flag is downstream of the await — so the flag is pinned for the life of the
client. The retry then works perfectly and makes no difference: the new socket
opens, its `authenticate()` takes the `if (this.isAuthenticating) await
this.authPromise` branch onto the dead promise, and waits forever. Auth never
completes, `reportConnected(true)` never fires, and every `ws.fetch` hangs
because `REQUEST_TIMEOUT` only starts after auth.

That is why Retry does nothing (it re-issues the fetch, which queues behind the
same dead auth), why a reload fixes it (fresh client), and why the app can show
"Offline" while holding an ESTABLISHED socket to a server answering in ~1ms.

**Fixed and verified end-to-end.** `openPromise` now rejects when a socket closes
before opening, so the stuck auth settles and the flag clears. Same cold-start
race, measured before and after:

| | before | after |
| --- | --- | --- |
| WS connect | `close code=1006 opened=false` | same |
| server binds | 1s later | 1s later |
| sync status | **Offline, indefinitely** | **Connected** |
| error screen | shown until reload | none |

Unit tests fail without the fix; the second one times out at 5002ms, which is
the deadlock reproducing.

Three things to separate when fixing: a connect that never opened must still
schedule a retry (this is boot ordering, not connectivity); Retry should re-establish
the connection rather than only re-issue the request; and a queued fetch needs a
timeout that runs whether or not auth ever completed, so it can fail honestly
instead of hanging. The message should also stop claiming the network is down when
what it observed was one failed connect.

Same family as M8 and the false-offline work earlier in this note: a transient
condition recorded as a permanent verdict.

### M13 — A newly created resource sorts to the top of the sidebar (fixed)

`RelayTableTest`, created during the M10 work, renders first in the drive tree
rather than last:

```
Joeps drijf | RelayTableTest | D | Tekenign | Ontology | Hey wereld | ChatRoom | ...
```

Noted because it first looked like the resource was missing from the device that
created it, which would have been serious. It is not: the store holds it with
`loading: false` and no error, and it is in the DOM — just in an unexpected
position, so the eye slides past it in a list you know the shape of.

**Fixed.** `sortOrder` and `createdAt` share a number space on purpose —
drag-and-drop mints a fractional key between two neighbours' keys and the server
sorts by the same fallback. A member carrying neither fell back to its array
index, which is not in that space at all: an index of 3 against timestamps
around 1.7e12 sorts to the very front. Measured on the affected drive,
`RelayTableTest` and `Tekenign` had neither property.

Keyless members now inherit the preceding member's key, so they stay where the
server put them. Verified in the running app: the tree ends
"Meetings | Tekenign | Ontology | RelayTableTest" where it previously began
"RelayTableTest | Tekenign".

(This session's findings are numbered M13-M16: `develop` independently used
M9-M12 for different findings while this branch was open, and the note now
carries both sets.)

## Two-person session, 2026-08-17

Joep invited a colleague who also holds a legacy secret. Four reports, which
turned into five findings once the fourth was traced.

**State of play**

| | status |
| --- | --- |
| M17 invite does not switch drive | **fixed** |
| M18 agent names do not propagate | **fixed** |
| M19 "Show profile" opens the wrong resource | **resolved by M18** — the page was right, its contents were a stub |
| M20 colleague sees no rows | explained by M21, not its own bug |
| M21 rows refused because the class is missing | **cause fixed and deployed**, origin still unexplained |
| M22 read-only invitee gets a stuck outbox entry | **fixed** |
| M23 sign-in on a device with no data opens an empty workspace | **fixed** |

Two fixes went in for M21 and are on the branch:

- `fix(validation): an unknown class must not reject the write` — the write is no
  longer refused for a reason the writer cannot act on.
- `fix(outbox): stop discarding table rows in silence when the class is missing`
  — if a commit IS refused structurally, it blocks visibly instead of retrying
  forever in silence.

Neither was deployed at the time of writing, so a console from before the next
deploy still shows `errorCode: 0` and the old behaviour. The two stuck rows
("Henk", "Blaa") are still in the reporter's outbox and should drain on their own
once the server carries the validation fix — no re-typing — which is the cleanest
single check that it worked.

**What is still not explained**, and matters most for the next session: the table
reached the server and its row class did not, on the same drive. M21 records the
parenting asymmetry that probably causes it, as a hypothesis with the test that
would settle it. The fixes above mean this no longer costs data; they do not mean
it is understood.

Joep invited a colleague who also holds a legacy secret. Four distinct problems,
recorded here so each can be reproduced and fixed on its own rather than as one
vague "sharing is broken".

### M17 — Accepting an invite shows the drive but does not switch to it (open)

The invite link opened the shared drive's contents, while the sidebar kept
showing the accepting user's own private drive.

**Already reproduced, by accident, during the M15 work.** After accepting the
same invite in a fresh browser, `localStorage['drive']` held
`"https://atomic.ontola.io"` — the server root — rather than the target's
`did:ad:W2Q3m…`. Two visible consequences: the sidebar rendered `/` instead of
the drive name, and `/search?parents=https://atomic.ontola.io` returned 500,
because the server root is not a resource. Setting the key by hand and reloading
fixed everything.

That also means the invite path leaves the client subscribed drive-wide to the
WRONG drive, which is its own class of bug: `subscribeToDrive()` sends
`encodeSub(store.getDrive())`, so nothing on the shared drive fans out live to
that session. It is very likely why the fourth item below was invisible even
before the deploy gap.

**Reproduce:** accept an invite as a second agent, then read
`localStorage['drive']`. It should be the invite's target.

**First place to look:** whatever the invite accept flow calls after minting the
agent — it navigates to the drive without going through the same drive-setting
path the switcher uses. Related to M6, which is the same class: what "current
drive" means is decided in more than one place.

### M18 — Agent names do not propagate, except through presence (open)

Both users' names migrated correctly from their legacy agents, and presence
shows them correctly. Everywhere else — chatroom avatars, for example — the
other person's name does not appear or does not update live.

Presence is the odd one out because it carries the name IN the payload: the
agent announces itself, so the receiver never has to resolve anything. Every
other surface resolves the agent subject to a resource and reads `name` off it,
which needs that resource to be fetchable and to update live.

An agent resource lives on no drive. So it is outside the drive-wide
subscription that everything else relies on, which fits the symptom exactly:
correct after a fetch, never updated after that, and missing entirely where the
fetch is not attempted.

**Worth deciding before coding**, and Joep's instinct is the right shape: agent
identity needs a home. Options to weigh — a per-drive "profile" resource (the
name as it appears on THIS drive, ACL'd with the drive), a server-level profile
collection, or making agent resources first-class subscribable objects. The
first keeps the existing rights model; the last is the smallest code change and
the largest privacy question, since it makes every agent readable to anyone who
can name it.

**Reproduce:** two agents in one chatroom, rename one, watch the other's UI.

### M19 — "Show profile" opens the wrong resource (open)

The avatar menu's "Show profile" opens the *following* resource instead of the
agent's profile.

`PresenceAvatarMenu.tsx:48` does `navigate(constructOpenURL(agentSubject))`,
which looks right — so the likely fault is what `agentSubject` holds at that
point, not the navigation. The same string is also used by
`FollowStatus.tsx`, so check which component actually rendered the clicked menu
before assuming.

**Reproduce:** open the sidebar avatar menu for another live session, click Show
profile, compare the opened subject against that agent's subject.

### M20 — A colleague's browser does not show rows this session created (explained by M21)

**Cause found — see M21.** The rows were never saved: the server rejects every
row commit because the table's class is missing there. Nothing was going to
show them, on any bundle. The deploy-gap reasoning below was wrong, and it was
wrong in a way worth noticing — it explained the symptom plausibly enough that
I deployed before checking whether the writes had succeeded at all.

The colleague loads the app from the Home Assistant add-on, whose binary — and
therefore whose embedded bundle — was built at 18:35. Every client-side fix from
this session landed at 20:21-20:22:

| fix | lands |
| --- | --- |
| rows that arrive from a peer are drawn (M15) | 20:22 |
| a live update that cannot apply is recovered (M14b) | 20:22 |
| a connect that never opened no longer pins auth (M16) | 20:22 |
| keyless children stop sorting to the top (M13) | 20:22 |

M15 is exactly this symptom, measured and fixed on this branch. So the first
step is to redeploy HA from a build that contains it and retest — not to open a
new investigation.

If it still reproduces after that deploy, the next suspect is M17: a session
subscribed to the wrong drive receives no live fan-out for the shared one.

### M21 — Rows are silently discarded when their class is missing server-side (cause fixed; origin open)

This supersedes M20's "probably the deploy gap" guess. The rows never reached
anyone because they were never saved. From the console of the person who typed
them, repeating for every row:

```
[postCommit] Server error: Failed getting class did:ad:ViKExaq3nm6t… not found locally
[Outbox]     drain failed for subject: did:ad:9SWmXNZ…   (name: "Henk")
[Outbox]     drain failed for subject: did:ad:I4h_29uw…  (name: "Blaa")
```

Confirmed against the server: that class returns `Resource not found`, not
`Unauthorized`, so it is genuinely absent rather than hidden by rights. The
table resource itself IS there. So a table exists on the server whose row class
does not, and every row commit referencing it is rejected.

**The failure is silent, and that is the part to fix first.** The row appears in
the grid as you type it. Nothing marks it unsaved, nothing surfaces the rejection,
and the outbox retries the same commit forever. The only way to find out is to
open the console. Two people spent a session believing sync was broken when in
fact their writes were being refused one layer down and the UI was telling them
everything was fine.

Note the outbox HAS the vocabulary for this: `error_code::MISSING_REQUIRED_PROPERTY`
and friends classify terminal errors so an entry can stop retrying and stay
visible. "Class not found" is not in that registry, so it falls through to
retry-forever with no surface.

**Two separate fixes, both now made:**

1. *Visible instead of silent.* `MISSING_CLASS` added to the shared error
   registry, the server's "Failed getting class <subject>" classified into it,
   and the client matching on both code and message so an older server behaves
   the same. Blocking rather than terminal: the row is well-formed and would
   apply once the class exists, so discarding it would throw away a write the
   user believes they made.
2. *Not refused in the first place.* `Resource::get_classes` had always
   documented "Returns an empty vector if there are no classes found", but a `?`
   made one unresolvable class abort the call — and `check_required_props` runs
   it on every commit, so an unknown class became a rejected write. It now skips,
   with a warning naming the class and the unvalidated resource.

   The trade: required-property validation does not run for classes this store
   cannot see. A store cannot enforce a contract it does not hold, the same write
   already succeeds with no class at all, and this is data integrity rather than
   access control — rights are enforced elsewhere and unaffected.

**Still to do:** whatever makes a table's class reachable wherever the table is.
Creating a table on one node and using it on another should not depend on the
class having travelled by luck. The fixes above stop that costing data; they do
not make the class arrive.

**Where the class goes, and why that is the likely asymmetry.** The two
resources are NOT parented alike. `NewTableDialog` puts the table under the
folder the user picked, but the row class under
`resolveOntologyParent(store, driveSubject)` — the drive's `defaultOntology`,
falling back to the drive itself. So creating one table writes to two different
places, with two different sets of rights.

The rows in the field case carry `drive = did:ad:kgOPf15k…`, which is a drive
shared WITH that user, not their own. That fits: the table landed somewhere they
could write, and the class had to go into that drive's ontology, which they may
not be able to write. The table commit succeeds, the class commit does not, and
the table is left naming a `classtype` the server has never heard of.

Consistent with what the server reports now: the table returns
`not publicly readable` (present, private) while the class returns
`not found` (absent).

**Not yet confirmed** — this is a hypothesis with the shape of the evidence
behind it, not a diagnosis. What would settle it: create a table on a drive
shared with you and watch the console at CREATION time, not at row time. If a
class commit is rejected there, this is it. If the class commit succeeds and the
class still never appears, the fault is in sync rather than in rights, and the
ontology-parenting is a red herring.

Worth noting either way: with the outbox fix above, a rejected class commit is
now blocking-and-visible rather than silent, so the next attempt should say what
went wrong instead of leaving it to be reconstructed from a console.

**Reproduce:** create a table on one node, add a row from a browser talking to
another node, watch the console. Expect `Failed getting class`, a row that looks
saved, and an outbox that never drains.

### P1 — Proposal: show discovered-but-unpaired nodes on the Sync page

The Sync page shows two lists, and neither is discovery:

- **Paired devices** — `localStorage['atomic-peers']` (`SyncRoute.tsx:473`).
  Only nodes the user explicitly added.
- **Server peers** — `managedInfo.peers`, from the server's `/server` resource.
  That is `peer_resources()` (`server/src/plugins/server_info.rs:60`) =
  `live_peer_ids()` (currently connected) + `get_known_peers(store)`
  (previously paired, persisted).

Both mean "already related to this node". A node that has merely been
*discovered* appears nowhere.

Meanwhile the transport is discovering constantly. From the HA add-on's log,
its node found this laptop's node over the LAN with no relay hop:

```
add_node_addr{node=6041773d78}: inserting new node in NodeMap
  relay_url=None source=local.swarm.discovery
```

So through an evening of pairing attempts the two machines kept finding each
other, while the page that exists to pair them had nothing to show — and the
user was asked to shuttle a node ID between machines by hand (see C1, where the
input would not even accept it).

**Proposal.** `iroh_transport` already holds the discovered set. Expose it on
`/server` as a third category — discovered, not yet paired — and render those as
one-tap pairing suggestions above the manual entry field.

That deletes the most awkward step in the flow: on a LAN, pairing becomes
"press the device that appeared" rather than "copy this 52-character string to
the other machine". Manual entry stays for the off-LAN case.

Worth care in the design: a discovered node is *not* trusted, and the list is
attacker-influenced on a shared network. It must read as a suggestion to act
on, never as something already connected, and the node ID must stay visible so
a user on an untrusted network can verify what they are pairing with.

### M9 — Live sync echoes forever between two idle nodes (fixed)

With both nodes live and nobody typing, they traded **355 frames in 58 seconds**
(~8.6KB each, ~50KB/s):

```
267 x imported update for did:ad:agent:QmfpRIB    <- the account's agent resource
 87 x imported update for did:ad:W2Q3m_ZUK0cz2    <- the drive
```

The live read loop held the importing flag — which is what stops the push loop
re-broadcasting — only when the imported subject was *this node's own agent*.
The comment above it described the ping-pong exactly; the guard just covered one
case of it. So the device whose agent it is stays quiet, the peer for whom it is
a stranger's agent re-sends it, and a drive (nobody's own agent) echoes on both
sides. Suppression now wraps every live import.

**Better fix, not taken here:** `DbEvent` already carries `source_id`. The push
loop could skip only the peer an update came from, instead of globally muting
all broadcasts for the duration of an import — a global `AtomicBool` means one
task's import silences another task's local edit. That needs `persist_update` to
accept a source and the push loop to read it.

### M10 — Peer-synced resources never reach the search index (fixed)

49 resources arrived over Iroh and produced **zero** `INDEXING` events on the
receiving node. Search indexing hangs off the CommitMonitor
(`server/src/commit_monitor.rs:828`), which watches commits flowing through the
server; peer sync writes straight to the store via `add_resource_opts`.

The *query* index is updated (`update_index: true`), so drive listings and
collections do show the data — it is only search that cannot see it. The failure
is invisible until someone reaches for search and concludes their data did not
arrive.

### M11 — Sync status is decorative (fixed)

Three sightings in one session, all pointing the same way — the status is
computed from something other than what happened:

- **"In sync"** on a peer that was being refused every subject (9 refusals).
- **"Synced 1 resource"** when 49 had just landed.
- The paired-device card shows no last-sync time, no volume, and no node ID,
  while the server card beside it shows all three. A user cannot tell a working
  link from a broken one.

Same family as the revoke button in PR 1275, which reported success while
leaving access behind. Worth treating as one problem: a status that is not
derived from the last actual transfer will eventually lie in the dangerous
direction.

**Fixed:** `/iroh-sync` returns both directions, so the toast reads "sent 49,
received 1" rather than "Synced 1 resource". The device card gained last-sync
time, the node ID, and what the last sync moved each way — `KnownPeer` now keeps
`last_sent` / `last_received` beside `last_synced`. Deliberately per-sync rather
than a lifetime total: a running counter has to survive re-pairs, store resets
and partial syncs, and becomes fiction the first time one is missed.

### P2 — Nodes relay signed writes, so relaying should not require write access (serve side done)

Getting two of the owner's own nodes to sync required pasting one node's agent
DID into the other's share dialog and granting it write. Nothing asked for it,
nothing said it was missing, and until it was done the sending node refused all
49 resources while the UI showed "In sync".

The owner's objection is the right one: **the two nodes are not writing, they
are passing along writes the owner already signed.**

**The receive side already agrees with that.** A relayed commit is validated
against its own signer, not the peer that carried it
(`lib/src/sync/engine.rs:428`):

```rust
validate_rights: true,
validate_for_agent: Some(signer.to_string()),
```

Safety comes from the commit's signature and the author's rights. Also requiring
the *relaying* peer to hold write access adds nothing — it checks the courier's
credentials instead of the letter's seal. Drop it and rely on what already runs.

**The serve side is different and should not be waved through.** Handing
resources to a peer IS disclosure; without a check, anyone who dials could pull a
private drive. But the authorisation should be **the owner's pairing intent**,
not an ACL entry naming the peer's agent. Pairing is already an explicit,
authenticated act by the owner.

The codebase has exactly this idea, in one direction only: `may_accept_drive_write`
relaxes via `trust_owned` when `initiated_by_us` — "I dialled you, so I will take
your relayed writes to drives I own". There is no mirror on the serve path: "I
paired with you, so you may replicate drives I own." Adding that symmetry removes
the manual grant.

So: two changes, not a new subsystem.

1. **Receive** — stop requiring the relaying peer to have write rights.
2. **Serve** — authorise replication by pairing, not by the peer agent's ACL.

**Done: (2).** `collect_readable_snapshots` takes the dialled peer's node id; a
peer the owner deliberately paired with is served what THIS node can read, and
nothing more. `known_peers` is a sound basis because only the initiator records a
peer — the accept side deliberately does not ("the local user never chose to sync
with this peer"), so the list means "nodes this user dialled".

**NOT done: (1),** and deliberately. See P3: the peer wire carries raw CRDT
state, not signed commits, so the peer's identity is the only credential
available. Removing that check would let any node that dials you inject arbitrary
state.

Neither needs delegation tokens or issued keys. Note also that a node never needs
the owner's private key to relay: commits are signed client-side and travel
intact; a node signs only its own AUTH frame, with its own key (`peer.rs:1259`,
`protocol.rs:156`). Any design that has a node holding the owner's secret — as
`adoptAgentOnDevice` does today — is a convenience, not a requirement.

### P3 — What signed peer writes would cost, and what they would buy

Follows P2. The premise there — "nodes are not writing, they are passing along
signed writes" — does not describe the wire today:

```rust
pub struct SyncPushEntry {
    pub subject: String,
    pub loro_bytes: Vec<u8>,
}
```

Bulk `SYNC_PUSH` and live `UPDATE` both carry **raw merged CRDT state**: no
signature, no author. The signed-commit validation
(`engine.rs`, `validate_for_agent: Some(signer)`) is on the commit path — HTTP
`/commit`, WS `COMMIT` — not the peer path. So a peer is not a courier with
sealed letters; its identity is the only credential on the wire, which is why
`may_accept_drive_write` checks the peer's own rights.

**What already exists.** Loro changes carry a `peer_id` for the authoring peer
(`lib/src/loro.rs:52`), and a Commit signs its `loro_update` bytes — so on the
commit path, ops ARE attributable to an agent. Two things are missing: peer sync
exports a *merged snapshot*, so original signatures do not travel with it, and
nothing binds a Loro `peer_id` to an agent.

**Level 1 — exchange commits instead of state.** Smallest conceptually: the
receiver already knows how to validate a commit against its signer's rights, so
the relaying peer would need no rights at all. Costs: history grows unboundedly,
onboarding becomes replay-the-log rather than take-a-snapshot, and **compaction
destroys provenance** — collapsing history into a snapshot discards the very
signatures that authorised it. This trades away the main advantage of
state-based sync.

**Level 2 — bind `peer_id` to an agent.** A signed statement that a Loro PeerID
belongs to an agent; receivers attribute incoming changes by `peer_id` and check
that agent's rights. Keeps snapshot sync, much cheaper than level 1. Limit: it
constrains what a node may author *as itself*, and does not preserve authorship
through merges.

**Level 3 — signatures preserved per op-range across merges.** Byzantine-tolerant
CRDT territory. Loro does not do this natively; research-adjacent rather than an
afternoon's work.

**Does it increase security?** Yes, in one specific way. Today an admitted peer
can inject ARBITRARY state into any drive it is admitted for, including content
that appears authored by someone else — trust is per-node and coarse. With
authorship-bound writes a relay can only pass along validly-authored changes; it
cannot fabricate another user's edits. That is the difference between trusting
the machine and trusting the author, and it matters for multi-user drives,
untrusted hosting, and the blast radius of one compromised device.

**What it would NOT fix:** confidentiality (reads still need authorisation or
end-to-end encryption), withholding (a relay can always drop data), rollback to
stale state (needs signed version vectors), availability.

**Where that leaves the current design.** Sound *if you only pair nodes you
trust* — which is what P2 implemented: pairing as a deliberate choice by the
owner, standing in for a hand-written ACL grant. Fair for one person's laptop
and their Pi. Weaker than it looks the moment you sync with someone else's
server, which is the case worth designing for before it exists.

### M12 — Presence does not cross a peer link, because it was never wired (open)

> **Update 2026-09-03:** the wire is no longer missing. `EPHEMERAL (0x40)` has a
> codec, a peer send/receive path and a server bridge, with an Iroh e2e
> (`e2e_presence_crosses_the_link_without_being_stored`). What is still open is
> the two-device check on real hardware. The finding below is the original
> report and describes the pre-fix state.

Two machines syncing the same drive over Iroh still cannot see each other's
cursors. Not a regression: presence has no peer-to-peer path at all.

The tag exists and nothing uses it:

- `lib/src/sync/protocol.rs:45` — `pub const EPHEMERAL: u8 = 0x40;`
- `lib/src/sync/peer.rs` — **zero** references. Never sent, never handled.

Every working presence path is client-to-server WebSocket:
`LORO_EPHEMERAL_UPDATE` in `lib/src/client/ws.rs` and
`server/src/handlers/web_sockets.rs:434`, fanned out by `LoroSyncBroadcaster`
to the *subscribers of that server* (`loro_sync_broadcaster.rs:190`,
"broadcast to all subscribers except the sender").

So presence is per-server. A browser on `atomic.ontola.io` and a desktop app on
`localhost:9883` are two islands: drive state flows between them over Iroh,
presence does not. Both users are "alone" while editing the same document.

**What wiring 0x40 involves.** Not much protocol — the shape already exists —
but presence is unlike everything else the peer link carries, and the
differences are the work:

1. **It must never touch the store.** Every existing peer frame ends in a write
   (`persist_update` / `add_resource_opts`). An `EPHEMERAL` frame must fan out
   and be dropped. Routing it through the same path would persist cursor
   positions into the CRDT and sync them forever.
2. **It is high-frequency.** Cursor movement is orders of magnitude noisier
   than commits. It needs its own budget and backpressure; the live channel is
   currently shared, and M9 showed what happens when that channel is saturated
   (the push loop lags and silently drops events, `RecvError::Lagged => continue`).
3. **Scope is per drive, and identity is per agent — not per node.** The
   WebSocket path fans out to subscribers of a subject. Across a peer link the
   sender is a node that may be relaying several agents' presence, so frames
   need to carry the originating agent and be filtered by drive readability on
   arrival, or one peer leaks who is editing what to a node that cannot read it.
4. **Echo suppression applies here too.** The same loop that produced M9's storm
   would apply at cursor frequency. The `source_id` mechanism added for
   M9 should carry over rather than be reinvented.
5. **It should degrade silently.** Presence failing must never affect drive
   sync — it is the least important thing on the link and should be the first
   dropped under load.

Worth doing: "why can't I see myself from my other machine" has no satisfying
answer today, and the reserved tag says someone already intended this.

## Fixed between 0.41.0-beta.2 (Jul 25) and 2026-08-15 — do not chase

Recorded because the first draft of this note treated them as live, and
someone reading the git history deserves to know they were resolved rather
than dropped.

- **The `unknown-drive` dead end.** On the July build, pairing from a node
  with no drive stopped at "Your workspace didn't arrive". Current code gets
  past that screen — but by provisioning a local drive rather than fetching
  the peer's, so the underlying problem is C0, not fixed.
- **"Paired with the device" reported as success while nothing synced.** The
  `count === undefined` branch (`PairingFlowProvider.tsx:280`) still exists
  and is still reachable. If shown, it should say plainly that no data
  moved.
- **The failure text sent people to a device that could not help** ("Open
  the app on your other device, then pair again"). Same story.
- **Second launch panicked** on an unwrapped redb open. Now handled — see C3
  for what remains.

## Unverified on a current build

- **"Connecting…" never resolving for a cross-origin server.** On the July
  build the desktop showed `atomic.ontola.io — Connecting…` indefinitely
  while the server logged successful upgrades (`/ws`, `101`); same-origin in
  a browser it showed `In sync`. Not re-tested after the rebuild.

## What this cost, and why

Roughly an afternoon went into diagnosing a deadlock that current code does
not have. The reasoning was sound and the evidence was real — logs, `file:line`
paths, a reproduction on a deliberately cleaned store — but it was
**source from the working tree explaining behaviour from a three-week-old
binary**, and the two had diverged. Every "confirmed" step made the wrong
conclusion feel firmer.

Two things would have caught it immediately:

1. **Check the binary's provenance before diagnosing from it.** The app was
   dated Jul 25; the tree had moved through PRs 1257 and 1260 and the vault
   work. That should have been the first question, not the last.
2. **Rebuild before writing findings up, not after.** The rebuild took ~15
   minutes and refuted the headline finding on the first try.

Worth keeping in mind for the Android app too, where the same "install an
old bundle, reason from current source" trap is one `adb install` away.

### Reproduced locally, 2026-08-17 afternoon

Two scratch agents (Alice, Bob) against one local server, in two browser
origins so each has its own store. Everything below is from that run, not from
reading the code.

**M17 — fixed.** Accepting an invite left `drive` pointing at the invitee's own
private drive: `persistAgentAfterInvite` returned only the personal drive, the
caller activated it, and `goToRedirect` activated it a second time after the
redirect had already happened. The drive the invited resource lives on was
already being computed one line away, to bookmark it in the switcher — it was
just discarded. Now returned and preferred, with the personal drive as the
fallback (which is the new-agent case, where the current drive would otherwise
still be `baseURL`). Verified: after accepting, `drive` is the shared drive and
the sidebar reads its name. The e2e invite test now asserts
`current-drive-title`, which it did not before — the old assertion passed with
the bug, because the *page* showed the drive all along.

This cost more than a wrong label. The drive-wide subscription follows the
current drive, so an invitee sat on a shared drive with no live fan-out, and
never joined its presence channel.

**M18 — root cause found.** Not a resolution or live-update problem. Alice
asking the server for Bob's agent gets:

    Unauthorized. No .../properties/read right has been found for
    did:ad:agent:d9Im… in this resource or its parents

Agent resources are created with no read grant for anyone but their owner, and
they live on no drive, so no drive-level grant reaches them either. Every
consumer that resolves an agent to show a name — chat avatars, member lists,
"Show profile" — is reading a resource it is not allowed to read. Presence is
the sole exception because the name travels inside the presence payload.

The client hides this instead of surfacing it: it renders a locally-derived
stub with `isA: agent`, the `publicKey` recovered from the DID suffix, and a
`createdAt` of *now*. That stub looks renderable, so the local-first fallback
never retries the server. Hence "names don't propagate" rather than "you can't
read this agent".

Fixing it is a design decision, not a patch — see the options recorded with the
question to Joep. Whatever we choose, the client should stop fabricating a
stub that is indistinguishable from a real profile.

**M19 — not what it looked like.** `Show profile` navigates to
`constructOpenURL(agentSubject)`, which resolves to `/app/show?subject=<agent
DID>` and renders the agent page. Verified working for an agent you *can* read
(your own). For anyone else you land on the M18 stub: no name, no personal
drive, a fabricated timestamp. Keeping M19 open only to confirm against the
reporter's exact wording ("opens the following resource"), since the
navigation target itself is correct.

**M22 — new: a read-only invitee gets a permanently stuck outbox entry.**
Right after accepting a *view* invite, Bob's client signs a commit against the
shared drive and the server refuses it, correctly:

    Unauthorized. No .../properties/write right ... for did:ad:agent:WA6I…

The commit carries the whole drive — `name`, `isA`, `read` (both agents),
`write`, `genesis` — which is what a Loro export from an empty version vector
looks like. So this is not a stray edit: the drive's doc was hydrated locally
through operations that count as *local*, and the outbox then tried to push
them.

Traced far enough to be sure of the shape: `markDirty` for the drive is called
from the `subscribeLocalUpdates` handler (the stack runs through loro wasm), so
a genuine local op is being applied to a doc the invitee only has read on. It
only happens on the resource's FIRST hydration in that store — visiting the
same drive afterwards produces only `setLastCommitValue`, which is correctly
exempt. `isOwnedSubject` returns true for every `did:` subject, so "ours to
POST" is decided by namespace and never by rights.

The retries are bounded (`BLOCK_AFTER_FAILURES`), so it parks rather than
hammers — but it parks as a blocked entry, which is why an invitee who has
written nothing still sees "Changes pending" forever. Not yet fixed; the cold
repro to finish it is a second drive + invite with `Resource.prototype`
instrumented before accepting.

### M22, root cause and fix

The heal pass in `Resource.getLoroDoc()` writes every JSON-AD propval the
incoming snapshot lacks into the CRDT. `createdBy` is always one of those: the
server derives it from the genesis certificate and ships it as a propval, but
never stores it in the document. So every hydration wrote it — a LOCAL
operation — which marked the subject dirty and signed a commit for a value the
client never authored.

`lastCommit` and `createdAt` were already exempt for exactly this reason.
`createdBy` now joins them in one named set, `DERIVED_BY_SERVER`. They stay in
the read cache, so `get()` and JSON-AD round-trips are unchanged.

Verified by repeating the identical action four times with two agents on one
server: the first three accepts (before the fix) each queued a commit for the
shared drive and collected 401s; the fourth (after) left the outbox empty.

Worth noting what this was costing on resources you CAN write: a redundant
commit on every hydration, which is part of the write amplification we have
been chasing separately.

### M18, the shape of a fix

Decision taken: a **public Profile resource per agent**. The agent resource
keeps the private things — keys, the `personalDrive` pointer — and a separate,
publicly readable resource carries the display name (avatar later). One grant
fixes chat avatars, member lists and "Show profile" together, and publishes
nothing but the name the user chose to show.

The open question is **discovery**: given an agent DID, how does another client
find that agent's profile without reading the agent?

- *Deterministic DID* does not work. A resource's DID is the owner's signature
  over its genesis certificate, so only the owner can compute it.
- *Well-known HTTP subject* (`<server>/agents/<publicKey>/profile`) is
  constructible by anyone from the DID suffix and needs no index or endpoint.
  It reintroduces an HTTP subject in a codebase deliberately moving to DIDs.
- *Server-side index* — the server records `profileOf` on apply and answers
  `GET /profile?agent=<did>`. Cleanest fit with DID subjects; costs an
  endpoint, an index and a migration for existing agents.

Recommendation: the server-side index. It is the only one that stays honest
about subjects, and the endpoint is small.

Whichever we pick, the client should stop fabricating an agent stub that is
indistinguishable from a real profile. Today an unreadable agent renders with
`isA: agent`, the `publicKey` recovered from the DID suffix and a `createdAt`
of *now* — which is why this read as "names don't update" rather than "you are
not allowed to read this".

### M18, fixed: agents are public

Joep's call, and it dissolves the discovery problem the Profile design ran
into: if the agent resource is readable, nothing needs to find a second
resource. No new class, no index, no migration.

Two halves, and the second is the one that would have been easy to miss.

**Server.** Anyone may READ an agent; writing stays owner-only, asserted in
the same test. This is stated once in `check_rights_impl` rather than granted
per agent at creation, so it covers every agent that already exists —
including legacy `internal:/agents/…` spellings, which normalise to the same
DID.

**Client.** Opening the read on the server changes nothing by itself, because
every client already holds a cached stub for the agents it has seen and has
stopped asking for them. "Trust the local copy while online" is sound for
anything under a drive — the drive's SUB delivers deltas — but agents are
under no drive, so nothing ever refreshes them. A cached agent could stay
wrong forever. Now re-checked once per agent per session, then trusted.

Verified with two agents on one server: the presence avatar's label goes from
`did:ad:agent:WA6IORw…` to `Bob`, and "Show profile" renders a real profile,
including Bob's real creation time — where the synthesized stub reported
*now*.

**M19 falls out of this.** The navigation was always correct; the page just
had nothing in it. Closing it with M18.

One loose end worth a look: the profile now shows `personal-drive: Server
error` to someone who can read the agent but not the drive it points at. The
pointer is visible (that is the consequence of making agents public) but a
resource you may not read should not render as an error.

## Running the pipeline locally, 2026-08-17 evening

Every CI run on this branch sat queued for most of the day, so nothing had
validated it. Running the pipeline locally found two Rust failures CI would
have reported first, and then a much longer thread.

### Two peer-sync tests were failing on the branch — fixed

`two_devices_sync_via_engine` and `undo_syncs_to_peer_via_engine` pull a
private drive as `ForAgent::Public` and assert something comes back.
`69fc5a7e` ("always hand a peer your own agent resource on connect")
tightened what an unidentified pull sees; the iroh end-to-end test was
updated with it and these two were missed. Both model two devices of the
SAME person — the test asserts the agents share an `initialDrive` — so the
owner is who the pull should claim to be.

### Repeat materialization merges, flagged genesis or not — fixed

Joep's call: deterministic personal drives mean two devices mint the same DID
for the same drive, so a second materialization is normal and should merge.
The branch already did that via `repeat_genesis_is_mergeable` — but only for
commits declaring `is_genesis`. Whether a second device's from-scratch doc
drains as a genesis or as an ordinary commit is an accident of which client
path exported it, and the ordinary path hit the causality guard: creation
defaults, every value losing to stored state, read as silent data loss and
refused. Observed live as a 500 loop on the owner's own home drive from their
second browser.

The cert decides, not the flag. It must verify against the subject AND name
the signer — and for a `did:ad:` subject the DID *is* the signature over that
cert, so a repeat can only be the same author. Nothing an attacker can reach.

### M23 — signing in on a device with no data opens an empty workspace

`sign-in-without-data.spec.ts` fails on the branch, and on CI. It encodes:
signing in with a secret whose workspace this device has never held must stop
and say so, not present an empty workspace under your name.

Cause, established by instrumenting `localStorage.setItem('drive')` with stack
traces during a live sign-in — three layers, each hiding the next:

1. `0409e86e` added `store.ensurePersonalDrive()` to sign-in, so **the drive
   resource always exists**, on every device, including one holding none of
   the account's data. Every "do I have my data?" check reads that as yes.
   Proven by stubbing `ensurePersonalDrive` at runtime: the card appears.
2. Fixing only the sign-in gate does nothing. `ConnectDeviceStep`'s arrival
   poll (`driveIsHere`) asks the same question again and calls `onConnected`,
   which navigates straight back out of the card. The traces show `""` written
   by the sign-in flow, then the drive DID written by `onConnected`.
3. Switching the predicate to "the drive has children" **also** fails:
   `createDrive` creates the drive's default Ontology, so a freshly
   materialized drive has a child immediately.

**A fix that looked right and was not.** Predicate = "has a child that isn't
the default ontology". The two target specs passed. The full suite went from
161 passed / 7 failed to **60 passed / 106 failed**, with 11 specs parked on
the connect-device card: that predicate asks the server's query index, on the
sign-in path, and an index that isn't warm answers "empty" for a drive that
does have data. Reverted.

**The approach that should work**: ask the local ClientDb whether this device
held the drive BEFORE this sign-in materialized it. No server round trip, no
search index — that dependency is exactly what broke the attempt above. Both
consumers already funnel through `deviceHasDriveData`, so it is one edit.

### Baseline to measure against

CI on the current HEAD: `fmt`, `clippy`, `nextest`, `pnpm build`, `pnpm lint`
and `pnpm test` all pass; it fails only in e2e, with **3 failed and 1 flaky**
in the shard that failed and 40 passed in the other. Local full-suite is 161
passed / 7 failed. These are different measurements — CI shards, and CI serves
the production bundle behind a service worker while local runs hit the vite
dev server. `plugin › install a plugin` fails locally on every run and does
not appear in CI's list at all, which is that divergence, not a bug.

Rust is 570/570 locally.

### Two ways to waste an hour, both hit today

- The browser bundle resolves `@tomic/lib` to `lib/dist`. Editing
  `browser/lib/src` and reloading proves nothing until `pnpm build` runs in
  `browser/lib` — HMR does not cover it.
- `cargo build -p atomic-server --features db-redb` exits **0** while building
  nothing: that feature belongs to `atomic_lib`, not the server. The stale
  binary keeps serving.

Both produced confident, wrong verifications. Check the artifact's mtime
before trusting a result — and prefer a runtime experiment (stub the function,
hook the setter) over reading code to decide what is happening.

## M23 fixed — ask before writing, 2026-08-17 late

The predicate was never the problem. The **order** was.

`0409e86e` put `store.ensurePersonalDrive()` ahead of the gate, so by the time
anything asked "does this device have my data?", the drive resource existed —
because sign-in had just written it. Every check downstream reads that as yes.
The two layers underneath it were consequences, not separate bugs:
`ConnectDeviceStep`'s arrival poll asks the same question and navigates back
out of the card, and `createDrive` also makes the default Ontology so "the
drive has children" is true as well. Nothing writes a decoy drive now, so
there is nothing for either to find, and both dissolve untouched.

The materialization stays — on the branch where the answer is yes. There it is
*nearly* a no-op, and the "nearly" is the point: `createDrive`'s existing-drive
path still seeds the switcher list and calls `maybeMigrateOldPersonalDrive`,
which is what adopts an older, pre-derivation home's `drives`, `sharedWithMe`
and `favorites` lists onto the derived one.

Which forced a second change. A pre-derivation account's data is not under the
derived home yet — the adoption above is what moves it — so asking only about
the derived subject reports "no data" for someone whose workspace is sitting on
the server they just authenticated against. Telling them their data is on
another device would be false, and it would skip the adoption that makes it
true. So the gate also asks about `agent.initialDrive`, which the old secret
carries. This is not a widening of what counts as "your data": it is the same
reachability question, asked about the drive the secret was actually made for.
Secrets minted after derivation carry no `initialDrive`, so a stranger's
sign-in is unaffected — which is why the two target specs still pass.

Worth recording that the earlier attempt failed for a reason that had nothing
to do with the diagnosis. "Has a child that isn't the default ontology" is a
*correct* description of a materialized-but-empty drive. It broke the suite
because of where it asked: the server's query index, on the sign-in path, which
answers "empty" for a populated drive whenever it isn't warm. A right predicate
in the wrong place cost 100 specs. This change adds no query the plain
reachability check wasn't already making.

### Measured, not assumed

Local full suite on a fresh store: **162 passed / 6 failed**, against the
161/7 baseline, with both target specs flipping green.

Every one of the six is attributed by A/B — same specs, fresh store, with the
change and with it reverted:

| spec | without | with |
| --- | --- | --- |
| `sign-in-without-data` (×2) | fail | **pass** |
| `chatroom` | fail | fail |
| `offline-create-then-online` | fail | fail |
| `plugin › install a plugin` | fail | fail |
| `template › apply sveltekit template` | fail | fail |
| `delete resource` | pass in isolation | pass in isolation |
| `sign in with secret, edit profile, sign out` | pass in isolation | pass in isolation |

The last two fail only under full-suite load and pass alone — `delete resource`
carries a comment about exactly that (a success toast that expires in ~2s, so
under load it is gone before the first poll). `apply sveltekit template` fails
on a SvelteKit **build** error, before the browser is involved at all.

Unit tests 591/591.

**A measurement trap worth the note.** The first full run of this change
reported 8 failures; four of them evaporated on a fresh store. The e2e store
had reached 141MB — right at the ~150MB line where specs start failing on
timing rather than on bugs. `du -sm .e2e-store` before believing a failure
list, and re-run with `--fresh` before believing a regression.

## Getting CI green — and a local harness that can actually see it

Merging needs green, and "attributed as pre-existing" is not green. CI's last
real run (4 shards, retries on) had **five hard failures**: the two
`sign-in-without-data` specs, `chatroom`, `offline-create-then-online` and
`quick-add`. Four others — `aggregates`, `documents`, `offline-chatroom`,
`perf-sidebar-reload` — fail and pass on retry, so they do not fail the
pipeline. `plugin › install a plugin` and `apply sveltekit template` fail
locally and appear nowhere in CI's list.

### The thing that made these debuggable

**Half the suite never touches the vite dev server.** Any page reached through
a server-issued URL — an invite link, `/app/dev-drive` — loads the SPA that
`atomic-server` has embedded in its own binary. `FRONTEND_URL` only points the
*first* page. So `chatroom` opens page1 on vite and page2 on the production
bundle, which is why it failed identically on CI and locally while three
separate source fixes changed nothing at all: none of them were ever loaded.

Two settings reproduce CI's serving path locally:

    VITE_E2E=true cargo build -p atomic-server     # /app/dev-drive only exists
                                                   # in a prod build with this
    FRONTEND_URL=http://localhost:9886 SERVER_URL=http://localhost:9886 \
      npx playwright test

Without `VITE_E2E` the dev routes are absent from the bundle and every spec
dies in `before()` on a 30s `waitForURL` — which looks nothing like its cause.
With them, the suite runs against the same artifact CI serves. This retires
"local and CI serve different things" as a standing excuse: they no longer
have to.

The cost is that a source change now needs a ~50s rebuild to reach page2. That
is the price of testing the artifact rather than the sources.

### chatroom — the invite flow threw away the home drive

Root-caused with `window.store` diagnostics at the failing assertion, which
reported the drive present, `sharedWithMe` holding the chatroom, and:

    Cannot derive this agent's personal drive: its key signs
    non-deterministically and no derived subject was stored.

A drive's subject IS its owner's signature over its genesis cert, and a
WebCrypto key signs differently every time — so it can only be computed while
the raw private key is in hand. `Agent.fromSecret` does that and stores it.
The invite path had the raw key, built a secret from it, then discarded the
result twice: it constructed the Agent without `personalDrive`, and persisted
through the keypair overload of `saveAgent`, which writes that field as
`undefined` because it has no secret to re-derive from.

After that the derivation is impossible forever. `usePersonalDrive` fell back
to `initialDrive`, a new agent has none, and `usePersonalDriveList` returned
an empty list — the panel renders *nothing* when the list is empty, so a
resolution failure looked exactly like "nobody shared anything with you".

Fixed by deriving it at both agent-minting sites and storing the secret rather
than the keypair. `persistAgentAfterInvite` also stopped minting a drive of
its own: it wrote the home index to a drive the sidebar never reads, since the
sidebar resolves the home from the key and not from the Agent's pointer.

### offline-create-then-online — a test that predates derived homes

`store.createDrive('Offline-Created Drive', …)` never said `personal: false`,
and `personal` defaults to true. A personal drive is now the derived home,
returned untouched when it exists — so the call handed back the dev drive and
the assertion compared it against a name it never got to use. Same class as
the two peer-sync tests in `b2d168dd`.

## Desktop ↔ Home Assistant, on today's builds — 2026-08-17 evening

Both ends rebuilt from this branch: the HA add-on binary cross-compiled
(`aarch64-unknown-linux-musl`, checksum-verified on install, previous kept as
`atomic-server.prev`), the desktop run from the same tree. The served bundle
hash on `https://atomic.ontola.io` matches the local build exactly, so what was
tested is what was built.

```
HA node       did:ad:node:5066634d0786d35c927f2ec099e911fe4924c035ec463c8a3c6cb6ff37aad9bb
desktop node  did:ad:node:6041773d78f964b03087801b602be64c3558d2b8dea7221453135468df4e574a
```

### Sync works in both directions

Pairing survived the upgrade — the desktop still lists `local-atomic-server` as
paired, and a manual sync ran the full handshake: authenticated as the agent,
version vectors compared (`hashes match, in sync`), live mode, read and write
loops up.

Live propagation, no manual sync in either case:

| direction | created | arrived |
| --- | --- | --- |
| desktop → HA | 16:13:19 | 16:13:24 |
| HA → desktop | 16:30:44 | 16:30:49 |

The second one was written by a *different agent* on the HA server, which makes
it a real test of the relayed-write path rather than an echo.

### The invite flow, against a real replica

An invite token minted on the desktop and opened against `atomic.ontola.io`
verified there — proof the drive and the signer's agent had both synced across.
Accepting produced, on the HA server:

- a new agent with its **derived personal drive set** — the fix in `bd6af81c`.
  Before it, an invite-created agent could never name its own home, which is
  what left "Shared with me" permanently empty;
- the **invited drive** as the active one (M17);
- the new agent added to the drive's `write` list by `add_rights`, which uses
  `save_locally` and so is not itself subject to the rights check.

### Two things worth following up

**Write amplification reaches the relayed path.** One resource creation caused
**seven** `INDEXING` passes on the HA server. Same shape as the OPFS finding,
now on the server's search index — and this one runs on a Raspberry Pi 5.

**The post-accept unauthorized window is reliable, not occasional.** Between
accepting and `add_rights` landing, the client's writes to the target drive are
refused with `No write right has been found for did:ad:agent:…`. `InvitePage`
already treats the drive-bookmark as best-effort for exactly this reason, but
against a remote replica the window fires every time rather than rarely, so
anything in that path that is *not* best-effort will fail there.

### quick-add — the keystroke that lands mid-save

CI's snapshot said it precisely: the field still held "Bread" and no row had
been added. `create()` clears the field before it awaits anything, so had it
run at all the field would be empty — it took the early return, and with text
present the only remaining cause was `busy`. The bar is used at speed and the
window is wider than it looks: a row becomes visible when `onRowCreated` fires
in `.then()`, while `busy` clears later in `.finally()`.

Removing that gate is safe on its own terms — submitting the same item twice
is already impossible, because the field is cleared before anything is awaited
and `ready` is false until something new is typed.

**The test that proved it, and the one that didn't.** The first attempt delayed
the HTTP `/commit` route and passed against the bug: commits travel over the
**websocket** while connected, so it held nothing open. `routeWebSocket` is
what creates a real in-flight window. Only running the new test with the fix
reverted exposed this — it had already gone green and looked like proof.

Final: 3/3 red without the fix, 5/5 green with it, all four quick-add specs
passing.

### Reading CI honestly

Two ways a run lied today, both worth checking before debugging anything:

- **Cache replay** (below) — the one that is actually provable.
- **Cache replay.** A docs-only commit does not touch the e2e cache key, so the
  run replays the previous result — identical failures *and* identical shard
  times to the tenth of a minute, which re-executed tests cannot produce. To
  force a real e2e run, change something under `browser/`.

**It was host contention after all — and the instrument could not see it.**
The scattered failures were first blamed on runner contention, then withdrawn
because `uptime` inside the WSL2 runner reported an idle box. That check was
worthless: **WSL2's loadavg reports the Linux VM's own load and cannot see the
Windows host starving it.** Joep was gaming on that desktop. Measure
throughput instead — `ssh mancave "time (for i in $(seq 1 3000000); do :; done)"`,
~2.5-2.9s on a quiet host — which does reflect starvation.

The numbers, once the host was free: **9 failures -> 2**, shard 1 from 18.4m to
13.7m, with `calendar`, `aggregates`, `kanban` x2, `filePicker`, `onboarding`
and `e2e > folder` all passing. Nothing was wrong with them.

Two lessons worth more than the incident. `gh run rerun` **replays the dagger
cache** — the re-run returned byte-identical failures *and* identical shard
times, which re-executed tests cannot produce, so it is never a way to retest
after a bad-environment run; only a change under `browser/` forces execution.
And a correctness A/B cannot clear a change of *load* effects, which is why
the quick-add fix was still rewritten to queue rather than to remove the
in-flight gate: keeping exactly one save open is what the original code
guaranteed, and that guarantee should not be dropped by accident.


### What is left, and what it is not

The dashboard em-dash (`Total spent—Sum amount`, `Expenses—Count`) was a
real totals bug, not "this PR's problem later". An empty local-DB page
dropped `aggregates`, and `useTableAggregates` asked once — if that read
hit the index before the puts landed, ResourceUpdated never fired again
because the rows were already in the JS store. Fixed by keeping empty-set
statistics on the collection, and by having the dashboard specs await
`waitForRowsMaterialized` — which drains the ClientDb worker, so a query
issued after it cannot answer from an index that is missing rows the grid
already shows.

An earlier revision also had `useTableAggregates` retry an empty read eight
times, flushing on each attempt. That was dropped: it is product code polling
to hide an index lag the readiness signal already covers, and it made a
legitimately empty table — a freshly created one — flush eight times on every
mount, against the OPFS write-amplification work.

Document specs were failing on the same Loro cursor widget that splits
"New paragraph" into `Ne Dev User w paragraph`. Assertions now read the
editor with those decorations stripped; the widget is `aria-hidden` so it
does not land in the a11y tree either.


**One thing this PR did cause, found late.** Persisting the invite agent as a
secret rather than a keypair also adopts that agent on the device by default —
so accepting an invite on a desktop that already holds its owner's agent would
have repointed the embedded node's identity. Storage was what the fix needed;
the adoption was not. Now `adoptOnDevice: false`.