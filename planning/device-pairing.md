# Device Pairing — sync onboarding UX between a server and a phone/tablet

> **Status:** Proposal (2026-07-08), revised 2026-07-10. Owns the
> pairing/onboarding UX and the QR/deep-link envelope. C0 (invented
> personal-drive DID) is **superseded** by derivation; M6 (HTTP drive
> hijacks `serverUrl`) is **closed**. Remaining: extra-workspace inventory,
> M4 (pre-0.40 DID auth). Resolves
> [`serverless-p2p.md`](./serverless-p2p.md) Open Question 3 (key transport)
> and narrows OQ1 (LAN discovery) and OQ4 (drive enrollment). Trust rules are
> inherited from serverless-p2p Principle 1 and are not renegotiated here.
>
> **Current (2026-07-17).** "Same-agent AUTH is the only trust gate" below is
> superseded: `683a25d4a` removed `is_same_agent_as_ours`. AUTH proves *an*
> agent; per-subject `check_read` / per-drive `may_accept_drive_write` decide
> what crosses, and the acceptor persists `KnownPeer` based on who dialed
> (`lib/src/sync/peer.rs` `is_paired_peer`). The routing-only envelope and
> "the secret never goes in the QR" are unchanged — the rule that a stranger
> "receives nothing" becomes "receives only what its agent may read".
> Wording is left as written; see
> [`sync-onboarding-ux.md`](./sync-onboarding-ux.md) for the current model.
>
> **2026-07-10 — the `onboard` kind is gone.** A pairing code is routing only.
> It never carries an agent secret, and one that claims to is refused. See
> "Why the secret does *not* go in the QR".
>
> **2026-08-15 — field test.**
> [`pairing-ux-field-test.md`](./completed/pairing-ux-field-test.md) walks this UX on a
> real self-hosted server plus the desktop app. C0 (a blank node minting a
> *different* personal-drive DID because it looked up the `personalDrive`
> pointer) is **superseded**: the home subject is derived from the Agent key,
> so every device names the same drive. Pairing + live sync between desktop
> and the HA node was verified 2026-08-17. What remains is not identity —
> extra workspaces still have to arrive via that shared home's `drives` list
> (or an explicit pull), and M4 still blocks reading pre-0.40 HTTP drives.
>
> **2026-08-20 — M6 closed.** Opening an adopted `https://…` drive no longer
> moves the home server. A bare origin is still a server switch; an HTTP
> drive with a path is fetched cross-origin. See the field-test M6 write-up.
>
> Context: the Android Tauri app boots and syncs as of 2026-07-08 (embedded
> server + webview, Iroh transport ready). What's missing is any humane way
> to get a second device holding the same agent talking to the first.

## Goal

A person running atomic-server (desktop app, home server, or another phone)
gets their phone/tablet syncing the same data with **one scan and zero typed
identifiers** — and every reconnect after that requires **no action at all**.

Cross-agent sharing is out of scope (that's
[`authorization-sync.md`](./authorization-sync.md)'s knock/inbox ceremony).
This doc is about *my own devices*.

## The three separable problems

Pairing conflates three questions; the design keeps them separable, and the
QR envelope simply bundles their answers:

1. **Identity** — get the agent secret onto the new device.
2. **Routing** — tell the new device where an existing node is
   (NodeID / relay hint / LAN URL). Routing is never trust (Principle 1).
3. **Enrollment** — which drives this pairing syncs (`KnownPeer.drives`).

## What exists today (inventory)

- Agent secret is already a portable base64 JSON
  `{privateKey, subject: did:ad:agent:…}`; the browser imports it via
  `Agent.fromSecret` (`browser/lib/src/agent.ts`, `agentStorage.ts`) and the
  server mints one on first boot.
- Every node has a `did:ad:node:…` (Iroh NodeID). `SyncRoute.tsx` shows the
  local one (`/iroh-node-id`) with a copy button, accepts a pasted peer DID,
  and triggers `/iroh-sync`. `KnownPeer{nodeId, label, lastSync}` lives in
  localStorage.
- The server announces drives via pkarr at boot (`serve.rs`).
- Same-agent AUTH is the only trust gate; `engine::handle_frame` applies
  peer `COMMIT`s with full validation (serverless-p2p P1/P4 receiving half).
- Nothing renders or scans QR codes yet; no deep-link registration; no mDNS.

## Decision: one envelope, routing only

One QR/deep-link format, and it never carries identity. It says where to reach
a node and which drives to sync; the dialed peer still has to prove the same
agent key over AUTH before a single resource crosses. This is exactly
serverless-p2p P3's "QR contains routing only".

### Why the secret does *not* go in the QR

**Superseded 2026-07-10.** This document originally chose "secret in the QR"
for v1 (option A below). Two things killed it:

- **A device can't read its own secret back out.** Since `6cdab0e3` the agent's
  private key is stored as a non-extractable `CryptoKeyPair`
  (`helpers/agentStorage.ts`), specifically so no plaintext copy sits beside
  it. Nothing can mint an `onboard` code. Option A is not merely unwise, it is
  unimplementable as written.
- **The consuming half was an open door.** `atomic:` is a registered scheme,
  so *any* app or web page on the device can fire that deep link — not only the
  camera. A handler that imported an identity from a link would let a poster or
  a phishing page silently sign a fresh install in as an attacker, after which
  everything its owner wrote would sync to the attacker's node. The code and
  its "switch account?" dialog were removed 2026-07-10; `secret=` is now
  refused by the decoder rather than parsed.

Options considered:

- **A. Secret in QR — rejected, see above.** The argument was that the browser
  UI already exposes "copy your secret" with identical sensitivity. It doesn't
  hold: copying is an explicit act by the key's owner, while a scanned or
  tapped link is an act by whoever wrote the link.
- **B. Routing-only QR + secret over the Iroh channel (the plan).**
  QR carries `{node, relay hint, one-shot token}`. New device dials the
  node (E2E-encrypted QUIC, endpoint authenticated by the NodeID from the
  QR), presents the token; the *existing* device shows "Device 'Xiaomi Pad'
  requests your identity — allow?" and ships the secret through the channel
  once. The optical channel never carries the key; a photographed QR leaks
  routing plus a token that the on-screen confirm gates. This is a lite
  form of the knock/inbox primitive — build it when that lands.
- **C. Two manual steps** (paste secret, paste node DID) — **the current
  behaviour.** A new device signs in by entering its secret, then pairs. This
  is what the post-sign-in connect-device screen assumes.

## Envelope format

Deep-link URI so the system camera opens the app directly
(`tauri-plugin-deep-link`; intent filter in `desktop/gen/android`):

```
atomic:pair?v=1
             &node=did:ad:node:…            # issuing node
             &url=http://192.168.0.153:9883 # optional LAN/WS fast path
             &drives=*                      # or repeated: &drives=<subject>&drives=…
```

`atomic:` is the transport, `did:ad:node:` is the identity; they nest rather
than compete, so a node is written the same way here as everywhere else in the
system. Two constraints forced the wrapper, and both are worth recording:

- **A QR scanned by the system camera has to launch the app**, which needs a
  scheme the app registers. `did:` can't serve: iOS `CFBundleURLSchemes`
  registers a bare scheme, so claiming `did` claims `did:key` and `did:web`
  too. (Android alone *could* scope it — `<data android:scheme="did"
  android:sspPrefix="ad:"/>` — but a platform-specific pairing code is a worse
  inconsistency than the one it fixes.)
- **A bare DID has nowhere to carry `drives`**, which is what tells a freshly
  signed-in device *which* drive to pull.

Rules:

- The query is plain and readable — no base64 blob. `:` and `*` stay literal
  (both legal in a query per RFC 3986); only `url` is percent-encoded. An
  escaped `node=did%3Aad%3Anode%3A…` would be no more legible than the blob
  this replaced.
- A bare `did:ad:node:…` is also accepted on input, as a code for all drives —
  for someone who copied just the node identity.
- `v` is mandatory; unknown `v` → "update the app" error, never best-effort
  parsing.
- `drives=*` means all drives, and may not be combined with named ones.
- **`secret=` is refused, not ignored.** A code carrying an identity is a
  malformed pairing code, and the whole code is rejected. See "Why the secret
  does *not* go in the QR".
- `url` is a hint, not identity: after connecting, the same-agent AUTH gate
  decides everything. A tampered `url`/`node` can at worst make the device
  dial a stranger who then fails AUTH.
- The same payload renders as a QR *and* works as a tap/paste link
  (desktop → desktop pairing without a camera).

## Flows

### Server/desktop → phone (first device onboarding)

**Revised 2026-07-10** — a pairing code never carries identity, so this is two
acts, not one. Step 1 is unavoidable until P3 lands (see "Why the secret does
*not* go in the QR"):

1. Phone (fresh install): sign in by entering the agent secret. The device now
   holds the identity but none of the data, and the post-sign-in
   **connect-device screen** leads with exactly that.
2. Existing device: Sync page shows its `pair` QR + code outright (routing
   only, safe on screen). Phone scans it, or shows its own for the existing
   device to scan — a peer sync reconciles both ways.
3. On scan: persist `KnownPeer{node, agent, drives}`
   → connect WS at `url` if reachable (LAN bulk reconcile is much
   faster), else Iroh session via relay → initial reconcile → "Paired with
   \<server name\>".

### Phone ↔ phone / already-provisioned device

Same screen, but the QR is `kind: "pair"` (no secret). Acceptor persists the
`KnownPeer` only after inbound AUTH proves the same agent subject
(serverless-p2p P3 auto-accept rule, unchanged).

### Reconnect (no UX)

Paired devices reconnect with zero action: dial `KnownPeer`s directly; if
unreachable, resolve current NodeIDs via pkarr (drive → nodes) and dial
those. Discovery output is routing-only — `KnownPeer` records are written
exclusively by the pairing flows above.

## Auto-discovery

Discovery is routing sugar, never trust — same-agent AUTH remains the only
gate, so discovery cannot become a security hole by construction:

- **mDNS / LAN** (Iroh local-swarm discovery): the phone's pairing screen
  lists "Atomic node found at 192.168.0.153" so the user taps instead of
  scans. Also gives serverless-p2p OQ1 its LAN-only answer: local discovery
  + direct QUIC, no relay required on a shared network.
- **pkarr** (already announced by the server): *re*-discovery for paired
  devices that roamed networks. Useless for first pairing (nothing to look
  up yet) and grants nothing.

## SaaS-assisted pairing (account login as rendezvous)

For cloud-account holders, `atomic-saas` can make pairing fully automatic —
"log in on a new device and it just syncs." Two of the three legs already
exist there:

- **Identity**: `/api/recovery-secret` (atomic-saas `main.rs`) stores the
  agent secret encrypted under a user-chosen recovery password;
  `GettingStartedFlow` already restores it on sign-in. SaaS never sees the
  plaintext key — the product stays non-custodial.
- **Routing (the missing piece)**: a per-account **device directory** —
  `{device_id, name, node_id, relay_hint?, http_origin?, platform,
  last_seen}` with register/list/revoke endpoints authenticated by the
  portal session. Each signed-in device upserts its record on connect
  (managed nodes already report `iroh_node_id` via heartbeat; this extends
  the idea to the user's own devices).
- **Enrollment**: the account's enrollments already say which drives live
  where.

New-device flow: sign in → restore secret (recovery password) → fetch
device directory → write `KnownPeer`s → dial managed node over WS +
personal devices over Iroh → reconcile. No QR, no typing.

Why this is safe under Principle 1: SaaS-provided node-ids are routing
only. A compromised control plane can hand out wrong node-ids, but the
dialed stranger fails same-agent AUTH and receives nothing — SaaS never
becomes a trust root by operating the directory. (It does learn device
count/liveness; the directory is opt-in and per-account.)

Guardrails:

- **FOSS guardrail #3 holds**: the directory client is the *browser/app*
  posting under the user's cloud session (like the existing
  `helpers/managed/*` code) — never the open-core server phoning home.
  Self-hosters have no session and keep the QR path as the full-featured
  flow; SaaS is a third *issuer* of the same `KnownPeer` data, not a
  different mechanism.
- Remaining friction is the recovery password, which is deliberate
  (non-custodial). v2: passkeys with the PRF extension derive the
  encryption key, making "sign in with passkey" a true one-step restore.
- The directory doubles as the portal's "your devices" list with
  routing-level revocation (remove device → record deleted everywhere).
  Key-level revocation stays out of scope: all devices share the agent key.

## Security notes

- **Stop logging `agent_secret`.** The server prints the full secret to
  stdout on first boot — on Android that lands in logcat (world of debug
  tooling, bug reports, `adb logcat` history). Verified present 2026-07-08.
  Replace with "open Settings → Devices to pair a device". This ships with
  P0 below regardless of everything else.
- A pairing code carries no identity, and one that claims to is refused. This
  is what lets the deep-link handler act without a prompt: `atomic:` links can
  be fired by any app or web page, so a link must never be able to sign a device
  in as someone else. Removed 2026-07-10 along with the `onboard` kind.
- Scanning a malicious `pair` QR dials an attacker node that then fails
  AUTH and gets nothing (adversarial tests in serverless-p2p P4 cover the
  frame-level guarantees).
- Deep-link handler must be idempotent: the shell re-dispatches pending links
  (cold start), and the frontend dedupes by URI.

## Drive enrollment (narrows serverless-p2p OQ4)

v1 pairs the whole agent (`drives: "*"`), but `KnownPeer.drives` is written
from the envelope from day one, so per-drive narrowing later is a UI change,
not a migration. The QR issuer UI can add a drive picker when someone asks
for it.

## Phases

### P0 — hygiene (independent, do first)

- [x] Remove `agent_secret` from first-boot log output (server). **Fixed
      2026-07-09** — `set_default_agent` (`server/src/appstate.rs`) logged
      the whole config file (secret included) via `tracing::warn!` on
      first boot; now logs only the config path + a pointer to the
      pairing/sign-in flow.
- [x] `SyncRoute`: show local node DID as QR (`pair` kind). **Built
      2026-07-09** as a "Pair device" dialog (`PairDeviceDialog.tsx`,
      QR renderer: `uqr`, zero-dep SVG).

### P1 — pairing flow (server/desktop ↔ phone)

- [x] Envelope encode/decode module in `browser/lib` (versioned, unit-tested
      against tampered/unknown payloads). **Built 2026-07-09**
      (`browser/lib/src/pairing.ts`, 16 tests): unknown `v` gets a
      distinct 'unsupported-version' error code; an envelope carrying a
      secret is rejected; encode round-trips the validator. **Rewritten
      2026-07-10** as a readable URI (no base64) with the `onboard` kind
      removed entirely.
- [~] ~~"Pair new device" screen rendering the `onboard` QR~~ — **removed
      2026-07-10.** It was already dead: it read the secret via
      `getAgentSecretFromIDB()`, which `6cdab0e3` deleted along with the
      plaintext key record. The Sync page now shows the routing-only `pair`
      QR + code outright (no dialog, no reveal, nothing to blur), and also
      accepts a pasted `atomic:pair` link or a bare `did:ad:node:…`.
- [x] Phone: `atomic:` deep link — **verified on-device 2026-07-09**
      (Xiaomi Pad): a cold-start `pair` VIEW intent lands as a persisted
      `KnownPeer` carrying the Mac's node DID. **No in-app scanner needed
      for v1**: the QR encodes the `atomic:` URI, so the system camera
      IS the scanner — the in-app scan path (OQ1) is only for devices
      whose camera app won't open custom schemes.
      Two hard-won Android findings:
      1. `tauri-plugin-deep-link`'s Kotlin side **drops every intent when
         `deep-link.mobile` is missing from tauri.conf.json** (its
         `isDeepLink()` returns false on empty config) — a manual
         manifest intent filter alone opens the app but the link never
         reaches the plugin. `mobile: [{ "scheme": ["atomic"] }]` fixes
         it AND auto-generates the manifest filter at build time.
      2. `Builder::on_page_load` **never fires on Android**, and a
         `webview.eval` into a not-yet-loaded page is silently lost — so
         "flush on page load" cannot work. Delivery is at-least-once
         instead: the shell re-dispatches pending links every 3s for
         2 min (`desktop/src/lib.rs`), and `helpers/deepLinkQueue.ts`
         dedupes by URI so each link is handled once per page.
- [x] Import (**built 2026-07-09**, `components/PairingLinkHandler.tsx`):
      a link → KnownPeer + an immediate reconcile + the Sync page.
      Unsupported version → "update this app" toast. Receiver paths
      verified live in the web app by dispatching the DOM events.
      **Revised 2026-07-10:** the identity-importing half (`Agent.fromSecret`
      → `setAgent` → `saveAgentToIDB`) and its "Switch account?" dialog were
      removed. Any app or web page can fire an `atomic:` link, so a link
      must never be able to sign this device in as someone else; the decoder
      now refuses a code carrying `secret=`. What remains grants nothing, so
      it needs no prompt.

### P2 — pair flow + discovery sugar

- [ ] `pair` kind end-to-end between two provisioned devices (auto-accept
      iff same agent; `KnownPeer` capability record per serverless-p2p P3).
- [ ] mDNS candidate list in the pairing screen (tap instead of scan).
- [ ] pkarr-based redial when `KnownPeer` NodeIDs go stale.

### P2.5 — SaaS device directory (parallel track, mostly atomic-saas)

- [x] `devices` table + register/list/revoke endpoints (portal-session
      auth) in atomic-saas; portal "your devices" list with remove.
      **Built + verified live 2026-07-08** (`atomic-saas/src/devices.rs`;
      `GET /api/devices`, `PUT`/`DELETE /api/devices/{device_id}`).
      Cross-account `device_id` claims are rejected (409) so a session on
      a shared machine can't hijack/revoke another account's routing
      entry; node DIDs validated as `did:ad:node:<64 hex>`; upsert
      preserves `created_at`, bumps `last_seen`.
- [x] Browser: upsert own device record + seed `KnownPeer`s from the
      directory. **Built 2026-07-09** (`helpers/managed/devices.ts`,
      fired once per session from `IdentityReconcileGate` after
      convergence; no-op without a managed session). Upsert is
      Tauri-only — a plain web tab has no Iroh node of its own, so
      `/iroh-node-id` would name the connected server, not the device.
      On 409 (device id owned by another account — shared machine) the
      id is rotated and retried once. Seeding merges into the same
      `atomic-peers` localStorage records the QR flow writes (existing
      entries win), so the sync engine can't tell the flows apart.
      Deliberately NOT done: auto-dialing the seeded peers — they show
      in the Sync page's peer list, one tap to sync. Auto-reconcile on
      seed can come with P2's `SyncSession` work.
- [ ] Later: passkey + PRF-derived encryption key for one-step restore.

### P3 — channel-provisioned secret (after knock/inbox)

The only sanctioned way an existing device may hand its identity to a new one.
Until it lands, a new device signs in by entering its secret; there is no
one-scan onboarding, by design.

- [ ] `onboard-request` kind: routing + one-shot token in QR; secret flows
      over the authenticated Iroh channel after on-screen confirm. The QR
      still carries no key — only routing and a token the confirm gates.
- [ ] Requires the agent secret to be reconstructable on the *sending* device,
      which `6cdab0e3` deliberately made impossible for the stored keypair.
      Resolve that first: either re-derive from a user-supplied passphrase at
      send time, or send a freshly-minted delegated key rather than the root.

## Open questions

1. ~~**QR scanner dependency**~~ — **Resolved 2026-07-09:**
   `tauri-plugin-barcode-scanner`. The Android WebView won't grant
   `getUserMedia` to web content, so a `BarcodeDetector` scanner can't work;
   the native plugin owns the camera and permission. It's compiled in for
   mobile only, so the scan affordance is gated on `isMobileTauri()`.
2. ~~**Expiry semantics for `onboard` QRs**~~ — **Moot 2026-07-10.** A `pair`
   code is routing only and grants nothing, so a screenshot of it ages out to
   no consequence; there is nothing to expire. Expiry returns with P3's
   one-shot token, where it falls out of the token machinery for free.
3. **Multi-agent devices** — the flows assume one default agent per device.
   If/when a device holds several agents, the Sync page needs to say *which*
   identity a pairing code belongs to, since AUTH is per-agent.

## Carried over from the pairing field test (2026-09-04)

The field notes moved to [`completed/pairing-ux-field-test.md`](./completed/pairing-ux-field-test.md); the item below is the one still open that belongs here.

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
