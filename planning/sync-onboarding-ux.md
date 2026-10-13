# Sync & Onboarding UX

> **Status:** Reference, not a build plan. The current cross-client model of what can reach what, the agreed language, the existing paths, where the logic lives and what is tested. Update it when a sync or onboarding screen changes; it has no "done".

How we talk about sync, what can actually reach what, and which paths exist.
Read this before changing any sync/onboarding screen in **any** client — the
same person meets several of them, and should not have to learn each one.

Applies to: the data-browser (browser tab), the data-browser in Tauri
(desktop/mobile), the Flutter canvas app, and atomic-server.

---

## 1. What can reach what

Most UX mistakes here come from getting this wrong. It is not symmetric.

| From → to | How | Hard constraint |
| --- | --- | --- |
| device ↔ device (either one always-on) | Iroh, by scanning a code — a node id needs no address, port or certificate | each side serves what the other's key **may read** (`check_read`), per subject |
| device → always-on device | Iroh, or a push over WS if you have its address | needs write rights there, signed as *your* agent |
| always-on device → device | WS subscribe + fetch | the device must know its address |
| browser tab ↔ anything | only through an always-on device | a browser tab **is not a node**: it cannot pair, and holds nothing |

Three consequences that keep being forgotten:

- **An always-on device is still a device.** It signs in as its own agent, but
  that decides nothing: rights do, per subject, on every transport
  (serverless-p2p Principle 2). It is a peer that happens never to sleep and
  that you do not carry. Peer sync used to refuse it — that refusal is gone,
  and with it the idea that a workspace needs HTTP to reach one.
- **A secret restores who you are, not what you have.** Signing in on a new
  device gets you an identity and an empty workspace. Something still has to
  carry the data.
- **Connecting another device is optional.** After trying available recovery,
  browser/Tauri sign-in opens a writable derived private home and offers a
  device/backup nudge. Creating that home does not mean old content was
  recovered. Foreign workspace links never synthesize a replacement. The
  Flutter login still uses `resume_app_session` and its needs-sync screen;
  it has no browser private-home materialization path yet.
- **Connecting is not pushing.** Connecting to a device fetches a workspace
  you lack; it never offers the one you have. A workspace made before you
  connected anywhere exists in exactly one place until someone pushes it.

## 2. Language

The same concept has been called a server, a sync hub, a connection and a node
— in three clients. Pick one word and keep it.

| Say | Not | Why |
| --- | --- | --- |
| workspace | drive, store | "drive" is our schema's word, not a person's |
| your devices | peers, nodes | a node is an implementation detail |
| device; *always-on device*, or its address (`atomicserver.eu`) | server, hub, sync hub, node | a server is a device that never sleeps — three words for one thing taught three mental models |
| pairing code | envelope, node DID, `atomic://pair` URI | it is a code you scan |
| sync | replicate, reconcile, promote | one verb, whatever the transport |

Rules of thumb:

- **Name what the person wants, not the mechanism.** "Where your data is",
  not "Sync hub URL". The address is the answer, not the concept.
- **Ask for plumbing only when there is plumbing to do.** Nothing that has no
  data yet should be asked where to sync it.
- **A dead end is not a question.** Do not offer a box to type into if no
  answer exists. "Connect the server your workspace lives on" asked a phone
  user to name something that had never existed; the answer was a code, three
  lines up the page.
- **Say where things are, plainly.** "This is `localhost:9883`, the always-on
  device this browser reads from — not the browser itself." Mechanism belongs
  in a footnote, never in the headline.
- **A state is not an error.** No device connected, unreachable, data
  elsewhere — these are normal, and read as normal.
- **An unreadable workspace has unknown sync and backup status.** A failed
  read does not establish that another device has the data. The browser's
  `syncSummary` reports the failed read; Flutter's device settings currently has
  no corresponding workspace-status summary, only connection controls and
  operation errors.

## 3. The paths

Every combination someone can actually get into. "Crosses by" is the only step
that moves data.

| Start | Then | Crosses by | Works today |
| --- | --- | --- | --- |
| new account in browser | mobile / desktop later | device connects the same address, fetches | ✅ |
| new account on Tauri desktop | browser later | desktop pushes workspace up, browser reads it | ✅ `promoteLocalDrive` |
| new account on Tauri desktop | Tauri mobile later | pairing code, either direction | ✅ |
| new account on Flutter mobile | Tauri desktop later | pairing code | ⚠️ untested across the two apps |
| new account on Flutter mobile | another Flutter mobile | pairing code | ✅ |
| new account on Flutter mobile | browser later | scan the browser's code — the always-on device it reads from — or push over WS | ✅ Iroh, or `syncDriveToServer` |
| new account anywhere | atomicserver.eu later | device pushes up, then everything reads from there | ⚠️ untested |
| new account in browser A | browser B, no machine in common | **nothing crosses** | ❌ by design — say so |

The last row is the one to get right in copy: two browser tabs with no machine
between them cannot reach each other, ever. Neither is a node.

## 4. Where the logic lives

Keep these in step. A change to one is usually a change to its twin.

| Concern | Browser | Flutter |
| --- | --- | --- |
| sync screen | `data-browser/src/routes/SyncRoute.tsx` | `packages/atomic_flutter/lib/src/server_settings_section.dart` |
| settings shell | (same route) | `packages/atomic_flutter/lib/src/agent_settings_dialog.dart` |
| onboarding, data elsewhere | `data-browser/src/views/getting-started/ConnectDeviceStep.tsx` | `flutter/lib/screens/login_screen.dart` |
| pairing code, show / scan | `components/PairingCode.tsx`, `ConnectToDeviceForm.tsx` (`ScanCodeButton`), shown by `ConnectDevice.tsx` | `flutter/lib/screens/pair_screen.dart` |
| pairing code, format | `browser/lib/src/pairing.ts` | `pair_screen.dart` (`_parsePairingUri`) |
| URL rules (scheme, local address) | `data-browser/src/helpers/serverUrl.ts` | `flutter/lib/atomic/server_url.dart` |
| what a machine says about itself | `data-browser/src/helpers/managedServer.ts` | `flutter/lib/atomic/server_info.dart` |

A FOSS node on a public address must not present **Create account** as if it
were an open host — that path calls `createDrive` and, under today's
`OpenPolicy`, stores the stranger's workspace. The proposed `/server` fields
and welcome branches live in
[`foss-public-host-mode.md`](./foss-public-host-mode.md). Localhost Create
account does not change.
| push a workspace up | `browser/lib/src/store.ts` (`promoteLocalDrive`) | `AtomicClient.syncDriveToServer` |

**Which servers the browser's Devices list shows.** `SyncRoute` renders every
origin in `serverURLStorage`'s known-servers list. Origins get in through
`setServer` (switching, Cloud Sync enrollment) and through `AppSettings`
registering the origin the app itself was served from — but only after
`/server` answers like a node (`isAtomicServer` in `managedServer.ts`). That
guard exists because of atomic-saas's shared app origin
(`app.atomicserver.eu`): it serves the SPA but is not an atomic-server, and
without the check it appeared on /sync as a phantom "always-on device" next to
the real node (`node1.atomicserver.eu`) — with a Switch action that would
point the store at a non-server. A failed check also removes the origin, so
entries registered blindly by older builds clean themselves up. Browser-only:
the Flutter app has no equivalent auto-registration.

Shared, and authoritative over all of the above:

- `lib/src/sync/peer.rs` — pairing, AUTH, and the rule that rights decide
- `lib/src/sync/replicate.rs` — `replicate_drive_to_remote`, the push
- `server/src/plugins/server_info.rs` — `/server`, what a machine says it is
- [`device-pairing.md`](./device-pairing.md) — the code's wire format
- [`unified-sync.md`](./unified-sync.md) — where the transports are heading

## 5. What is tested

| Level | Covers | Where |
| --- | --- | --- |
| Rust unit | pairing AUTH; a different agent syncs what it may read, is told why when it may read nothing, and pushing to an empty device is not a failure | `lib/src/sync/` |
| Rust integration | replication, a fresh client reading a replicated workspace | `server/tests/it/replicate.rs` |
| Rust integration | `/server`, `/drive-usage` | `server/src/tests.rs` |
| Dart unit | URL rules, pairing code parsing, signing parity with Rust | `flutter/test/atomic/` |
| Browser e2e | two servers, sync between them | `browser/e2e/` |

**How the suite missed the flow it exists for.** Nine of the ten Iroh e2e
tests are built on `setup_pair`, which loads *one agent's secret into both
devices*. The tenth used two agents and asserted that nothing crossed. So the
fixture itself encoded "peers are one person's devices" — the assumption the
identity gate was made of — and the entire two-account half of the space,
which is every flow involving an always-on device, had no test that could
fail. A test suite shaped by an assumption cannot question it.

The lesson is not "write more tests". It is: **a fixture is an assumption**.
When one setup function opens nine tests, read what it decided for them.

Gaps worth knowing, rather than rediscovering:

- **No test crosses two clients.** Every path in §3 is verified by hand. The
  Flutter↔Tauri pairing row has never been run at all.
- **No test measures the push direction from Dart.** The Rust side now covers
  "push to an empty device"; nothing above it does.
- **Dart signing is checked against Rust by golden vectors**
  (`lib/src/genesis_test_vectors.json`), not by a live handshake. That caught a
  real bug (base64 alphabet); it would not catch a header the server ignores.
- **The push path has no Dart-side test.** `syncDriveToServer` is covered by
  Rust replication tests underneath, and nothing above.

---

*If you change vocabulary or a flow here, change it in both clients and update
this table. A person moving from the phone to the laptop should not notice
they moved.*

## Cloud Server setup (2026-09-07)

The hosted browser now offers setup for existing portable drives on another
server. The source's `/replicate-drive` copies its complete data and verifies
receipt; the browser keeps its source connection and offers “Use Cloud Server”
only after that copy succeeds. Local-only drives connect to the assigned node
before promotion. Enrollment alone is not a successful transfer: pending or
empty placements must not override the source on the next app launch.

The account portal hands setup to `/app/sync?drive=…`, preserving the selected
drive. It shows hosting beside each drive and keeps unfinished setup actionable.
The confirmation explains that hosting is a readable copy, distinct from Vault.
Flutter has no equivalent managed-hosting setup action; its generic device
connections are unchanged. The browser's source-server path also applies to an
embedded node, but native runtime verification remains separate.

### Hosting consent and drive switcher (2026-09-07)

The hosting action explains Local, Vault and Server before an explicit “Agree
and enable Cloud Server” action. The paired control plane requires consent
version 1 and persists account, agent and server timestamp on the enrollment.
Existing records retain unknown consent; no consent is inferred from a drive
being present. Browser switcher rows carry compact service state labels, with
one Storage and hosting action for details. Unknown cloud status stays explicit.

### Plan steps and automatic hosting (2026-10-05)

The Sync page's account card is a header (atomic.place, email, recovery,
Manage account) over "Your plan": Cloud Vault, then Cloud Server, both drawn
by the same `ServiceRow` (`components/Cloud/ServiceRow.tsx`): name and a
Current / Included / Offered badge, one fixed tagline, selling points while
off, one status line with a coloured dot, a `details` slot, then actions,
primary first. Cloud Server is the step up and includes Cloud Vault. The
managed node itself is listed under Devices with every other server.

There is no "Finish setup". A drive with a paid plan (`source: stripe` from
`/api/billing/subscription`), or one already enrolled, enrolls and switches by
itself and shows "Moving…"; a failure shows the reason and Try again. Consent
is asked only for a plan nobody bought (`source: grant`, or no `source` from an
older control plane), because hosting stores a readable copy. The checkout is
where a buyer agrees to that. Flutter has no plan UI, so nothing changes there.

## Desktop workspace discovery (2026-09-08)

A restored Tauri identity now inspects its personal drive's PKARR peer before
asking the user to fetch. The inspection authenticates, reads only the drive
resource to check access, and discards the snapshot. It imports no data and
creates no remembered pairing. A successful result names the device from HELLO;
only “Fetch workspace” starts sync, followed by a fresh local readability check.
An address can supply a node ID when PKARR discovery fails. Device names are
self-reported display labels, never identity or authorization evidence.

Flutter already attempts PKARR through `syncConnectivityNow`; its automatic
fetch behavior is unchanged in this desktop debugging change. The new shared
Rust inspection is available for a future matching confirmation step there.

### Account recovery after code sign-in

The browser/Tauri Account recovery card offers recovery-code unlock independently of passkeys, including after a WebAuthn failure. A portal session plus the existing recovery code can add a passkey without replacing the code or older passkeys. Each passkey uses its own PRF salt. Flutter has no corresponding envelope-management card yet.

### One set of account sign-in options

Every screen that signs in to the account (the portal's sign-in page and its
homepage panel, the app's sign-in and restore steps) renders the same
`AccountSignIn` from `@tomic/service-ui`: Google, passkey, email link. The app
adds only what the portal cannot do, pasting an agent secret. Native builds that
cannot hold the account cookie link the device with a code instead. Flutter has
no account sign-in yet.

## Shared Flutter settings package

`packages/atomic_flutter` now owns the Canvas settings and Devices widgets.
Canvas delegates storage and transport through `flutter/lib/atomic/settings_backend.dart`.
Atomic Audio can provide its own adapter without copying the dialog. The browser
SyncRoute remains the visual/wording twin; this extraction changes no browser
behavior. Pairing and authentication screens remain host-owned for now.

## Sync page layout (2026-10-08)

Top to bottom: a **sync problem banner** (only when something is wrong), the
account card, then Devices, then one **Connect a device** section, then
Developer.

- **Plan rows share one `details` slot.** Both rows draw usage with
  `UsageMeter` (bar plus "X MB of Y GB"). When Cloud Server is the current
  service, the Cloud Vault row ("Included") shows no bar and no quota, only
  "N objects · X MB backed up" and a muted note that the backup is part of the
  Cloud Server plan: the vault's allowance there is a Cloud Server entitlement
  (50 GiB, against 100 MB for free Cloud Vault), and quoting it on the vault
  row reads as the vault's own limit. The bar returns at 90% of the quota even
  when included. Cloud Vault adds a **Manage storage**
  action in its row actions (subtle, like Restore and Turn off) that opens the
  breakdown inside the row. Cloud Server, once on, shows
  `CloudServerDetails`: the usage meter with "(see where space goes)", a line
  "N resources · Synced <ago>", and the drive's web address
  (`DriveAddress`, backed by `helpers/managed/aliases.ts` against the portal's
  `/api/aliases`: reserve, rename, release, debounced availability check,
  "Setting up" until a node confirms). Control plane routes that do not exist
  yet (HTML or 404) become one plain sentence, never a parse error.
- **Devices.** The managed node is a bordered card like "This device" and every
  other server: title, status pill, Disconnect. Usage and the address live on
  its plan row, not on the device card.
- **Connect a device** (`components/ConnectDevice.tsx`) always renders below the
  device list, as one card of two halves. "Show this device" (QR and copyable
  code) keeps its old gating: a peer node, or a server that is not
  mid-hosting. "Add a device" is one input that takes a pairing code (handed
  to `deliverDeepLink`, native only) or a server address (added as before);
  `helpers/connectInput.ts` decides which. A browser tab cannot take a code,
  so a pasted code answers with where it can be entered. A Scan button shows on
  mobile Tauri. `focusConnectDevice()` is the one way other screens lead here.
- **Sync problem banner** (`components/SyncProblemBanner.tsx`, wording in
  `helpers/syncProblem.ts`). The sidebar's warning icon links to it
  (`/app/sync#sync-problem`). It separates *ours* (unexpected errors, commits
  that keep failing: "a problem on our side", Try again, reported to Sentry
  once) from *yours* (the server does not hold the workspace: Connect a device
  or turn off server sync; no write access; plan full: storage) and plain
  connection loss (Try again). A commit that keeps failing is reported by the
  outbox (`reportRepeatedCommitFailures`); the page reports only what that does
  not cover (`reportSyncProblem`). Flutter has no equivalent banner.
