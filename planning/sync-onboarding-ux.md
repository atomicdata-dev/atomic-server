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
| sync screen | `data-browser/src/routes/SyncRoute.tsx` | `flutter/lib/atomic/widgets/server_settings_section.dart` |
| settings shell | (same route) | `flutter/lib/atomic/widgets/agent_settings_dialog.dart` |
| onboarding, data elsewhere | `data-browser/src/views/getting-started/ConnectDeviceStep.tsx` | `flutter/lib/screens/login_screen.dart` |
| pairing code, show / scan | `components/PairingCode.tsx`, `ConnectToDeviceForm.tsx` | `flutter/lib/screens/pair_screen.dart` |
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
