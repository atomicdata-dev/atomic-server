# FOSS public host mode — expose HTTP, do not host strangers

> **Status:** Phase 1 + 2 built (2026-08-23). OQ5 library path closed
> 2026-09-05 (`admit_unknown_drive`: `Public` never creates a drive; Owner
> enrolls only the owner). Phase 3 (rate limits, Iroh stream refusal) is
> untouched.
>
> Three decisions changed during the build; the body below has been corrected
> where it said otherwise, and [Resolved decisions](#resolved-decisions) records
> why. Companion to
> [`cloud-sync-managed-node.md`](./cloud-sync-managed-node.md) (managed
> allowlist), [`unified-sync.md`](./unified-sync.md) Open Question 5
> (bootstrap admission), and [`sync-onboarding-ux.md`](./sync-onboarding-ux.md)
> (welcome / pairing copy).
>
> This is the FOSS-side answer to the same abuse the managed node already
> closes: a reachable node must not become a free sync hub. The open core
> already has the *mechanism* (`SyncPolicy` / `AllowlistPolicy`). FOSS never
> installs it. That is the gap.

## Goal

A person can put a stock `atomic-server` on the public internet — a site, a
wiki, their own workspace reachable from a phone — **without** letting
strangers store a workspace on it.

Two things that must stay true:

- **Public read of what the owner shared stays public.** `ATOMIC_HOME_DRIVE`,
  the public Agent on a Drive, invite links, and ordinary `check_read` do not
  change.
- **FOSS never phones home.** No control plane, no email, no portal. The
  owner is an agent DID the operator puts in `ATOMIC_OWNER_AGENT`.
  Guardrail #3 in `cloud-sync-managed-node.md` is not renegotiated here.

## The hole today

FOSS boots `OpenPolicy`: every drive is admitted, there is no quota, and a
drive that does not exist locally is treated as a bootstrap and accepted
(`import_sync_push` and `admitted_for_drive` both carve this out;
`unified-sync.md` OQ5). Combined with the current welcome screen, a public
FOSS node is an open registration form for free storage.

Anyone who can reach the origin can:

| Path | What happens |
| --- | --- |
| Welcome → **Create account** | `NewIdentitySection` mints a DID agent and `store.createDrive()` POSTs a genesis commit. `OpenPolicy` admits it. The stranger now has a private workspace on *your* disk. |
| `POST /commit` genesis | Same write, no UI required. |
| Iroh `SYNC_PUSH` of a new drive | `/server` advertises `did:ad:node:…`. AUTH is only identity proof. A missing drive hits `Err(_) => true` and is imported. |
| `PUT /blob/{hash}` | Gated by `admit_drive_write`. Under `OpenPolicy` that is a no-op, so a freshly minted drive can also take file bytes. |

What is *already* fine, and must not be “fixed”:

- ACL on **existing** resources (`check_read` / `check_write`). A stranger
  cannot read a private Drive just because they can reach the host.
- `--public-mode` is the opposite of this feature (skip auth). Do not reuse
  the name or the flag.
- Managed nodes already install `AllowlistPolicy` from the control plane.
  This plan is the self-hosted equivalent, populated locally.
- Unsolicited Iroh peers are not written to the known-peers table (F9).
  Connection ≠ enrollment.

The old `/setup` invite is no longer the onboarding path.
`AppState` no longer creates a root Drive; the data-browser’s new-identity
flow does. Docs that still tell people to accept `/setup` are describing a
vestige. There is **no owner** on a FOSS node today — the first visitor and
the hundredth are the same to `OpenPolicy`.

## What “sync with it” means

**Host a workspace** = this node stores and serves a Drive (commits, Loro
snapshots, blobs) as an always-on replica.

That is what we gate. These are different, and stay allowed:

- A visitor **reads** a Drive the owner marked public.
- A collaborator the owner **invited** reads and writes *that* Drive
  (ordinary hierarchy rights). They do not get a blank Drive of their own.
- The owner’s **other devices** sign in as the same agent and push/pull
  the owner’s Drives over HTTPS or Iroh.

A later “host your friend’s workspace here” invite is a different product
(multi-tenant FOSS). Out of scope until someone asks for it.

## Decision: `HostMode { Open, Owner }`

| Mode | Who may enroll a new Drive | Default |
| --- | --- | --- |
| **Open** | Anyone. Today’s `OpenPolicy`. | `ATOMIC_DOMAIN` is `localhost` / loopback / a private IP |
| **Owner** | Only an **authorized-to-create** agent. `AllowlistPolicy` with **zero** grace, persisted on disk. | Everything else (public hostname, `--https`, an explicit flag) |

Override: `--host-mode=open|owner` / `ATOMIC_HOST_MODE`. Never infer
silently from `--https` alone without logging the chosen mode at boot —
a tunnel used for local dev must be able to stay Open.

**Do not** use `AllowlistPolicy`’s 10-minute bootstrap grace in Owner
mode. That window is how a stranger dumps a Drive before anyone notices.
Managed nodes need grace because enrollment is eventually consistent with
a control plane. FOSS enrollment is local and synchronous.

### Who is authorized to create a Drive

Narrower than “has write on some hosted Drive”:

1. The **owner agent** — the DID in `ATOMIC_OWNER_AGENT` /
   `--owner-agent`. That is the only claim mechanism.
2. Later, and only if we add it: a comma-separated
   `ATOMIC_OWNER_AGENTS` list, or a `createDrive` grant. Not v1.

A collaborator with `write` on Drive D may write to D. They may not
genesis a new Drive on this node. Treating “write on an enrolled Drive”
as “may enroll” is the abuse vector with extra steps.

The owner’s second device is the same agent DID (they imported the
secret). Creating another Drive auto-enrolls because the signer *is* the
owner.

The env holds the **agent DID**, never the secret. The node does not
sign as the owner; it only admits signers that match. If someone pastes
a full secret JSON, reject boot with “that is a secret; this flag wants
`did:ad:agent:…`” — people will try.

### How a Drive gets on the allowlist

On a successful Drive genesis whose signer is authorized-to-create:
persist the Drive subject in the allowlist (redb `PluginMeta`, reload on
boot). Existing Drives at the moment the node flips Open → Owner are
snapshotted in. After that, strangers get `NotEnrolled` on every write
path that already consults `admit_decision`:

- `commit.rs::validate_and_build_response` (`POST /commit`, WS `COMMIT`)
- `engine::import_sync_push`
- `peer::admitted_for_drive` (Iroh live `UPDATE` / `DESTROY`)
- `handlers/blob.rs::put_blob`

Agent subjects (`did:ad:agent:…`) stay exempt, keyed on
`commit.subject.is_agent_did()` — never on a claimed `IS_A`. That
exemption is small; it is not a Drive. Rate-limit it (below) so it
cannot become unbounded profile spam.

### Bootstrap (closes OQ5 for Owner)

Replace `Err(_) => true` (“missing Drive ⇒ admit”) with:

- **Open:** keep today’s carve-out.
- **Owner:** admit a missing Drive iff the authenticated signer is
  authorized-to-create; then enroll it. Otherwise `NotEnrolled`.
  `ForAgent::Public` never creates a Drive.

This is “reject-until-known”, not first-writer-wins. There is no
first-writer: the owner DID is in the process environment before the
socket opens.

## Claim: `ATOMIC_OWNER_AGENT`

Identity is already local-first. A secret is a keypair; the agent DID
is `did:ad:agent:{publicKey}` and does not need a server to exist. It
is reasonable to expect someone who is about to bind `:443` to already
have one — created on localhost, in the desktop app, or on a phone —
and to paste that DID into the node’s env.

```env
# The DID only. Never the private key / secret JSON.
ATOMIC_OWNER_AGENT=did:ad:agent:AbCdEf...
```

That is the whole claim. No setup token, no “first visitor to
`/setup` owns the machine,” no one-shot Create account on the public
origin. Those are claim races on a public socket; an env the operator
set is not.

**Owner mode without a valid `ATOMIC_OWNER_AGENT` fails closed.** Do
not fall back to Open (that would make a missing line in `.env` an
open hub). Do not boot a “waiting for first user” state. Refuse to
start and print where to get the DID:

```text
Owner mode needs ATOMIC_OWNER_AGENT=did:ad:agent:…
Create an account on localhost or in the app first, then copy the
agent ID from Settings (or the `subject` field of your secret).
To run an open node on purpose: ATOMIC_HOST_MODE=open
```

Validate the value: must be a `did:ad:agent:` DID. Reject a pasted
secret, an `https://` agent URL, or an empty string.

The env is the source of truth every boot — not a value we persist
and can drift from. Changing the var changes who may enroll new
Drives. Already-enrolled Drives stay hosted (collaborators keep
`write` on them). `--initialize` cannot mint a new owner.

Where the person copies the ID:

- Settings / the agent profile (copy button).
- The secret JSON’s `subject` field.
- After a local Create account, one line of copy: “Going to put this
  on the internet? Set `ATOMIC_OWNER_AGENT=` to this ID.”

## Setup UX

Two journeys. The welcome screen tells them apart from `/server`
(see [Node advertisement](#node-advertisement)).

### 1. Localhost (Open) — do not touch

`Create account` → local DID → `createDrive` → it lands. This is the
FOSS path `managedServer.ts` exists to protect. E2E `before` /
`devDrive` stay on it. This is also how a new operator *gets* the
DID they will put in the env.

### 2. Going public — env, then expose

1. They already have a secret (localhost, desktop, or phone).
2. They set `ATOMIC_OWNER_AGENT`. That alone selects Owner mode —
   a public `ATOMIC_DOMAIN` and `--https` are about links and certs,
   not about who may write.
3. Boot. Snapshot every Drive already on disk into the allowlist
   (so a localhost-then-expose move does not lock the owner out of
   data that is already there).
4. They sign in on the public URL with the same secret. New Drives
   they genesis enroll because the signer matches the env.

Copy, in the owner’s language from `sync-onboarding-ux.md`:

> Visitors can see what you have shared. They cannot store their own
> workspace on this always-on device.

A VPS image with no prior localhost step is the same journey: create
the identity in any Atomic client first (the keypair is local), put
the DID in the server’s env, deploy, sign in. The public welcome
page never offers Create account.

### After boot (Owner + env set)

Welcome screen:

- **No** “Create account” that creates a Drive on this node.
- **Sign in** (secret / passkey) — the owner on a new browser.
- **I have an invite** — existing resource-invite flow, if they arrived
  on one.
- If `ATOMIC_HOME_DRIVE` is set and the public Agent may read it: skip
  welcome and show the site. That is the public-website case.

A stranger who pastes their own secret signs in as themselves and sees
nothing they may read — same as today — and cannot `createDrive` here.
`promoteLocalDrive` / “use this always-on device” must fail with the
same sentence the welcome page used, not a generic 403.

### Collaborators and second devices

| Person | How they get in | What they can host |
| --- | --- | --- |
| Owner, new browser | Sign in with the secret | Their Drives (auto-enroll new ones they genesis) |
| Owner, phone | Pairing code (routing) + same-agent AUTH, or HTTPS + secret | Same |
| Collaborator | Resource invite → `read`/`write` on a Drive | That Drive only |
| Stranger | Nothing | Nothing |

Pairing stays routing-only (`device-pairing.md`). The gate is the
signer, not the NodeID.

## Node advertisement

`GET /server` already tells the client whether the node is managed.
Add three facts (absent ⇒ treat as Open, so old nodes keep working):

| Property | Meaning |
| --- | --- |
| `hostMode` | `open` \| `owner` |
| `acceptsNewDrives` | `true` only in Open. Owner is always `false` — new Drives enroll only when the signer matches `ATOMIC_OWNER_AGENT`. |
| `ownerSet` | whether `ATOMIC_OWNER_AGENT` is set (Owner mode that booted) |

In Owner mode, **do not** give `ForAgent::Public` the Iroh node id or
the peer list. Those are a device inventory and a dial target. The
owner’s signed-in session still gets them (Sync page, pairing QR). A
stranger with a leaked NodeID can still *attempt* an Iroh connect;
writes fail admission. Hiding the id removes the convenient listing.

`accountCreationTarget` grows a third branch:

- managed + portal → portal (unchanged)
- FOSS Open → local Create account (unchanged)
- FOSS Owner → no create; Sign in / invite

Keep this pure and unit-tested next to `managedServer.test.ts`. Do not
infer “locked” from `managed: false` alone — that is every FOSS node.

## Protection against malicious users

Admission is the load-bearing gate. These are the leftovers that
admission does not cover.

1. **Claim is config, not a request.** `ATOMIC_OWNER_AGENT` is set
   before bind. A missing or invalid value refuses to start in Owner
   mode. There is no HTTP path that becomes the owner.
2. **`--initialize`** — cannot mint an owner (the env still wins).
   Still log a warning if run on a non-loopback Owner bind; it is
   not a claim reset.
3. **Agent spam** — the agent-DID exemption lets anyone persist a tiny
   Agent resource. Either require the signer to be the owner / an
   invite-accept, or rate-limit unknown-agent `POST /commit` (token
   bucket per IP + per agent). Unbounded profile writes are the
   residual.
4. **Expensive public endpoints** — `/search`, `/query`, `/commit`,
   `/blob`, WS upgrade. A public website needs some of these; a
   stranger does not need unlimited blob PUTs. Cheap per-IP limits on
   the write endpoints, independent of ACL.
5. **Iroh slot exhaustion** — leave Iroh on (phones may use it). Do
   not persist unknown peers (already true). Optional follow-up: after
   AUTH, close the stream if the agent is not the owner and has
   `check_read` on no hosted Drive. Public-site visitors do not need
   Iroh; they use HTTP.
6. **Do not treat CORS as a write gate.** Writes are signed. Permissive
   CORS stays; it is how a public page is read from another origin.
7. **Optional disk cap** for the whole node, even for the owner, so a
   stolen secret cannot fill the disk. Nice-to-have; not v1.

`--public-mode` remains a documented footgun: “skip auth, do not bind
this to the internet.” Owner mode is the flag people actually want
when they say “public but mine.”

## What we will not do

- Put a control-plane client, heartbeat, or portal URL into the open
  `atomic-server` binary.
- Require email to run a FOSS node.
- Put the agent **secret** in the environment. The DID is enough.
- Change the localhost Create-account path.
- Equate “has write on a shared Drive” with “may enroll a new Drive.”
- Reuse `--public-mode` or name the feature “public mode.”
- Make the node sign as a principal to pull private Drives
  (`cloud-sync-managed-node.md` — the node relays and serves).

## Implementation sketch

Small, in this order. Each step is independently shippable and
testable.

### Phase 1 — policy on the node (no UI)

- `HostMode` on `Opts` / `Config`. Default: Open on loopback/private
  domain, Owner otherwise. Log the choice.
- Owner mode **requires** `ATOMIC_OWNER_AGENT`. Invalid/missing →
  exit with the message above. Never fall back to Open.
- On Owner boot: `Db::set_sync_policy(AllowlistPolicy)` with
  `set_grace(Duration::ZERO)`. Owner DID comes from the env every
  time. Persist only `allowed_drives` (redb `PluginMeta`).
- On Open → Owner flip (or first Owner boot with existing data):
  snapshot every Drive already stored into `allowed_drives`.
- Drive genesis whose signer equals `ATOMIC_OWNER_AGENT` → enroll.
- Close the missing-Drive carve-out in Owner mode (OQ5).
- `/server` emits `hostMode`, `acceptsNewDrives`, `ownerSet`. Redact
  node id + peers for `Public` when Owner.

Tests (protocol / glue):

- Owner rejects a stranger’s Drive genesis over `POST /commit`,
  `SYNC_PUSH`, and Iroh live write.
- Owner accepts the owner agent’s second Drive and enrolls it.
- Collaborator with `write` on an enrolled Drive can commit there and
  cannot genesis a new Drive.
- Open mode (localhost default) still admits a stranger Drive — existing
  e2e `devDrive` / `createDrive` stay green.
- Snapshot-on-flip: a Drive created under Open still admits after the
  policy is installed.

### Phase 2 — welcome

- `accountCreationTarget` third branch + `managedServer.test.ts`.
- Welcome: hide Create account when `hostMode === owner`.
- After local Create account, show the agent DID and one line about
  `ATOMIC_OWNER_AGENT` for people who will expose a node later.
- `createDrive` / `promoteLocalDrive` error copy when the node refuses
  enrollment.

Tests (flow):

- Welcome unit: Owner → no Create account; Sign in stays.
- Server: Owner boot without `ATOMIC_OWNER_AGENT` exits non-zero.
- Server: pasted secret / non-agent DID is rejected at boot.
- Browser e2e stays on localhost Open; add one Owner-mode server
  integration test rather than a full Playwright public-bind.

### Phase 3 — abuse leftovers

- Rate-limit unknown-agent `/commit` and `/blob`.
- Optional: refuse Iroh streams whose AUTH agent has no `read` on any
  hosted Drive.
- Docs: installation “going public” section; FAQ “how do I put this on
  the internet without hosting other people”; retire `/setup` as the
  primary onboarding story.

## Docs and copy

- `docs/src/atomicserver/installation.md` — new subsection after
  HTTPS: create an account first, set `ATOMIC_OWNER_AGENT`, then
  expose; default Owner on a public domain; `ATOMIC_HOST_MODE=open`
  escape hatch for a *deliberate* multi-user FOSS node.
- `docs/src/atomicserver/gui.md` — stop leading with `/setup`.
- `docs/src/atomicserver/faq.md` — “How do I make my data private, yet
  available online?” already points at the public Agent. Add: the node
  being reachable is not the same as the node hosting strangers.
- `planning/unified-sync.md` OQ5 — Owner mode is reject-until-known;
  Open keeps the carve-out.
- `planning/sync-onboarding-ux.md` — welcome branches; language:
  “always-on device,” not “sync hub.”

## Resolved decisions

Recorded because each reverses something this document originally proposed.

### 1. `ATOMIC_DOMAIN` decides nothing (reverses OQ1)

OQ1 asked whether Owner should be the default as soon as `ATOMIC_DOMAIN` is not
localhost, and leaned yes. That is **fail-open in the deployments that matter
most**.

`ATOMIC_DOMAIN` defaults to `localhost` and exists to build links and to satisfy
the LetsEncrypt challenge. Behind Docker with nginx/Caddy/Traefik, or behind a
Cloudflare or Tailscale tunnel, the process never learns its public name: the
domain still reads `localhost` while the whole internet reaches it. Inferring
"Open, this is a private box" there hands out a guarantee we cannot keep — and
the same rule would have hard-failed every `ATOMIC_DOMAIN=example.com` HTTP node
on upgrade. Backwards on both ends.

So the mode is decided by **explicit configuration only**:

1. `ATOMIC_HOST_MODE` — the operator said so.
2. `ATOMIC_OWNER_AGENT` is set — naming an owner is not done by accident.
3. Neither — Open, exactly as before host mode existed.

Domain, `--https`, and port are still read, for exactly one purpose: deciding
whether an Open node prints a warning. A wrong guess there costs a line of log
noise instead of a stranger's workspace.

`ATOMIC_DOMAIN` itself is **not** deprecated — it still feeds `get_origin()` /
`server_url` and the cert. What was deprecated is domain-as-identity: drives,
agents, and nodes are `did:ad:…`, so the domain no longer names anyone's data.
That is what makes it a bad security signal and a fine display one.

### 2. Upgrades are grandfathered, not broken

An existing node with no new configuration keeps booting and keeps admitting
whoever it admitted yesterday. A security change that stops a running server is
one operators route around.

What an unconfigured node gets instead is a boot warning, but only when there is
a sign of *intent to publish* — `--https`, a routable `ATOMIC_DOMAIN`, or port
80/443. Notably **not** the bind address: `--ip` defaults to `::`, so warning on
a non-loopback bind would fire on every dev run and every test, and a warning
that always fires is one nobody reads.

The residual gap is honest and documented: a proxied node shows no signal at all,
so it is never warned. The docs carry that case instead — it is the one the FAQ
and the installation guide both lead with.

### 3. Enrollment is derived from the store, not persisted

The sketch said to persist `allowed_drives` in redb `PluginMeta`. Simpler and
impossible to drift: on Owner boot, scan the resource tree for Drives and enroll
what is there (`Db::drive_subjects`). A drive that exists is a drive this node
hosts; next boot re-derives the same answer.

That also *is* the snapshot-on-flip behaviour the plan wanted, for free. The scan
is O(store) once per boot, deliberately not index-backed: a stale or partial
query index would answer "fewer drives than you have", which here silently locks
the owner out of their own data.

## Still open

2. **May the owner grant `createDrive` to another agent?** No. Invite-to-a-Drive
   covers collaboration. Host-your-own-Drive is multi-tenant and needs its own
   invite type.
3. **Disable Iroh in Owner mode?** No. HTTPS is enough for the browser, phones
   still pair, and the node ID is now redacted from unauthenticated `/server`.
4. **Name.** `hostMode` / Owner. Settled.
5. **Refuse to start vs. start locked when Owner has no owner?** Refuse. A
   process that never bound is an operator error visible in `journalctl`; one
   that bound and admits nothing looks like a broken site.
6. **Should a proxied node be detectable at runtime?** Open. An `X-Forwarded-*`
   header or a non-local `Host` on a live request would prove reachability that
   boot-time config cannot. Would close the one gap above, at the cost of a
   warning path that fires from request handling.
