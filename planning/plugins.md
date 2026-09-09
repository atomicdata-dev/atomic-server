# Plugins: One Model for Views, Automations, and Importers

**Consolidation proposal (2026-09-08):** [Atomic extension architecture](extension-architecture.md)
defines the target boundaries and phased retirement of overlapping models. This
document retains earlier design and implementation history; its “one model” title
does not mean the existing UI bridges and lifecycles have already converged.

> **Status:** Partial, off `develop`. Track A built 2026-08-21 (`run` end to end: sandbox, planner, applier, secrets, server placement, scheduled and query-triggered runs, auto-apply); Track B revised 2026-08-22 onto that substrate. The code lives on `feat/plugin-model` (PR #1307). Absorbed `llm-wasm-gui-plugins.md`, `importers.md` and `habits-app.md` on 2026-09-01.

## Status

**Strategy review (2026-09-05):** see [plugin-model-review.md](plugin-model-review.md).
Static review of `feat/plugin-model` at `ccfbb1e14` found gaps between the intended
capability/review guarantees and the server host implementation. The review also
proposes immutable releases and connection instances for the integration store.
The user authorized implementation. The review checklist is authoritative for
implemented guarantees and remaining store/sync work; older “built” descriptions
below must not be read as proving those lifecycle guarantees.

Track A built (2026-08-21): `run` works end to end — sandbox, planner, applier,
secrets, server placement, scheduled and query-triggered runs, auto-apply.
Track B revised (2026-08-22) onto the substrate Track A proved: a plugin's
source is a property on a resource in the drive, not an artifact on the
server's filesystem. See Track B for why that one choice decides sharing,
rights, history and whether an assistant can ship a plugin at all.

**Where the code is (2026-09-01):** everything "built" above lives on
`feat/plugin-model` (PR #1307, open), not on `develop`. On `develop` the only
plugin surfaces are the installed-zip path (WASM class extenders + the
`@tomic/plugin` iframe RPC from #1197); the UI-plugin RPC there still answers
`query`/`search` with the string `'not implemented'`
(`views/PluginView/pluginRPC.tsx`). This document is authoritative for the
direction either way; read the "Built" markers as "built on that branch".

This document absorbed the three earlier plugin plans on 2026-09-01:
`llm-wasm-gui-plugins.md` (state profiles, application documents, builder,
runtime matrix), `importers.md` (the import pipeline and trusted importers)
and `habits-app.md` (the external-app dogfood). What was still useful from
each is under "Folded plans" at the end; the rest was either built by Track A
or restated here.

## Why

Three product goals, one platform:

1. **The LLM writes the custom logic.** A user says "when someone spends €100,
   send them a discount code", or "show these rows as a kanban", and gets it.
   No node editor, no visual builder — the model writes code, and the host
   makes that safe to run.
2. **Get data in, and keep it in sync.** A Notion export, a Google Calendar, a
   CSV, an internal API. A one-shot import and a periodic sync are the same
   pipeline with a different trigger.
3. **Highly tailored GUIs without bloating ours.** A spreadsheet, an image
   editor, a habit tracker — hosted by Atomic, not built into the Data Browser.

Today these are four layers with four vocabularies: server-side WASM class
extenders, front-end iframe custom views, a proposed importer transform, and a
proposed automation script. Each has its own manifest, permission model, and
lifecycle. The design is hard to explain, which is a reliable sign it is also
hard to secure. This document collapses it.

## The Model

> **A plugin declares when it runs, what it may touch, and exports `view`,
> `run`, or both.**

```ts
// interactive: renders UI, long-lived, holds a scoped grant
view(ctx: ViewContext): void

// one-shot: proposes changes, reviewable before they take effect
run(ctx: RunContext): Verdict
```

Everything else — importer, automation, validator, custom view, embedded app —
is a value in a manifest field, not a separate concept.

| What we call it today | What it is |
| --- | --- |
| Class extender `before_commit` | `run`, trigger `commit:before`, returns problems |
| Importer transform | `run`, trigger `manual`, capability `parse` |
| Scheduled connector (Notion, Calendar) | `run`, trigger `cron`, capabilities `network` + `secrets` |
| Automation ("email at €100") | `run`, trigger `query:entered` |
| Importer skill | `run` + fixtures + instructions |
| Custom resource view | `view`, capability `atomic.read/write`, slot `resource-page` |
| Custom table cell / row renderer | `view`, slot `table-cell` |
| Custom dashboard block | `view`, slot `dashboard-block` |
| Spreadsheet (IronCalc) | `view`, capability `documents.loro` |
| Image editor (miniPaint, #1204) | `view`, capability `documents.blobs` |

One `Plugin` class. One manifest. One lifecycle. No `Automation` class, no
`Importer` class, no `ImporterSkill` class.

### The verdict

`run` returns a proposal, never a side effect:

```ts
interface Verdict {
  intents: Intent[];    // create / set / remove / destroy, not yet committed
  problems: Problem[];  // { severity, message, subject?, property? }
  cursor?: string;      // opaque resume token, for incremental sync
}
```

This is the join that collapses three layers into one. A validator returns
problems and no intents. An importer transform returns intents and no problems.
An automation returns both. A connector returns intents plus a cursor.

Because `run` cannot write, the host owns validation, preview, approval, and
commit for every one of them — one code path, one audit trail, one undo. It
also means the sandbox has almost nothing to contain: a function with no store
access, no network, no secrets, and no clock has no authority to abuse.

### Triggers

Declared in the manifest; the host, not the plugin, decides when to call.

| Trigger | Semantics |
| --- | --- |
| `manual` | User-invoked. Registers as an `ActionDefinition` (see [`actions.md`](./actions.md)), so it appears in ⌘M, context menus, and derived AI/MCP tools for free. |
| `cron` | Durable schedule. `nextRun` persisted; explicit catch-up policy for windows missed while offline. |
| `timer` | Relative to a resource field ("3 days before `dueDate`"). Re-armed when the field changes. Neither cron nor query; users ask for it constantly. |
| `query:entered` / `query:left` / `query:changed` | Edge-triggered off watched queries (`server/src/commit_monitor.rs`). **Edges, not levels** — "customer passed €100" must fire once, so each firing records `(plugin, resource) → version` and is idempotent under reindex, backfill, and replay. |
| `commit:before` | Admission policy. See "Plugins are not a validity rule". |
| `commit:after` | Reaction. Always enqueued, never inline (below). |
| `webhook` | Inbound HTTP with a per-plugin secret; raw body reaches `ctx` unparsed. |

### A plugin declares what it needs

```js
export const manifest = {
  secrets: [{ name: 'google', origin: 'https://www.googleapis.com',
              description: 'Google Calendar API token' }],
};
```

`manifest` and `run` are the only exports that mean anything. The declaration
lives in the source rather than in resource properties so it cannot drift from
the code that spends it: one file says `secret:google` and asks for `google`.
The page renders one labelled field per declared secret, and the origin
allowlist comes from the declaration.

This replaces an earlier compromise where a plugin's reachable origins were
inferred from whichever secrets happened to exist — which had "can reach" follow
from "has a credential for", backwards. A plugin that spends a handle it forgot
to declare is still offered a slot, with the origin read from the URLs its
source requests, because the author who forgot is the one who cannot work out
where to enter it.

### Capabilities

One manifest drives every enforcement point. Grants are recorded against
`(drive, plugin subject, artifact hash, capability)` and are signed Atomic
authorization state — never browser local storage.

```json
{
  "capabilities": {
    "atomic":    { "read": [{"scope": "page"}], "write": [], "query": [], "subscribe": [] },
    "documents": { "loro": [], "blobs": [] },
    "network":   { "origins": [] },
    "secrets":   [],
    "parse":     ["csv", "zip"],
    "storage":   { "quotaBytes": 1048576 },
    "runtime":   { "fuel": "standard", "memory": "standard" },
    "ui":        { "slots": [] }
  }
}
```

From this single object the host derives the Wasmtime linker features and
limits, the plugin agent's Atomic rights, the iframe CSP, the permitted RPC
methods and scopes, and preview behaviour. There is no second permission model.

### Placement is the host's decision

The plugin author does not choose a runtime, and neither does the LLM. The host
derives placement from trigger and capabilities:

| Condition | Runs in |
| --- | --- |
| `view` | Null-origin sandboxed iframe (unchanged; the strongest part of today's design) |
| `run`, `manual` trigger, user present | Web Worker inside a null-origin iframe, `connect-src 'none'`, time budget via `terminate()` |
| `run`, unattended trigger, or needs `network`/`secrets` | Wasmtime, via a shared JS interpreter component |

The transform has no authority in the first two cases, so origin isolation plus
a CPU budget is adequate containment; WASM buys nothing there. WASM earns its
place server-side, where a sandbox inside a Rust process is the only option and
fuel metering, the memory limiter, and capability-scoped host imports already
exist.

Prefer **one host-owned interpreter component** (QuickJS-shaped: the script is
data, artifacts are kilobytes, promotion needs no build step, one binary to
audit) over componentizing each script into its own ~10MB artifact.

**Validated by spike (2026-08-20).** A Rust component using `rquickjs`
(QuickJS bindings) built for `wasm32-wasip2` and run under the wasmtime 45 the
server already uses:

| | |
| --- | --- |
| Component size, release | 1.1 MB, shared by every plugin |
| Fresh instantiate + run | 0.18 ms |
| Script as data | yes — passed in as a string, no per-plugin build |
| Custom host imports | yes — JS calls a global that reaches Rust and back |
| Runaway script | fuel traps it; the host is not taken down |

The two things that could have killed the approach both held: QuickJS's C
compiles for `wasm32-wasip2` without a bespoke sysroot, and a component can
take a script *and* import host functions rather than having to be generated
per script. Startup is far below one network round trip, so per-run
instantiation — which is what keeps a run from inheriting anything from the
last — costs nothing worth optimizing. Reserve
per-script components for anything hot enough to notice interpretation, or for
plugins written in a compiled language. The WIT world stays language-agnostic,
so that remains a reversible decision.

**Same source, two engines** is the hazard this creates. Browser JS and QuickJS
diverge on `Intl`, `Date` parsing, number formatting, and newer regex features.
Since fixtures are the trust mechanism, pin the engine version in the release,
re-run fixtures in the *target* runtime at promotion, and refuse to activate on
mismatch.

## What the LLM Writes

TypeScript, against `@tomic/lib` plus generated ontology types
([`json-schema-code-first.md`](./json-schema-code-first.md)), type-checked by
the pinned browser toolchain before anything runs.

```ts
export function run(ctx: RunContext): Verdict {
  const overdue = ctx.query({ isA: Task, dueBefore: ctx.trigger.at });
  return { intents: overdue.map(t => ctx.set(t, { status: 'late' })), problems: [] };
}
```

The model never sees the WIT world, the component model, or the placement
decision. If it has to reason about any of those, goal 1 is dead.

The reason this works is unglamorous: models are fluent in TypeScript, and
generated ontology types turn "mapped employer onto `description` instead of a
link to `Organization`" into a compile error rather than a runtime surprise.
Typecheck is the cheapest rung of the feedback loop; schema validation of the
returned intents (`lib/src/validate.rs` semantics) is the second.

**Not MoonBit, not AssemblyScript, not Python.** LLM fluency is the entire
premise of goal 1 and it points one way. The WIT boundary keeps other languages
possible later without touching the platform.

## Trust: the one split that does not collapse

- **`run` output is reviewed.** The host renders the intents as a diff, the
  user approves, the host commits with provenance. The code holds no authority
  at any point.
- **`view` authority is granted upfront.** You cannot approve every brush
  stroke, so the grant is scoped to a document before the plugin runs.

One sentence: *code that proposes changes gets reviewed; code you interact with
gets a scoped grant.* Everything else in this document is configuration under
that split.

`view` grants are scoped by **state profile**, which bounds what "interactive"
can reach:

| Profile | App owns | Atomic owns |
| --- | --- | --- |
| `atomic.write` | Values for explicitly granted properties | Resource doc, schema, authorization, signing |
| `documents.loro` | A dedicated payload Loro doc | Metadata, authorization, signing, transport, presence |
| `documents.blobs` | Opaque serialized bytes | CAS blobs, revisions, heads, conflict preservation |

Details of each profile are under "Application state profiles" in the folded
plans below; what belongs here is that they are *capability values*, not
separate plugin kinds.

## Local-first: plugins are not a validity rule

Resolves #1193.

> **A signed, authorized commit is valid. A plugin cannot make it invalid.**

With no single authority, `commit:before` cannot be a global veto. Trying to
make it one forces plugins into consensus — determinism, versioned lockstep
across every node, and no HTTP — and network access is precisely what importers
and connectors need. So do not buy a guarantee that cannot be delivered:

- **At the authoring edge** (the client composing the commit; the first node
  accepting it over HTTP): `commit:before` is an *admission policy*. Reject
  there, before the commit exists. This is where users experience validation
  and where today's server behaviour already sits.
- **Everywhere else** (a peer receiving it over sync): it is a *lint*. It may
  flag or quarantine. It cannot un-exist a commit another node accepted.

Divergence under partition becomes visible rather than pretended away.

The corollary is a large simplification: if plugins are not a validity rule,
**no client needs to run the server's WASM to agree on what exists.** Front-end
plugins are already JS and run natively in the browser; server-side WASM stays
where the authority and the network access are. Shipping jco (3–5MB) to every
client, or transpiling server-side and syncing the assets, is not needed.
Revisit only when a concrete plugin must run identically on both.

## Deletions

Consolidation that only adds a unifying label is fake. This model is real only
if the following go:

1. **`on_resource_get` is removed.** It returns a decorated resource rather
   than a verdict, it defeats caching, and under the rule above it means
   different nodes serve different content for the same subject. Where the use
   case is computed fields, that is a derived-properties feature of the data
   model, not a plugin hook. This is the deletion most worth arguing about and
   the one that buys the most simplicity.
2. **Unrestricted frontend `commit()` is removed**, replaced by
   capability-scoped writes. Without this, `view` capabilities are decorative.
3. **`ImporterSkill` never becomes a class.** Fixtures and instructions are
   plugin fields; every plugin benefits from fixtures, not just importers.
4. **Three permission models become one.** GUI grants keyed by
   `namespace.name` in local storage, WASM manifest permissions, and Atomic
   rights collapse into the capability manifest above.
5. **Zip-as-lifecycle is removed** in favour of
   `PluginProject → PluginBuild → PluginRelease → InstalledPlugin`. A mutable
   uploaded zip is not a release, and `pluginFile` changing is not an install.
6. **The `plugin.wasm` requirement is removed** so UI-only and `run`-only
   releases do not have to ship a no-op component.

## Security Debt to Clear First

Front-end plugins already ship (#1197), and today they are the weakest
boundary in the system — more practical authority than server-side WASM, with
less review:

- **Open, and the one that matters.** iframe CSP is `connect-src *`
  regardless of manifest (`plugin_ui.rs`). Everything else in that header is
  locked down; this is not. The plugin's JavaScript may reach any origin on
  the internet.

  It is worth more than the others because it is the back wall the read
  grants do not have. The dialog asks "may this plugin read this resource?",
  the user says yes — and nothing then stops the plugin POSTing it anywhere.
  Tightening who may read while the exit stays open is half a control, and
  the half that is missing is the one that makes the other half mean
  something.

  Not a one-line fix: `PluginUIManifest` carries only `css`, so there is no
  network permission on this surface to honour — the `network` permission in
  `plugin.json` gates server-side WASM. It needs a manifest field, an install
  dialog that shows it ("this view talks to api.example.com"), and a
  `connect-src` built from it.

  **Measuring now.** Both iframe responses carry the strict policy as
  `Content-Security-Policy-Report-Only` alongside the unchanged enforcing one,
  so nothing is blocked and violations surface as the plugins that would
  break. The strict `connect-src` is `'self'` plus whatever the manifest's
  `network.origins` declared — the same field `plugin_secret.rs` already reads
  to bound the host-side fetch, so a plugin's two halves make one claim.
  `'self'` is unconditional: the server that served the frame is the one place
  talking to is not exfiltration.

  Reports go to the console and to `securitypolicyviolation` in the frame, not
  to the server — there is no `report-uri`. That is enough to watch a suite
  run or your own session, and NOT enough to learn what other people's plugins
  do. Collecting that means an endpoint and a decision about storing other
  people's telemetry.

  What remains is the default, and it should be picked from what the reports
  say rather than guessed: enforce `'self'` + declared, and every plugin
  reaching an origin it never declared breaks with a console CSP error — no
  prompt, nothing to click. Keep `*` and nothing is fixed until plugins
  update. The other half is `PluginPermissions.tsx`, which renders a Network
  row that says "Network" where it could name the origins.
- **Fixed.** Grants lived at `atomic.plugins.ui.<namespace.name>`, so consent
  given to a plugin on your drive was inherited by any plugin of the same name
  on a drive someone else shared with you, and it survived that plugin's code
  being replaced. The key is now the plugin resource's subject — unique per
  drive — plus a blake3 hash of the served `.ui.js`, which `UIPluginListItem`
  publishes. Approving code approves *that* code. A plugin whose artifact
  cannot be read is left out of the listing rather than described without a
  hash: "allow this?" means nothing if the host cannot say what "this" is.
- **Fixed, and it was misdescribed.** `postMessage` does use `'*'`, but it is
  forced: both frames are sandboxed without `allow-same-origin`, so every end
  is null-origin and there is no origin to name. Both hosts already validated
  `e.source` against the frame. The real hole was the other direction — the
  `@tomic/plugin` client accepted `message` events from anyone, so anything
  able to post into the frame could answer a pending request or push a
  `resource-notification` and hand the plugin a resource that does not exist.
  It checks `e.source === window.parent` now. Messages remain **unversioned**.
- **Low, and conditional — leave it alone.** Implicit read scope includes
  anything parented under the page's `isA` class resources. It was written for
  schema reads and reads broader than that, but on an ordinary drive it grants
  nothing at all: a class is parented UNDER its ontology (`plugin-app.ts`
  creates it with `parent: ontology.subject`), so nothing is parented under a
  class and the set is empty.

  **It only bites if data is parented under a class or ontology resource.**
  That is a legal shape and nothing forbids it; it just is not what the
  tooling produces. Anyone doing it should know they have made that data
  readable by any plugin rendering that class, without a prompt.

  Two things bound it further. The ancestry walk also grants when an ancestor
  is publicly readable, which sounds worse than it is: `check_rights` walks up
  and returns on the first grant with no deny, so rights are additive and a
  resource under a public ancestor is already public to everyone. And every
  read goes through the signed-in user's store, so a plugin can never reach
  what the user cannot. This limits a plugin WITHIN the user's reach; it is
  not what protects the drive.

  Narrowing costs more than it buys: denial prompts on `getResource`, but
  `query` and `search` filter silently, so results would quietly get smaller
  and look like a bug. Record the condition, spend the effort on
  `connect-src`.
- **Defanged.** `pluginFile` changing auto-executes an install — but only for
  someone who can already write the plugin resource, which is the rights model
  working. What made it sharp was consent outliving the code; now that the
  grant key carries the artifact's hash, replacing the code asks again.

This is cheap to fix now and expensive once third parties exist.

### Two surfaces, and which one a gap is in

There are two hosts, and reading a gap against the wrong one wastes a
half-day. Say which is meant:

- **The app host** — `chunks/AppPage/AppFrame.tsx` + `hostStore.ts`, an
  iframe served by the server's `/plugin-ui`, talking over `postMessage`.
  This is what `create_app` writes and what this plan's `run(ctx)` model is
  about. Its data surface is complete: `get`, `query`, `create`, `save`,
  `destroy`, `subscribe`/`unsubscribe`, and an unknown op throws by name.
- **The UI-plugin RPC** — `views/PluginView/pluginRPC.tsx` + the
  `@tomic/plugin` package, shipped in #1197.

The security debt above is the second one. So was the RPC's incompleteness:

- `query` and `search` resolved through the **success** path with the string
  `'not implemented'`, so a plugin asking for rows was handed a sentence and
  told it had worked. Both are implemented now — `query` through a collection
  (search drops property/value filters on its local-index fallback, which
  would answer a narrow question with the whole drive), `search` scoped to the
  page. Both return only what the plugin may read: `getResource` checks access
  one subject at a time, so an unfiltered query would have been the way around
  it.
- `subscribe` never replied on any path, leaking the caller's pending request
  — and on refusal the plugin went on believing it was watching a resource it
  would never hear about. Every path answers now, refusal included.
- An unknown message resolved with the string `'UNSUPPORTED MESSAGE'`. It is
  an error now.
- `handleCommit` wrote into the host's copy before the save that could reject
  it, leaving the user looking at an edit the server refused and the next
  unrelated save carrying it along. It reverts on failure.

`create` is **not** missing from the app host — `hostStore` has had it. It is
missing from the UI-plugin RPC, which is a smaller claim than this section
used to make, and does not block the habits app (folded below).

Neither surface is unit-tested: `data-browser` has no jsdom environment and no
`.test.tsx` at all, so anything touching a frame or a hook is reachable only
from e2e. Worth fixing before this grows.

Still open, all verified present today: the five bullets above (`connect-src *`
at `plugin_ui.rs:326`, grants at `useStoredPluginGrants.ts:26`, `postMessage`
`'*'`), and `create` on the UI-plugin RPC.

## Build Order

Two tracks share one lifecycle. They are genuinely independent and can run in
parallel.

### Track A — `run`

- **A1. The `run` primitive. Built.** `Verdict` (`{intents, problems, cursor}`),
  a deterministic I/O-free sandbox, the Worker runner, the planner (mints
  subjects, resolves `local:` refs, validates against the schema), the applier,
  the code-first schema, the run log, the preview/approve dialog, a plugin page,
  and an e2e spec over the whole path.
- **A2. Concurrent apply. Built, but not what this item said.** Applying was
  strictly sequential; it now runs waves of chains that cannot affect each other
  (creates one wave per dependency level, everything else chained per subject).
  100 creates at 5ms/write went 564ms → 74ms.
  **The OPFS claim above is still unverified**: 20 creates produce exactly 20
  commits, so nothing amplifies in *this* path, but the test store has no
  ClientDb attached and commits are not OPFS writes. The importer open
  question about the ClientDb bulk-write ceiling (folded below) is therefore
  still open.
- **A3. Secrets + host-side fetch. Built.** See `plugin-secrets.md` (on
  `feat/plugin-model`, arrives with PR #1307). Ambient network access is gone,
  both egress paths are address-checked, secrets live outside the resource
  graph, and a plugin spends `secret:<name>` in a header without ever seeing the
  value. Proved end to end: a plugin fetched an echo endpoint and the response
  showed the substituted credential.
- **A4a. Server placement. Built.** One 1.2 MB component (`plugin-runtime`,
  QuickJS via `rquickjs`) runs every plugin, embedded in the server binary. The
  script is an argument, not an artifact, so promoting a plugin from the browser
  is a placement decision rather than a build. Placement is derived: a plugin
  runs server-side once it has a secret.
- **A4b. Scheduled runs. Built; the queue is not.** A plugin carries an
  interval, a loop finds what is due, and it runs in the embedded runtime with
  its secrets. An unattended run **fetches but does not write**: nobody is there
  to approve at 3am, so the verdict waits against the schedule and the plugin's
  page offers it for review. The schedule advances before the run, so a hang is
  not retried every tick; missed windows are skipped, so a server off for a
  fortnight owes one run rather than three hundred.

  Still missing, and still needing a real queue: retries with backoff,
  dead-lettering, `timer` triggers relative to a resource field, per-plugin
  cursor state, and moving `commit:after` off the commit path — it is still
  synchronous there, so one slow webhook stalls every write on the drive.

- **A4c. Applying automatically. Built.** A schedule can carry a grant: a
  named agent, the time it was given, and the run that was reviewed before
  giving it. Once it is there, an unattended run plans and writes instead of
  waiting.

  Three things make that safe to offer. It is only offered after the plugin has
  produced a run someone applied — approving code by its description rather
  than by what it does is what propose-then-approve exists to avoid. Every
  write is checked against the granting agent's rights, not the server's: the
  commit is signed with the server's key because that is the only one it holds,
  so without that check a plugin would be a way to write anywhere. And the
  vocabulary needed to log the run is resolved *before* anything is written — a
  run that wrote and could not say so would be worse than one that refused.

  This needed a planner and an applier in Rust, so there are now two of each.
  The risk is not duplication but drift: a planner that disagrees with the one
  that drew the preview means the changes someone approved are not the changes
  that were made. Both are pinned by the same fixtures in
  `testdata/plugin-plans/`, run by `plugin-plan.fixtures.test.ts` and by
  `plugins::plan::fixture_tests`. Add a case to one and both must agree.

  Writing it turned up something the browser had known and the server had not:
  a resource under a DID drive gets its subject from a genesis certificate, so
  it cannot be minted by path. The applier lets the store mint and reports back
  what it got — which is why `create` returns a subject at all.
- **A5. Query triggers. Built; one gap.** A plugin can carry a filter and run
  when a resource enters or leaves it. The edges were free: the store already
  decides membership for `SUBSCRIBE_QUERY`, so a trigger is a standing claim on
  those same events by something other than a WebSocket. Storing a trigger
  registers its query as watched, so one cannot exist un-watched.

  The two ways this goes wrong are guarded. A plugin does not answer its own
  echo — the subjects its run wrote are remembered and skipped, or an importer
  that creates a row matching its own query runs forever. One that loops anyway
  is stopped after thirty runs in a minute, with the reason recorded on the
  trigger rather than in a log line that scrolls past. Repeated edges inside a
  short window run once; that window is in memory on purpose, because after a
  restart there are no events to replay either.

  The gap: without an auto-apply grant, a triggered run happens and its verdict
  is **dropped**. A schedule has a next run to hang a verdict on and a page that
  offers it for review; an edge does not, and it will not come round again. The
  answer is to write the verdict as a `plugin-run` record with a proposed
  status, so the log becomes the queue of things waiting — which is also what
  A4b's single `pending_verdict` slot should become.

  Also still missing: `change` edges (a watched property moving within the
  query), which the index does not distinguish from a no-op today.

### Track B — `view`

Revised 2026-08-22, after Track A shipped. The original plan built `view` on
the installed-artifact model (a zip on the server's filesystem). That is now
the wrong substrate, and the reason is worth stating precisely, because it
decides the rest.

**Where the code lives is the only axis that matters.** Five things in this
repo call themselves plugins, and they differ in one respect that dominates
every other: the Rust class-extenders are compiled in; the WASM extenders and
the iframe views are files under `plugin_path`, installed from an uploaded zip;
`run` plugins are a property on a resource in the drive; table templates are
config plus a `case` in `TablePage`.

Everything asked of an app that people share follows from that one axis. Source
in the drive syncs, carries rights, is versioned by commits, and can be written
by an assistant in a chat. A file under `plugin_path` does none of those: it
does not reach another node, it has no ACL to attach a share to, it has no
history, and installing one means building a bundle and uploading a zip — a
loop no LLM can drive. Track A did not build sync, rights or history for
plugins; it got them by putting the source in a resource.

So `view` moves onto that substrate, and the work is:

- **B1. Built (2026-08-22).** An `App` resource with its own ontology and an
  entry point; `/plugin-ui` serving that plugin's source from the store;
  a bootstrap that imports the module and calls `view({ root })`. Verified end
  to end: an app created through `createApp` renders in the frame, and the
  same request without a token is refused.

  What is **not** built yet: `ctx` is `{ root }` and nothing else, so a view
  can render but cannot read or write. That is B3, and until it lands an app
  is a static page. Class-to-view is untouched and still on the installed
  path, as planned.

- **B1 (original scope). One source, two exports.** A plugin resource's `plugin-source` may
  export `run`, `view`, or both. `/plugin-ui` serves that source instead of
  reading `plugin_path`, and the iframe bootstrap imports the module and calls
  `view(ctx)`. The null-origin iframe stays exactly as it is — it is a real
  boundary, and the CSP reason it must be a network response rather than
  `srcdoc` (see `PluginView.tsx`) is unaffected by where the bytes come from.
  `/plugin-list` gains the drive's resource-hosted views beside the installed
  ones, so both work during the migration.

- **B2. Built (2026-08-22).** `POST /plugin-view-token` mints a capability
  scoped to one `(drive, plugin)` for five minutes, checked against the
  requesting agent's *read* rights so it can never widen what that person
  could already see. Held in memory: they last minutes, a restart just means
  the page mints another, and keeping them out of the store means they cannot
  sync somewhere they would still be valid.

- **B2 (original note). The iframe cannot authenticate — mint it a capability.**
  This is the one genuinely new problem and it has to be solved before B1 ships. Today
  `/plugin-ui` needs no rights check because plugin files live outside the
  rights system. The moment source is a resource, serving it unauthenticated
  publishes drive content to anyone who can guess a subject — and a
  null-origin iframe cannot sign a request, so it cannot ask for it as the
  user. Nor can the parent hand the bytes over directly: `blob:`, `data:` and
  `srcdoc` all inherit the parent's CSP, which is what forced the network
  response in the first place.

  So the authenticated parent mints a short-lived token scoped to
  `(drive, plugin)` and puts it in the iframe URL. Defaulting to
  world-readable instead would be a rights hole that looks like a convenience,
  which is exactly the shape of mistake `did-agent-signature-is-not-authorization`
  was.

- **B3. Built (2026-08-22).** A view receives `{ root, store }`, and that
  store is shaped after `@tomic/lib`'s — `getResource`, `query`,
  `newResource`, and resources with `get`/`set`/`save`/`destroy`. The client
  is `server/src/plugins/assets/view-client.js`, embedded rather than
  generated so it stays lintable.

  **Writes are confined to the app's own subtree**, which is what makes this
  usable before B4 exists: an app writing its own data needs no dialog, and
  anything else is refused with a message saying so. Reads are deliberately
  *not* narrowed — they go through the host page's store and are already
  bounded by what the signed-in person may see, and narrowing further would
  stop an app showing data it was pointed at.

  Still on the old vocabulary: installed plugins, which keep the
  `MessageType.*` RPC until they are ported or retired.

  Subscriptions push (2026-08-22): the host holds the store subscription and
  posts through to the frame, released on unmount. One hazard found by testing
  it — adding a child counts as a change to its parent, so a view that
  subscribes to its app and writes into it on every notification feeds itself.
  Same shape as the re-trigger loop query triggers guard against server-side,
  but here it is the author's to avoid, so the client says so.

- **B3 (original scope). One data API, two transports.** There are three vocabularies for the
  same five operations today: `Store` (`@tomic/lib`), the `MessageType.*` RPC
  (`browser/plugin/src/types.ts`), and `ctx.read/query/http` (the run sandbox).
  For an assistant this is the most expensive duplication in the whole design,
  because it has to guess which dialect it is writing before it writes
  anything — and only one of the three appears in the docs and examples.

  Collapse to one: ship a `Store` whose transport is `postMessage`, and make
  `run`'s `ctx` that same `Store` narrowed to reads plus intent recording. The
  RPC stays as the wire format; it stops being an API anyone writes against.

- **B4. Superseded (2026-08-22) by issued agents.** A `plugin-grant` class
  was built and then removed the same day. It was the parallel permission
  model `issued-agents.md` (PR #1275, closed; the note travels with PR #1307)
  says not to
  build, and its worst property was where it applied: only in the browser
  host. A scheduled run, a query-triggered run and an auto-apply never
  consulted it, so an app's permissions meant one thing in a tab and nothing
  at 3am.

  What replaced it: **an app is issued its own Agent**, and `createApp`
  grants that DID `write` on the app. Rights inherit down the parent tree, so
  "an app may write its own data" is what the ordinary rights walk says
  rather than a rule restated here — and it is the same answer on every path,
  because it is the only rights system there is. Revoking is taking the DID
  off the list. Writes become attributable, which also answers the provenance
  wart under A4c, where an auto-applied run writes as the granting agent with
  the server's key.

  The agent resource is parented to the drive, never the app: an app may
  write its own subtree, so its agent kept there would be a public key the
  app could replace.

  **Unattended runs sign as the app (2026-08-23).** The key lives on the node,
  in a tree of its own and wrapped by the node key. It has to live there
  rather than with the person: an app importing at 3am has nobody to ask for
  a credential, so whatever signs its writes must be openable unattended.

  Its own tree, apart from plugin secrets, and that separation is load-bearing
  — a plugin secret is spent by substituting `secret:<name>` into a header, so
  an app key stored under a name could be posted to any origin the plugin may
  reach. Neither accessor returns it: one reports which DID an app writes as,
  the other hands the agent to a closure that signs.

  Creates matter most and were the last to be fixed: under a DID drive the
  signature *is* the subject, so signing as the server does not mislabel the
  author, it mints the app's own data under the server's name.

  **Still open.**

  1. *Reads.* Writes now go through the server signed as the app, so a tab
     and a cron run land identically and the ACL is a real bound in both.
     Reads still run on the session's store: an app sees what the person
     looking at it can see. That asymmetry is deliberate — a write persists
     and is attributable, a read is already on their screen — and routing
     reads too would cost a round trip and the cache for every property an
     app renders. Worth revisiting if least privilege should extend to what
     an app may *see*, which is a real question rather than a settled one.
  2. *Collaboration works on a shared node (2026-08-24).* Sharing an app is
     sharing a resource — the same rights arrays, the same dialog, the same
     invites. Read to open it, write to use it. Rights ascend the parent
     chain, so one act shares the schema, the view, the handlers and the data,
     and the view being a child means nothing is shared twice.

     Writes stay authored by the app whoever clicks: two people using one app
     produce one voice, rather than a history that depends on who was at the
     keyboard. That falls out of where the key lives — the node holds it, so
     everyone reaching that node writes as the app.

     What is still open is the *second node*. If a collaborator syncs the drive
     to a node of their own, that node has no key for the app, so it cannot
     write as it. Either it is issued one on first use — automatic consent,
     the thing grants exist to make explicit — or the identity becomes
     per-node-per-app and the app speaks with as many voices as it has hosts.

- **B4 (original scope). Grants become resources.** View-plugin grants live in `localStorage`
  today (`useStoredPluginGrants.ts`). A shared app therefore re-prompts every
  collaborator on every device, and the approval travels with nobody — so a
  "shared" app is not actually shared until this moves onto the drive. Same
  manifest that declares `run`'s secrets declares what `view` may touch, for
  the reason the secrets manifest works: in the source, it cannot drift from
  the code that spends it.

- **B5. The apps themselves.** `documents.blobs` + an image editor (#1204),
  then `documents.loro` + a collaborative one, then view slots
  (`table-cell`, `dashboard-block`). Unchanged from the original plan; only
  the substrate under them changed.

### The App resource

Added 2026-08-22. A view is a screen for a class; an app is a thing you open.
The pieces for the second already exist and are unrelated to each other —
code-first schema, dashboards and blocks, table templates, custom views, `run`
handlers — so "make me an app" has no single place to put the answer. `App` is
that place.

**An `App` is a parent whose children are its parts.** That is the whole
design, and it is chosen for the same reason source-as-data was: it makes
sharing, deletion, copying and sync fall out of what a drive already does.
Rights ascend the parent chain, so granting someone the app grants them its
schema, its views and its handlers in one act. Copying the subtree copies the
app. None of that is machinery this plan has to build.

An app holds:

- **its own ontology**, as a child. Not the drive's. `ensureSchema` writes into
  the drive's default ontology today (`plugin-schema.ts:137`), so two
  vibecoded apps that both invent a `Task` collide in one namespace — and the
  app stops being portable, because its schema is somewhere else. Scoping the
  ontology to the app fixes both.
- **one root view** — a plugin resource exporting `view`, named by the app's
  `entrypoint`.
- **any number of `run` handlers** as children: cron, query triggers, manual.
- **its data**, or a pointer to where its data lives.

Two things it deliberately is not. It is not a silo: an app reuses an existing
class by referring to its subject, which is just how Atomic works, so nothing
is needed to make apps compose. And it is not a package: no registry, no
versions, no build. Copying a subtree is the distribution mechanism.

**One root view, not many.** An app with several screens should be one module
doing its own routing inside one iframe, not N iframes with host-mediated
navigation. That is what makes it feel like an app rather than a set of custom
renderers, it is what an LLM will write if left alone, and it keeps the app's
state in one place. View *slots* — `table-cell`, `dashboard-block` — remain a
separate feature (B5) and should not be confused with this; those are the host
embedding a fragment, which is the opposite direction.

**Sync must not activate an app.** Already a decision under Shared, and worth
restating here because apps make it far more tempting to break: receiving a
drive that contains an app must not run its code, and its handlers must not
start firing, until someone on this node approves it. An app that runs because
it arrived is a drive-shaped worm.

#### What this changes about the build order

An app opens by name, not by class. The existing plugin system has only the
class-to-view path (`/plugin-list` → `getPluginForClass`), which needs class
resolution, view slots and a precedence rule when two plugins claim a class.
An app's root view needs none of that: the `App` resource names its entry
point directly.

So B1 can land without touching `/plugin-list` or `CustomViewProvider` at all —
render an app's root view from its `entrypoint`, and leave class-to-view on the
installed path until B5. That is a materially smaller first step than the
original ordering implied, and it is the one that actually demonstrates the
goal: an assistant writes an app into a drive, someone else opens it.

### Apps and tables

Added 2026-08-24. An app's rows live in a **Table**, not in a list the app
draws. Structurally these are the same thing — a table's rows are its
children, found by a collection on `parent` — so what a Table adds is a row
class and display config. That difference buys sorting, filtering, editable
cells, add-column, keyboard navigation, aggregates and export, for rows an app
created, without the app implementing any of it. And someone who wants the
data rather than the app can open the table.

The starter is why this matters more than it sounds. It drew a `<ul>`, which
is a worse table, and it is the file every future app is copied from — the
same mistake [`table-templates-and-mini-apps.md`](./table-templates-and-mini-apps.md)
records the Timer making, reproduced in the one place that propagates it.

So `createApp` gives an app a row class in its own ontology and a Table for
its rows; the view client can ask for both; the starter uses them.

**Not every app is a table**, and this is a nudge rather than a rule. A
drawing app, a timer and a dashboard are not tables, and an app is free to
ignore the one it was given.

#### An app as a view on a table — built 2026-08-24

An app can now be a view of a table someone already has, not only of the one
it was born with. `viewKind` is a plain string in the ontology, so an app's
subject is a valid one, told apart from the built-ins by shape. It is kept out
of the `ViewKind` union on purpose: the built-ins are a closed set with labels
and icons compiled in, apps are open-ended data, and folding them together
gives every exhaustive match a case that cannot be written.

This answers [`table-templates-and-mini-apps.md`](./table-templates-and-mini-apps.md)'s
complaint directly — a new mini-app is data in a drive rather than another
`case` in `TablePage`.

**Adding a way to look at rows never takes one away.** An app arrives as a new
tab, is never made the default, and the table's own views are untouched. One
way that could still have broken, caught by the test: a table with no saved
views shows an *implicit* Table tab, which disappears the moment a real view
exists — so adding an app to a fresh table would have removed the table. The
Table view is now created explicitly first.

A node that has never heard of a given app falls back to the table rather than
an empty tab, because `normalizeViewKind` already narrows anything unknown. An
app view degrades to the rows it is a view of, which is the right failure.

Inside the frame, `getData()` returns the table the app was pointed at and its
own otherwise, so one app is its own thing on its own page and a way of
looking at someone else's rows on a table tab, without knowing which it is.

**An app declares what it can show.** A table's view menu lists only apps that
claim its row class. Without that, every app on a drive is offered for every
table — a calendar app for a table of invoices, with no hint it will not work
until someone tries it, and a menu nobody can read once there are fifty.
`createApp` declares the class it just made, so an app starts able to show its
own rows and nothing else; being offered on someone else's table means adding
that class deliberately. An app that declares nothing is offered nowhere
rather than everywhere, because an app written against its own schema breaking
on a stranger's rows is the failure worth defaulting away from.

This is the same idea as `class-url` on the WASM extenders, which name the
classes they apply to. Two mechanisms for one concept until that path is
retired — see below — though the vocabulary now matches.

What that will *not* give is an app that **embeds** the table. A view runs in
a null-origin iframe, and the isolation that makes third-party code safe is
exactly what stops it importing the host's React components. Embedding needs
the host to render a table into a region the app lays out — the inverse of
B5's slots, host-provided fragments rather than app-provided ones, with
layout crossing the frame boundary. Worth keeping as a separate question
rather than smuggling it into "apps are views on tables".

### Retiring the artifact path — what still holds it up

Audited 2026-08-22 against `server/wit/class-extender.wit`. A WASM extender
exports `class-url`, `on-resource-get`, `before-commit` and `after-commit`. Of
those, the source-as-data model can express `after-commit` (that is what query
triggers are), and `on-resource-get` is already a deliberate deletion — a
computed resource on read is a cache-coherence hazard, recorded under
Deletions.

Two things genuinely have no equivalent yet, and until they do the zip path
stays:

1. **`before-commit`** — a synchronous veto. A query trigger fires *after* the
   write has landed and can only propose a compensating change, which is not
   the same as refusing an invalid one. The answer is a third export,
   `validate`, running in before-commit position. Nothing in-tree depends on
   this hook for domain logic today — the only callers are plugin installation
   itself (`plugin.rs`) and the WASM dispatcher (`wasm.rs`) — so it is a
   capability to preserve, not a feature to migrate.
2. **Per-plugin config** — `get-config` hands a plugin user-editable JSON. The
   new model has secrets and nothing else.

One smaller difference worth a decision rather than a port: a WASM plugin
commits *as its own agent* (`get-plugin-agent`), so its writes are attributable
to it. An auto-applied `run` writes as the granting agent with the server's
key. The plugin-agent model is the better provenance story and should probably
win.

Note that B1 shrinks this question rather than answering it. The installed zip
bundles `ui.js` beside `plugin.wasm`; once views come from the drive, what is
left on disk is only the commit hooks — a much smaller thing to keep, and a
much smaller thing to replace.

### Shared

- **S1. Lifecycle.** `PluginProject` / `PluginBuild` / `PluginRelease` /
  `InstalledPlugin`, signed publication, drive approval, node activation as
  three separate events. Sync never activates code.
- **S2. Browser builder.** Pinned toolchain and dependency catalog, isolated
  worker, no npm, no arbitrary build scripts. Produces immutable artifacts with
  logs and test reports.
- **S3. LLM authoring tools. Partly built.** `create_plugin` writes a plugin's
  source; `run_plugin` runs it and returns the verdict *and its problems*, so
  the assistant can correct itself — which is the whole premise of letting it do
  the work. Nothing is applied: the tool hands back to the user, who reviews the
  diff. The contract lives in the tool description, because that is what a model
  reads before its first attempt rather than after its first failure. Still
  missing: a project/build/test/preview loop and `propose_plugin_install`, which
  belong with Track B's release machinery.

## Decisions

- One `Plugin` artifact with two entry points. Importers, automations,
  validators, views, and embedded apps are manifest values, not classes.
- **A plugin's code is data in the drive, not an artifact on a filesystem**
  (2026-08-22). Sync, rights, history and shareability are then properties the
  drive already has, rather than four things a plugin system has to reinvent —
  and "the assistant writes it and it runs" stays true, because there is no
  build and no install step in between. The installed-zip path is preserved
  only for what it can still do that this cannot; see Track B.
- **An app is a parent whose children are its parts** (2026-08-22). Sharing,
  deletion, copying and sync then fall out of the drive's existing hierarchy
  rather than being reinvented per app. Its ontology is scoped to it, not to
  the drive, so two apps can both invent a `Task` and either can be copied
  somewhere else intact. One root view doing its own routing, not many views
  with host-mediated navigation.
- **One data API.** Authors write against `Store`. The iframe RPC is a
  transport for it, not a second vocabulary, and `run`'s `ctx` is the same
  `Store` narrowed to reads plus intents. Three dialects for five operations is
  a tax paid mostly by whoever is writing the plugin — which is usually a model
  that has only read about one of them.
- `run` returns `{intents, problems, cursor}` and never writes. The host owns
  validation, preview, approval, and commit for all of them.
- Placement is derived by the host from trigger and capabilities. Authors and
  LLMs never choose a runtime.
- TypeScript is the authoring language everywhere; WASM is the server-side
  containment layer, not a compilation target for speed.
- Prefer one shared interpreter component server-side over per-script
  componentization; re-run fixtures in the target engine at promotion.
- Plugins are not a validity rule. `commit:before` is admission policy at the
  authoring edge and a lint everywhere else. jco on every client is not needed.
- One capability manifest drives Wasmtime limits, plugin-agent rights, iframe
  CSP, and RPC scope. Grants are signed Atomic state keyed by artifact hash —
  on the drive, not in `localStorage`, or a shared app re-prompts every
  collaborator on every device and the approval travels with nobody.
- Secrets never enter LLM context, generated code, prompts, or logs. A plugin
  that "needs" a credential in `run` is a design error: the host fetches.
- `on_resource_get` is removed; computed fields are a data-model feature.

## Open Questions

- Does `commit:before` as admission policy need a user-visible "this node
  rejected a commit your peer accepted" surface, or is quarantine enough?
- Where do plugins live once written — private drive-local artifacts, or a
  shared gallery with signed releases and the review rules under S1?
- Does `timer` warrant its own index, or is it a degenerate query trigger over
  a date property?
- Should `run` support streaming/chunked verdicts for very large imports
  (500MB Takeout zips), or is chunking the host's job above the plugin?
- Which pinned dependency catalog is acceptable for the browser builder?

## Relationship to Other Plans

- [`connector-scale.md`](./connector-scale.md) — proposed bidirectional connector
  ecosystem on this plugin substrate. Adds the missing durable remote-operation
  and reconciliation contract; does not introduce a second executable plugin model.

- [`actions.md`](./actions.md) — `manual` triggers project into the action
  registry; a plugin action is an `ActionDefinition` like any other.
- [`dashboards.md`](./dashboards.md) — custom blocks are `view` plugins in the
  `dashboard-block` slot; built-in blocks stay core.
- `plugin-secrets.md` (on `feat/plugin-model`) — A3 in full: secret storage,
  handle substitution, and the one guarded egress that replaces ambient
  network access.
- [`personal-information-suite.md`](./personal-information-suite.md) — its
  connector runtime needs (scheduler, cursor state, secrets) are A3 and A4.
  First-party Google/Microsoft connectors remain products, not generated
  plugins.
- The habits app (folded below) — first external-app consumer; blocked on
  the UI-plugin RPC `query` on `develop`.

## Folded plans

Absorbed 2026-09-01. Each kept only what this document had not already
restated or Track A had not already built.

### Application state profiles (from `llm-wasm-gui-plugins.md`)

Nothing in this section is built. It is the `view` half of "Trust: the one
split that does not collapse", spelled out per profile.

**Application documents (`documents.loro`).** An app like IronCalc owns its
own Loro document; Atomic owns a metadata resource beside it:

```text
ApplicationDocument metadata resource (Atomic-owned)
  subject · isA · parent · read / write · applicationRelease · payloadSubject

Application payload document (application-owned Loro)
  arbitrary Loro containers and application schema
```

The payload is opaque to the property materializer and the search index. The
host checks that the plugin may edit that payload subject, then signs and syncs
its deltas; a payload delta can never mutate the metadata resource, and the
payload has no rights of its own — every check resolves through the metadata
resource. Payload commits must carry incremental Loro updates with periodic
compaction snapshots, not a full snapshot per edit
([`disk-storage-and-persistence-optimization.md`](./disk-storage-and-persistence-optimization.md)
fix #1). SDK shape: `atomic.openLoroDocument({ document, mode })` returning
`{ doc, onRemoteUpdate, publishLocalUpdate, setEphemeralState }`; the host owns
transport, signing, persistence, rate limits and presence.

**Opaque checkpoints (`documents.blobs`).** A photo editor has no mergeable
state and should not be forced to invent one. `atomic.openBlobDocument(subject)`
gives `readHead()` and `saveCheckpoint(bytes, { mimeType, expectedHead })`. The
host hashes and stores the bytes through `BlobBackend`, writes immutable
checkpoint metadata, advances the head through the normal outbox path, signs
outside the sandbox, and keeps a conflicting checkpoint as a branch when
`expectedHead` is stale. Coarse collaboration, explicit conflicts, no semantic
merge. Retained checkpoints grow unbounded without a retention + blob-GC policy
(keep recent + tagged, GC unreferenced) — the blob twin of the retained-snapshot
problem in `disk-storage-and-persistence-optimization.md`.

**Neither profile exposes the user secret, arbitrary signed commits, or the
Atomic metadata Loro document.** They are for ordinary third-party apps too;
LLM-generated views are one consumer.

**Runtime capability matrix.** Not every node can execute every plugin;
expose availability instead of assuming it:

| Node role | Store/sync metadata | Fetch artifact | Build JS/TS | Preview / execute GUI | Execute server-side |
| --- | --- | --- | --- | --- | --- |
| Blind encrypted replica | Yes, opaque | Policy-controlled bytes | No | No | No |
| Browser / local OPFS node | Yes | On demand | Yes | Yes | No |
| Native / server verifier | Yes | On demand | Yes when enabled | Yes | Yes |
| Native / mobile verifier | Yes | On demand | No initially | Possibly | No initially |

Build, preview, AI inspection and execution need a trusted verifier with
plaintext access; granting one access to encrypted content is a confidentiality
decision later revocation cannot undo. Artifact bytes are metadata-first and
fetched on demand; arrival never activates code (S1).

**Builder boundary (S2, detail).** A dedicated browser worker: materialize the
project into an in-memory workspace, pinned template + SDK version, type-check
and bundle to one `ui.js` (+ optional `ui.css`), run static validation and
state-profile integration tests, package an immutable release, return
artifacts + logs + provenance. No npm, no arbitrary build scripts, no
dependency network; a pinned dependency catalog cached with the app. First
stack: TypeScript + a small DOM helper or SolidJS, one UI entry point. Admission
limits (source count/size, artifact size, log size, build time, CPU, memory,
dependency count, fuel, storage quota) apply at mutation and build time, not
only at execution. Generated schemas go through a reviewed release step
([`json-schema-code-first.md`](./json-schema-code-first.md)), never as a side
effect of loading code.

**Still-open items from the old gap list, not covered above or by Track A:**

- iframe CSP derived from granted capabilities (the `connect-src` item under
  Security Debt); serve immutable UI files by artifact hash; a read-only
  `plugin-asset:` mapping for package assets instead of inlining everything.
- Version and runtime-validate RPC messages; a per-frame channel token.
- Batch reads (`getResources(subjects[])`) on the UI-plugin RPC; push a
  context-changed event instead of the pull-only `PageContext`.
- View slots and deterministic selection (first-`isA` only, last plugin in
  `/plugin-list` wins today); discovery that works from the local node while
  offline instead of a server-only `/plugin-list` refresh.
- An external-developer dev loop: serve an unpacked plugin through the
  production iframe host with a visible preview capability set, so iteration
  is not build → zip → upload → extract → refresh.
- Open: should a release contain independently versioned UI and runtime
  modules if WASM modules return; which concrete use case justifies an
  optional WASM runtime module after the JS/TS state APIs ship.

### Importers (from `importers.md`)

The pipeline decision stands and Track A built its middle: a transform is a
`run` plugin with trigger `manual` and capability `parse`, its verdict is the
preview, and the host commits. What the importer plan still adds:

```text
acquire  -> parse       -> map/transform      -> validate  -> preview  -> commit
(host)      (host,         (`run`, pure)         (host,       (host UI)   (host,
 upload/     first-party                          schema       user        provenance,
 fetch/      CSV/XLSX/JSON/                       oracle)      approves)   idempotent)
 OAuth)      ICS/VCF/HTML/mbox/zip)
```

- **Level 0, no code.** Below ~100 records the assistant imports directly with
  `get_user_classes`/`get_schema` + `create_resource` in the compact dialect
  ([`json-ad-compact.md`](./json-ad-compact.md)), everything under one parent
  for undo. Open: does Level 0 need write batching (one commit per resource
  today)?
- **First-party parsers, not generated ones.** CSV (type inference + column
  stats), Excel, JSON, ICS, VCF, bookmarks HTML, mbox, zip trees. The LLM
  receives parsed records and a *sample* (first N + column stats, ideally
  stratified), never the full file. ICS/VCF/mbox overlap
  [`personal-information-suite.md`](./personal-information-suite.md) M2.
- **Trusted importers first (decision 2026-07-14).** Ontola authors, tests and
  signs first-party importers (Notion export-zip is the forcing function:
  databases → tables, pages → documents, nesting → folders, files → File
  resources) before any client-publishing story. Fixtures make trust
  verifiable — any node re-runs `transform(fixture) === expected` before use —
  and "verified by Ontola" is a publisher signature, not a string. Per the
  Deletions list this is not an `ImporterSkill` class: fixtures and
  instructions are plugin fields.
- **Provenance and idempotency.** An import lands as a subtree under an
  `ImportRun` (original bytes as a blob, transform pinned by hash, stats);
  resource identity derives from `(importer, externalId)` so a re-run updates
  instead of duplicating, content hash as fallback; undo is one destroy.
  Imports never mutate pre-existing resources except as a separately approved
  diff.
- **Schema mapping: reuse first.** Search existing classes/properties (incl.
  vector search over descriptions, `server/src/vector_search/`), define only
  the residue code-first, prefer links over copied strings.
- **Security beyond the sandbox.** SSRF via "import from URL" needs a
  confirmation showing the resolved target plus private-range blocking (host
  fetch, not browser fetch). Sample records are attacker-controlled content;
  containment is structural (no network, no store, same approval gate). No
  importer gets drive-wide write scope.
- **Second engine.** Pyodide (15–60 MB, lazy, cached) behind the same
  records-in/JSON-AD-out contract for heavy tabular surgery; not the
  foundation. AssemblyScript, MoonBit, JupyterLite, cloud execution by
  default: no.
- **Open:** streaming transforms / chunked commits for 500 MB Takeout zips and
  the ClientDb bulk-write ceiling (A2 above); PDF/image/audio sources are
  extraction (LLM-per-record), out of scope but must not be precluded.

### Habits app (from `habits-app.md`)

A habit tracker built strictly as an external developer would — public
`@tomic/*` packages and the iframe view only, no new `case` in
`ResourcePage.tsx`, no built-in ontology, no bespoke endpoint — so that every
point of friction is a finding rather than a workaround. Not started; kept
because it is the cheapest end-to-end test of goal 3.

- **Data model worth keeping:** `Completion` is one immutable resource per
  tap (append-only), never a `count` register — a +1 on an offline watch and a
  +1 on the phone must merge to 2. `localDate` is stored explicitly so a 23:30
  tap counts for the day the user experienced. ~11k resources/year is fine.
- **Blocker on `develop`:** the UI-plugin RPC `query` still returns
  `'not implemented'` (`views/PluginView/pluginRPC.tsx`), so a view cannot ask
  for "completions for these habits, newest first". Fixed on
  `feat/plugin-model` (PR #1307), where the app host also has `query` and
  `create`.
- **Other findings it should surface:** no range/date filter in queries
  (page a `sort_by=localDate` collection until the boundary passes;
  [`multi-property-filter.md`](./multi-property-filter.md)); plugin views
  vanish offline while discovery is `/plugin-list`; apps cannot ship an
  assistant skill (install-time skill registration as a manifest capability);
  standalone local-first client DX ([`SDK-API-design.md`](./SDK-API-design.md)
  tutorial); watch-class pairing ([`device-pairing.md`](./device-pairing.md)).
- **Watch:** Wear OS in Flutter on the Rust core (the canvas app's pattern),
  offline tap = one `Completion` in the outbox; not a thin HTTP client.
