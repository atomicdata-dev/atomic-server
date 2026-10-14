# Host ABI: apps on a typed, real-time, multi-machine host

**Status:** Accepted direction (Joep, 2026-10-14). Step 0 in progress; nothing
else built. Pre-v1: the ABI may break until it is declared v1.

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

- [ ] Frame CSPs (`server/src/handlers/plugin_ui.rs`) get `connect-src 'none'`
      and both carry a `sandbox` directive. Today `connect-src *` lets a view
      that may read drive data send it to any host.
- [ ] Integration-proxy requests from frames go through the host (a
      `proxyFetch` host op restricted to the minted capability's origin)
      instead of a direct `fetch` from the frame.

### 1. One host ABI (pre-v1)

- [ ] Write the ABI: read (`get`, `get-many`, `query` with filters and
      completeness, `subscribe`), write (`apply(intents)`, `undo`), events
      (`events(cursor)`), outside world (`fetch(operation)`, `invoke-action`),
      state (resources under the installation), and calls
      (`call(interface, function, args)`). Interaction is not a kernel op: it
      is `call` on the built-in `atomic:ui/*` apps (principle 7).
- [ ] Typed records instead of JSON strings; batch operations.
- [ ] Generate Rust bindings and TS types plus the frame client from it.
- [ ] Port the three runtimes (class-extender WIT, plugin-runtime WIT, frame
      `store`) onto it. Legacy RPC, `plugin.json` and `/app-write` go once the
      catalog apps are ported; stored installations stay readable.
- [ ] Conformance suite: run published catalog releases against each host
      build (regression test until v1, a promise after).

### 2. Scoped grants

- [ ] Replace the six capabilities with `(scope, rights)` grants enforced in the
      one place grants are intersected today (`host_core.rs`).
- [ ] Consent dialog shows scopes in plain language.
- [ ] Covers #1740, #1741, #1849 and most of #2235 with one mechanism.

### 3. One event stream

- [ ] Durable, cursor-based stream: query edges, commits on a class, cron,
      field timers, inbound webhooks, "connection needed", tombstones (#1850).
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
- [ ] Views match subclasses of the class they declare, so drive classes that
      extend a shared class get its views (to settle with atomic-plugins, whose
      views match the exact class).
- [ ] The compat diff (#2239) runs in `ensureOntology`, the ontology editor and
      on release publish, not only in the CLI. Retire `ensureSchema`.

### 5. Exports, calls and introspection

- [ ] Every app export (function, stream, view) is a resource under its
      `Release`: name, description, input and output schema, effect
      (`read` / `write` / `external`).
- [ ] MCP tools, Cmd+K actions, in-app AI tools, bindings and docs are all
      derived from those resources (today only manifest `actions` become MCP
      tools, `server/src/plugins/actions.rs`).
- [ ] The host ABI itself is described the same way.

### 6. Placement and multiple machines

- [ ] Leases for background work, as resources.
- [ ] Forward a call to a node that can run it (WS or Iroh), same signature,
      async.
- [ ] Apps needing a secret run on the node that holds it.

### 7. Proof

- [ ] One Rust component (for example the Money statement parser) called by a
      JS app through a typed interface, in the browser and on the server.
- [ ] One built-in extender (form or chatroom) rewritten as a module on the
      ABI, as a second conformance test next to the Kanban plugin.

## Not now

- New per-wish frame ops (#1734, #1735, #1736, #1739): fold into the built-in
  `atomic:ui/*` apps and `call` instead.
- Growing plugin routes (#2176) into websockets and sidecars (#1722, #1723)
  before steps 1 and 2; otherwise routes get their own rights model and ABI.

## Open

- Whether kernel features beyond the step 7 proof should use the ABI.
- Settling with atomic-plugins (Michiel): subclass matching, where shared
  classes live, and how "pieces" (views, integrations, lenses) map onto exports.
