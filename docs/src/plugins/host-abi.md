# Host ABI: writing an app in Rust

> [!WARNING]
> Pre-v1. The host ABI (`atomic:host@0.1.0`) may change without notice until it is declared v1. The plan is in `planning/host-abi.md`.

The host ABI is one typed interface between AtomicServer and a sandboxed app.
An app is a WebAssembly component (`wasm32-wasip2`) that imports four interfaces and exports one:

| Interface | What it gives the app |
| --- | --- |
| `store` | `get`, `get-many`, `query` (class, parent, filters, cursor), `apply` (create, set, remove, destroy), `subscribe` |
| `net` | `fetch` by manifest operation id. The host knows the operation's method, endpoint and effect, and substitutes `secret:<name>` in headers |
| `events` | `set-filters`, `next` and `ack`: the drive's durable event stream, read from a cursor |
| `calls` | `providers`, `describe` and `call` to the other apps in the drive |
| `app` (export) | `invoke` answers a call to one of the app's declared exports. `on-event` handles an event |

The definition is [`atomic-host/wit/host.wit`](https://github.com/ontola/atomic-server/blob/develop/atomic-host/wit/host.wit).
An app has no filesystem, no sockets and no clock beyond WASI's: everything it can reach is one of these imports, and the host checks every one against the app's rights.

## Rights

An app runs as its Installation's own [agent](../agents.md).
That agent can read and write exactly what the drive's rights give it (see [Access Rights](creating-plugins.md#access-rights)).
Nothing runs as the server.

- A read needs both the caller and the app's agent to be allowed to read, and the resource to be inside the Installation's [read scope](#scopes).
- `store.apply` plans the intents with the same planner as every other plugin write, then checks write rights on every target before it writes anything. The outcome tells the app what happened:
  - `committed`: written, signed by the app's agent.
  - `proposed`: the caller may write there but the app's agent may not, or the target is outside the Installation's write scope (or it has no identity). Nothing is written. The host keeps the intents as a proposal for review.
  - `refused`: the plan is wrong, or the caller may not write there, or the intents touch an Installation, plugin or Release. Nothing is written; `problems` says why.
- When an app calls another app, the callee runs with **its own** Installation's rights and scopes, not the caller's. `calls.call` accepts a list of `handle`s for per-call capabilities, but they are ignored for now.
- When a person or tool calls an export over HTTP, the rights are the signed-in agent's **and** the callee's. Calling through an app never gives anyone more than they have.
- `POST /host/call` first checks the drive: the signed-in agent must be able to read it, and to write it when the export's `effect` is `write` or `external`, or when the providing app declares any `secrets` in its manifest. Running a plugin can spend its secrets, so it takes the same rights as changing it (as for `/plugin-run`); a reader can call a `read` export of an app without secrets, not of one with. This is checked at every hop of a chain, not only the first. A stranger gets `forbidden` before any app is loaded or run.
- A caller's own manifest bounds what it causes: `calls.call` only reaches interfaces the calling app lists in `uses` (see below), and its Installation's call scope. Without it the call is `forbidden`.
- A host that vouches for its caller can narrow the effects with `allowEffects` on `/host/call`. The data browser sends `["read"]` for a frame, because it cannot yet ask the person to approve a write, an external effect or a dialog. A frame has no network of its own, so it cannot send a wider list.
- One entry call has a total budget, however the apps fan out: 64 calls between apps and a shared pool of fuel (16G instructions, sixteen apps' default allowance). Each instance takes up to its own fuel limit from the pool and gives back what it did not use. Past either, calls fail with `depth-exceeded`. The entry call itself is stopped after 30 seconds (`trap`).

### Scopes

What an app may reach is an explicit list on its Installation, set by whoever installs it, in three ordinary properties:

| Property | Value | Limits |
| --- | --- | --- |
| `readScope` | resources | Reads: each listed resource and everything below it |
| `writeScope` | resources | Writes (`store.apply` targets), the same way |
| `callScope` | JSON array of interface names | `calls.call`, on top of the manifest's `uses` |

`full-drive-access` is the widest scope: the whole drive, for reads and writes.

- A property that is not set does not limit that kind of access; the agent's own rights still do. A set property is the complete list: `readScope: []` reads nothing.
- Scopes are rights and limits at once. Activating the Installation puts the app's agent on the read or write list of every listed resource (the normal [access rights](creating-plugins.md#access-rights), so anything inheriting from there is covered), and the host refuses anything outside the lists even if the agent was given more by hand. The same code runs for every runtime, so a scope holds for a component, a module and a run plugin alike.
- The person who installs can only hand out what they hold: every listed resource must be in the drive and writable by them, or the Installation is refused and nothing is installed.
- A scope that shrinks makes the earlier rights inert for the host, but does not remove the agent from the old lists.

## An app: the counter

`plugin-examples/host-abi-counter` exports `atomic:example/counter@1` `increment`: it reads a resource with `store.get`, writes the count plus one with `store.apply`, and returns the new count.

`Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.48.1"
serde_json = "1"
```

`src/lib.rs`:

```rust
wit_bindgen::generate!({
    path: "../../atomic-host/wit",
    world: "sandboxed-app",
});

use atomic::host::{
    events::Event,
    store::{self, Intent, Outcome},
    types::{Error, PropVal, Value},
};
use exports::atomic::host::app::Guest;

struct Counter;

impl Guest for Counter {
    fn on_event(_event: Event) -> Result<(), Error> {
        Ok(())
    }

    fn invoke(interface: String, function: String, args: String) -> Result<String, Error> {
        match (interface.as_str(), function.as_str()) {
            ("atomic:example/counter@1", "increment") => increment(&args),
            _ => Err(Error { code: "not-found".into(), message: "no such export".into() }),
        }
    }
}

fn increment(args: &str) -> Result<String, Error> {
    let args: serde_json::Value = serde_json::from_str(args)
        .map_err(|e| Error { code: "invalid-argument".into(), message: e.to_string() })?;
    let (subject, property) = (args["subject"].as_str().unwrap(), args["property"].as_str().unwrap());

    let resource = store::get(subject)?;
    let current = resource
        .propvals
        .iter()
        .find_map(|pv| match (&pv.value, pv.property == property) {
            (Value::Integer(n), true) => Some(*n),
            _ => None,
        })
        .unwrap_or(0);

    let applied = store::apply(&[Intent::Set((
        subject.to_string(),
        vec![PropVal { property: property.to_string(), value: Value::Integer(current + 1) }],
    ))])?;
    if applied.outcome != Outcome::Committed {
        return Err(Error { code: "not-committed".into(), message: format!("{:?}", applied.outcome) });
    }
    Ok(serde_json::json!({ "count": current + 1 }).to_string())
}

export!(Counter);
```

Build it:

```sh
cargo build --target wasm32-wasip2 --release -p host-abi-counter
```

## The manifest

An app is a release whose manifest has `"runtime": "wasip2/1"` and `"world": "sandboxed-app"`, and lists what it offers in `exports`.
An app that calls other apps lists the interfaces it will call in `uses` (same form as an export's `interface`, once each, world `sandboxed-app` or `extension`): `"uses": ["atomic:example/counter@1"]`. An app that lists none calls nobody.
Each export has an `interface` (`package:name/interface@major`), a `function` (kebab-case), a `description`, an `inputSchema` and an `outputSchema`, and an `effect` (`read`, `write`, `external` or `interactive`).
The schemas are a bounded JSON Schema subset: a flat object of `string`, `integer` and `boolean` properties, each with a `description`, and `additionalProperties: false`.
The host validates the arguments before the app runs, and the result before the caller sees it.

```json
{
  "schemaVersion": 2,
  "runtime": "wasip2/1",
  "world": "sandboxed-app",
  "name": "counter",
  "namespace": "example",
  "version": "0.1.0",
  "exports": [
    {
      "interface": "atomic:example/counter@1",
      "function": "increment",
      "description": "Adds one to an integer property of a resource and returns the new value.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "subject": { "type": "string", "description": "The resource to count on." },
          "property": { "type": "string", "description": "The integer property that holds the count." }
        },
        "required": ["subject", "property"],
        "additionalProperties": false
      },
      "outputSchema": {
        "type": "object",
        "properties": { "count": { "type": "integer", "description": "The count after incrementing." } },
        "required": ["count"],
        "additionalProperties": false
      },
      "effect": "write"
    }
  ]
}
```

Network access works as for other plugins: declare `operations` (and `secrets`) in the manifest, and the app calls them with `net.fetch`.
Only `read` operations can be fetched directly; an external write is something a person approves.

## Calling another app

```rust
use atomic::host::calls;

let result = calls::call(
    "atomic:example/counter@1",
    "increment",
    &serde_json::json!({ "subject": subject, "property": property }).to_string(),
    &[],
)?;
```

The host finds the app in the same drive that declares `atomic:example/counter@1` `increment`, validates the arguments against its `inputSchema`, runs it in a fresh instance with its own rights, validates the result against its `outputSchema` and returns it.
A call to an interface nobody provides fails with `not-found`.
Apps may call each other at most 8 deep, and one entry call may cause at most 64 calls in all (`depth-exceeded`). The interface must be in the calling app's `uses`, or the call is `forbidden`.
`plugin-examples/host-abi-caller` calls the counter twice (`bump-twice`) and shows the depth limit (`recurse`).

`calls.providers(interface)` lists the installations that provide an interface, and `calls.describe(interface)` returns their exports with the schemas, so an LLM or a UI can discover what is callable.

## Calling an export from outside

The browser and MCP are not components, so they call over HTTP:

```
POST /host/call
{ "drive": "did:ad:...", "interface": "atomic:example/counter@1",
  "function": "increment", "args": { "subject": "...", "property": "..." } }
```

The request is signed with a version 2 signature (`signRequest(url, agent, {}, { method, body })`), which covers the method and the body, so a captured request cannot be replayed with other arguments. It may carry `"allowEffects": ["read", ...]`; an export whose effect is not listed is `forbidden`, at every hop of the chain, so an app called with `["read"]` cannot pass the call on to one that writes. The answer is `{"result": ...}`, or `{"error": {"code": ..., "message": ...}}` with a status that follows the code (`forbidden` 403, `not-found` 404, `invalid-argument` 400, `unsupported` 501).

## Exports as tools

Every export of an installed `sandboxed-app` is also an MCP tool on `/mcp`, so an LLM finds it with `tools/list` and calls it with `tools/call`, without knowing about apps.
The name is made from the interface and the function: lowercase, every character outside `a-z0-9_` becomes `_`, and a double underscore separates them, so `atomic:example/counter@1` `increment` is `atomic_example_counter_1__increment` (a name over 64 characters keeps its tail behind a short hash of the whole). The description and `inputSchema` are the export's own, plus an optional `drive` argument for when several shared drives provide the same tool (the first one is the default).

A tool call takes the same path as `POST /host/call`: the connection's issued agent must read the drive, and write it for a `write` export or an app that declares secrets, at every hop. On top of that the person's choice counts: a read-only connection is only offered `read` exports of apps without secrets.
`external` and `interactive` exports are not offered over MCP yet.

## From a frame (TypeScript)

A drive app's frame calls an export through its store, with the signed-in person's rights. The host sends the signed `POST /host/call` for it, and for now only runs exports whose `effect` is `read`; a `write`, `external` or `interactive` export is `forbidden` from a frame until the host can ask the person to approve it. (`store.call(op, args)` is the transport under every store method, as before.)

```ts
import { store, HostError } from '@tomic/plugin';

try {
  const { value } = await store.callExport('atomic:example/counter@1', 'increment', {
    subject,
    property,
  });
} catch (e) {
  if (e instanceof HostError && e.code === 'forbidden') {
    // e.code is one of the codes above; e.message is for people.
  }
}
```

`store.callExport` resolves to the parsed result. A drive app served by `/plugin-ui?format=client` has the same `store.callExport`, whose errors carry `code` but are plain `Error`s. `AppExport`, `Effect` and `HostErrorCode` are exported as types. They are hand-written from `atomic-host/wit/host.wit`, and a test checks the codes against the Rust host. Packaged views (not drive apps) do not support `call` yet.

## From a QuickJS run plugin

A plugin that runs in the server's QuickJS runtime (`/plugin-run`, triggers, schedules) has the same `store`, `net` and `calls` as a component, as globals with the same names and error codes. A failed call throws an `Error` with `code`.

```js
export function run(ctx) {
  const page = store.query({ class: TASK, filters: [{ property: DONE, op: 'eq', value: { tag: 'boolean', val: false } }], limit: 50 });
  const { count } = calls.call('atomic:example/counter@1', 'increment', { subject, property });
  return { intents: [] };
}
```

Values cross as `{tag, val}` (the WIT variant case: `string`, `integer`, `link`, `resource-array`, `json`, ...), fields are camelCase. Available: `store.get`, `getMany`, `query`, `net.fetch` (the body is text) and `calls.providers`, `describe`, `call`. They are the same host code as for a component, so the rights are too: reads need the caller and the Installation's agent, `net.fetch` only reaches manifest operations, and `calls.call` goes through the same checks as above (`manifest.uses`, write on the drive at every hop for `write` and `external` exports).
A run plugin lists `uses` in its manifest like an app does. Its calls are limited to `read` exports, as for a frame. `store.apply` is `needs-approval`: a run plugin proposes writes by returning intents, which the host plans and applies after review. `subscribe`, `undo`, `search` and `events` are `unsupported`.
`ctx.http`, `ctx.read` and `ctx.query` keep their shapes and are shims over `net.fetch` (which also takes the URL form `{method, url, headers, body}` there), `store.get` and `store.query`; `ctx.integration` is unchanged.

## A server module: hooks in the commit and read path

A class extender is a **server module**: a component of world `server-module`. It has the same `store`, `net` and `calls` as an app, from the same code, and it exports `hooks` instead of `app`. It is installed by the operator (manifest `world: "server-extension"`) and extends the classes `hooks.classes` names.

| Export | When |
| --- | --- |
| `classes` | Once, when the module is loaded. The classes whose reads and commits it extends |
| `before-commit(commit, after)` | Before a commit on one of the classes is stored. `after` is the resource as the commit leaves it; the state before is still readable with `store.get`. An `error` problem refuses the commit, a `warning` is logged. A trap or running out of fuel refuses it too |
| `after-commit(commit, after)` | After it is stored. A failure is logged and never undoes it |
| `on-get(resource, agent)` | Before a resource is returned to `agent`. The answer replaces it, `none` leaves it, an error fails the read. The subject of the answer is always the one asked for |

`commit` carries the subject, the signer, the commit as JSON-AD (`commit-json`) and `is-new`. A commit signed by the module's own agent does not trigger it, so a module does not react to its own writes.

One import is new, because a module has no caller to ask:

| Import | What it gives |
| --- | --- |
| `context.get` | The Installation, the agent the module acts as (`none` for a module in the operator's `global` folder, which reads as the public and writes nothing) and the Installation's config as JSON text. The user can edit the config at any time |

A module runs as its Installation's agent, which is the only identity it has: reads are checked against that agent, `store.apply` is signed by it and gets the same `committed`, `proposed` and `refused` outcomes as for an app, and an Installation, plugin or Release cannot be changed through it. There is no separate rights code and no way to read or write as someone else. A module reads only what its agent was given (its scopes or `full-drive-access`, or access granted on the Installation page), and its scopes limit it the same way as an app.

Two things differ from an app, both because a module runs inside the server's own path and nobody is there to approve:

- `net.fetch` may use operations whose `effect` is `write` (an app is limited to `read` and has to propose the rest).
- A hook has no entry call to meter, only its own fuel and memory (the `extended-fuel` and `extended-memory` capabilities widen them).

A module's `calls` reach the apps installed in its drive, through the same registry and the same checks as any other call: the interface must be in the module's manifest `uses`, and the module's agent is the caller, so a `write` or `external` export needs write on the drive (`full-drive-access`).

What the old `atomic:class-extender` interface became:

| Class extender | Server module |
| --- | --- |
| `get-resource(subject, agent?)`, `query(property, value, agent?)` | `store.get`, `store.query` with an `eq` filter. There is no `agent` override: the old host ignored it too |
| `get-plugin-agent()`, `get-config()` | `context.get` |
| `commit(commit-json)` | `store.apply`. A raw signed commit has no ABI function: intents are planned like every other write, which also checks the datatype of each value |
| `fetch(http-request)` | `net.fetch` by operation id. A module declares `operations` in its manifest instead of `network.origins`, and gets no `wasi:http` or sockets |
| `class-url`, `on-resource-get`, `before-commit`, `after-commit` | `hooks.classes`, `on-get`, `before-commit`, `after-commit` |

A module's folder (`/`, with the `storage` capability writable) is kept.

The Rust helper crate `atomic-plugin` wraps this: implement `ClassExtender` and call `export_plugin!`. `plugin-examples/host-abi-module` shows the raw interface.

## Events

Every applied commit appends one row to its drive's event log, in the same batch that stores the commit (`lib/src/db/drive_events.rs`, `Tree::PluginMeta`). Sequence numbers only grow, so a cursor is the last sequence an app handled.

- `set-filters` replaces the app's subscription. A filter has `class`, `subtree` and `property`; fields that are set must all match, and an event is delivered when any filter matches. An app that never subscribed gets every event it may read.
- `next(cursor, max)` returns events after `cursor`, oldest first. With no cursor it starts at the app's checkpoint. Reading does not consume.
- `ack(cursor)` moves the checkpoint forward and never back. Filters and checkpoint are stored in the db, so after a restart the app gets what it missed exactly once.
- Delivery is rights-checked at read time: an event is only returned when the caller and the Installation's agent may read the resource (and its `readScope`). For a destroyed resource the parent is asked. The log keeps seven days.

## Not built yet

- `store.search` and `store.undo` return `unsupported`, as does the `ne` filter. `class` matches the class exactly, not its subclasses.
- `events` carries one event per applied commit. Query-edge triggers, cron, field timers, inbound webhooks and tombstones do not feed it yet, and the host does not call `on-event` itself: an app pulls.
- Proposals from `apply` are kept in memory.
- Handles passed to `calls.call` are ignored.
- A frame cannot call `write`, `external` or `interactive` exports (approval UI). An export's `effect` is what its author declared, so an approval UI must not rely on it alone. Every hop is still bounded by the signed-in agent's rights and the callee's own grant.
- Publishing a `sandboxed-app` package through `/plugin-release-package` is not wired: the example tests publish a release record and package directly. Activating an Installation of such a release only mints its identity.
- `net.fetch` reads response bodies as text.
