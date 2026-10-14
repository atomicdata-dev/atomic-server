# Host ABI: writing an app in Rust

> [!WARNING]
> Pre-v1. The host ABI (`atomic:host@0.1.0`) may change without notice until it is declared v1. The plan is in `planning/host-abi.md`.

The host ABI is one typed interface between AtomicServer and a sandboxed app.
An app is a WebAssembly component (`wasm32-wasip2`) that imports four interfaces and exports one:

| Interface | What it gives the app |
| --- | --- |
| `store` | `get`, `get-many`, `query` (class, parent, filters, cursor), `apply` (create, set, remove, destroy), `subscribe` |
| `net` | `fetch` by manifest operation id. The host knows the operation's method, endpoint and effect, and substitutes `secret:<name>` in headers |
| `events` | `next` and `ack`: one pull stream with a cursor |
| `calls` | `providers`, `describe` and `call` to the other apps in the drive |
| `app` (export) | `invoke` answers a call to one of the app's declared exports. `on-event` handles an event |

The definition is [`atomic-host/wit/host.wit`](https://github.com/ontola/atomic-server/blob/develop/atomic-host/wit/host.wit).
An app has no filesystem, no sockets and no clock beyond WASI's: everything it can reach is one of these imports, and the host checks every one against the app's rights.

## Rights

An app runs as its Installation's own [agent](../agents.md).
That agent can read and write exactly what the drive's rights give it (see [Access Rights](creating-plugins.md#access-rights)).
Nothing runs as the server.

- A read needs both the caller and the app's agent to be allowed to read.
- `store.apply` plans the intents with the same planner as every other plugin write, then checks write rights on every target before it writes anything. The outcome tells the app what happened:
  - `committed`: written, signed by the app's agent.
  - `proposed`: the caller may write there but the app's agent may not (or it has no identity). Nothing is written. The host keeps the intents as a proposal for review.
  - `refused`: the plan is wrong, or the caller may not write there, or the intents touch an Installation, plugin or Release. Nothing is written; `problems` says why.
- When an app calls another app, the callee runs with **its own** Installation's rights, not the caller's. `calls.call` accepts a list of `handle`s for scoped capabilities, but they are ignored for now.
- When a person or tool calls an export over HTTP, the rights are the signed-in agent's **and** the callee's. Calling through an app never gives anyone more than they have.

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
Apps may call each other at most 8 deep (`depth-exceeded`).
`plugin-examples/host-abi-caller` calls the counter twice (`bump-twice`) and shows the depth limit (`recurse`).

`calls.providers(interface)` lists the installations that provide an interface, and `calls.describe(interface)` returns their exports with the schemas, so an LLM or a UI can discover what is callable.

## Calling an export from outside

The browser and MCP are not components, so they call over HTTP:

```
POST /host/call
{ "drive": "did:ad:...", "interface": "atomic:example/counter@1",
  "function": "increment", "args": { "subject": "...", "property": "..." } }
```

The request is signed like other plugin routes. The answer is `{"result": ...}`, or `{"error": {"code": ..., "message": ...}}` with a status that follows the code (`forbidden` 403, `not-found` 404, `invalid-argument` 400, `unsupported` 501).

## Not built yet

- `store.search` and `store.undo` return `unsupported`, as does the `ne` filter. `class` matches the class exactly, not its subclasses.
- `events` is an in-memory queue per installation. Nothing feeds it from query triggers, cron or commits yet, and the host does not call `on-event` itself.
- Proposals from `apply` are kept in memory.
- Handles passed to `calls.call` are ignored.
- Publishing a `sandboxed-app` package through `/plugin-release-package` is not wired: the example tests publish a release record and package directly. Activating an Installation of such a release only mints its identity.
- `net.fetch` reads response bodies as text.
