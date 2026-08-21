# Plan fixtures

One verdict in, one expected plan out. Run by **both** planner implementations:
the TypeScript one the browser uses (`browser/lib/src/plugin-plan.test.ts`) and
the Rust one the server uses for unattended runs.

They exist because there are two planners and there will go on being two. The
browser plans against a local store, offline, on drives that never reach a
server; the server plans for runs nobody is watching. Neither can do the
other's job.

Duplication is survivable. Drift is not — a planner that disagrees with the one
that drew the preview means the changes someone approved are not the changes
that were made, which is the single assumption the approval gate rests on. So
the two are pinned here rather than trusted to stay in step.

## Shape

```jsonc
{
  "name": "what this pins",
  // Properties the planner may resolve. Anything else does not exist.
  "schema": { "<property url>": { "datatype": "...", "shortname": "..." } },
  // Resources that already exist. Anything else does not.
  "resources": { "<subject>": { "<property url>": <value> } },
  "verdict": { "intents": [...], "problems": [...] },
  "expect": {
    "blocked": false,
    // Substrings that must appear among the plan's problems.
    "problems": ["..."],
    // Changes in plan order. Creates are matched by `localId`, since the
    // subject a store mints is not knowable in advance.
    "changes": [
      { "op": "create", "localId": "x",
        "properties": [{ "property": "<url>", "to": "..." }] }
    ]
  }
}
```

An expectation names only what the case is about. A fixture that asserted every
field would fail for reasons that are not the thing it pins.
