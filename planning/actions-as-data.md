# Actions as data: one description for ⌘K, the assistant, MCP and plugins

**Status:** Proposal (2026-10-20), not built. Requested by Joep in the MCP
thread. Extends [`actions.md`](./actions.md) (the TS registry), builds on
[`mcp-endpoint.md`](./mcp-endpoint.md) (`POST /mcp`) and feeds
[`host-abi.md`](./host-abi.md) step 5 (exports are resources). Does not touch
PR #2257.

## Problem

The same verbs are described in four places, in two languages:

| Place | What it holds | Lines |
| --- | --- | --- |
| `browser/data-browser/src/actions/` (`ActionDefinition`) | label, helper, shortcut, `run(ctx)` with UI context | ~1,900 incl. tests |
| `useAtomicTools.ts` + `assistant-tools.ts` | bespoke assistant tools with zod schemas | 1,971 + 303 |
| `server/src/mcp/tools.rs` | 11 hand-written tool descriptors (`name`, `title`, `description`, `inputSchema`, `annotations`) | 576 |
| `server/src/plugins/actions.rs` | plugin `Action` (`name`, `title`, `description`, `operation`, bounded `InputSchema`) | 2,299 (whole module) |

`ActionDefinition` mixes two things: a *description* (id, helper, shortcut,
danger) and an *execution* that takes an `ActionContext` full of UI (`navigate`,
`openComments`, `addChild`). The context is why nothing outside the browser
can reuse it, and why `/mcp` grew its own list.

The MCP tool descriptor and the plugin `Action` already have the same shape.
That shape is the common denominator.

## Proposal

1. **`ActionSpec`: a description with no code.** Fields: `id`, `title`,
   `description` (today's `helper`), `inputSchema` (the bounded JSON Schema
   subset `plugins/actions.rs` already validates), `effect`
   (`read` | `write` | `external`, mapped to MCP `annotations`), `needsUi`
   (true for dialogs, navigation, sharing), optional `shortcut`, `danger`,
   `keywords`. Stored as a resource so it can be listed, translated and
   versioned; before that exists, one JSON file embedded by both Rust
   (`include_str!`) and TS.
2. **Surfaces are projections of the spec.**
   - `/mcp` `tools/list` returns every spec with `needsUi: false`, filtered by
     effect and by the token's `write` flag. `tools/call` runs the Rust
     implementation. `delete_resource`, `edit_resource` and friends stop being
     hand-written JSON.
   - ⌘K, ⌘M, context menus and hotkeys keep their TS `label`, `icon` and
     `run`, but get id, description, shortcut and danger from the spec.
   - The assistant derives tools from the spec instead of `deriveActionTools`
     plus zod copies.
   - Plugin exports (host ABI step 5) are specs with a provider; no new list.
3. **Execution lives where the data lives.**
   - Data-only verbs (delete, trash, restore, favorite, move, tags, edit) are
     commits. One implementation in `atomic_lib`, called by the server for
     `/mcp` and compiled to WASM for the browser. This is the same split
     `host-abi.md` principle 1 describes (only Rust crosses WASM).
   - UI verbs stay TypeScript and are not MCP tools.
   - Per-keystroke work (⌘K filtering, availability checks) stays TS; do not
     cross the WASM boundary for it.
4. **Lightweight clients go through the node.** The app requires WASM/OPFS
   already. Scripts, the CLI and MCP clients call `/mcp` rather than carrying a
   third implementation. Write that into `docs/` as the supported model.

## Phases (each must net-remove code)

0. **Spec + derive.** DONE: `ActionSpec` and `server/src/mcp/tools.json` list all
   11 built-in tools (7 read, 4 write) for `tools/list`; output verified
   byte-identical. Gate met: net lines in `server/src/mcp/tools.rs` went down.
1. **Data verbs to Rust.** Move trash, restore, delete, favorite onto one
   `atomic_lib` function each. Delete the TS copies in `@tomic/lib`'s `Store`
   where the Rust one is called instead. Coordinates with the Trash work
   ([#2267](https://github.com/ontola/atomic-server/pull/2267) TS,
   [#2275](https://github.com/ontola/atomic-server/pull/2275) Rust).
2. **Assistant on specs.** Replace the bespoke tools that duplicate `/mcp`
   verbs with spec-derived ones; keep rich tools (tables, forms) bespoke.
3. **Plugin exports.** After Joep and Michiel agree the ABI, exports register
   specs; `/mcp` lists them with `effect` as the safety edge. No change before
   [#2257](https://github.com/ontola/atomic-server/pull/2257) is decided.

## Measure before phase 1

Benchmark "delete 1,000 resources" through (a) the TS Store, (b) Rust on the
node via `/mcp`, (c) Rust-WASM in the browser. Report time and bundle size
(WASM growth). If (c) is clearly slower for one-click actions, keep that verb
in TS and only share the description.

## Open questions

- Spec as resources in the drive, or as a shipped file until ABI step 5?
  Recommendation: shipped file first, resources when the ABI exports land.
- Which `effect` does a trash-vs-destroy pair get, and does `/mcp` expose both?
- Translating descriptions: wuchale ignores model-facing strings
  (`@wc-ignore`), so the spec's `description` stays English; labels stay in
  the TS layer.
- Net code: counted per phase in the PR description, not estimated here.
