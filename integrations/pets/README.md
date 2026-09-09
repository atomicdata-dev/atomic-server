# Pets (demo)

A trivial, read-only demo integration: five static demo pets, imported into a
Pets table with a small code-first ontology (species, breed, age, mood).
There is no provider, account, API key or network call — `manifest.operations`
and `manifest.secrets` are both empty. Its only purpose is to exercise the
touch points a real API plugin needs: an ontology, an import mapping into the
shared sandbox, an installable connection, and a table a document or an LLM
can query afterwards.

Open Integrations → Pets → Set up connection. This creates a Pets table
beneath the installed connection and imports the five demo pets. Re-running
reconciles: unchanged pets are skipped, same as every other importer here.

## Architecture

`plugin.ts` bundles the static data and mapping into `plugin.js`, and runs in
the same sandboxed server host as every other integration
(`server/src/plugins/js_runtime.rs`). It never calls `ctx.http`.
`schema.ts` defines the ontology with `ensureSchema`, the same code-first
mechanism `mt940` and `clockify` use.

## Why this exists

This is the first step of rebuilding the API-plugins direction from
[PR #1383](https://github.com/ontola/atomic-server/pull/1383) on top of the
plugin model in `feat/plugin-model`. That PR discovered OpenAPI-described
providers under a `REFLECTOR_ROOT/spec` folder and ran live OAuth imports.
Here, the touch points are proven out first with data that needs none of
that: no discovery, no OAuth, no secrets. The next step is to replace the
static `data.ts` with a provider discovered through the localthought proxy,
once that discovery path exists.
