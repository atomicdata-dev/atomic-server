# API plugins

**Status:** Exploratory, on `feat/api-plugins` (branched from `feat/plugin-model`,
PR #1307). Rebuilds part of the direction from
[PR #1383](https://github.com/ontola/atomic-server/pull/1383) — OpenAPI-discovered,
live OAuth provider imports — on top of the plugin model instead of a separate
Reflector-backed importer.

## Where PR #1383 left off

PR #1383 discovered integrations under a `REFLECTOR_ROOT/spec` folder (declarative
OpenAPI + OAuth overlays), and ran live imports through `reflector-rs` /
`atomic_lib`'s importer, either from the CLI or from a running server with
signed browser-bound OAuth. That work is not being ported wholesale: this
branch is instead re-deriving the same end state — a user picks a provider,
signs in, and gets data — as an ordinary plugin installed from `integrations/`,
so it shares one review, secrets, and sandbox story with every other plugin
instead of a parallel one.

## First step: `pets`

[`integrations/pets`](../integrations/pets/) is the first commit here, and is
deliberately trivial: a static demo collection with a small code-first
ontology (species, breed, age, mood), no provider, no OAuth, no secret. It
exists only to walk every touch point a real API plugin needs, before adding
the parts that make a provider real:

- an ontology, ensured into the drive with `ensureSchema` (`schema.ts`)
- an import mapping into the shared sandbox (`plugin.ts` + `import-records.ts`)
- a committed, reproducible `plugin.js` bundle (`esbuild --bundle --format=esm`)
- registration as a bundled integration (`IntegrationDiscovery.tsx`)
- an installable connection resource + table + view (`ConnectPets.tsx`)
- a server-side sandbox test (`server/src/plugins/pets_tests.rs`)
- [x] a browser flow that installs, reviews, applies and displays all five pets
  (`browser/e2e/tests/plugins.spec.ts`)
- certification metadata (`package.json` `atomicCertification`)

## LocalThought and Syncables follow-up

Work continues on `codex/localthought-api-plugins`: dynamic catalog discovery,
signed account handoff, rotating host-owned credentials, Syncables pagination,
platform-specific typed ontologies, and a paginated Pets mock integration proxy.
See [the integration README](../integrations/localthought/README.md) for its
configuration, behavior and tests.

- [x] Replace public demo discovery with the live platform catalog.
- [x] Implement signed account connection and return flow using `TENANT_SECRET`.
- [x] Use Syncables with the catalog OAD for discovery, pagination and ontology.
- [x] Add the mock proxy and wire the updated Pets browser journey into CI.
- [x] Verify live GitHub OAuth, fetch and reviewed import (29 issue/PR records; proxy v38).
- [x] Verify Google Calendar OAuth/import against the live service (54 records, including 32 events; proxy v39).

Calendar live follow-up: proxy PR #30 fixes catalog base paths (deployed v39).
OAuth and paginated reads work, but an unbounded import exceeds 5,000 records.
- [x] Add explicit UTC event date bounds and verify a scoped live import.

- [x] Rebase onto `2ca03bd2c`, verified tree-identical to requested `550cc5f`.
- [ ] Make branch CI pass. Local JS suite, lint, typecheck, Rust handler tests
  and focused Pets E2E pass. Main run 34349742940 exposed independent Cargo
  cache locks around a shared registry; link the locks into the shared volume.

Main run 34350517612 passed dependency installation with the shared locks, then
failed the full-app compiler sweep at its 5-second default (7.8 seconds actual).
Give only that bulk test a 30-second budget; retain all compilation assertions.

Run 34352390180 was canceled before jobs started when another branch replaced
it in the default single pending slot. Set `queue: max` on main-pipeline so
pending validations can wait sequentially instead of displacing one another.

## Browser migration

`codex/browser-integrations` moves the LocalThought flow off AtomicServer.
Catalog parsing and pagination run in the Atomic WASM bundle; the browser owns
the tenant handoff and rotating connection code, then maps fetched records into
locally reviewed proposals. Companion branches in Syncables and integration-proxy
provide WASM compatibility and CORS. See `integrations/localthought/README.md`.
Legacy direct integrations, action infrastructure and scheduling remain separate.
