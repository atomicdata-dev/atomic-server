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

## Next: discovery through the localthought proxy

Once the touch points above are proven, the next step is a real provider
discovered rather than hand-written: querying a **localthought proxy** to find
which APIs can be imported (an OpenAPI-shaped discovery service, playing the
role PR #1383's `REFLECTOR_ROOT/spec` scan played), then generating the same
shape this document just walked — ontology, mapping, plugin — from what it
returns instead of from a person writing `integrations/<name>/*.ts` by hand.
That discovery protocol, and how much of a discovered plugin can be generated
versus reviewed and hand-finished, is not designed yet.
