# @tomic/form-app

The published-form runtime served at `GET /form/:id` by atomic-server. A small
Vite app (no `@tomic/lib`, no Loro) that mounts
[`@tomic/form-renderer`](../form-renderer) against one JSON definition and
POSTs one JSON body on submit. See `planning/atomic-forms.md` (Phase 4).

## How it's served in production

`server/build.rs` builds this package as part of the browser workspace build
and copies `dist/` into `assets_tmp/form-assets/`, which gets embedded into
the `atomic-server` binary alongside the data-browser dist. `GET /form/:id`
(`server/src/handlers/form.rs::form_page`) serves `form-assets/index.html`
with the form's definition JSON injected inline as
`window.__FORM_DEFINITION__`, so the first paint skips a fetch round-trip.
`vite.config.ts` sets `base: '/form-assets/'` so the built asset URLs match
where they're embedded, and `html.cspNonce: 'ATOMICSERVER_NONCE'` so Vite
stamps every script/link tag with a nonce placeholder the server substitutes
per-request (mirrors `data-browser`'s `vite.config.ts`).

## Local dev

Two ways to iterate:

- **Through the embedded build** — `cd server && cargo run` (rebuilds the
  whole browser workspace, including this package, when sources change; set
  `ATOMICSERVER_SKIP_JS_BUILD=true` to skip and reuse the last build). Visit
  `http://localhost:9883/form/:id`. With the skip flag set, rebuild this
  package yourself after `@tomic/form-renderer` changes (`pnpm --filter
  @tomic/form-app build`) — otherwise the public route keeps a stale
  renderer while the builder preview (Vite HMR) shows the new one.
- **HMR against a running server** — `pnpm dev` here starts a Vite dev
  server on `:6748`. It fetches `/form/:id/definition` and POSTs to
  `/form/:id/submit` directly against `http://localhost:9883` (atomic-server
  already sends permissive CORS headers, so no proxy config is needed for
  either the GET or the POST). Visit `http://localhost:6748/form/:id` — the
  `id` segment is read from `window.location.pathname` the same way the
  embedded build reads it, so both entry points share `src/api.ts` unchanged.
