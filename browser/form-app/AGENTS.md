# Form App

## Local Setup

- `http://localhost:6748` — published-form runtime with HMR (`cd browser/form-app && pnpm dev`), see below.

### Iterating on the published form runtime

`atomic-server` embeds `browser/form-app/dist` at *compile* time (`server/build.rs`),
so a change to `form-app` / `form-renderer` needs a `cargo build` + restart before
`/form/:id` shows it. Two ways around that, in order of preference:

1. **The builder's Preview tab** (`localhost:6747`) already imports
   `@tomic/form-renderer` from source, so anything that lives in the renderer
   hot-reloads there with no server involved.
2. **`cd browser/form-app && pnpm dev`** for the shell around it (`App.tsx`,
   `api.ts`, `index.html`, embed/captcha wiring). Open
   `http://localhost:6748/form/<publish-slug-or-did>`: Vite serves the page,
   and `/form/:id/{definition,submit,challenge,image}` are proxied to
   atomic-server (`VITE_ATOMIC_SERVER_URL`, read from `data-browser`'s
   `.env.development[.local]`). The app then takes its
   no-`window.__FORM_DEFINITION__` path and fetches the definition instead —
   same runtime, one extra request. Note `dev` serves from `/`, while the
   embedded build is based at `/form-assets/`.
