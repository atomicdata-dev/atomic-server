# Atomic Forms — Phased Implementation Plan

Builds on [`atomic-forms-research.md`](./atomic-forms-research.md) (tool comparison,
requirements, schema sketch). This document turns that research into concrete,
phased technical work. Each phase ends in a demoable state.

**Feature in one line:** build forms/surveys in the data-browser, publish them at a
lightweight `/form/:id` route (no data-browser bundle), collect submissions —
without the visitor needing an agent — into an existing Table resource.

## Architecture decisions (made up front)

### 1. Agent-less submission goes through a dedicated server endpoint

Two options were considered:

- **(a) Ephemeral keypair in the visitor's browser** + `PUBLIC_AGENT` append grant on
  the submissions table. Works today — the commit handler auto-creates agent
  resources for unknown signers (`server/src/handlers/commit.rs` ~line 118), and
  `check_rights` honors `PUBLIC_AGENT` grants (`lib/src/hierarchy.rs`).
- **(b) Dedicated `POST /form/:id/submit` endpoint**: plain JSON body, server
  validates and writes the submission row itself, signed by the **server agent**.

**Decision: (b).** Rationale:

- Publish/unpublish gating, one-time private-link codes, captcha verification, and
  per-form validation **cannot** be enforced on the generic `/commit` path without
  polluting it with form-specific logic.
- A public append grant lets anyone write *arbitrary* children under the table —
  spam surface with no validation. The endpoint validates against the form
  definition before anything is persisted.
- The published form runtime stays tiny: no Loro WASM, no ed25519 signing, no
  `@tomic/lib` store. It fetches one JSON definition and POSTs one JSON body.

Trade-off: submissions lose per-visitor provenance (all rows signed by the server
agent). Acceptable for forms; revisit if we ever want authenticated submissions
(then option (a) becomes an *additional* path).

### 2. Published form is a separate, minimal frontend package

- New workspace package **`browser/form-app`** — a small Vite app (React, styled
  in isolation, no `@tomic/react`, no Loro). Target: < ~100 KB gzipped.
- Shared package **`@tomic/form-renderer`** (`browser/form-renderer/`) — pure React
  components that take a **plain JSON form definition** + `onSubmit` callback. No
  store dependency. Used by both `form-app` (published) and the data-browser
  (preview mode), satisfying the "reuse embedded rendering for preview" requirement.
- `server/build.rs` already builds the browser workspace and embeds
  `data-browser/dist`; extend it to also embed `form-app/dist` under a
  `form-assets/` prefix in the same `static_files` map.

### 3. Server serves a denormalized "form definition JSON", not JSON-AD

`GET /form/:id/definition` walks the Form → pages → fields graph server-side (with
server-agent read), gates on published state, and emits one denormalized JSON
document (pages with fields inlined, short key names, validation rules included).
The runtime never parses JSON-AD or resolves subjects. This also means the form
resources themselves **do not need public read rights** — publish state is a
property, not a rights change, and the submissions table stays private.

### 4. Schema lives in `lib/defaults/forms.json`

Same pattern as `lib/defaults/table.json`: JSON-AD array of Class/Property
resources under `https://atomicdata.dev/...`, imported in `lib/src/populate.rs`.
TS constants regenerated with `@tomic/cli` (`ad-generate ontologies`) into
`browser/lib/src/ontologies/`.

### 5. Submissions reuse the existing Table feature end-to-end

The "New Form" flow mirrors `NewTableDialog.tsx`: create a data **Class** (one
Property per question, added to the drive's default ontology), create a **Table**
with `classtype` = that class, create the **Form** resource pointing at both.
Submission rows are children of the table with `isA` = data class — exactly what
`useTableData.ts` queries. Results-in-a-table then costs nothing.

---

## Data model

Prefix all new subjects `https://atomicdata.dev/classes/form/...` and
`https://atomicdata.dev/properties/form/...` to keep the namespace tidy.

### Form (class)

| property           | type                          | notes                                          |
| ------------------ | ----------------------------- | ---------------------------------------------- |
| `name`*            | String                        |                                                |
| `form-data-class`* | Resource\<Class>              | the generated submission class                 |
| `form-target-table`* | Resource\<Table>            | where submissions land                         |
| `form-pages`*      | ResourceArray\<FormPage>      |                                                |
| `published-at`     | Timestamp                     | reuse existing `published-at`; absent = unpublished |
| `form-settings`    | JSON                          | progress bar on/off, confirmation message, etc. |
| `form-styling`     | JSON                          | phase 6: colors, fonts, logo                   |

Publish state = `published-at` set/unset. Scheduled unpublish (phase 7) adds
`form-close-at`.

### FormPage (class)

`name`, `form-fields`* (ResourceArray — mixed field + layout resources; no
classtype since multiple class-types aren't supported), `form-conditions`
(phase 6), `cover-image`, `image-position`.

### FormField (class) — one class, type as enum property

Deviation from the research sketch (which used a generic class + per-type sibling
classes): use **one `FormField` class** with a `form-field-type` string enum
(`short-text`, `long-text`, `email`, `number`, `date`, `datetime`, `checkbox`,
`radio`, `multi-select`, …) and a `form-field-options` JSON property for
type-specific settings (placeholder, min/max, options list, likert labels…).

Rationale: per-type classes (`FormTextField`, `FormLikertField`, …) each need their
own Class + Property resources, migrations when options change, and the builder
must swap `isA` when the user changes a question's type — a very common action.
A tagged JSON options bag keeps type-switching a single property write. The
denormalized definition JSON hides this from the renderer either way. Validation
of the options bag lives in one Rust + one TS module.

Common properties: `name`*(the question label), `description` (helper text),
`form-maps-to`* (Resource\<Property> on the data class), `required` (Boolean),
`form-field-type`* (String), `form-field-options` (JSON), `form-conditions`
(phase 6).

### Layout elements

`FormHeading` (`name`), `FormParagraph` (`description` markdown), `FormBanner`
(phase 6), `FormRow` (phase 6, nested `form-fields`). These sit in the same
`form-fields` array; the definition serializer emits them as non-input blocks.

### FormCondition (phase 6)

As per research: `field` (Resource\<FormField>), `operator` (enum: equals /
not-equals / contains / greater-than / less-than), `value` (JSON). Stored on
fields and pages under `form-conditions` (AND semantics).

### Field type → datatype mapping

| field type            | Property datatype                | notes                          |
| --------------------- | -------------------------------- | ------------------------------ |
| short/long text, email | `string`                        | email adds a validation rule   |
| number                | `float` (or `integer` option)    |                                |
| date / datetime       | `date` / `timestamp`             |                                |
| checkbox              | `boolean`                        |                                |
| radio                 | `string` (`allowsOnly` via SelectProperty pattern later) |
| multi-select          | `resourceArray` of Tags **or** JSON string array — decide in phase 2; JSON array is simpler and matches how the definition JSON works |

---

## Phase 1 — Schema + ontology plumbing

Deliverable: form classes exist on every server; TS constants available.

- [ ] `lib/defaults/forms.json` with the classes/properties above (phase-1 subset:
      Form, FormPage, FormField, FormHeading, FormParagraph + properties).
- [ ] Import in `lib/src/populate.rs` next to `table.json` (~line 273).
- [ ] Add subject constants to `lib/src/urls.rs`.
- [ ] Ask/wait for human to create the ontology on atomicdata.dev (agents can't do this currently) (Needed for TS generation).
- [ ] Regenerate TS ontologies: `cd browser/lib && pnpm generate-ontologies`.
- [ ] Doc page in `docs/` describing the Form data model (public spec surface).
- [ ] Test: `cargo test -p atomic_lib` populate round-trip (classes resolvable
      after `populate_default_store`).

## Phase 2 — Form builder in the data-browser

Deliverable: create and edit a form with basic fields; submissions class/table
wired up; no public runtime yet.

- [ ] **New > Form**: `NewFormDialog` under
      `components/forms/NewForm/CustomCreateActions/CustomForms/`, registered like
      `NewTableDialog`. On create: data Class (into default ontology, same logic as
      `NewTableDialog.tsx:54-75`) → Table (`classtype` = class, parent = form or
      folder) → Form resource (one starter page).
- [ ] **FormBuilderPage** as a lazy chunk (`src/chunks/FormBuilder/`, route
      registered in `views/ResourcePage.tsx` switch on the new class) — follow the
      `TablePage` chunk pattern so the builder doesn't bloat the main bundle.
- [ ] Builder UI: page list sidebar; field list per page; add/reorder/delete fields
      (reuse drag/drop + input components from `components/forms/`); field settings
      panel (label, helper, placeholder, required, min/max, default, options).
- [ ] **Property sync**: creating a field creates the mapped Property on the data
      class (`form-maps-to`); renaming a field updates the Property's name;
      deleting a field keeps the Property (data preservation) but unlinks it.
      Encapsulate in a `useFormFieldPropertySync` hook — this is the trickiest
      invariant in the builder.
- [ ] Field types (must-have set): short text, long text, email, number, date,
      datetime, checkbox, radio group, multi-select checkboxes. Non-input: heading,
      paragraph.
- [ ] Publish/unpublish toggle writing `published-at` (UI only enforces; server
      enforcement lands in phase 3).
- [ ] E2E spec: create form via New > Form, add fields of each type, reload,
      verify persistence. (Uses the standard `test-utils.ts` `before` hook.)

## Phase 3 — Submission pipeline (server)

Deliverable: `POST` a JSON submission against a published form; row appears in the
table. Testable with `curl` before any runtime exists.

- [ ] `server/src/handlers/form.rs` with two handlers, registered in
      `routes.rs::config_routes` **before** the catch-all `ANY` routes:
  - `GET /form/{id}/definition` — resolve form subject from `{id}` (see below),
    check `published-at`, walk the graph with server-agent read, emit denormalized
    definition JSON. `404` if unknown, `403`/`410` if unpublished.
  - `POST /form/{id}/submit` — body = `{ "values": { "<propertySubject>": <json> } }`.
    Validate → create submission resource (parent = target table, `isA` = data
    class) via server-side `Resource` + `save()` (CommitBuilder → Loro at sign
    time, so Loro state + datatype tags are handled by existing infra).
- [ ] **Form id ↔ subject resolution**: form subjects are `did:ad:{genesis}` —
      too ugly for a share URL. On first publish, generate a short random slug
      (e.g. 10 chars base58), store it as `form-publish-id` on the Form, and index
      `publish-id → subject` in redb (small map in `Tree::PluginMeta`, like known
      peers). Route param is the slug.
- [ ] **Server-side validation** (`lib` or `server` module, unit-tested in
      isolation): required, min/max length + value, email/URL shape, option
      membership for radio/multi-select, datatype coercion. Declarative rule set
      derived from the same field definitions the definition JSON exposes, so the
      TS renderer (phase 4) implements the identical rules from the identical data.
- [ ] Reject when: form unpublished, unknown property, extra properties, table or
      data class missing.
- [ ] Basic abuse control now (cheap): per-IP token bucket on the submit route +
      an auto-added honeypot field rejected server-side when filled. Captcha is
      phase 6.
- [ ] Integration test (`server/src/tests.rs` or a `--test forms` file): populate,
      create form + table via server agent, publish, GET definition, POST valid +
      invalid submissions, assert row exists / errors are correct, unpublish →
      `410`.

## Phase 4 — Published form runtime + `/form/:id` route

Deliverable: the full must-have loop — share a link, anyone submits without an
account.

- [ ] **`@tomic/form-renderer`** (`browser/form-renderer/`): React components
      rendering a definition JSON — pages, all phase-2 field types, layout blocks,
      client-side validation mirroring phase-3 rules, multi-page navigation,
      submit + success/error states. Props: `definition`, `onSubmit`, later
      `theme`. No `@tomic/lib` dependency.
- [ ] **`browser/form-app`**: Vite app mounting the renderer; reads a
      `window.__FORM_DEFINITION__` global (injected by the server) with a fetch
      fallback to `/form/:id/definition`; POSTs to `/form/:id/submit`.
- [ ] **`GET /form/{id}` route** (HTML): follow `single_page_app.rs` — HTML shell
      template with CSP nonce, inject the definition JSON inline (kills the fetch
      waterfall), script tags pointing at embedded `form-assets/*` hashed bundles.
      Unpublished/unknown → minimal "not available" page.
- [ ] **`build.rs`**: build `form-app` in the existing browser build step; copy
      `form-app/dist` into the embedded asset map under `form-assets/` (brotli
      precompression comes free from the existing `precompress_assets`).
- [ ] **Vite dev story**: in dev, `/form/:id` on :9883 serves the embedded build;
      for HMR iteration run `form-app` dev server directly against
      `localhost:9883` endpoints (CORS already permissive for GET; verify POST).
      Document in `form-app/README.md`.
- [ ] **Preview mode** in the builder: data-browser imports `@tomic/form-renderer`,
      builds the definition JSON client-side from the resources (share the
      serializer shape with the Rust one via a fixture test), renders in a dialog
      or split pane with submissions disabled.
- [ ] E2E spec: build + publish a form, open `/form/:slug` in a **fresh
      unauthenticated context**, fill and submit, then as the owner verify the row
      in the table view. This is the flagship e2e for the whole feature.

## Phase 5 — Results & lifecycle polish

Deliverable: pleasant creator experience around the collected data.

- [ ] Form page shows submission count + link to the table; empty states.
- [ ] "Open form" / "Copy link" affordances; QR code (component exists for Iroh
      pairing — reuse).
- [ ] Unpublish keeps the definition endpoint returning `410` with a friendly
      closed-message page.
- [ ] Results summary view (per-question aggregates: bar chart for choice fields,
      histogram for numbers, list for text) as a tab next to the table view.
      Client-side aggregation over the collection is fine at expected volumes.
- [ ] Delete-form flow: what happens to table + data class (keep by default,
      offer cascade).

## Phase 6 — Should-haves (each independently shippable)

Rough priority order:

1. **Embedding**: `<iframe>` snippet; `/form/:id?embed=1` drops the page chrome;
   set `frame-ancestors` CSP appropriately on that route (currently forms route
   would inherit none); `postMessage` height auto-resize.
2. **Captcha**: ALTCHA-style proof-of-work (self-hosted, no third party, fits the
   privacy stance) — server issues challenge in the definition response, verifies
   on submit. Keep the verifier behind a trait so Turnstile/hCaptcha can slot in.
3. **Private links**: one-time codes, generated in bulk by the owner, stored
   hashed in redb keyed by form; `?code=` checked + atomically consumed on submit.
4. **More field types** (each = enum value + options schema + renderer + validator +
   datatype mapping): phone, URL, currency, dropdown multi-select, likert, rating,
   picture choice, file upload (needs upload path for anonymous users — scoped,
   size-limited `POST /form/:id/upload` writing into the commit as a blob), choice
   matrix, table input, location/address.
5. **Branching**: FormCondition resources; evaluator implemented once in TS
   (renderer + preview) and once in Rust (server must ignore validation errors on
   hidden fields); shared JSON fixtures keep the two in lockstep.
6. **Styling/theming**: `form-styling` JSON (accent color, background, font, logo,
   corner radius) → CSS variables in the renderer; theming UI in the builder;
   embed inherits.
7. **Progress bar** (trivial once settings exist).

## Phase 7 — Could-haves (sketch only)

- **AI question suggestion**: reuse the AI sidebar infra; given a question label,
  generate `{type, options}` — maps 1:1 onto `form-field-type` +
  `form-field-options`.
- **AI form builder skill**: expose form CRUD as an agent skill.
- **Question randomization**: per-page flag; shuffle in the renderer, seed stored
  in the submission for reproducibility.
- **Dynamic text**: `{{field-shortname}}` interpolation in labels/paragraphs.
- **Partial submissions / drafts**: localStorage in the runtime (no OPFS in the
  embed); resume via draft token in the URL.
- **Scheduled publish/unpublish**: `form-open-at` / `form-close-at` checked by the
  definition + submit handlers — no scheduler needed, just timestamp comparison.

## Open questions

- [ ] Multi-select storage: JSON string-array vs Tag resources + `resourceArray`.
      JSON is simpler and self-contained; Tags integrate with table cell rendering.
      Decide in phase 2 when wiring the table view.
- [ ] Does the submit handler live behind a feature flag (`forms` cargo feature)
      like `vector-search`, or always on? Leaning always-on (it's core product).
- [ ] Definition JSON versioning: add `"version": 1` from day one so the runtime
      can evolve.
- [ ] Subdomain/multi-drive: `{id}` slug is server-global in the redb map; confirm
      that's acceptable vs. scoping per drive.

## Testing summary

| layer                | what                                                        |
| -------------------- | ----------------------------------------------------------- |
| `atomic_lib` unit    | populate round-trip; validation rules; definition serializer |
| server integration   | publish gating, submit happy/sad paths, honeypot, rate limit |
| `form-renderer` unit | field rendering + client validation (vitest, shared fixtures with Rust validator) |
| e2e (Playwright)     | builder CRUD; publish → anonymous submit → row in table     |
