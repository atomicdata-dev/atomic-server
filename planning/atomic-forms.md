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

### 6. The results Table is a child of the Form, not a sibling

Revised in Phase 5 (originally the Form and its target Table were both created
with the same outer `parent` — siblings under whatever folder the user clicked
"New" from). The Table's final `parent` is now the Form's own subject, and it
is reached through a **"Results" tab** inside `FormBuilderPage` rather than
its own sidebar entry.

**Creation order constraint**: `form-target-table` is a required property on
the Form class, so it must be present in the Form's *genesis* commit — the
server rejects a genesis commit missing a required property outright (500,
"Property ... missing. Is required in class Form"). That means the Table's
subject has to exist before the Form's does, which conflicts with wanting the
Table's `parent` to be the Form. `NewFormDialog.tsx` resolves this by
creating the Table first with a temporary `parent` (the same outer `parent`
the Form itself gets), including `form-target-table` in the Form's genesis
`propVals`, then re-parenting the Table to the Form's subject in a follow-up
commit inside `onCreated` (alongside creating the starter page). The Table is
briefly parented outside the Form for one commit but this resolves before the
dialog closes.

Rationale: the table is an implementation detail of "this form's collected
data", not an independent resource someone browses to on its own — nesting it
under the Form keeps the sidebar tree honest about ownership and puts results
one click away from the builder instead of a separate navigation. This mirrors
how Tables already hide their own row children from the sidebar
(`ResourceSideBar.tsx`'s `hideChildren`) — Forms get added to that same list so
the Table doesn't *also* render as a nested sidebar item now that it's a
child (would duplicate the Results tab and confuse drop targeting).

No migration for forms created before this change — Forms is still a beta
feature with only local/dev data in play.

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
| `form-published-at`     | Timestamp                     | |
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

## Phase 1 — Schema + ontology plumbing - DONE

Deliverable: form classes exist on every server; TS constants available.

- [x] `lib/defaults/forms.json` with the classes/properties above (phase-1 subset:
      Form, FormPage, FormField, FormHeading, FormParagraph + properties).
      Namespacing follows table.json's flat style (not the `form/`-path-segment
      style originally sketched above) — see decision note below.
- [x] Import in `lib/src/populate.rs` next to `table.json` (~line 271).
- [x] Add subject constants to `lib/src/urls.rs` (new `// ... for Forms` section).
- [x] Ask/wait for human to create the ontology on atomicdata.dev (agents can't do this currently) (Needed for TS generation).
- [x] Regenerate TS ontologies: `cd browser/lib && pnpm generate-ontologies`.
- [x] Doc page in `docs/` describing the Form data model (public spec surface):
      `docs/src/schema/forms.md`, linked from `SUMMARY.md`.
- [x] Test: `cargo test -p atomic_lib --features db-redb --lib populate_forms_ontology`
      (`lib/src/store.rs`) — populate round-trip, classes resolvable after
      `populate_default_store`. Full suite (224 tests) and `atomic-server` build
      verified green.

**Deviations found during implementation:**

- **Namespacing is flat**, not path-namespaced as drafted in the Data model
  section above — matches every existing ontology bundle (table.json etc.).
  Classes: `classes/Form`, `classes/FormPage`, etc. Properties get a `form-`
  prefix baked into the shortname only where form-specific
  (`form-data-class`, `form-maps-to`, `form-field-type`, ...); generic ones
  stay unprefixed (`required`, `cover-image`, `image-position`,
  `published-at`).
- **`published-at` didn't already exist** anywhere as a shared property (only
  unrelated site-template ontologies used that name) — created fresh as a
  generic, unprefixed `timestamp` property so it stays reusable outside Forms.
- **`form-field-type` and `image-position` are plain `String` properties
  without `allowsOnly`.** The JSON-AD parser requires `allowsOnly` array
  members to be URL-parseable subjects (`lib/src/parse.rs` `try_to_subject`,
  backed by `check_valid_url`), so it can't hold plain enum strings like
  `"short-text"`. The enum values are documented in each property's
  `description` and in `docs/src/schema/forms.md`; enforcement is deferred to
  the application layer (form builder now, Phase 3's server-side validation
  module later) rather than switching to a resource-based enum (which the
  plan explicitly wanted to avoid for `form-field-type`).
- Excluded from Phase 1 (per the plan's own phase-6 tags): `form-styling`
  (Form), `form-conditions` (FormPage, FormField).
- `forms.ts` needed to be manually created in the browser/lib/src/ontologies/ directory (`@tomic/cli` does not work at the moment due to version differences)

## Phase 2 — Form builder in the data-browser - DONE

Deliverable: create and edit a form with basic fields; submissions class/table
wired up; no public runtime yet.

- [x] **New > Form**: `NewFormDialog` under
      `components/forms/NewForm/CustomCreateActions/CustomForms/`, registered like
      `NewTableDialog`. On create: data Class (into default ontology, same logic as
      `NewTableDialog.tsx:54-75`) → Table (`classtype` = class, parent = form or
      folder) → Form resource (one starter page).
- [x] **FormBuilderPage** as a lazy chunk (`src/chunks/FormBuilder/`, route
      registered in `views/ResourcePage.tsx` switch on the new class) — follow the
      `TablePage` chunk pattern so the builder doesn't bloat the main bundle.
- [x] Builder UI: page list sidebar; field list per page; add/reorder/delete fields
      (reuse drag/drop + input components from `components/forms/`); field settings
      panel (label, helper, placeholder, required, min/max, default, options).
- [x] **Property sync**: creating a field creates the mapped Property on the data
      class (`form-maps-to`); renaming a field updates the Property's name;
      deleting a field keeps the Property (data preservation) but unlinks it.
      Encapsulate in a `useFormFieldPropertySync` hook — this is the trickiest
      invariant in the builder.
- [x] Field types (must-have set): short text, long text, email, number, date,
      datetime, checkbox, radio group, multi-select checkboxes. Non-input: heading,
      paragraph.
- [x] Publish/unpublish toggle writing `published-at` (UI only enforces; server
      enforcement lands in phase 3).
- [x] E2E spec: create form via New > Form, add fields of each type, reload,
      verify persistence. (Uses the standard `test-utils.ts` `before` hook.)

## Phase 3 — Submission pipeline (server) - DONE

Deliverable: `POST` a JSON submission against a published form; row appears in the
table. Testable with `curl` before any runtime exists.

- [x] `server/src/handlers/form.rs` with two handlers, registered in
      `routes.rs::config_routes` **before** the catch-all `ANY` routes:
  - `GET /form/{id}/definition` — resolve form subject from `{id}` (see below),
    check `published-at`, walk the graph with server-agent read, emit denormalized
    definition JSON. `404` if unknown, `403`/`410` if unpublished.
  - `POST /form/{id}/submit` — body = `{ "values": { "<propertySubject>": <json> } }`.
    Validate → create submission resource (parent = target table, `isA` = data
    class) via server-side `Resource` + `save()` (CommitBuilder → Loro at sign
    time, so Loro state + datatype tags are handled by existing infra).
- [x] **Form id ↔ subject resolution**: form subjects are `did:ad:{genesis}` —
      too ugly for a share URL. On first publish, generate a short random slug
      (e.g. 10 chars base58), store it as `form-publish-id` on the Form, and index
      `publish-id → subject` in redb (small map in `Tree::PluginMeta`, like known
      peers). Route param is the slug.
- [x] **Server-side validation** (`lib` or `server` module, unit-tested in
      isolation): required, min/max length + value, email/URL shape, option
      membership for radio/multi-select, datatype coercion. Declarative rule set
      derived from the same field definitions the definition JSON exposes, so the
      TS renderer (phase 4) implements the identical rules from the identical data.
- [x] Reject when: form unpublished, unknown property, extra properties, table or
      data class missing.
- [x] Basic abuse control now (cheap): per-IP token bucket on the submit route +
      an auto-added honeypot field rejected server-side when filled. Captcha is
      phase 6.
- [x] Integration test (`server/src/tests.rs` or a `--test forms` file): populate,
      create form + table via server agent, publish, GET definition, POST valid +
      invalid submissions, assert row exists / errors are correct, unpublish →
      `410`.

**Implementation notes:**

- `server/src/forms.rs` (moved out of `lib/src/forms.rs` — this logic is
  server-only, not part of the reusable `atomic_lib` API) holds the pure
  definition-builder, validation, and slug mint/resolve logic;
  `server/src/handlers/form.rs` is thin HTTP glue with its own plain-JSON
  `FormApiError` (the runtime never parses JSON-AD, per decision #3).
- Slug bootstrapping: rather than reopening phase 2's `PublishToggle` (which has
  no server touchpoint), `{id}` resolves either to an existing slug in the redb
  index or to the form's own `did:ad:{genesis}` pure_id as a fallback. The first
  successful `GET .../definition` for a published, slug-less form mints and
  persists one — see "Slug bootstrapping decision" above, which is now the
  answer to the open question below on definition-JSON-vs-slug-on-publish.
- Resolves two of the "Open questions" below: the submit handler is **always
  on** (no `forms` cargo feature), and the `{id}` slug map is intentionally
  server-global in redb (matches how `did:ad:` subjects already work).
- Verified with `cargo test -p atomic_lib --features db-redb --lib forms::` (9
  new tests), `cargo test -p atomic-server --lib` (41 tests incl.
  `form_submission_flow`), and a manual pass against a live `cargo run` server +
  browser-built/published form: `GET` by DID and by minted slug, valid submit
  (`201`, row lands in the table), honeypot rejection (`400`), invalid-email
  validation (`400`), and pre-publish/unpublished gating (`410`).

## Phase 4 — Published form runtime + `/form/:id` route - DONE

Deliverable: the full must-have loop — share a link, anyone submits without an
account.

- [x] **`@tomic/form-renderer`** (`browser/form-renderer/`): React components
      rendering a definition JSON — pages, all phase-2 field types, layout blocks,
      client-side validation mirroring phase-3 rules, multi-page navigation,
      submit + success/error states. Props: `definition`, `onSubmit`, `preview`.
      No `@tomic/lib` dependency; ships its own `style.css`.
- [x] **`browser/form-app`**: Vite app mounting the renderer; reads a
      `window.__FORM_DEFINITION__` global (injected by the server) with a fetch
      fallback to `/form/:id/definition`; POSTs to `/form/:id/submit`.
- [x] **`GET /form/{id}` route** (HTML): follows `single_page_app.rs` — HTML shell
      template with CSP nonce, definition JSON injected inline (kills the fetch
      waterfall), script tags pointing at embedded `form-assets/*` hashed bundles.
      Unpublished/unknown → minimal dependency-free "not available" page (410/404).
- [x] **`build.rs`**: builds `form-app` as part of the existing `pnpm -r build`
      step (topologically after `form-renderer`, its workspace dependency); copies
      `form-app/dist` into the embedded asset map under `form-assets/` (brotli
      precompression comes free from the existing `precompress_assets`). Backfills
      `form-assets/` even when the main JS build is skipped
      (`ATOMICSERVER_SKIP_JS_BUILD=true`, set repo-wide by `.envrc`) so
      `include_str!("../../assets_tmp/form-assets/index.html")` always has
      something to compile against.
- [x] **Vite dev story**: in dev, `/form/:id` on :9883 serves the embedded build;
      for HMR iteration `form-app`'s own `pnpm dev` (`:6748`) fetches/posts
      directly against `:9883` (CORS is `Cors::permissive()`). Documented in
      `form-app/README.md`.
- [x] **Preview mode** in the builder: `FormPreviewDialog.tsx` imports
      `@tomic/form-renderer`; `buildFormDefinition.ts` is a hand-mirrored TS port
      of `build_form_definition`/`build_block` (same shape, not a shared fixture —
      see deviation below), rendered in a dialog with `preview` disabling submit.
- [x] E2E spec (`browser/e2e/tests/forms-submission.spec.ts`): build + publish a
      form, open `/form/:did` in a **fresh unauthenticated context** (`browser.
      newContext()`), fill and submit, then as the owner verify the row in the
      table view. Plus an unpublished-form → 410 case. Both green.

**Deviations / notes found during implementation:**

- **No shared TS/Rust fixture test** for the definition serializer (the plan's
  "share the serializer shape... via a fixture test"). `buildFormDefinition.ts`
  mirrors `server/src/forms.rs` by hand instead — same field names/shapes, kept in
  sync manually. Worth adding a fixture-based cross-check later if the two
  drift.
- **Found and fixed a real bug while writing the e2e spec**: `FormRenderer`'s
  `<label>` and its `<input>` shared the exact same `id` (the label used it for
  `aria-labelledby` on radio/multi-select groups; `FieldInput` used the same
  value for the actual input's `id`). Duplicate IDs silently broke
  `htmlFor`/label association. Fixed by giving the label its own `${inputId}-label`
  id, threaded through `FieldInput` as a separate `labelId` prop.
- **Local dev gotcha (not a code bug)**: a local server whose on-disk store
  predates a newly-added default property (e.g. `form-publish-id`, added in
  Phase 3) will 404 trying to resolve it, because `populate_default_store` only
  re-runs on an already-initialized store when `ATOMIC_REPOPULATE_DEFAULTS=true`
  is set. Hit this manually verifying the flow; restarting with that env var
  fixed it. Worth remembering for anyone else's stale local dev DB.
- The Phase 2 e2e (`forms.spec.ts`, "persist across reload") was independently
  found failing/flaky on `develop`-equivalent code with none of this phase's
  changes applied (verified by stashing `FormBuilderPage.tsx` and re-running) —
  a pre-existing outbox/sync race, not a Phase 4 regression. Out of scope here.

## Phase 5 — Results & lifecycle polish

Deliverable: pleasant creator experience around the collected data. The
results *summary/aggregate view* (bar charts, histograms) is deferred to
**Phase 5b** below — this phase only wires up the raw submissions grid.

- [ ] Architecture change: results Table becomes a **child** of the Form
      (decision #6 above), reached via a **"Results" tab** in
      `FormBuilderPage` next to the existing field-builder view (which becomes
      a "Fields" tab). `NewFormDialog.tsx` creates the Form first, then the
      Table parented to it (mirrors how the starter page is already created
      in `onCreated`). `ResourceSideBar.tsx`'s `hideChildren` gets
      `forms.classes.form` added.
- [x] Results tab renders the existing `TableResource` component
      (`chunks/TablePage/TableResource.tsx`) against the target table — full
      grid functionality for free, no new table UI.
- [ ] ~~Submission count (badge on the "Results" tab) + custom empty state~~
      **Dropped during implementation.** A standalone `useSubmissionCount`
      hook (`useCollection` with the same `parent`+`isA` filter
      `useTableData` uses) reliably returned a stale `0` for tables that
      genuinely had rows — confirmed with fresh, never-before-queried
      tables, so it wasn't a caching artifact from manual testing. The
      *same* `TableResource`/`useTableData` pipeline, used directly (e.g.
      navigating straight to the table's own page), correctly showed the
      rows every time. ~~Root cause not fully isolated~~ **Root-caused and
      fixed later — see "Submission rows invisible until reload" below.**
      The tab still just renders `TableResource` directly (which has its
      own, already-correct empty grid); a count/badge can now be revisited.
- [x] **Bug: submission rows invisible until reload (fixed).** Reported as
      "form results tables don't show their rows unless I refresh"; also
      explains the stale `useSubmissionCount` above. Two independent causes:
      1. **Server** (`server/src/handlers/form.rs::submit_form`): rows were
         created via `Resource::new_instance` + `save()`, producing an
         `internal:/response/{id}` subject with **no `drive` propval**. The
         CommitMonitor's drive-scoped fan-out routes a commit only to
         subscribers of the resource's `drive` — with none, the commit
         reached no WS client, so connected browsers never heard about new
         submissions (client-created rows always get `drive` stamped at
         genesis; this server-agent path skipped both that and the
         rights-path safety net in `commit.rs`). The `internal:` subject
         also resolved to a different string per transport (`http://…` on
         WS push vs `internal:/…` via drive sync), double-indexing the same
         row in OPFS. Fix: stamp `drive` (from the target table, falling
         back to the form) with `set_unsafe` and create the row via
         `save_as_genesis()` so it's a canonical `did:ad:` resource like
         every other table row.
      2. **Client** (`TableResource.tsx`): the grid's frozen
         `baselineMemberCountRef` (which exists so this-session typed rows
         never remount mid-edit) never grew when members were added
         *remotely* — the collection's live-membership bridge dutifully
         appended the row (`totalMembers` grew) but the grid kept rendering
         the frozen count. Fix: when the collection grows beyond
         `baseline + this-session materialized rows`, rebase the session
         onto the grown collection (same move as the existing queryKey
         rebase). Applies to any table receiving rows from another
         client/agent, not just form results.
- [x] "Open form" / "Copy link" affordances; QR code via a new `qrcode`
      dependency (none existed in the repo). Publishing mints the share slug
      immediately (one `GET /form/{did}/definition` call right after
      `published-at` is set) instead of waiting for a visitor's first request
      to mint it lazily.
- [ ] Unpublish keeps the definition endpoint returning `410` with a friendlier,
      form-specific closed-message page (copy + light styling pass on the
      existing dependency-free `not_available_page`).
- [x] Delete-form flow: `Resource.destroy()` never cascades, so "keep table +
      data class by default" already happens for free. Add an explicit
      cascade option in a form-specific delete dialog: also destroy the
      table + its submission rows (not the generated data Class/Properties).

## Phase 5b — Results summary view - DONE

- [x] Results summary view (per-question aggregates: bar chart for choice fields,
      histogram for numbers, list for text) as a third top-level **"Summary"
      tab** in `FormBuilderPage`, next to Fields and Results.

**Architecture (decided during implementation, revising the original
"client-side aggregation over the collection" sketch):**

- Client-side aggregation over all rows was rejected (fetching every row into
  the browser just to count it is wasteful). A dedicated
  `GET /form/:id/summary` endpoint was also considered but rejected: it would
  need its own auth check, while a **ClassExtender on the Form class** runs
  inside the rights-checked resource-GET path — authorization comes for free
  (`for_agent` = requesting agent, checked by `check_read` before extenders
  run; the row query re-runs as the same agent).
- `forms::build_form_summary` (`server/src/forms.rs`) reuses the
  Phase 3 definition walk for field order/metadata, queries rows once
  (`parent` = target table AND `isA` = data class, capped at 10 000, drive =
  form's `drive` propval falling back to `drive_prefix_from_subject`), and
  aggregates per field type: option counts for radio/multi-select (configured
  order, zero-filled, unknowns folded into "Other"; multi-select iterates the
  `Value::Json` arrays natively), checked/unchecked for checkbox, nice-width
  (1·2·5×10ⁿ) histogram bins + min/max/mean for number, and a capped
  (100-answer) sample for text/email/date/datetime. Unit-tested alongside the
  Phase 3 `forms::` tests.
- `server/src/plugins/form.rs` (chatroom-extender pattern) sets the result as
  an **ephemeral** `form-submission-summary` propval (new default property,
  datatype JSON) on the served resource — never persisted, never part of the
  Form's Loro doc. Aggregation errors are logged and the Form is served
  without the prop.
- **Caveats accepted:** the extender only runs on the plain-HTTP GET path.
  The data-browser's OPFS-first store skips that path when it has local data
  (`store.ts` "trust OPFS + live WS updates"), and the WS GET frame serves
  raw Loro state. Extenders also don't run on live commits, so updates
  arrive via an explicit **Refresh button**, not realtime.
- **Found during verification: extender propvals must not pass through the
  JS store at all.** Two real bugs surfaced when `SummaryTab` initially read
  the summary via `fetchResourceFromServer` + `resource.get()`:
  1. **Permanent staleness**: hydration "heals" JSON-AD-only props into the
     resource's local LoroDoc (`resource.ts` `getLoroDoc`), and every later
     hydration rebuilds propvals *from Loro* — so the summary stayed pinned
     to its first-fetched value no matter how often it was re-fetched.
  2. **Commit leak (the exact risk the plan flagged)**: the healed-in
     summary op was exported and **signed into a later rename commit**
     (verified by decoding the commit's `loroUpdate` — it contained
     `form-submission-summary`), persisting a stale server-computed value
     into the form's real CRDT state.
  Fixes: `SummaryTab` now fetches the JSON-AD **directly** (same
  `/did?subject=` + `signRequest` scheme as `Client.fetchResourceHTTP`) and
  keeps the summary in component state — the store never sees it. And
  `@tomic/lib`'s `Resource` got an `isCacheOnlyProp` guard (alongside
  `lastCommit`/`createdAt`) so `form-submission-summary` can never be seeded
  or healed into a local LoroDoc even when a Form is HTTP-fetched
  incidentally. Leak regression-tested: post-fix rename commit delta is 273
  bytes and free of the prop (contaminated one was 2.6 KB with it). Note:
  the chatroom extender's `messages`/`nextPage` props have the same
  theoretical exposure via the heal pass — untouched here, worth a look if
  chatrooms ever misbehave after HTTP fetches.
- UI: `chunks/FormBuilder/Summary/` — `SummaryTab` (fetch + refresh +
  response count), `ChoiceBars` / `Histogram` / `AnswerList` (hand-rolled
  single-hue styled-components charts; no chart dependency). Covered by an
  extended `forms-submission.spec.ts` (summary after first submission,
  Refresh picks up the second).

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
- [x] Does the submit handler live behind a feature flag (`forms` cargo feature)
      like `vector-search`, or always on? **Resolved in phase 3: always on.**
- [x] Definition JSON versioning: add `"version": 1` from day one so the runtime
      can evolve. **Done in phase 3** (`FormDefinition.version`).
- [x] Subdomain/multi-drive: `{id}` slug is server-global in the redb map; confirm
      that's acceptable vs. scoping per drive. **Resolved in phase 3: server-global,
      same as `did:ad:` subject resolution.**

## Testing summary

| layer                | what                                                        |
| -------------------- | ----------------------------------------------------------- |
| `atomic_lib` unit    | populate round-trip; validation rules; definition serializer |
| server integration   | publish gating, submit happy/sad paths, honeypot, rate limit |
| `form-renderer` unit | field rendering + client validation (vitest, shared fixtures with Rust validator) |
| e2e (Playwright)     | builder CRUD; publish → anonymous submit → row in table     |
