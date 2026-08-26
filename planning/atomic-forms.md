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
      class (`form-maps-to`); renaming a field re-derives the Property's
      `shortname` unless the user pinned one in the field settings panel
      (see [form-field-shortnames.md](./form-field-shortnames.md) — the
      Property carries no `name`, the Label lives on the FormField);
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
  **Superseded**: the redb slug map is slated to be replaced by generic
  ShortLink resources — see [`shortlinks.md`](./shortlinks.md).
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

[x] **Embedding** — DONE. `<iframe>` snippet with a copy button in a new
   "Embed" tab inside `ShareLinkPanel`'s popover (alongside the existing
   Link tab); `?embed=1` drops the full-viewport shell styling client-side;
   `frame-ancestors` opened up; `postMessage` height auto-resize.

- **`frame-ancestors *`, not an allow-list.** Published forms already have
    no auth/rights gate — anyone with the share link can view and submit —
    so allowing any site to iframe that same public content adds no new
    trust boundary. Applied unconditionally to `form_page` (not gated on
    `?embed=1`, which the server never parses — see below), and also added
    to `not_available_page` (previously had **no** CSP header at all), so a
    stale/unpublished embed shows the friendly closed-form card instead of a
    browser-blocked blank frame.
- **`?embed=1` is read client-side only**, via
    `new URLSearchParams(window.location.search)` in `form-app/src/api.ts`'s
    `isEmbedMode()` — no `web::Query` extractor needed server-side, keeping
    decision #2's "runtime stays tiny" property. `App.tsx` tags `<html>`
    with an `atomic-form-embed` class and passes `embed` into `FormShell`
    (`atomic-form-shell-embed`), and `form-renderer`/`form-app` CSS drop the
    `min-height: 100%`/`100vh` chain under those classes — otherwise the
    `ResizeObserver` height report reflects the forced-full-viewport height
    instead of the form's real content height.
- **Resize protocol**: `form-app/src/embedResize.ts` posts
    `{ type: 'atomic-form-resize', height }` to `window.parent` via `'*'`
    (arbitrary embedding origin, no sensitive payload — same choice the
    existing `pluginRPC.tsx` postMessage calls make). The copied snippet's
    own inline listener matches on `event.source === iframe.contentWindow`
    (not the iframe's `id`, which only exists to make `getElementById` easy)
    so multiple embedded forms on one page don't cross-resize each other.
- **Found while writing the e2e test, not a product bug**: `frame-ancestors
    *` does not cover `about:blank` embedders per spec (Chrome: "'*' matches
    only URLs with network schemes ... The scheme 'http:' must be added
    explicitly"), and Chrome's Local Network Access checks separately block
    a synthetic/routed origin from framing a genuine `localhost` target. A
    real embedding site (served over http/https) hits neither restriction —
    only `page.setContent()`/`page.route()`-based test harnesses do. Fixed
    by having the e2e spec spin up a real local `http` server to host the
    wrapper page (`forms-submission.spec.ts`).
- Covered by `forms-submission.spec.ts` ("embed snippet renders
    chrome-less and auto-resizes in an iframe": publish, read the exact
    snippet out of the Embed tab's `CodeBlock`, host it on a real local HTTP
    server, verify chrome-less rendering + resize + anonymous submit from
    inside the iframe) and `cargo test -p atomic-server --lib` (CSP header
    assertions in `form_submission_flow` for both the published and
    unpublished HTML page).
[x] **Captcha** — DONE. ALTCHA proof-of-work (self-hosted, no third party),
   always-on for every published form (no per-form toggle: solving is
   invisible background CPU work, so there's little reason to opt out).
   Verifier lives behind the `CaptchaVerifier` trait
   (`server/src/captcha.rs`, on `AppState`) so Turnstile/hCaptcha can slot
   in later (async `verify` for their HTTP round-trips).
- **Official libraries, not hand-rolled**: the `altcha` crate
    (altcha-org's own Rust implementation of PoW v2: `create_challenge` /
    `verify_solution` / `solve_challenge` — the latter also powers the
    tests) and the `altcha` npm widget v3 (~34 kB gzipped web component;
    form-app bundle now 144 kB gzipped). What the libraries *don't*
    ship, `AltchaVerifier` adds: an HMAC secret (random, persisted in redb
    `Tree::PluginMeta` like the publish-slug map, so restarts don't
    invalidate in-flight solutions) and one-time-use replay protection (an
    in-process consumed-nonce map with lazy TTL pruning, same layer as the
    submit rate limiter).
- **Deviation from the sketch above** ("server issues challenge in the
    definition response"): the widget's native flow is a challenge URL it
    fetches itself, so there's a publish-gated `GET /form/{id}/challenge`
    endpoint instead (stateless to issue — challenges are HMAC-signed, no
    bookkeeping until verify). The definition response carries
    `captcha: { provider, challengeUrl }` so the runtime knows what to
    render; builder previews get no `captcha` field and render no widget.
- **Difficulty**: PBKDF2/SHA-256, cost 5000, deterministic counter
    1000–4000 (below the docs' 5000–10000 so mid-range phones solve in a
    couple of seconds — deterrence comes from combining with the rate
    limiter + honeypot). Challenges expire after 1 h. Under `cfg(test)`
    difficulty drops to near-zero so debug-build tests solve natively.
- **Client**: `FormRenderer` renders `<altcha-widget auto="onload">`
    (visible checkbox card above Submit, mounted-but-hidden on earlier
    pages so solving starts at page load), disables Submit until the
    widget's `statechange` reports `verified`, and rides the solved payload
    to `onSubmit` under `CAPTCHA_VALUE_KEY` (honeypot pattern); form-app
    lifts it into the body's top-level `altcha` field. The `altcha` package
    is a dependency of **form-app only** (side-effect import registers the
    element); form-renderer ships a hand-written JSX declaration
    (`altcha-widget.d.ts`) so the data-browser preview never pulls in the
    solver. Widget card themed via `--altcha-*` → `--atomic-form-*` CSS-var
    mapping in form-renderer's `style.css`.
- **CSP**: `form_page`'s header gained `worker-src 'self' blob:` — the
    widget's single-file bundle spawns its solver Web Workers from blob:
    URLs.
- Covered by: `cargo test -p atomic-server --lib captcha::` (6 tests:
    roundtrip, replay, tamper, foreign-secret, expiry, malformed),
    `form_submission_flow` (definition carries config; solve → 201;
    missing payload → 400; replay → 400), and `forms-submission.spec.ts`
    (widget visible, Submit gated on background solve, anonymous + embed
    submits flow through it).
[x] **Private links** — DONE. One-time invite codes modeled as **resources,
   children of the Form** — not a redb side-table (consistent with how
   submission rows already work, and reuses querying/commits/rights/sync
   instead of a second storage system).
  - **`FormInviteCode` class**: `form-code` (String, required, the code
      value) + `used-at` (Timestamp, unset = unused). `parent` = the Form.
      A `used-by` link to the submission row was considered and deferred
      (anonymity implications). Revoke = `destroy()`.
  - **Codes stored plaintext, not hashed.** Hierarchy rights already
      restrict reads to form editors (children of the Form are private), and
      an attacker who can read the DB has all form data anyway — hashing
      protected nothing meaningful while blocking re-export. The definition
      endpoint can't leak codes: it walks `form-pages`, not children.
  - **Access mode is a Form property**: public ("anyone with the link",
      current behavior) XOR invite-only. Mixed mode is deliberately not
      supported — a still-working public link would void the feature's
      guarantees (controlled audience, one response per person). When
      invite-only, **the definition endpoint also requires a valid code**,
      otherwise the questions leak to anyone with the URL.
  - **Lookup**: query `form-code = X` via the **basic-path** `PropValSub`
      index alone, then verify the hit's `parent` is the expected form. Do
      NOT query `parent + isA + form-code` — the multi-filter complex path
      lazily persists a watched query per distinct filter, i.e. one per code
      value ever looked up (`Tree::WatchedQueries` bloat).
  - **Validation vs consumption**: validate at definition-fetch time
      *without* consuming (used/revoked/unknown → rejected before the visitor
      fills anything in); consume atomically at submit. Commits are not
      compare-and-swap, so the submit handler serializes check-and-consume
      with an in-process per-form mutex (single server process; the rate
      limiter already lives at that layer). Inside the mutex, mark `used-at`
      first, then create the submission row — the reverse order allows double
      submission if row creation races/fails.
  - **Bulk generation** happens client-side via normal commits (reuses all
      existing machinery; owner-signed, so provenance is honest). N codes = N
      signed genesis commits through the outbox — cap a batch at a few hundred
      and measure before considering a server-side bulk endpoint.
  - The consumption commit fans out over WS like any other, so owner-facing
      used/unused state updates in realtime with zero extra plumbing.
  - Share-slug resolution is unrelated to codes and moves to ShortLinks —
      see [`shortlinks.md`](./shortlinks.md).
  - **UI**: lives in the Settings tab, now divided into collapsibles like the
      app settings page (`SettingsGroup`/`SettingsSection`): the existing
      appearance settings under **Appearance**, private links under
      **Form access** (`FormAccessSection.tsx`).

  **Implementation notes (all of the above shipped as designed; deviations
  and specifics below):**

  - Schema: `FormInviteCode` class (`form-code` required String, `used-at`
    recommended Timestamp) + `form-access` String property on Form
    (`public` default when absent XOR `invite-only`), in
    `lib/defaults/forms.json`, `urls.rs`, the hand-mirrored
    `browser/lib/src/ontologies/forms.ts`, and `docs/src/schema/forms.md`.
    `used-at` is a generic, unprefixed property (like `required`) so it
    stays reusable outside Forms.
  - Server (`server/src/forms.rs`): `is_invite_only`, `check_invite_code`
    (basic-path `form-code = X` query exactly as planned — the
    watched-query-bloat warning is baked into a comment — verifying
    `parent` by `pure_id()` and `isA` in code, returning
    `Valid(resource) | Used | Invalid`), `consume_invite_code`
    (`used-at` = now, server-agent `save()` — fans out over WS, so the
    owner's code list flips to "Used" in realtime; verified in the e2e).
  - Gating (`handlers/form.rs::check_form_access`): `GET /form/{id}` (HTML,
    definition is injected inline so the page itself must be gated) and
    `GET .../definition` take `?code=`; `POST .../submit` takes a top-level
    `code` body field. Missing/invalid → 403, used → 403 with an
    "already been used" message (rendered by the friendly
    `not_available_page` for the HTML route). **Deliberately not gated**:
    `/challenge` (stateless PoW, leaks nothing) and `/image` (branding, and
    per-code URLs would break its public cache header) — both stay
    publish-gated only.
  - Submit consumes atomically: non-consuming pre-check *before* captcha
    verification (an invalid code shouldn't burn the visitor's one-time
    PoW payload), then re-check + consume under an in-process **per-form
    `tokio::Mutex`** (`form_submit_lock`, same layer as the rate limiter),
    `used-at` written *before* the row is created, per the plan's ordering
    rationale.
  - Runtime (`form-app`): reads `?code=` client-side
    (`getInviteCodeFromLocation`), appends it to the definition fetch
    fallback and the submit body; `fetchDefinition` now surfaces the
    server's 403 reason instead of a generic message. No renderer changes.
  - Bulk generation is client-side as planned (`createInviteCodes` loops
    `store.newResource` + `save()`), batch capped at 200, 10-char codes
    from an unambiguous alphabet via `crypto.getRandomValues`. The code
    list uses `useCollection` (`parent` = form AND `isA` = FormInviteCode —
    bounded at one watched query per form, unlike per-code lookups).
    Revoke = `destroy()`. `ShareLinkPanel` shows an invite-only notice so
    the plain share link isn't copied in confusion.
  - Covered by: `cargo test -p atomic-server --lib forms::` (access-mode
    default + check/consume/revoke unit tests), `form_submission_flow`
    (invite-only 403s on definition/page/submit, non-consuming definition
    fetch, consume on submit → `used-at` set, replay 403 on both paths,
    switch back to public), and a new `forms-submission.spec.ts` e2e
    (Settings → Form access → invite only → generate 2 links → visitor
    without code gets friendly 403, with code submits, second visitor with
    same link gets used-code page, owner sees "Used" in realtime).
  - **Wuchale**: new UI strings required `pnpm exec wuchale` (data-browser)
    — until extraction runs, dev shows `[i18n-404:*]` placeholders. The
    extraction also refreshed some unrelated stale catalog entries
    (obsolete `#~` markers) — pre-existing drift, not from this change.
    Non-English translations for the new strings are left for the
    AI-translation flow (no `OPENROUTER_API_KEY` locally).
  - **Human follow-up needed**: add `FormInviteCode`, `form-access`,
    `form-code`, `used-at` to the public atomicdata.dev forms ontology
    (same step as `form-styling` above). Local dev servers need one
    restart with `ATOMIC_REPOPULATE_DEFAULTS=true`.
  - The Phase 2 e2e (`forms.spec.ts` "persist across reload") remains
    environment-flaky (fails on this machine on a clean tree too —
    verified via stash A/B; publish/options commits report
    `pendingDirtyCount === 0` yet never reach the server). Same
    pre-existing outbox/sync race already documented under Phase 4; not a
    Private Links regression.
[x] **More field types** — DONE, except file upload. Shipped: phone, URL,
   currency, dropdown, dropdown multi-select, likert, rating, picture choice,
   choice matrix, table input, address. Each is an enum value +
   `form-field-options` schema + builder settings editor + renderer input +
   client validator + server validator/coercion + datatype mapping; summaries
   route onto the existing choice-count / histogram / answer-sample paths
   rather than growing new ones. See
   [`form-field-types.md`](./form-field-types.md) for the type table,
   decisions, and what turned up along the way (notably: picture-choice option
   images ride a gated `?file=` on `/form/{id}/image`, and long dropdown menus
   were unreachable app-wide until `components/Dropdown` learned to cap its
   height).
- **File upload is deliberately still open** and wants its own work item: it
    needs an anonymous upload path (scoped, size-limited
    `POST /form/:id/upload`) before a field type can exist for it.
[x] **Branching** — DONE. FormCondition resources on pages, fields, and layout
   blocks; evaluator implemented once in TS (`form-renderer/src/conditions.ts`)
   and once in Rust (`server/src/forms.rs`); shared fixtures
   (`testdata/form-conditions.json`) keep the two in lockstep. Server
   `validate_submission` skips hidden fields (required-on-hidden is not an
   error; submitted values for them are dropped). Builder: "Show when" editor
   in the field settings pane and the page pane (when no field is selected).
- **Schema**: `FormCondition` class (`form-condition-field` required AtomicURL
    to FormField, `form-condition-operator` required String enum, 
    `form-condition-value` recommended JSON) + `form-conditions` ResourceArray
    on FormPage / FormField / FormHeading / FormParagraph. Operator is a
    plain String without `allowsOnly` (same limitation as `form-field-type`).
    AND semantics; empty list = always visible.
- **Definition JSON**: conditions inlined as `{ field, operator, value }`
    where `field` is the referenced question's `form-maps-to` (the runtime
    never sees FormField subjects). Omitted when empty.
- **Evaluation** walks the form in document order. A referenced field that is
    itself hidden (or unanswered) fails the condition, so later questions
    cannot be unlocked by submitting a value for a hidden predecessor.
    `contains` is a case-insensitive substring on strings and membership on
    multi-select arrays. `greater-than` / `less-than` compare numerically,
    falling back to lexicographic string order (ISO dates work).
- **Renderer**: hidden blocks are not rendered; Next/Back/progress/Submit
    skip hidden pages; the last *visible* page is the submit page.
- **Human follow-up needed**: add `FormCondition` + `form-conditions` /
    `form-condition-field` / `form-condition-operator` / `form-condition-value`
    to the public atomicdata.dev forms ontology (same step as `form-styling`).
    Local dev servers need one restart with `ATOMIC_REPOPULATE_DEFAULTS=true`.
- Covered by: `testdata/form-conditions.json` (TS + Rust),
    `definition_inlines_field_conditions`, `populate_forms_ontology`,
    and `forms-submission.spec.ts` (radio → required follow-up hidden when
    No, shown+filled when Yes).
[x] **Styling/theming** — DONE (except fonts/logo, not requested). Shipped:
   cover image (5 position modes), text/main/background colors, 3 corner
   roundness levels, edited in a new **Settings tab** in `FormBuilderPage`.
- **Storage**: image reuses the generic `cover-image` + `image-position`
    properties at Form level (added to Form's `recommends`; enum extended to
    `top | left | right | behind | full`). Colors + roundness live in the new
    `form-styling` JSON property (`textColor`/`mainColor`/`backgroundColor`
    hex, `roundness`: `sharp | rounded | round`).
- **Anonymous image access**: `/download` is rights-checked, so the
    definition's `styling.imageUrl` points at a new publish-gated
    `GET /form/{id}/image` (`handlers/form.rs::form_image`) that resolves
    `cover-image` server-side and delegates to the shared
    `download_file_handler_partial` — stored mimetype (SVG works in `<img>`,
    scripts never execute: `attachment` + `nosniff`), `?w=&q=&f=` processing
    and a 1h public cache header. Consistent with decision #3: publishing
    stays a property, the File stays private.
- **Renderer**: new `FormShell` component in `@tomic/form-renderer` owns the
    page chrome (image layouts, card, title) + CSS-var overrides
    (`stylingVars`), incl. derived `--atomic-form-text-light`/`border` via
    `color-mix` and a luminance-picked `--atomic-form-on-accent` for button
    text. Used by `form-app` **and** `FormPreviewDialog` — the preview is now
    pixel-identical to the published page (and finally shows the title).
    Custom colors apply as-is in both light/dark schemes.
- **Found & fixed along the way**:
    1. JSON-datatype values written while the Property resource is
       unresolvable (form-styling isn't on atomicdata.dev yet → no `json`
       datatype tag) rehydrate as raw JSON *strings*; spreading that string
       corrupted the next write into indexed characters. All readers now
       parse defensively (`parseStylingValue` in `SettingsTab.tsx`, mirrored
       in `buildFormDefinition.ts`; `Ok(Value::String)` arm in
       `server/src/forms.rs::build_form_styling`). `SettingsTab` also sets
       `validate: false` on the form-styling `useValue` — each validating
       set otherwise blocks up to 10s on the failing property fetch.
    2. `ColorSetting`'s debounced write is flushed on unmount, otherwise a
       color picked right before switching builder tabs was dropped (ref
       updated in an effect — mutating it during render gets dropped under
       the React Compiler).
    3. `server/build.rs`: in `ATOMICSERVER_SKIP_JS_BUILD` dev loops the
       embedded `form-assets/` was backfilled only when *missing*, so a
       rebuilt `form-app/dist` stayed stale forever. It now refreshes on
       every build-script run (dest cleared first so hashed bundles don't
       pile up).
- **Human follow-up needed**: add `form-styling` to the public
    atomicdata.dev forms ontology (same Phase-1 step) — until then the
    data-browser logs a 404 for the property and skips validation/tagging
    (functionally fine, see fix 1). Local dev servers need one restart with
    `ATOMIC_REPOPULATE_DEFAULTS=true`.
- Covered by `forms-submission.spec.ts` (theme in Settings tab → publish →
    anonymous visitor sees custom accent + radius), `cargo test -p
    atomic-server --lib forms::` (`definition_includes_styling`), and a
    manual pass (all 5 image modes with an SVG, colors, roundness,
    anonymous submit).
[] **Progress bar** (trivial once settings exist).

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
