# One template model, multiple entry points

Status: initial built-in implementation, 2026-09-11. The create-drive gallery,
workspace composition, table adapter and isolated previews are implemented locally.
The broader portable resource-graph format below remains a migration plan; website
imports, durable install journals, shared schema IDs and recorded tours are not
implemented by this change.

## Relevant existing direction

- `table-templates-and-mini-apps.md`: templates are data and view configuration;
  new domain workflows do not get bespoke renderers. Existing table builders
  and assistant tools must remain the shared creation path.
- `demo-experience.md`: previews use real editable resources on a fresh local-only
  drive, with existing cleanup and exit machinery. The shipped director is tied
  to one team scenario; it is not a general template runtime.
- `tours.md`: tours are recorded meeting resources, replayed as navigation and
  narration. This player is still proposed. Scripted mutation/performance is a
  separate optional demo capability, never run on a user's adopted workspace.
- SaaS `planning/VERTICALS.md`: template -> demo/tour -> recording -> landing page.
  Extract common infrastructure while implementing a second concrete use case;
  do not build an engine in advance. Students and small teams are onboarding
  paths, not a reason to encode vertical-specific behavior in core.
- `website-templates.md`: preserve actual local-ID-to-DID mappings, reference
  rewriting, target-drive scope and repeat-application behavior.
- `content-i18n.md`: distinguish localized display metadata from document content.
- `schema-catalog.md` in the main checkout: shared semantic definitions and pinned
  dependencies stay distinct from mutable listings, presentation and instances.
  The full catalog/distribution architecture remains a proposal.

Some older status paragraphs undercount templates or mark completed capabilities
as open. Verify against code: `TABLE_TEMPLATES`, `buildTableFromSpec`,
`chunks/Demo/startDemo.ts`, `demoWorkspace.ts`, `Template/template.ts`.

## Proposed product contract

A template describes a reusable resource graph. One table, a folder of notes,
a website, and a whole workspace use the same format. Size and destination
change; the concept does not. A student workspace composes a reading-list table,
a task board and documents, rather than copying their schemas into new code.

One template can be:

1. Added under a parent in an existing drive.
2. Used to create a new drive during onboarding or from the drive switcher.
3. Instantiated in an isolated local demo with example content.
4. Used by the assistant to propose and then apply a setup.
5. Captured for a gallery preview, video or vertical landing page.

Context determines available actions and target capabilities. New Table filters
for a table entry point; onboarding filters for useful workspace starting points.
A small table need not have a workspace tour or marketing page.

## Common package, optional parts

The logical manifest contains:

- Identity/version, publisher/license, localized title/description/icon and tags.
- Stable template-local resource keys, declared roots and entry points, and
  composition references to exact component template versions.
- Structure: schema bindings, tables, views, folders and initial document layout.
- Optional example-content layer: sample rows, document text, files and demo
  personas. Empty adoption retains essential defaults and schema enumeration
  values; sample rows and performance content are separate.
- Pinned schema/template dependencies and required application capabilities.
- Optional tour references, preview targets and bundled static assets.

Do not require every component to populate every field. Do not put React
components, arbitrary JavaScript, secrets, credentials, live subscriptions or
production permission grants into the portable manifest. Bundled adapters can
bridge existing generators initially; the exported format is declarative.
Plugins remain a separate explicitly granted dependency, never silently installed.

Catalog listing and release content are different identities. A mutable listing
can recommend a new release; installed instances keep their recorded release.
A local built-in catalog is enough for the first migration. A public marketplace
or frozen-schema distribution service is not a prerequisite.

## One instantiation pipeline

`resolve -> validate -> plan -> review -> instantiate -> record provenance`

- Resolve the dependency closure and check required capabilities before writes.
- Produce a reviewable plan for the chosen destination, locale and example policy.
- Reuse existing table/schema/document creation primitives behind this boundary.
- Allocate fresh instance IDs, then remap internal references, parent links, view
  bindings, document resource references and tour stops. Handle cycles explicitly.
- Preserve references to shared schema definitions; do not clone or modify a
  shared Property to customize one template. Existing-property pilot support is
  ahead of this worktree and must be reconciled before implementation.
- Bind ownership and permissions from the current actor and destination. Template
  source authors and demo personas acquire no rights in an adopted drive.
- Record instance/release identity and a local-key-to-subject map. A retry resumes
  the same operation; explicitly adding another copy allocates a new instance.
- Persist progress so failure identifies a partial instance without duplicating
  resources on retry. Do not claim transactional rollback that the store lacks.
- Updating a template does not overwrite user edits. Migrations are separate,
  reviewed operations; a newer catalog release is not an automatic migration.

Server URL is a transport detail, never a resource identity or a required
argument for offline instantiation. Existing HTTP-based website import can remain
an adapter during migration; a demo cannot call it and claim to be serverless.

## Demo and adoption

Preview uses the same template release and production resource views, with the
example layer enabled. Register local-only routing before the first save and
track every created subject for teardown. Demo data must not enroll in Cloud
Server, Vault, peer discovery or the account's normal drive catalog. Reuse and
audit the existing demo lifecycle; its local-only flag alone does not establish
all of those exclusions.

The gallery shows content-based previews (sidebar and selected pages) with one
preview action. Inside the demo: Use this template and Exit demo.

Use this template creates a fresh instance with examples off by default. It does
not copy exploratory edits or convert scripted personas into collaborators.
Keep my demo edits would be a distinct future action, requiring explicit export
and permission sanitization. Don't confuse it with template adoption.

The current theatrical demo remains a supported bundled adapter. Extract its
common lifecycle when adding the second template; don't rewrite the director or
build the proposed tour player just to ship the gallery.

## AI and marketing consume the same model

The chat proposes a template manifest/composition and revises it conversationally.
It can reuse catalog templates and supported generic table configuration. Validate
it with the same schema, capability checks and review pipeline as human-authored
templates. No separate AI-only installer or unconstrained tool writes during
preview. Missing provider setup uses existing AI setup UI; errors preserve the
conversation and proposal. Input is sent only to the configured provider.

A preview image or video records a real instance at an explicit template release,
app revision and locale. Store that provenance with the asset so UI/template
changes can identify stale captures. Marketing copy may be tailored to a vertical;
all Start/Try actions resolve to the same release the capture describes. A page
must not promise a workflow merely because a tag or screenshot exists.

## Migration and acceptance

- [ ] Agree the small manifest and instantiate-plan interfaces using an existing
      Project Tasks table and the shipped demo workspace as concrete fixtures.
- [x] Wrap `TABLE_TEMPLATES` / `buildTableFromSpec` without copying catalog specs.
- [ ] Extract demo lifecycle and adapt the current demo as the second fixture;
      preserve its director and real production renderers.
- [ ] Prove the same table template installs into an existing drive and composes
      into a new drive, and its demo creates equivalent structure plus samples.
- [ ] Add the website adapter, testing DID remapping and repeat-application rules.
- [x] Build the create-drive gallery, real previews, blank path and AI proposal
      chat on these interfaces; use existing UI components.
- [ ] Test local-only demo isolation, cleanup/restart, fresh adoption, schema ID
      reuse, cyclic references, failed-install resume and explicit second copy.
- [ ] Verify exported/imported templates include no credentials or source rights.
- [x] Capture mobile/desktop gallery previews from the actual template instances.
- [ ] Add public publishing, recorded tours and automated media generation only
      after the common model is proven by those consumers.

Open design choices: exact portable representation of table-builder specs versus
fully materialized resource graphs; content export/remapping for Loro documents;
and release addressing before frozen package distribution ships. Settle these
with the two fixtures, not by defining a new renderer or speculative DSL.

## Verified initial slice (2026-09-11)

- [x] One built-in catalog wraps existing table configurations; Student, Team and
  Personal compose these exact definitions with documents. New Table and New Drive
  share table instantiation. The current interactive demo is preserved via its adapter.
- [x] New Drive page and dialog use the same gallery and naming UI. Templates open
  actual editable local resources; adoption defaults to a fresh drive, examples off, with an explicit option to keep the actual preview graph and edits.
- [x] Unit tests cover composition, missing versions, cycles, duplicate keys and
  AI output validation. The AI proposes existing tables plus document outlines;
  arbitrary new table schemas are not supported yet.
- [x] Chromium E2E covers mobile preview, fresh adoption without preview edits or
  sample rows, retention of edited preview content, blank creation and all four existing table-template workflows.
- [ ] Live configured-provider AI acceptance, initial identity-signup handoff and
  cross-browser/mobile-device acceptance still need verification.
- [ ] Persist release provenance and resumable installation progress. Current UI
  exposes a partial drive after failure and prevents a duplicate submission;
  it does not claim rollback or resume.

This is a built-in composition layer, not yet a portable import/export format.
Existing table builders still mint their schema properties in this worktree.
Reconcile the shared-schema pilot before claiming semantic ID reuse.

- [x] Demo chat distinguishes scripted speakers from signed creators; only known personas in the active local demo can override the displayed speaker.

- [x] Keep demo content and my edits promotes the local preview into the saved-drive list; the preview marker survives failed saves so adoption can be retried. This does not enable Cloud Server.
