# Shared schemas, templates, and import mappings

**Status:** Catalog architecture remains a proposal. A built-in task/template reuse pilot is in implementation (2026-09-07); frozen package distribution remains open.

Atomic's interoperability promise needs shared meaning, stable contracts, and
distribution through everyday workflows. Build a curated central catalog whose
releases remain independently usable, cacheable, and mirrorable. Start with a
small collection of useful schemas connected to templates and importers.

Companion: [connector-scale.md](connector-scale.md) extends this to ongoing
bidirectional sync, including council and school systems. Shared schemas reduce
mapping work; the connector contract establishes actual read/write capabilities
and reconciliation behavior. Connector opportunities extend beyond the initial
SaaS acquisition verticals.

## Evidence and existing direction

- [Motivation](../docs/src/motivation.md) makes property reuse and cheaper
  standardization explicit goals. [Schema](../docs/src/schema/intro.md) ties
  property identity to both datatype and human-readable meaning.
- [Schema routes](completed/schema-routes-decision.md) already accepts frozen
  definitions plus optional schema on the write path. This proposal adds
  discovery and governance; it does not replace that decision.
- [Code-first schema](json-schema-code-first.md) contains conflicting guidance:
  its accepted-decision header says frozen, while Identity Model, registration,
  trust, and open questions still recommend signed mutable definitions first.
  Reconcile these before implementation; do not treat both as current policy.
- [Templates](table-templates-and-mini-apps.md) provide useful workflows today.
  In `browser/data-browser/src/chunks/TablePage/createTableFromSpec.ts`,
  `TableColumnSpec` now supports existing Property references (task pilot, 2026-09-07);
  other columns still create new properties. `createRowClass` also creates a
  local class. The special row name property is reused. Template reuse alone
  therefore does not establish shared domain semantics.
- [Plugins/importers](plugins.md#importers-from-importersmd) already specifies
  reuse-first mapping, first-party importers, fixtures, provenance, and preview.
- Relevant GitHub issue bodies retrieved on 2026-09-05:
  [#1099](https://github.com/ontola/atomic-server/issues/1099) JSON Schema;
  [#1207](https://github.com/ontola/atomic-server/issues/1207) code-first schemas and migrations;
  [#1144](https://github.com/ontola/atomic-server/issues/1144) schema DIDs;
  [#1208](https://github.com/ontola/atomic-server/issues/1208) frozen resources;
  [#1104](https://github.com/ontola/atomic-server/issues/1104) bundled schemas;
  [#507](https://github.com/ontola/atomic-server/issues/507) mutable schema cache mismatch;
  [#1238](https://github.com/ontola/atomic-server/issues/1238) templates;
  [#1134](https://github.com/ontola/atomic-server/issues/1134) importer workflow;
  [#924](https://github.com/ontola/atomic-server/issues/924) CSV cleanup;
  [#677](https://github.com/ontola/atomic-server/issues/677) shared schema discovery scopes.
  Search results did not expose reliable issue state or comments, so these are
  evidence of requirements, not a current backlog-status audit.
- [PR #1262](https://github.com/ontola/atomic-server/pull/1262)'s retrieved
  description includes schema locks, useSchema, and version pointers. It lists
  cycle materialization and Iroh transport as remaining work. Its implementation
  and reported tests were not independently verified in this research.

## Separate the things that evolve differently

| Layer | Contents | Proposed identity |
| --- | --- | --- |
| Property definition | Meaning, value representation, units where applicable | Frozen definition |
| Class / validation profile | Shared properties and contextual constraints | Frozen definition |
| Release | Exact definitions, dependency lock, examples, supported dialect | Frozen manifest |
| Package / listing | Publisher, discoverability, release history, recommended release | Mutable signed DID |
| Presentation | Labels, translations, order, widgets, local display preferences | Mutable resources or pinned template release |
| Mapping / migration | Exact source and target contracts, transform, fixtures, loss report | Pinned artifact plus signed provenance |

Use HTTP for human-readable catalog pages, JSON Schema endpoints, and artifact
delivery. Preserve existing HTTP vocabulary identities. Do not mass-rekey core
data to launch the catalog. A hash proves content integrity; publisher signatures
and curator endorsements establish provenance and recommendation separately.

The semantic part of a definition must distinguish concepts with identical
datatypes: invoice due date and birth date are both dates. Hashing just shape
would falsely equate them. Conversely, translations and cosmetic labels should
not churn property IDs. Specify a canonical semantic definition, with a stable
concept discriminator or normative meaning, separately from presentation.
Correcting normative meaning changes the frozen definition; editing display
prose does not. Canonicalization cannot discover semantic equivalence.

Frozen releases must include their dependency closure, available persistently
offline. Unchanged properties retain their IDs between releases. Mutually
recursive definitions need explicit graph/bundle canonicalization and
addressing; independently hashing references in a cycle is insufficient.
Mutable HTTP dependencies need pinned snapshots or an explicit versioned core
contract before claiming the entire release has immutable semantics.

## Domain packages and existing market standards

**Direction added 2026-09-05:** The catalog should help establish shared
standards within markets, grounded in existing standards wherever possible.
Schema selection belongs in the vertical product strategy, alongside the target
workflow, template, importer, and adoption partners.

Reconciled with the restored SaaS
[`VERTICALS.md`](https://github.com/ontola/atomic-saas/blob/f6e4ad69a84fe34cc1987cb92b171a0baadc590e/planning/VERTICALS.md)
and its `COMPETITORS.md` companion, read directly from fetched `origin/main`
on 2026-09-05. The vertical plan remains proposed: agencies/consultancies first
for recurring revenue, field research second through grants and partnerships,
GLAM through consortium work. Startups are default onboarding, not a separate
vertical. Public sector, CRM, and healthcare are not current targets. Its VD1
still leaves final confirmation of the two verticals open. Competitor figures
and market claims were not re-audited here.

This gives the catalog two complementary adoption tracks:

- **Agency workflow reuse:** shared Project, Organization, Person, Task and
  Deliverable concepts, with editable templates and Notion/CSV mappings. Start
  with one real agency workflow. Use existing contact/calendar standards at
  exchange boundaries, but do not invent a claim that the whole agency schema
  conforms to one universal standard. The goal is usable imports and shared
  data across projects, not building a full CRM or accounting product.
- **Field research standards:** choose one discipline with a real partner,
  model its observations and provenance, and prove offline capture followed by
  exchange with an external domain tool or repository. This is the stronger
  formal standards pilot. FAIR is a set of principles, not a single schema or
  a badge earned by using Atomic IDs; publish specific capabilities and evidence.

The vertical plan's template → tour → video → landing page pipeline should gain
a shared schema/profile and tested exchange underneath it. The demo should show
actual import, reuse, and export. Domain depth stays in packages/plugins; core
provides the general identity, validation, mapping, and resolution mechanisms.
Catalog work must not become a prerequisite for buyable hosting, prices, or the
first useful importer—the SaaS plan explicitly puts those first for MRR.

Organize domain packages as: shared concepts + versioned standard profiles +
templates + import/export mappings + conformance fixtures. Reuse cross-domain
concepts when semantics agree, while retaining domain-specific constraints.
Become a practical implementation and contributor to existing standards; where
standards leave gaps, publish documented extensions and validate them with
independent adopters before promoting them as common practice.

Each standards alignment should record:

- Authoritative standard URI, edition/version, and exact term or clause.
- Relationship: inspired by, mapped to, implements a subset, extends, or conforms
  to a specified profile. These are distinct claims.
- Field-level mapping, including direction, units, cardinality, code lists,
  required transformations, and information loss.
- Supported and unsupported features; extension fields and their semantics.
- Pinned import/export implementations, fixtures, validation results, and
  attribution of who reviewed the claim. Claimed conformance and independent
  certification must be distinguishable.

A documentation link alone establishes none of these guarantees. Store mappings
as versioned resources so external standard updates do not rewrite the meaning
of existing data. Preserve external term identifiers in the mappings; an Atomic
Property can reference a standard concept without falsely claiming identical
representation. An RDF predicate is not automatically a resolvable Atomic
Property, and an XML schema term is not automatically a graph property.

Standards candidates aligned to these tracks, checked against primary sources.
These are candidates for evaluation, not implemented compatibility:

| Domain | Standard to evaluate | Concrete proof |
| --- | --- | --- |
| Agency contacts | [vCard, RFC 6350](https://www.rfc-editor.org/info/rfc6350/) | Import/export supported contact fields, preserving multiple values and parameters |
| Agency scheduling | [iCalendar, RFC 5545](https://www.rfc-editor.org/info/rfc5545/) | Round-trip supported events, explicitly testing timezone and recurrence behavior |
| Ecological fieldwork | [Darwin Core](https://www.tdwg.org/standards/dwc/) | Map biodiversity observations to a chosen term set and exchange representation; preserve IDs, context, and provenance |
| Archaeology / heritage research | [CIDOC CRM](https://cidoc-crm.org/) | Select a narrow profile with a domain partner; test mappings of objects, events, places, and evidence |
| Research dataset publication | [W3C DCAT 3](https://www.w3.org/TR/vocab-dcat-3/) | Describe datasets and distributions; this is metadata, not the schema of every observation |
| GLAM, later consortium scope | [Europeana Data Model](https://pro.europeana.eu/index.php/page/edm-documentation) | Test an agreed export profile with a contributing institution |

Ecology and archaeology are alternative pilot disciplines, not two additional
verticals to start simultaneously. Invoice standards such as UBL remain an
optional later exchange boundary if an agency workflow actually requires it.

Select the first vertical based on actual user access, integration pain,
standard availability, and a manageable conformance scope. Do not attempt a
complete industry model before demonstrating one valuable exchange workflow.
The first release should work with an external standards-based tool as well as
two Atomic workflows. Where conversion cannot be lossless, make that visible.

Keep schema definitions, mappings, and conformance fixtures portable and usable
without a hosted account. Hosted setup, maintained connectors, and operational
support can add commercial value without restricting the common language.

## Contribution and governance

Anyone can publish a package under their own identity. Becoming recommended is a
separate maintainer-reviewed action. Initial stages: draft, published,
recommended, deprecated. Begin with Ontola curation, adding domain maintainers
when actual communities emerge. A disagreement can remain a fork.

Offer Publish from a table/ontology and from code. Before submission, show close
matches, reuse opportunities, and differences. A proposal includes meaning,
examples/counterexamples, license, compatibility impact, and importer/template
consumers. Strip instance data and permissions from submissions by construction.
Reuse the existing fork/suggestion mechanism where suitable; semantic approval
is a review step even when a CRDT can mechanically merge edits.

Votes indicate demand. Show dependencies from public templates, apps, and
importers; successful compatibility fixtures; maintainer activity; and optional
aggregate adoption reports. Downloads are weak evidence of usage. Never claim
global counts from a local-first/private ecosystem. Do not let popularity
establish equivalence or silently change pinned releases.

## Changes and merging

| Change | Result |
| --- | --- |
| Rename a column, translate, change widget | Presentation change |
| Require an existing field in one workflow | New profile/class release; same Property |
| Add a custom field | Reuse another Property or mint only the new concept |
| Change datatype, units, cardinality representation, or meaning | New Property definition |
| Combine overlapping schemas | New release reusing original IDs where valid; explicit mappings elsewhere |

Model predecessor, deprecation, exact equivalence, broader/narrower meaning,
and conversion as different relationships. Scope assertions by publisher and
version. A successor relationship alone never authorizes query substitution.
For example, a date of birth cannot be reconstructed from an age in years.

Migrations pin both contracts, show a preview and affected records, describe
losses, retain provenance, and run only with the user's granted rights. Keep old
releases resolvable. Query adapters may avoid rewriting data, but only under an
explicitly selected mapping. Define read compatibility and write compatibility
separately; adding an optional field may still break an old closed validator.

## Templates and importers as adoption paths

Let a template bind columns to existing properties and install exact schema
dependencies, while creating fresh tables, views, and example instances. Keep
local configuration editable without copying shared definitions. Different
workflows can share useful properties without forcing one universal Task class
or status enumeration.

An importer selects a target schema/profile, proposes source-field mappings,
shows examples and ambiguity, then validates the planned output. Reuse the
confirmed mapping on later runs. Matching names or shapes is insufficient:
`Date` might mean invoice date or payment deadline; `Amount` needs currency,
units, and gross/net semantics. Preserve unmapped information and original
source bytes rather than inventing equivalence or silently dropping fields.

Publish tested mappings alongside schema releases. Bind external identity to
source account/dataset plus external ID, not only a generic importer name.
Reimports must distinguish source changes from local edits. The existing plugin
run/preview/apply model should execute transformations; no second importer engine.

## JSON Schema compatibility

Keep Atomic's independently identified semantic properties; use JSON Schema
2020-12 for structural constraints. JSON Schema already supports reusable
subschemas through `$ref` and `$defs`; the comparison docs' claim that properties
cannot be reused is too broad. Atomic's distinction is explicit semantic identity
of instance keys across datasets, not exclusive possession of reuse.
See [JSON Schema Core](https://json-schema.org/draft/2020-12/json-schema-core).

Specify two representations: full property-ID keys for direct JSON-AD validation,
and compact keys with an explicit reversible binding map. Detect alias collisions.
An ordinary JSON Schema import cannot infer semantic property identities.
Also, `$ref` references a schema, not a linked instance: mapping it directly to an
Atomic resource link requires an explicit annotation. Null and absent values,
embedded objects and linked resources, need distinct conversion rules.

Use a declared subset for native Atomic forms and generated types. Preserve
remaining JSON Schema constraints and evaluate them with an appropriate engine,
or explicitly reject unsupported validation; never silently weaken constraints.
Atomic annotations can preserve identity, datatype, class targets and recommendations.
Graph-aware checks must be separately reported: a generic JSON Schema validator
cannot establish a linked resource's class or existence from its string ID.

Add contextual constraints on classes/profiles, avoiding duplicate properties
just to impose a different minimum or enum. Prioritize scalar enums/ranges,
string bounds, array items/cardinality, and structured JSON. Keep graph resources
extensible by default; closed API payload profiles are a separate choice.
Declare format-assertion behavior and do not treat default as data insertion.
See [Validation](https://json-schema.org/draft/2020-12/json-schema-validation).

Optional schema acceptance is distinct from validation success. Report valid,
invalid, or unknown/incomplete. Strict app ingestion needs pinned dependencies
and shared JS/Rust fixtures; peer replication must not become dependent on a
live catalog lookup. This proposal does not redefine the accepted permissive
write-path policy.

## Next decisions and implementation sequence

- [ ] Reconcile stale code-first identity guidance with the accepted decision.
- [ ] Specify frozen semantic identity, presentation boundary, cycles, and locks.
- [ ] Add existing-property bindings to template creation.
- [x] Read the restored SaaS verticals plan and reconcile catalog priorities
      with its agency / field-research tracks (2026-09-05).
- [ ] Confirm pilot verticals with VD1; choose one agency workflow and one
      partner-backed field discipline, with an exact standard/profile.
- [ ] Add versioned standards-alignment metadata and conformance coverage to
      domain packages; verify exchange with an independent external tool.
- [ ] Prove one shared domain end to end: two distinct templates and one CSV
      importer use the same property IDs and can read each other's records.
- [ ] Verify offline restart, cosmetic customization, extension, and explicit
      version migration with that fixture.
- [ ] Define JSON Schema projection and conversion loss reporting; share JS/Rust
      validation fixtures at the cheapest layer per TESTING_COVERAGE.md.
- [ ] Launch a small curated catalog with publisher identities, immutable
      downloads, examples, consumers, and publish/suggest flow.
- [ ] Add public dependency metrics and community review after real adoption.

Success measure: records created through independently configured workflows are
usable together without hand-written per-app mapping, while custom fields and
old releases continue to work. Catalog size and votes are secondary.

## Task template reuse pilot (2026-09-07)

- [x] Table column specs can reference existing properties, validate their types/options, and attach without modifying their definitions.
- [x] Issue Tracker and Project Tasks reference the same Status, Assignee and Description properties; Project Tasks also references Due date.
- [x] GitHub setup can select compatible tables by property identity and preserve their row classes and views. Tables already referenced by an integration are excluded.
- [x] Verify existing-table setup and preserved views in the browser, plus the existing GitHub setup/automation regression.
- [ ] Exercise bidirectional provider sync against a populated shared-template table, including Blocked and conflicting local changes.
- [ ] Replace the embedded HTTP pilot vocabulary with frozen package distribution before treating this as the catalog implementation. This bridge uses the existing built-in defaults machinery; it is not a reversal of the accepted frozen-schema decision.
- [ ] Add local presentation aliases and explicit extension/migration UX; never edit the shared definition to customize one table.
- [ ] Migrate old template-created properties only through reviewed mappings. Existing tables are not automatically rekeyed.

The experimental vocabulary is in `lib/defaults/tasks.json` with matching
`browser/lib/src/task-schema.ts` references. Its identities are versioned HTTP
URLs resolved through the installed server, not a claim that a public catalog
has deployed those URLs. The browser and server both embed the definitions.
Assignee remains an explicitly documented text label, not a Person relation.
Status offers Todo, Doing, Blocked and Done. GitHub maps exactly the three
states it supports; Blocked must not silently map to Doing. Local class/view
configuration stays separate from shared properties. No external standard
conformance is claimed.

## Time Tracker / Clockify pilot (2026-09-07)

- [x] Time Tracker and Clockify import use the same per-drive time interval, Project, Person, Billable and source-identity properties through `timeTrackingSchema()` and table schema bindings.
- [x] Project/Person links use the table relation datatype, and duration remains derived from start/end instants.
- [ ] Verify live import and reuse across independently created Time Tracker tables.
- [ ] Replace per-drive schema allocation with frozen package dependencies; no external standard conformance or cross-drive identity is claimed.

See [Clockify](clockify.md) for import scope and findings. Existing tables retain
their original schema; migration requires an explicit reviewed mapping.
