# Typed app setup

- [x] Shared JSON Schema input contract and validation, with host-owned credentials outside arguments.
- [x] Generic Atomic form with dynamic choices, loading and errors.
- [x] Migrate GitHub's form; retain its installer as an explicit legacy adapter.
- [x] Assistant discovery and prefilled setup handoff, without credentials in model context.
- [x] Verify validation, credential isolation, and browser setup handoff.
- [x] Accept GitHub installation against a matching backend, including reuse of existing task views.
- [ ] Migrate remaining setup execution into the sandbox and make installation resumable.

Remaining convergence: migrate installer effects into the sandboxed action lifecycle,
resumable setup after partial creation, GitHub OAuth/account discovery, and Notion OAuth convergence.
A registered bundled setup adapter is trusted host code. Do not execute arbitrary
user-authored setup functions on the frontend origin. Registration is not a sandbox.


Validation: shared validator tests (3), package/schema/error tests (4), and browser
form/assistant-handoff tests (2) pass. Typecheck passes. The earlier installation failures were traced to a database latched after an I/O
error and a server executable without plugin routes. Reopening the database and
building the branch restored compatible-table discovery and credential storage. The
existing-table browser test now passes; the longer action-flow test also passes, including action review, permissions,
history cleanup and the assistant handoff. The pure setup normalization is currently
called by a bundled host adapter; exported setup functions in arbitrary stored
plugin source are not invoked yet. Dynamic dependent account/repository lookup,
portable setup permissions and translated package metadata remain open.

## Notion manual setup convergence

- [x] Package-owned Notion declaration and UUID normalization, shared with assistant discovery.
- [x] Replace the bespoke manual form with AppSetupForm; retain the existing OAuth entry point.
- [x] Verify malformed IDs fail before credential storage and leave the form retryable.

This removes the duplicate manual form, not the legacy installer. Both bundled
adapters still call host installers. Sandbox setup execution, resumable installation,
and OAuth discovery remain unchecked above. Package-authored setup labels remain
English until metadata localization is implemented.

## Installation prerequisite checks

- [x] Reproduce credential failure: `/plugin-secret` returns 404 for the newly created app resource.
- [x] Check server visibility of the workspace before either bundled installer creates resources.
- [x] Refuse local-only workspaces without uploading them; leave prerequisite failures retryable.
- [x] Diagnose missing resources: the running database rejected writes after an I/O error, while save() incorrectly reported retained outbox writes as persisted.
- [x] Verify installation, action review/permissions/history, and assistant handoff against the rebuilt plugin-branch server.

The shared preflight prevents starting against an unavailable workspace. It is not
an installation journal and does not prove the later resources have synced. The
server was reopened without deleting its data. The executable on disk also lacked
plugin routes, so a matching branch build is needed for full acceptance.

## Save acknowledgement

- [x] Reproduce a failed genesis returning `persisted` while still queued.
- [x] Return `offline` for retained outbox entries, including backoff; retry keeps the same subject.
- [x] GitHub and Notion stop immediately when the app's initial save is pending.
- [x] Client-library suite: 695 tests pass after rebasing onto the updated branch; frontend typecheck and library build pass.

This fixes acknowledgement reporting, not resumable multi-resource installation.

## Bundled GitHub source loading

- [x] Replace dynamic raw-module destructuring with a lazy installer module that statically imports the bundle, matching Notion.
- [x] Reject missing source before any GitHub installation writes.
- [x] Update the browser action test to open the Advanced disclosure.

The previous dynamic raw import yielded an undefined default in development;
the resulting release contained only `undefined` and its manifest, so discovery
worked but action execution reported a missing run export. Full action execution,
not schema discovery alone, is the regression check for this failure.

Browser acceptance uses synthetic credentials and a stubbed external approval transport; no live GitHub write was performed.

- [ ] Reduce installation round trips: cold GitHub setup can exceed ten seconds; browser acceptance now waits explicitly for installation navigation (30-second bound).


## Portable package boundary (September 11)

App packages must ultimately be importable as resources from another repository,
without adding provider imports to Atomic's frontend. Reuse the existing release
manifest and importer localIds; installing a package must not import credentials,
consent, installation identities or running schedules.

- [x] Validate JSON setup declarations through `parseSetupDeclaration`, exported
  by the library and plugin SDK. The current adapter registry validates before
  form rendering and assistant discovery; argument validation also validates the
  declaration, including partial drafts. Unknown schema keywords fail closed.
- [x] Cover JSON round-trip, detached metadata, invalid required fields, unsupported
  field constraints, choice hints, prototype keys and size limits with unit tests.
- [x] Import an inert package definition as a resource through the shared importer,
  planner and apply path. `app-package.ts` preserves the existing release payload
  and optional setup declaration; it rejects installation fields. The resource's
  native localId is the author-owned revision URI, scoped to the host-chosen parent.
  Reusing a revision URI for changed content produces an append-only conflict.
- [ ] Extend distribution to bundled schema/template resource graphs. Current
  release schema bindings reference external resources; they are not copied.
  Package import alone does not establish an immutable/verified runtime release.
- [ ] Replace bundled provider discovery with resource-backed package discovery.
- [ ] Move provider setup effects into the sandbox and existing reviewed effect
  lifecycle, then remove the trusted host installer adapters.
- [ ] Demonstrate installation of a package fixture maintained outside Atomic's
  source tree without rebuilding the frontend or server.

Declaration validation alone does not implement package import or sandbox setup.
Lookup names remain presentation hints; only the host decides which lookups an
installation may use. Credentials continue through the separate host flow.

The package content property stores canonical JSON **text** rather than a nested
JSON value. Existing importer/planner reference rewriting must not rewrite literal
`local:` strings inside code or setup metadata. The new class is `app-package`,
not `app` or `plugin-script`; copying it never enrolls an installation. Activation
must still extract/validate the code manifest in the sandbox, pin the release and
obtain fresh host consent. The package-supplied manifest is not evidence of what
its code exports. This step has library tests, not a browser installation flow.
