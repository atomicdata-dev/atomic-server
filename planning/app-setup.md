# Typed app setup

- [x] Shared JSON Schema input contract and validation, with host-owned credentials outside arguments.
- [x] Generic Atomic form with dynamic choices, loading and errors.
- [x] Migrate GitHub's form; retain its installer as an explicit legacy adapter.
- [x] Assistant discovery and prefilled setup handoff, without credentials in model context.
- [x] Verify validation, credential isolation, and browser setup handoff.
- [ ] Accept full installation against a matching backend and migrate remaining setup execution.

Remaining convergence: migrate installer effects into the sandboxed action lifecycle,
resumable setup after partial creation, GitHub OAuth/account discovery, and Notion OAuth convergence.
A registered bundled setup adapter is trusted host code. Do not execute arbitrary
user-authored setup functions on the frontend origin. Registration is not a sandbox.


Validation: shared validator tests (3), package/schema/error tests (4), and browser
form/assistant-handoff tests (2) pass. Typecheck passes. End-to-end installation
is not accepted: the broader tests could not discover a newly created shared task
table, and credential storage returned "Could not store GitHub credential on
AtomicServer". Investigate these against a matching healthy backend; do not infer
installation success from the form tests. The pure setup normalization is currently
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
