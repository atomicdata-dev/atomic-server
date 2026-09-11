# Standalone new-resource page

- [x] Extract the creation catalog from feat/plugin-model onto develop.
- [x] Keep develop's templates and importer; include only UI handoff dependencies.
- [x] Verify typecheck, catalog unit tests, search, nested table creation and mobile assistant handoff.
- [ ] Recheck nested website import after restoring a healthy local database.

The local disk filled during validation. The running server now rejects imports
with redb's "Previous I/O error occurred. Please close and re-open the database."
The website browser regression remains included; it must pass before merging.
Tests used the existing backend and generated WASM assets, not a fresh Rust build.

The plugin/schema architecture stays in PR #1307. This extraction uses the
existing parent-scoped importer API rather than bringing its replacement along.
