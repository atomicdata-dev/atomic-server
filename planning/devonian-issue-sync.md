# Devonian issue tracker sync

- [x] Verify Devonian main (`e11104f`) and AtomicServer PR #1394 (`a087a7ca7`).
- [x] Inspect native lenses, GitHub integration actions, comments and test coverage.
- [x] Add regression tests for bidirectional issues/comments, conflict handling and restart recovery.
- [x] Build a browser demo using Devonian, local-only Atomic storage and direct integration-proxy requests.
- [x] Verify 13 focused tests, 7 existing integration tests and frontend typecheck; document setup/limits and update coverage.
- [x] Verify native browser creation/comments both ways, close/reopen and reload without duplicates.
- [ ] Live connection: integration-proxy must support browser CORS preflight and expose X-Connection-Code. The deployed instance returned 401 without CORS on 2026-09-09.
- [ ] Verify live sync against a user-selected repository and proxy connection after that dependency is available.

Use Devonian HTTP subjects for the intermediate graph and scoped external mappings
for Atomic DIDs. Persist graph, mappings and request receipts in IndexedDB. Serialize
rotating connection codes; refuse to retry uncertain writes. No Node runtime,
AtomicServer plugin endpoint, tenant secret on AtomicServer, or server scheduler.
Live proxy currently lacks CORS; browser fixture verification remains independent.
Missing records are conflicts, not deletion requests.

- [ ] Rebase onto #1401 and reuse browser tenant challenge, callback and rotating transport.
- [ ] Expand HTTP mock for stateful GitHub issues/comments and add Playwright two-way sync coverage.
- [ ] Run focused tests, browser E2E and typecheck; update PR.
