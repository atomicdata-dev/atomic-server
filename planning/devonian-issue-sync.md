# Devonian issue tracker sync

- [x] Verify Devonian main (`e11104f`) and AtomicServer PR #1394 (`a087a7ca7`).
- [x] Inspect native lenses, GitHub integration actions, comments and test coverage.
- [x] Add regression tests for bidirectional issues/comments, conflict handling and restart recovery.
- [x] Build a browser demo using Devonian, local-only Atomic storage and direct integration-proxy requests.
- [x] Verify 13 focused tests, 7 existing integration tests and frontend typecheck; document setup/limits and update coverage.
- [x] Verify native browser creation/comments both ways, close/reopen and reload without duplicates.
- [x] Verify deployed v40 CORS preflight/exposed headers and browser GitHub OAuth.
- [ ] Verify live two-way writes: private sandbox reads return 404; approved public-repository reads succeed, but browser create returns 403. Resolve GitHub app permissions.

Use Devonian HTTP subjects for the intermediate graph and scoped external mappings
for Atomic DIDs. Persist graph, mappings and request receipts in IndexedDB. Serialize
rotating connection codes; refuse to retry uncertain writes. Tenant authentication and rotating credentials use #1401’s shared BrowserIntegrations client.
No Node runtime, AtomicServer plugin endpoint, tenant secret on AtomicServer, or server scheduler.
Live proxy CORS and OAuth now work; private-sandbox access is the remaining live blocker.
Missing records are conflicts, not deletion requests.

- [x] Rebase onto #1401 and reuse browser tenant challenge, callback and rotating transport.
- [x] Expand HTTP mock for stateful GitHub issues/comments and add Playwright two-way sync coverage.
- [x] Run 13 sync tests, 11 LocalThought browser tests, 7 existing GitHub integration tests, browser E2E and typechecks.

Continuation is on consolidated `feat/api-plugins` / #1387. Disposable live issues were closed.
