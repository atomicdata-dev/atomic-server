# Beta.6 local E2E validation — 2026-09-09

Scope: the full Atomic Server Playwright suite, including Firefox locks and opt-in WebKit storage tests, with local SaaS/Vault services. This is not native Tauri acceptance or the full SaaS portal suite.

## Current validation

- [x] Original failures reproduced and investigated.
- [x] Affected scenarios passed on focused reruns, including offline sync, private plugin rendering, Vault, and WebKit storage.
- [x] Library tests: 64 files, 392 tests passed.
- [x] Frontend production build and typecheck passed.
- [x] Final full 201-case run after the cache fix: **195 passed, 6 existing skips, zero failures (9.3 minutes)**. Playwright exited 0 and reported no failed tests.
- [x] Native server build, targeted formatting/lint checks, and git diff --check passed. The full Rust test suite was not rerun.

## Changes

- Dashboard reload diagnosis found that an older resource response was merged correctly in memory but persisted unmerged to OPFS. Cache writes now serialize the canonical merged resource; the regression is covered in store.test.ts and the dashboard reload E2E.

- Sign-in tests stop acting on the input after automatic submission and wait for the signed-in state. Storage tests navigate through the app instead of interrupting background requests with hard navigations.
- The outgoing data route no longer fetches an incoming `/app/` screen as a resource.
- Private plugin assets are fetched with signed requests in the parent and passed into the sandbox. The server enforces an opaque origin even without iframe sandbox attributes; the E2E suite checks this directly.
- Offline saves with no changes beyond the synced baseline clear only after loading a complete local snapshot. Unit tests verify that missing snapshots leave the queue intact.
- The duplicated-view test waits for selection before opening the active tab menu.
- Vault signup uses a valid example.com email fixture. macOS WebKit storage tests use fresh regular profiles because ephemeral contexts reject OPFS.

## Local setup

Frontend preview 6757, Atomic Server 9893, local SaaS 3040, MinIO 9110. Build variables: VITE_E2E=true, VITE_ATOMIC_SERVER_URL=http://localhost:9893, VITE_MANAGED_API_BASE=http://localhost:3040/api, VITE_MANAGED_PORTAL_URL=http://localhost:3040. Preview also receives VITE_ATOMIC_SERVER_URL for its proxy. Wait for `/server` readiness before starting tests.

MinIO refused uploads with 507 because the host was below its free-disk threshold. The disposable `atomic-beta6-e2e-minio-memory` container instead uses a 1 GiB tmpfs at /data with the atomic-vault-e2e bucket. The original test data remains untouched.

## Previous baseline and artifacts

Before these fixes, latest results across the initial full run and reruns were 174 passed, 20 failed, 6 skipped; this was not a clean full pass. Earlier reports remain at /tmp/beta6-e2e-first/playwright-report/index.html and /tmp/beta6-e2e-rerun/playwright-report/index.html.

Previous full-run log: /tmp/beta6-e2e-final.log; report preserved at /tmp/beta6-full-before-cache-fix/playwright-report/index.html. Focused logs: /tmp/beta6-fixes2-e2e.log, /tmp/beta6-final-focused.log, /tmp/beta6-plugin-webkit-final.log, /tmp/beta6-webkit-green.log. Reports and traces are temporary local artifacts, not CI evidence.

Six pre-existing skips: four opt-in profiling cases, drafts fixme, and Cmd+M context-menu fixme. No new skips or diagnostic allowlists were added.

Final log: /tmp/beta6-e2e-verified.log; HTML report: /tmp/beta6-e2e-verified/playwright-report/index.html. Test-owned services and MinIO were stopped after the run.
