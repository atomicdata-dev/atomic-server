# E2E diagnostic hygiene

- [x] Add an automatic Playwright warning/error gate and migrate all specs.
- [x] Cover additional contexts/tabs and bounded per-test expected diagnostics.
- [x] Verify failures with synthetic self-tests and run application probes.
- [ ] Resolve the existing diagnostic noise before release acceptance.

Import `test` from `browser/e2e/tests/fixtures.ts` in every spec. Unexpected console
warnings/errors and uncaught browser exceptions fail the test; all captured signals
are attached as `browser-diagnostics` JSON. Declare only deliberately triggered
failures with a reason, exact count and source URL where relevant. No global
allowlist. The feedback retry spec demonstrates an expected HTTP 500.

The initial strict application probe exposed signed-out API requests, premature
WebSocket traffic and React warnings. Root-cause fixes now make the original
five browser probes and seven portal probes pass with strict diagnostics. The
collector also excludes Playwright's final browser shutdown (after test cleanup
hooks), which is not an application operation.

- [x] Handle signed-out session discovery without protected data requests.
- [x] Authenticate before presence/ephemeral traffic and clear stale account drive.
- [x] Wait for local persistence during database handoff and flush the old worker.
- [x] Prevent closed file-picker searches and fix React label/input/render warnings.
- [x] Avoid private-ancestor probes when bookmarking child invitations.
- [x] Resolve Vault jobs surviving identity/session changes.
- [x] Resolve existing-tab onboarding with unresolved drive names.
- [ ] Replace the fake file-upload placeholder with proper pending-upload handling.
- [x] Resolve chat reply visibility and rerun the smoke chat scenario.
- [ ] Rerun complete strict suites and manual release flows.

The original eight portal identity/existing-tab tests pass; later passkey/recovery
coverage also passes (16 cases). Client library units: 368 passed; managed helpers
and local encryption-key tests: 183 passed. The combined browser acceptance run passed 26 cases (17 smoke + 9 diagnostic
self-tests); the portal suite passed 45 with 3 opt-in skips. The opt-in hosting
run passed all 3 scenarios plus 9 diagnostic self-tests. The expanded full browser
suite exposed additional failures; its first strict run was 141 passed, 46 failed,
6 skipped and 1 not run. These are not release acceptance results.

Additional regression tests cover atomic concurrent session-key creation, deferred
snapshot notifications, unsaved attachment parent identity, and occupied backup
object numbers. Failed/cancelled Vault passes never advance the export cursor.
Vite metadata and pairing proxies now follow `VITE_ATOMIC_SERVER_URL`, avoiding
requests to an unrelated developer node.

No blanket console or Sentry suppression was added. Deployment remains paused.
The app's 14 Node test-global / Document migration type errors are fixed; both
app and portal typechecks passed. Later changes still require final verification.

The fixture is mirrored in atomic-saas/portal/e2e for its own Playwright version.
The detailed policy, initial evidence and Sentry boundaries are documented in
atomic-saas/planning/E2E_DIAGNOSTICS.md. Rust stderr/Node runner diagnostics and
separately launched browsers are outside this fixture's scope. Keep test Sentry
transports disabled or fake; verify real ingestion separately.

## Full-suite follow-up

- [x] Share link-parser registration across editor lifecycles; keep telephone links.
- [x] Preserve graph type identity checks under React 19 memo replay (pnpm patch).
- [x] Accept browser comparison-operator aliases in Rust expression filters.
- [x] Requery computed-filter membership instead of optimistic scalar-only admission.
- [x] Include a copied document body in a fork's first genesis commit.
- [x] Preserve explicitly cancelled sync writes for reconnect without failure backoff.
- [x] Recover missing base state even when a resource first arrives as a delta.
- [x] Avoid local writes in the known unsupported-browser server-only mode.
- [x] Wait for WebSocket acknowledgments in the E2E commit watcher.
- [x] Build the test plugin fixture from current source.
- [x] Use a local public drive and mock MCP search in tests that are not testing external services.
- [ ] Verify remaining full-suite flows, starter hydration, and all catalog changes.

The second affected browser run passed 35 of 43. Follow-up library validation is
368/368, with a clean typecheck and build. Active browser reruns must finish before
updating this as complete. No production deployment or live Stripe charge occurred.

## Release verification follow-up, 2026-09-07

The last expanded browser run reached 180 passed, 7 failed, 6 skipped and 1 not
run. Fixes for those failures include durable local snapshots (including the
worker flush), stale WebSocket close events after reconnect, page-unload HTTP
and WASM cancellation, the editable dashboard title assertion, and the Sync
activity label's React key warning. Both generated website templates now pass.
The focused eight-case rerun passed six; the final two label cases then passed.

The portal rerun exposed rapid identity changes attaching an obsolete database
worker while the next identity was already active. A deterministic unit test
reproduces that sequence. Database startup now checks the active identity after
both the previous worker's flush and asynchronous key lookup; obsolete workers
cannot attach or reattach. The unit test fails before the fix and passes after it.

Current cheap-layer checks: 378 client-library tests, 497 Rust library tests
(7 ignored), the new database-handoff regression, app and library typechecks,
and the production app build pass. Final full browser and portal runs are in
progress; these focused results alone do not authorize a production release.

Local MinIO must be healthy before Vault tests (`/minio/health/ready`). An earlier
portal run was invalidated when disk exhaustion stopped OrbStack and MinIO;
service recovery is infrastructure repair, not a product fix. Tests use mock
billing and disabled/intercepted Sentry transports. Staging may deploy the verified
pair; production remains held under the SENTRY.md and beta/backup checklists.

### Final regression pass

The latest unit runs pass 381 client-library tests and 178 managed/helper tests.
Additional regressions cover stale session-discovery responses after logout and
clearing a pre-genesis not-found error after an authoritative snapshot or creation
acknowledgement. The cold-device recovery case passes three repetitions; invited
chat passes three repetitions after the acknowledgement fix. The fork diagnostic
was traced to the sidebar error label's translated icon markup and fixed there.
Temporary browser instrumentation has been removed.

A full portal run reached 47 passed and one logout-race failure before that fix.
The expanded browser run was interrupted near its final cases by trace recording
exhausting disk space. Redb then required reopening the local control-plane DB;
the subsequent 500s were infrastructure failures, not a clean product rerun.
The API and MinIO have been restarted. Final full suites run with `--trace off`
to fit available disk; browser warning/error assertions and screenshots remain on.

A fresh browser walkthrough exercised the drive switcher, its Storage and hosting
entry, Sync, and sidebar Feedback with no warning/error diagnostics. Screenshots
were inspected. With Sentry disabled locally, feedback correctly disables sending
and shows the support email; this does not verify production email delivery.

### Latest release gate (2026-09-07)

The completed full browser run reported **179 passed, 9 failed, 6 skipped**;
the portal run reported **47 passed, 1 failed**. These are not green release
results. Follow-up fixes cover startup polls before `window.store` exists,
waiting for the portal magic-link exchange before navigating away, the plugin
permissions heading's translated icon markup, and cancellation of Vault setup
requests on sign-out. The cancellation regression fails before the fix and passes
after it; 70 Vault/auto-backup unit tests and three account-switching E2E repeats
pass. Affected browser cases are being rerun with strict diagnostics enabled.

CI also exposed a missing patched-dependency directory in cached pnpm installs.
The server Dagger pipeline now copies `browser/patches` into each manifest-only
install layer. Both branches have been pushed; staging and production have not
been deployed by this verification pass. Production remains held.

Follow-up result: 16 affected browser tests passed, then the remaining cold-device
Vault restore passed after correcting its setup. The server still holds the old
drive, so recovery opens that drive; the test uses local-only mode to keep its
canary off the server, proves it is absent on the fresh device, then restores it
using Sync's Vault action. This avoids injected connection-failure noise while
still proving Vault supplied the missing data. Together the focused reruns cover
all nine failures from the full run, but are not a single clean full-suite run.
The queued CI checks remain a deployment gate.

### CI lint follow-up

The complete browser workspace `pnpm run lint` now passes, including formatting.
Fixed statement spacing, shadowed test variables and the database-handoff mock's
`any` type; no lint rules were disabled. Existing non-failing warnings remain.
Validation after cleanup: 381 library tests, nine diagnostic-fixture self-tests,
the database-handoff regression and the app typecheck pass. Generated local
`dist-hosted` output was moved outside the source tree before linting.
