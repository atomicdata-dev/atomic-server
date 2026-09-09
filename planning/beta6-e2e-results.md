# Beta.6 local E2E results — 2026-09-09

Tested commit: c9fe15630. Scope: the full Atomic Server Playwright suite, including configured Firefox locks and opt-in WebKit storage tests, with local SaaS/Vault services. This is not real Tauri device acceptance or a full SaaS portal-suite run.

## Results

- Full pass: 164 passed, 29 failed, 6 skipped, 1 not run (9.6 minutes).
- Single-worker failed-case rerun: 8 passed, 21 failed (7.3 minutes).
- After building CLI/Svelte dependencies, both template cases passed individually, including the previously unrun serial Svelte case.
- Latest result per case across runs: **174 passed, 20 failed, 6 skipped**. This is not one clean full-suite pass.

Initial setup failures involved the preview proxy, VITE_E2E and the managed API address. These were corrected before the failed-case rerun. Test services used ports 6757/9893/3040 and MinIO 9110, with disposable databases.

## Remaining failures

- [chromium] › tests/canvas-live-update.spec.ts:71:7 › canvas live update › a stroke drawn in one session appears live in another session viewing the same canvas
  - TimeoutError: locator.blur: Timeout 10000ms exceeded.
- [chromium] › tests/documents.spec.ts:41:7 › documents › create document, edit, page title, websockets
  - TimeoutError: locator.blur: Timeout 10000ms exceeded.
- [chromium] › tests/documents.spec.ts:175:7 › documents › shows a collaborator’s ephemeral cursor position
  - TimeoutError: locator.blur: Timeout 10000ms exceeded.
- [chromium] › tests/kanban.spec.ts:376:7 › kanban › view tab menu: change type, duplicate, and delete
  - TimeoutError: locator.click: Timeout 10000ms exceeded.
- [chromium] › tests/meetings.spec.ts:113:5 › start a meeting, join it, follow along, and end it
  - TimeoutError: locator.blur: Timeout 10000ms exceeded.
- [chromium] › tests/meetings.spec.ts:237:5 › records join and leave in the meeting chat ────────
  - TimeoutError: locator.blur: Timeout 10000ms exceeded.
- [chromium] › tests/offline-create-then-online.spec.ts:26:7 › offline create → online sync → disable localDB › offline-created drive loads after disabling localDB
  - Error: waitForSynced timed out. Outbox diagnostics: {"status":{"serverConnected":true,"syncInProgress":true,"pendingDirtyCount":1,"blockedCount":0,"serverUrl":"http://localhost:9893","drive":"did:ad:JsacRosa93F_ZoKH7dRPT1skj854W8E3u9j0e88g2tmZw7yVmq5RkjhoU3U7CdSuGKnMQgHQ2r9lpaSa0q7RBA","clientDbReady":true,"clientDbAttached":true,"lastDriveSync":{"drive":"did:ad:JsacRosa93F_ZoKH7dRPT1skj854W8E3u9j0e88g2tmZw7yVmq5Rkjh
- [chromium] › tests/onboarding.spec.ts:13:7 › onboarding › create new identity with verifySecret flow - profile name persists
  - TimeoutError: locator.press: Timeout 10000ms exceeded.
- [chromium] › tests/plugin.spec.ts:21:7 › Plugins › install a plugin ───────────────────────────
  - Error: expect(locator).toBeVisible() failed
- [chromium] › tests/presence-follow.spec.ts:27:5 › presence avatars and follow mode across two sessions
  - TimeoutError: locator.blur: Timeout 10000ms exceeded.
- [chromium] › tests/second-device-load.spec.ts:18:5 › a fresh-OPFS second device loads an existing drive’s contents @smoke
  - TimeoutError: locator.blur: Timeout 10000ms exceeded.
- [chromium] › tests/sign-in-without-data.spec.ts:62:7 › signing in on a device that holds none of the account’s data › stops, and says so, instead of opening a workspace
  - Error: Unexpected browser warnings/errors (2); first 20 shown, full browser-diagnostics attached
- [chromium] › tests/sign-in-without-data.spec.ts:80:7 › signing in on a device that holds none of the account’s data › leaves no other workspace active
  - Error: Unexpected browser warnings/errors (2); first 20 shown, full browser-diagnostics attached
- [chromium] › tests/sign-in-without-data.spec.ts:99:7 › signing in on a device that holds none of the account’s data › names the account’s own drive as the place to write
  - Error: Unexpected browser warnings/errors (2); first 20 shown, full browser-diagnostics attached
- [chromium] › tests/signout-signin-data.spec.ts:145:7 › sign-out / sign-in round trip › content made before signing out is still readable after signing back in
  - TimeoutError: locator.blur: Timeout 10000ms exceeded.
- [chromium] › tests/signout-signin-data.spec.ts:172:7 › sign-out / sign-in round trip › the local database key survives sign-out and is restored on sign-in
  - TimeoutError: locator.blur: Timeout 10000ms exceeded.
- [chromium] › tests/vault-backup-restore.spec.ts:236:7 › Cloud Vault backup and restore › a second backup after an edit stores more than the first
  - Error: signup failed: 400 {"error":"Enter a single valid email address, like name@example.com."}
- [chromium] › tests/vault-backup-restore.spec.ts:283:7 › Cloud Vault backup and restore › a device with no local data restores the workspace from the vault
  - Error: signup failed: 400 {"error":"Enter a single valid email address, like name@example.com."}
- [webkit] › tests/signout-signin-data.spec.ts:145:7 › sign-out / sign-in round trip › content made before signing out is still readable after signing back in
  - TimeoutError: page.waitForURL: Timeout 30000ms exceeded.
- [webkit] › tests/signout-signin-data.spec.ts:172:7 › sign-out / sign-in round trip › the local database key survives sign-out and is restored on sign-in
  - TimeoutError: page.waitForURL: Timeout 30000ms exceeded.

## Interpretation and next work

- [ ] Investigate the disappearing Agent secret field: shared helper blur/Enter waits block several collaboration, second-device and storage assertions.
- [ ] Investigate /app/welcome 404 diagnostics in signed-out and no-data flows.
- [ ] Investigate offline agent outbox drain, kanban deletion menu and plugin iframe rendering.
- [ ] Update Vault test email fixtures to valid domains accepted by the security validator, then actually exercise backup/restore. Current failures stop at signup.
- [ ] Diagnose WebKit dev-drive setup timeouts.
- [ ] Obtain a clean full-suite run after fixes; keep the release draft.

Skips: four opt-in performance instrumentation cases, one existing drafts fixme, and the existing Cmd+M context-menu fixme. No test was newly disabled.

## Local artifacts

- Full report: /tmp/beta6-e2e-first/playwright-report/index.html
- Failed-case rerun report: /tmp/beta6-e2e-rerun/playwright-report/index.html
- Logs: /tmp/beta6-e2e.log, /tmp/beta6-e2e-rerun.log, /tmp/beta6-next-e2e.log, /tmp/beta6-svelte-e2e.log

Reports contain screenshots and traces. These temporary local paths are not CI artifacts and are not committed.
