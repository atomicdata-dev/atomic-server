# Staging idle request audit — 2026-09-12

## Reproduction

- [x] Create a fresh staging account: `staging-e2e+requests-1789235386688@ontola.io`.
- [x] Create local data: **Request audit document**, with a description identifying this investigation.
- [x] Grant Cloud Server access through the existing audited per-drive admin API. No Stripe purchase or production change.
- [x] Accept hosting consent in the real deployed app.
- [x] Capture two 60-second idle windows (Sync page and document page), after a 10-second settling period, using Chromium DevTools Protocol.
- [x] Diagnose initial hosting failure and exercise the existing full-VV fallback in the disposable browser.
- [x] Verify managed-node import logs and signed HTTP document readback; UI shows **In sync**, 3 resources, 6.3 KB.

Deployed browser identifies itself as `0.41.0-beta.7`, commit `e110aa4`.
Account/browser state is isolated in `/tmp/staging-request-audit/profile` (parent directory mode 0700). No existing user drives were changed. The test account and its granted drive remain available for regression testing. Browser processes used by the test are closed when measurements finish.

## Healthy-state measurements

After successful remote readback, each window was 60 seconds with no user actions. These count observed HTTP requests, including preflights; WebSocket frames are separate.

| Request | Sync page | Document page |
| --- | ---: | ---: |
| Account `/me` | 31 | 18 |
| Enrollments | 17 | 5 |
| Recovery backup | 5 | 5 |
| Node metadata | 12 | 0 |
| Catalog POST + preflight | 4 | 4 |
| **Total (including Vault status requests)** | **72** | **33** |

Raw sanitized request URLs, times and initiator stacks: `/tmp/staging-request-audit/network.json`. No request bodies, credentials, or response bodies were recorded in that trace.

## Root causes

### 1. Node liveness polling retriggers account/enrollment checks

`browser/data-browser/src/routes/SyncRoute.tsx` polls `fetchManagedInfo(serverUrl)` every 5 seconds and calls `setManagedInfo(info)`. Every parsed response is a new object. The Cloud Server enrollment effect depends on the entire `managedInfo` object, rather than the provider/drive identity. Consequently, unchanged node metadata reruns `driveHasCloudEnrollment`, which calls `getManagedEnrollments(true)`, which first calls `/api/me` and then `/api/sync-enrollments`.

Result: every 5 seconds there is a `/server` → `/me` → `/sync-enrollments` sequence. This continues after successful sync. Node peer liveness changing does not imply account hosting enrollment changed.

### 2. Catalog refresh performs full identity reconciliation twice

`hooks/useAccountDriveCatalog.ts` refreshes every 30 seconds and on focus/online. `helpers/managed/driveCatalog.ts:DriveCatalogSync.refresh` calls its identity callback before and after POSTing the catalog. The callback runs `evaluateIdentityReconciliation`.

Each reconciliation calls `/me`, then both `getRecoverySecret` and `getManagedEnrollments`; each of those independently calls `/me` again. Thus one catalog refresh triggers **6 account checks + 2 recovery reads + 2 enrollment reads + 1 catalog POST**, plus the observed CORS OPTIONS preflight. These extra `/me` calls are not authorization requirements of the endpoints: each API request already authenticates on the server. Nevertheless, any optimization must preserve the before/after account-change and logout protections.

### 3. Backup watchers add periodic account checks

`components/CloudVaultWatcher.tsx` and `helpers/managed/vaultAutoBackup.ts` have 60-second retry paths. Backup work checks the account and may perform additional reconciliation/enrollment checks. These overlap the catalog refresh. They must continue to detect late account linking and data arrival, but should share work where safe and avoid uploading unchanged data.

### 4. Separate first-upload failure in hash-first sync

The UI accepted hosting setup and the managed node received the agent resource, but the new drive and document did not arrive. Signed HTTP readback returned 404. WebSocket diagnostics showed:

```
SYNC refused for <new-drive>: not readable
RBSR_FP refused for <new-drive>: not readable
```

`lib/src/sync/engine.rs:drive_items_for` requires the drive to exist and be readable before computing the hash-first probe. A drive being uploaded for the first time does not exist there yet. The client never reaches normal bootstrap through this rejected probe, leaving the UI at **Finish Cloud Server setup / Syncing**.

Diagnostic intervention was limited to this test browser: invoke its existing `sendReducedSyncState` path for the pending drive. RBSR timed out, then its existing catch branch sent a full version-vector SYNC. Normal server admission and signed import checks remained active. Server logs at `2026-09-12T18:00:56Z` confirmed **3 resources imported**, including the document. Signed HTTP readback succeeded and the UI showed **In sync**. No server binary or production setting was modified.

This establishes a first-sync regression in the hash/probe optimization, separate from the repeated HTTP metadata reads. It is not evidence of a PKARR/DHT failure.

## Fixes prepared for review

- [x] Scope enrollment refresh to provider URL, account refresh, drive and server; unchanged node metadata no longer retriggers it.
- [x] Reuse a freshly checked account inside compound reconciliation (three `/me` reads become one), while retaining both before/after catalog identity checks.
- [x] Share concurrent account reads without caching settled results; discard responses after logout, provider or device-token changes.
- [x] Pause node/catalog polling in hidden tabs, resume on visibility/focus/online, and prevent overlapping slow requests.
- [x] Let authenticated admitted/may-enroll missing drives start hash-first sync. Existing private roots still require read access; import still requires admission and valid signed data.
- [x] Cover account request counts, credential races, polling lifecycle and retries with Vitest.
- [x] Cover repeated live node polls and same-account focus refresh in Playwright against a real local server with a mocked SaaS API.
- [x] Cover first upload into an empty destination through signed import, asserting document content and denied anonymous/unadmitted/private access.

The 30-second visible catalog interval and its before/after identity checks remain intentional. Vault's backup retry lifecycle is unchanged. General rejected-probe timeout handling is a separate transport improvement; this fix addresses the verified first-upload refusal at its source.

## Validation and rollout

- Data-browser TypeScript check and local library builds pass.
- Managed-helper and polling tests: 226 passed across 18 files, with two Vitest workers.
- Rust sync tests: 56 passed, including empty-destination bootstrap and access checks.
- Focused Chromium regression: one worker; two real five-second polls plus focus refresh. The local server uses an isolated data directory.
- [ ] Merge/deploy after review and green CI.
- [ ] Repeat the two 60-second staging measurements on the deployed fix. Pre-fix counts above must not be presented as post-fix results.

No source fixes have been deployed by this task. The temporary staging test account and granted drive remain available for this final verification.
