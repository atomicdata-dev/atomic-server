# Desktop PKARR restore

- [x] Verify staging announcement: personal drive resolves to staging NodeID; node advertises Iroh relay.
- [x] Create isolated codex/desktop-pkarr-restore worktree from origin/develop.
- [x] Run isolated local Tauri build: Iroh connects; restore had no PKARR lookup.
- [x] Add native inspection regression and wire discovery plus explicit fetch to desktop.
- [x] Verify real staging connection, public-profile inspection and private-workspace denial for test identity.
- [ ] Verify user private-workspace fetch after user signs in.
- [x] Compare actual browser, staging and desktop child resources: restoration is NOT complete.
- [x] Reproduce staging rejection with the browser's existing resyncDrive path: private drive is not enrolled for sync.
- [ ] Resolve private-drive hosting policy/enrollment without bypassing managed admission.
- [ ] Reconcile browser changes to staging, then verify desktop content matches.
- [x] Add explicit loading stages after secret acceptance; offer discovery from missing-drive Sync screen.
- [x] Render full recovery screen in native WebKit with a fresh test sign-in; new copy and manual node address fallback are visible.
- [ ] Reproduce the beta.5 packaged-build missing text; dev rendering alone does not establish its cause.

User agent: did:ad:agent:Th4BIsoBJHrL3Wo9E_h9hI3tRs5yQFsVGDgJGg0ZyZ0
Drive: did:ad:0I5rRjyMDYOaRKAPYbesoGG7cJuoVFYskbhePk9MIXZSQZWvNoOUHPAm37UfIrSFwZRMej9tzWoXbLDkxu-0Bw
Staging node: 60720a76f65b7861fdb110af3b3232983df0063058690f0a68d9df2c46481243
No user data or secrets modified during live read-only discovery checks.

Live follow-up: browser and desktop use the same private drive DID. Browser document `did:ad:57wrjINk9xcY5RXaJJI9hEQPsoxPAwfYtaU3hh8btqxsj5x7oUdvF1knplnwxaHwufaq0JqH2i-O5I2fcI_gBg` is named `What s this!@?`, while authenticated staging HTTP GET and desktop return `Document`. Browser computeDriveSyncState contains 6 resources, including that document; staging parent query contains 3 children. Explicit browser reconciliation at 21:43 returned SYNC_PUSH rejected: drive is not enrolled for sync on this node. Linked desktop GET /api/sync-enrollments confirms only the OIHM... team drive is active, not the private drive. Browser had incorrectly shown In sync with its lastDriveSync belonging to YcXy... instead. Do not report restoration success from the drive resource or PKARR connection alone. User product-policy question is pending.

Native probe returns name `atomic-staging`. Unit test also explicitly fetches after inspection and confirms imported data. Typecheck passes. Debug app uses /tmp/atomic-desktop-pkarr, separate bundle identifier and staging portal override. No commit or push.
