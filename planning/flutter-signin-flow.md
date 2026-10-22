# Flutter sign-in, identity restore and first run: map and failure matrix

Audit of 21 Oct 2026 (mac thread), handed to the **cloud thread**, which owns
sign-in, the backup secret, session/keystore logic and Rust in `lib/`. Related:
[`flutter-secret-handback.md`](./flutter-secret-handback.md) (browser unlocks
the backup and hands the secret to the app), [`sync-onboarding-ux.md`](./sync-onboarding-ux.md).

Status legend: **fixed (remote)** = on `origin/claude/flutter-mobile-app-w8e9wz`
but not local; **fixed (local sha)** = committed locally, not pushed;
**WIP (uncommitted)** = in the mac worktree, not committed, for the cloud thread
to take or drop; **open** = proposal only.

## Map

```
main.dart  bootstrap() ─ initRust → resolveStoreDirectory → openDb ─┬─ error → StoreOpenFailedScreen (bootstrap.dart:51)
                                                                     └─ ok → AtomicApp → StoreRecoveryScreen? → LoginScreen
LoginScreen._tryAutoLogin (login_screen.dart:104)
  AtomicSession.loadEarly (session.dart, preload in main.dart:75)
    null ─────────────────────────────→ welcome
    session → AtomicClient.resumeSession → bridge resume_app_session (rust/src/api/simple.rs ~743)
               load_agent_from_secret; active drive = hint or derived personal drive;
               open_ws_sync(serverUrl) if set; "ok" iff the drive resource is local
      ok + name readable → home ;  else → needsSync
welcome ─ Get Started → createAgent → setup() → showSecret → home
        ─ I have a secret → signIn → _doSignIn (:266) → _signInWithSecret (:325)
              AtomicSession.save → resumeSession → ok? home : needsSync
        ─ Sign in with atomic.place → AccountLinkDialog → recoverIdentity → _signInWithSecret
needsSync (_buildNeedsSync :751 → _retryPeerSync :149)
  1. discoverHomeServer(drive) (atomic_client.dart:465): pkarr origins (≤12 s, Rust) → take(3) →
     parallel GET /genesis (4 s, 1 retry) → first verified → connect_home_server (Rust WS)
  2. syncConnectivityNow (Rust sync_connectivity_inner): ensure Iroh (≤10 s) → known peers →
     pkarr peers (4 at once, 22 s each); whole call capped at 50 s
  3. failure → NeedsSyncView(failure: SyncFailure.parse(...)) with Try again / Pair with QR / Paste node ID
```

Accepted secret: base64 (either alphabet) of JSON `{privateKey, subject, initialDrive?}`
(`Agent::from_secret`, lib/src/agents.rs:165; web `decodeSecret`,
browser/lib/src/CryptoProvider.ts:200 uses `atob` = standard alphabet only, but
`atob` skips whitespace). The app trims only leading/trailing whitespace
(login_screen.dart:254, :267).

## Failure matrix

| # | Platform | Where | What the person sees | Cause | Status |
|---|---|---|---|---|---|
| 1 | macOS | session save/load | `PlatformException(... -34018 ...)` on Sign In | data-protection Keychain needs an entitlement | fixed (local 27ce5342a, 7b25fc0a5: legacy keychain + in-memory fallback) |
| 2 | macOS | connect_home_server / WS | `PanicException(Could not automatically determine the process-level CryptoProvider…)` | rustls without a default provider | fixed (local 602f7de7a; remote c89b9b1df does the same in lib/src/client/ws.rs: expect a conflict) |
| 3 | macOS | openDb | "Failed to create redb at ~/Documents/atomic.redb: Operation not permitted" | TCC on ~/Documents | fixed (local 8cf054f8a, store in Application Support + migration) |
| 4 | all | needsSync | `staging.atomicdata.dev: ClientConnection closed before full header…` | stale keep-alive connection | fixed (local 602f7de7a, one retry in `_sendWithRetry`) |
| 5 | all | needsSync | "None of the 4 devices that announced your drive answered (… timed out after 20s)", minutes of "Looking for your devices…" | known peers dialled **one after another**, 22 s each, then pkarr 12 s + 22 s; resume and connect_home_server had **no WS connect timeout** (OS TCP timeout, 75 s+) | fixed (local, landed inside 0c69742d3: known peers dialled at once and in parallel with pkarr, resume WS ≤10 s, home-server connect ≤20 s; tests 65c4ef1ad) |
| 6 | all, account users | needsSync | p2p search although the drive is on an atomic.place node | server path only knows pkarr origins (`take(3)`, atomic_client.dart:472) and nothing from the account; the account's Cloud Server enrollments (`GET /api/sync-enrollments` → `http_origin`, atomic-saas src/enrollments.rs:437/611) are never asked; first verified origin only, no fallback to the next if connect fails (:514) | **WIP (uncommitted)**: `flutter/lib/atomic/drive_restore.dart` (server-first, all sources in parallel, next verified origin on failure, bounded, structured `[restore]` log), `AccountStore.hostedDriveOrigins/originsForDrive` (account_store.dart), tests `flutter/test/atomic/drive_restore_test.dart` (green). Not yet wired into LoginScreen |
| 7 | all | needsSync | endless spinner, raw errors | no deadline in the UI: the screen waits for `syncConnectivityNow` (≤50 s+10 s) | open: run servers + devices together, show the failure state after ~12 s while both go on (DriveRestore.run(patience, onSlow) does this), add "Use another account" to NeedsSyncView |
| 8 | all | needsSync details | log grows every retry | `AtomicClient.discoveryLog` (atomic_client.dart:463) is never cleared; its lines put first make `SyncFailure.parse` miss the host summary | open (replaced by DriveRestore's per-run log) |
| 9 | all | sign in | raw `PanicException(... Ed25519 private key must be 32 bytes)` for a cut-off key inside valid JSON | `generate_public_key` unwrap/expect (lib/src/agents.rs:227) | fixed (local 32a88d2d7: key length checked first, plain error; also reads the web's `initialDrive`) |
| 10 | phone | sign in ("it doesn't take my secret") | "That is not a secret…" or raw serde/JSON text | secret wrapped over lines (mail, notes), quotes, a `secret:` label, smart quotes, zero-width chars; only outer trim | fixed (local fca0dc6b5: `normalizeSecret`, flutter/lib/atomic/secret_input.dart, tests) but **not wired into `_doSignIn` yet**: proposal `_signInWithSecret(normalizeSecret(text))`, show `SecretFormatException.message` |
| 11 | Android | start | signed out silently after a backup restore / new phone / lock change; then "Couldn't save your sign-in" at every start | Auto Backup restores `FlutterSecureStorage.xml` whose keystore key did not travel: reads and writes fail; `_loadSecret` treated a read error as "nothing saved" | fixed (local fca0dc6b5: secure prefs excluded from backup (backup_rules.xml, data_extraction_rules.xml), write repairs by delete → deleteAll, `AtomicSession.lastLoadProblem` + `secretProblemMessage`), **not wired**: proposal in `_tryAutoLogin`: session null and `lastLoadProblem != null` → signIn step with that message instead of welcome |
| 12 | Android OEM (MIUI etc.), iOS before first unlock | start | silent sign-out | one transient keystore/Keychain read failure | fixed (local fca0dc6b5: one retry, then `SecretProblem.unreadable`; nothing deleted on read) |
| 13 | iOS/macOS | start after reinstall | welcome screen although the Keychain still has the secret | `load()` required the prefs server URL | fixed (local fca0dc6b5: a secret alone is a session with no server) |
| 14 | all, old backups | Sign in with atomic.place | dead end ("Finish setting up…") for backups with only passkey / recovery-code wrappers | app opens only `atomic-assisted` wrappers | fixed (remote d25159b5f, 8af6c47b5: falls through to the secret field, clears the half-done account session); full fix planned in flutter-secret-handback.md (remote edbf79fd9) |
| 15 | macOS second instance | openDb | "out of storage" advice for "Database already open" | `storeErrorAdvice` (store_recovery_screen.dart:190) knows only permission errors | open: classify `already open`/`lock` → "Atomic is already open in another window", `No space left`/os error 28 → disk full, rest generic |
| 16 | all | needsSync | the personal drive was never written anywhere (lazy first write) → nothing can ever be found | deterministic personal drive (planning/deterministic-personal-drive.md, "eager vs lazy") | open: when no server verifies and devices answered "none", offer "Start with an empty drive here" (`ensure_private_drive` merges later) |
| 17 | Android | after restore | the restored redb carries the old phone's Iroh node identity | redb (with the node key) is in the backup | open: exclude `app_flutter/atomic.redb*` from backup or regenerate the node key when the device id changes |

## Proposals for the cloud thread (in order)

1. Wire `DriveRestore` into LoginScreen (WIP files above): after `resumeSession`
   says `needs_sync`, `fromServers(deadline: 10 s)` on the sign-in/loading
   screen; found → home, no needsSync screen. Else needsSync runs
   `run(patience: 12 s, onSlow: show failure + actions)`; a late success still
   signs in. Sources: active + known servers, `AccountStore.hostedDriveOrigins`
   (8 s), `resolveDriveOrigins` (13 s). Inject through a small `SignInBackend`
   so widget tests can fake it.
2. Use `normalizeSecret` in `_doSignIn`/paste (row 10) and the
   `lastLoadProblem` message in `_tryAutoLogin` (row 11).
3. Rows 7, 8, 15, 16 as above. Keep `SyncFailure` summaries free of URLs.
4. Needs a device or server to verify: rows 11/12 on a real Android restore
   and a MIUI phone; row 6 against atomic.place with a real (test) account
   whose drive is enrolled on a node.
