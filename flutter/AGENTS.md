# atomic.place Flutter — Agent Context

## Sync & onboarding — read first

The Dart in `lib/atomic/` is a client of the same system the data-browser
talks to, and the same person uses both. Before changing anything about
signing in, servers, pairing or sync, read
[`../planning/sync-onboarding-ux.md`](../planning/sync-onboarding-ux.md): it
holds the shared vocabulary, the rules of what can actually reach what (rights
decide, on every transport — not whose device it is), every account/device path, and
the map of which file here twins which file in `browser/data-browser`.

Change a sync screen here → change its twin there, and update that doc.

## What This Is

The Atomic app: a cross-platform (Android, iOS, Web) Flutter client for Atomic
Data. Documents, chats and the other resources are shown through the web app's
embed views; native screens handle sign-in, servers, pairing, sync and the
chat/assistant. The Dart package is `atomic_app`.

## Architecture Decisions

### Storage: local-first with atomic_lib

The app keeps its data in a local `atomic_lib` database and syncs with an
Atomic Server (WebSocket) and with other devices (Iroh, QR pairing). Auth uses
Ed25519 keypairs (agents).

### Rust Integration: flutter_rust_bridge v2

- **Mobile (Android/iOS)**: FFI via `flutter_rust_bridge` — works with `dart:ffi`
- **Web**: WASM compilation — `flutter_rust_bridge` handles this, but `dart:ffi` is unavailable on web, so the bridge generates WASM bindings automatically
- Rust source lives in `/rust/src/` (crate `atomic_flutter_rust`). Keep it thin: logic that another host
  (Tauri, a native shell, the CLI) could use goes in `atomic_lib::host`
  (`lib/src/host/`: lists, chats, conversations, recents, embed dispatcher) with
  its tests; the bridge binds it to the global store (`rust/src/host.rs`).
- `atomic_lib` is referenced as a local path dependency: `../../../atomicdata-dev/atomic-server/lib`

### Package and identifier names

The Dart package is `atomic_app` and the Rust crate `atomic_flutter_rust`. The
Android `applicationId`/namespace (`com.ontola.atomiccanvas_flutter`, with the
matching Kotlin directory) and the iOS bundle identifier are legacy names kept
on purpose: changing them would orphan the installed app's keys and data.

## File Structure

```
lib/
├── main.dart                    # App entry, MaterialApp, theme
├── theme.dart                   # Re-exports AppColors (packages/atomic_flutter)
├── assistant/
│   └── atomic_assistant_api.dart  # AssistantApi over the bridge (the screens are in packages/atomic_chat)
├── rust_init.dart               # Platform-conditional Rust init
├── atomic/
│   ├── atomic_client.dart       # FFI wrapper (conditional import)
│   ├── session.dart             # Auth persistence (SharedPreferences)
│   └── widgets/                 # Sync + settings widgets
├── screens/
│   ├── login_screen.dart        # Agent auth screen
│   ├── pair_screen.dart         # QR pairing
│   └── sync_screen.dart         # Sync and servers
└── src/rust/                    # Auto-generated flutter_rust_bridge
```

## Dev Environment

- Flutter 3.44+ (via mise, see `flutter/.mise.toml`)
- Rust toolchain for flutter_rust_bridge (needs wasm32 target for web)
- atomic-server as backend (local or remote)
- Run: `mise exec -- flutter run -d chrome` (web) or `flutter run` (mobile)

## Gotchas

- `flutter_rust_bridge` auto-generates files in `lib/src/rust/` — don't edit those manually
- After `flutter_rust_bridge_codegen generate`, reset `pubspec.yaml`/`pubspec.lock`/`rust/Cargo.*` to HEAD and keep the `flutter_rust_bridge` version the repo pins (the codegen rewrites the version header in the generated files)
- `atomic_lib` path dependency means you need `atomicdata-dev` checked out alongside this repo
- On web, `dart:ffi` is unavailable — the bridge handles this but any new Rust bindings must be tested on web too
