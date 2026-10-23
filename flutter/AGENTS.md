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
- Rust source lives in `../packages/atomic_store_flutter/rust/src/` (crate `atomic_flutter_rust`). Keep it thin: logic that another host
  (Tauri, a native shell, the CLI) could use goes in `atomic_lib::host`
  (`lib/src/host/`: lists, chats, conversations, recents, embed dispatcher) with
  its tests; the bridge binds it to the default store (`rust/src/host.rs`).
- `atomic_lib` is referenced as a local path dependency (`../../../lib` from the package's `rust/`)

### Package and identifier names

The Dart package is `atomic_app` and the Rust crate `atomic_flutter_rust`. The
The permanent iOS bundle identifier and Android application ID are
`io.ontola.atomic`; the displayed app name is `atomic.place`. The product owner
explicitly approved replacing the legacy development IDs on 2026-10-20 for the
main app's first store release. Do not add canvas, Flutter, or implementation
names to store identity. Android's internal Kotlin namespace may remain legacy.

## File Structure

```
lib/
├── main.dart                    # App entry, MaterialApp, theme
├── theme.dart                   # Re-exports AppColors (packages/atomic_flutter)
├── assistant/
│   └── atomic_assistant_api.dart  # AssistantApi over the bridge (the screens are in packages/atomic_chat)
├── atomic/
│   ├── atomic_client.dart       # FFI wrapper (conditional import)
│   ├── session.dart             # Auth persistence (SharedPreferences)
│   └── widgets/                 # Sync + settings widgets
├── screens/
│   ├── login_screen.dart        # Agent auth screen
│   ├── pair_screen.dart         # QR pairing
│   └── sync_screen.dart         # Sync and servers
```

The Rust crate, the generated bindings (`lib/bridge`), the cargokit native
build and `BridgeStoreBackend` live in `../packages/atomic_store_flutter`
(path dependency); the app imports the bridge as
`package:atomic_store_flutter/bridge/...`.

## Dev Environment

- Flutter 3.44+ (via mise, see `flutter/.mise.toml`)
- Rust toolchain for flutter_rust_bridge (needs wasm32 target for web)
- atomic-server as backend (local or remote)
- Run: `mise exec -- flutter run -d chrome` (web) or `flutter run` (mobile)

## Gotchas

- `flutter_rust_bridge` auto-generates files in `packages/atomic_store_flutter/lib/bridge/` and `rust/src/frb_generated.rs` — don't edit those manually. Regenerate with `cd packages/atomic_store_flutter && flutter_rust_bridge_codegen generate` (version 2.12.0, as pinned); CI (`bridge-codegen` job in `.github/workflows/atomic-flutter.yml`) fails when the committed files differ from a fresh run. Delete a generated Dart file by hand when its Rust module is gone: the codegen leaves stale ones.
- Rust enums with fields need `freezed` in Dart; use a struct plus a unit enum instead
- New generic bridge functions go in `packages/atomic_store_flutter/rust/src/api/resources.rs` with `AtomicError`; the Dart face is `packages/atomic_store` (README layers in `README.md`)
- `atomic_lib` path dependency means you need `atomicdata-dev` checked out alongside this repo
- On web, `dart:ffi` is unavailable — the bridge handles this but any new Rust bindings must be tested on web too
