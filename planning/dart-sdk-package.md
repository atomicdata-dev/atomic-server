# Dart SDK as a published package

> **Status:** Proposal (2026-09-18). Nothing moved yet. Written alongside the
> docs refresh that added `docs/src/flutter.md`; that page currently points at
> a folder inside the reference app because there is nothing else to point at.

## Goal

`flutter/lib/atomic/` is a general-purpose Atomic Data SDK (`AtomicClient`,
`AtomicStore`, `AtomicSession`, `atomic_auth.dart`, the FRB bridge) that
happens to live inside the Atomic app. Extract it into a package other Flutter
apps can depend on, so the docs can say `flutter pub add atomic_data` instead
of "vendor this folder".

## What is general and what is app-specific

| General (moves) | App-specific (stays) |
| --- | --- |
| `openDb`, agent setup / load, drives, `getProperty` / `setProperty` | `screens/` (login, pairing, sync), `assistant/` |
| history (`warmResourceHistory`, `getResourceHistory`) | `main.dart`, theme, deep links |
| peer sync (`startPeer`, `peerSync`, `peerAnnounce`, `peerDiscoverSync`, known peers) | |
| WS sync (`openWsSync`, `syncDriveToServer`, `resumeSession`, `pollDbEvent`) | |
| `atomic_auth.dart` (pure-Dart request signing) | |
| `server_url.dart`, `server_info.dart`, `session.dart` | |
| `widgets/` sync + settings screens (twins of `SyncRoute` in the browser) | |

The old drawing API (`createCanvas*`, strokes, galleries) is gone from the
bridge, so the Rust side (`flutter/rust/src/api/simple/`) is now almost all
general: `state.rs`, `ws_sync.rs` and the peer functions.

## Shape

```
flutter/
  packages/
    atomic_data/            # the SDK: Dart + rust_builder + FRB config
      lib/
      rust/                 # today's flutter/rust
      rust_builder/
      pubspec.yaml          # name: atomic_data
  apps/
    atomic_app/             # today's flutter/, depends on ../packages/atomic_data
```

`flutter_rust_bridge` generates bindings per crate, so the app keeps a small
FRB crate of its own for app-specific functions, depending on `atomic_data`'s
crate for the store. Alternatively expose a generic `callAction(json)` from the
SDK and keep app logic in Dart.

## Steps

- [ ] Create `flutter/packages/atomic_data` with its own `pubspec.yaml`,
      `flutter_rust_bridge.yaml` and `rust_builder`; move the general Dart
      files and the generated `src/rust/` bindings.
- [ ] Point the Atomic app at the package with a path dependency; keep
      `make phone` / `make tablet` / `make web` working.
- [ ] Move the Dart unit tests in `flutter/test/atomic/` (URL rules, pairing
      parsing, signing parity with Rust) with the package.
- [ ] CI: `cargo test --manifest-path flutter/packages/atomic_data/rust/Cargo.toml`
      replaces the current `flutter/rust` invocation in `AGENTS.md` and the
      dagger job.
- [ ] Publish `atomic_data` to pub.dev from the `v*` tag, the same trigger that
      publishes `@tomic/*` to npm (`.github/workflows/release.yml`).
- [ ] Update `docs/src/flutter.md` (install line, import path) and
      `docs/src/tooling.md`.

## Open questions

- Package name: `atomic_data` vs `tomic` (matching the npm scope). Prefer
  `atomic_data`; the npm scope exists only because `atomic` was taken.
- The web target: FRB compiles to WASM, but the browser already has the
  `wasm/` crate through `@tomic/lib`. One WASM build or two? Not blocking for
  mobile.
- Whether `AtomicStore` (the `ChangeNotifier`) belongs in the SDK or in a
  separate `atomic_data_flutter` package, keeping the core pure Dart.
