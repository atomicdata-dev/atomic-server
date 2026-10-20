# Native Kotlin Android app (fork of the Flutter app)

Goal (Joep, 20 Oct): build the same companion app natively in Kotlin instead of
Dart, reuse the same Rust core, then compare speed and feel with the Flutter
app. Android only. Lives in `android-kotlin/`; `flutter/` is not touched.

## Decisions

- Branch `claude/project-thread-jnltv4`, forked from `claude/flutter-mobile-app-w8e9wz`.
- UI: Jetpack Compose + Material 3, tokens from `flutter/lib/theme.dart` / web app.
- Rust: UniFFI (proc-macro, Kotlin bindings) in `android-kotlin/rust` (crate
  `atomic_kotlin_rust`, cdylib). Logic stays in `atomic_lib::host`; the crate only binds.
  Sync/agent/peer glue that today sits in `flutter/rust/src/api/simple.rs` is
  reused by depending on `atomic_flutter_rust` as a path dependency (no copy,
  no edit of `flutter/`). Extract it into a shared crate later if the comparison favours Kotlin.
- Resources open in the bundled data-browser embed in one warm WebView, reading
  through `NativeClientDb` over `addJavascriptInterface` / WebMessage to Rust
  (same contract as the Flutter embed, `planning/flutter-resource-webview.md`).
- Android lessons: open redb once per process; HTTPS only via `lib/src/client/tls.rs`.

## Parity checklist (Flutter screens)

- [ ] Toolchain + empty app builds an APK (SDK, NDK, cargo-ndk, UniFFI)
- [ ] Store init, onboarding/login, recovery screen
- [ ] Home: Drives, Recents, AI Chats, Favorites, Messages (max 4 + show all), search
- [ ] Resource view in warm WebView (embed)
- [ ] AI chat
- [ ] Conversations (DM) and meeting chat
- [ ] Sync / settings (avatar button), pairing
- [ ] Tablet layout
- [ ] Performance comparison table vs Flutter (cold start, search per key, resource open)
