# Native Kotlin Android app (fork of the Flutter app)

Goal (Joep, 20 Oct): build the same companion app natively in Kotlin instead of
Dart, reuse the same Rust core, then compare speed and feel with the Flutter
app. Android only. Lives in `android-kotlin/`; `flutter/` is not touched.

## Decisions

- Branch `claude/project-thread-jnltv4`, forked from `claude/flutter-mobile-app-w8e9wz`.
- UI: Jetpack Compose + Material 3, tokens from `flutter/lib/theme.dart` / web app.
- Rust: UniFFI (proc-macro, Kotlin bindings) in `android-kotlin/rust` (crate
  `atomic_kotlin_rust`, cdylib). Logic stays in `atomic_lib::host`; the crate only binds.
  The sync/agent/peer glue of `flutter/rust/src/api/simple.rs` is COPIED (`atomic_flutter_rust`
  has no `rlib`, so it cannot be a dependency; no edit of `flutter/`). Extract it into a shared crate later if the comparison favours Kotlin.
- Resources open in the bundled data-browser embed in one warm WebView, reading
  through `NativeClientDb` over `addJavascriptInterface` / WebMessage to Rust
  (same contract as the Flutter embed, `planning/flutter-resource-webview.md`).
- Android lessons: open redb once per process; HTTPS only via `lib/src/client/tls.rs`.

## Parity checklist (Flutter screens)

- [x] Toolchain + app builds an APK (SDK, NDK, cargo-ndk, UniFFI); not yet run on a device
- [~] Store init, agent persistence, onboarding/login (secret, new agent), recovery + startup-failed screens: built, JVM-tested, not run on a device
- [~] Sync: WS session (reconnecting), home-server discovery, Iroh pairing (QR via CameraX + ZXing or pasted id), real write pusher
- [~] atomic.place account: agent sign-in against the portal, AI status/consent (stage 4); no device link code, no credits page
- [~] Home (built, JVM screenshots only): Drives, Activity, AI Chats (paged), Favorites, Messages (max 4 + show all), search card
- [~] Resource view in warm WebView (embed): built, bundled by Gradle, JVM-tested; never run on a device/emulator
- [~] AI chat: list, read, send, streamed hosted-AI reply with tools, context, new chat, windowed long chats (built, JVM-tested, never run on a device). Missing: voice, attachments, answer-top pinning
- [~] Conversations (DM) and meeting / chat-room chat: list, read, send, poll, rename; the embed's `openNative` opens them (built, JVM-tested)
- [~] `[perf]` marks as Flutter's and a `benchmark` build type with the seed (built; not measured)
- [~] Settings behind the avatar: agent, workspaces, device, servers, peers, edit profile (built, JVM screenshots)
- [~] Tablet layout and the Flutter UX since the fork (sidebar, bar, hold menu, search card, Activity, sections dialog, toasts): built, JVM-tested and screenshotted; never run on a device
- [ ] Performance comparison table vs Flutter (cold start, search per key, resource open)
