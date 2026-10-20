# atomic.place for Android, native Kotlin

A Kotlin / Jetpack Compose fork of the Flutter app (`../flutter`). Same Rust
core (`atomic_lib::host`), native UI. Plan and parity checklist:
`../planning/android-kotlin.md`. Applicationid `place.atomic.app.kotlin`, so it
installs next to the Flutter app.

```
android-kotlin/
  rust/     crate atomic_kotlin_rust (cdylib, UniFFI proc-macro bindings), own [workspace]
  app/      Gradle module: Compose UI, runs cargo-ndk + uniffi-bindgen + the embed build
  scripts/  build_embed.sh: the web embed (browser/data-browser, vite.embed.config.ts) as app assets
```

## Toolchain (reproducible, as set up in the cloud container)

Needs: JDK 17+, Gradle 8.14 (the wrapper downloads it), Rust (see
`../rust-toolchain.toml`), `unzip`, `curl`. The SDK lives outside the repo.

```sh
# 1. Android SDK: cmdline-tools, platform 35, build-tools 35, platform-tools, NDK 27
export ANDROID_HOME=/opt/android          # or ~/android
mkdir -p $ANDROID_HOME/cmdline-tools
curl -sSLO https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip
unzip -q commandlinetools-linux-13114758_latest.zip -d /tmp/clt
mv /tmp/clt/cmdline-tools $ANDROID_HOME/cmdline-tools/latest
yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager \
  "platforms;android-35" "build-tools;35.0.0" "platform-tools" "ndk;27.2.12479018"

# 2. Rust targets and cargo-ndk
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk --locked

# 3. Tell Gradle where things are (local.properties is gitignored)
echo "sdk.dir=$ANDROID_HOME" > android-kotlin/local.properties
```

`ANDROID_NDK_HOME` is derived by the Gradle task from `$ANDROID_HOME/ndk/27.2.12479018`.
There is no `/dev/kvm` in the cloud container, so no emulator runs there; UI is
checked with JVM screenshot tests (Roborazzi) instead, see below.

## Build and test

```sh
cd android-kotlin
(cd rust && cargo test)             # host-facing Rust, runs on the Linux host
./gradlew testDebugUnitTest         # Kotlin unit tests + Home screenshot tests
./gradlew assembleDebug             # cargo-ndk (arm64-v8a, x86_64) + uniffi-bindgen + APK
```

Gradle needs `ANDROID_HOME` (or `local.properties`) and reaches the network for
Maven artifacts. In the cloud container Maven Central answers 429 to the shared
proxy; a container-local init script (`~/.gradle/init.d`, not in the repo) that
adds `https://maven-central.storage-download.googleapis.com/maven2/` as first
repository fixes that. `-PrustRelease=true` builds the Rust core with the
fat-LTO `release` profile (slow); the default uses the `dev` profile.

`assembleDebug` (and anything that merges assets, also `testDebugUnitTest`) first
runs `buildEmbed`, which calls `scripts/build_embed.sh`: `pnpm install`, the
`@tomic/*` packages, then `vite build -c vite.embed.config.ts` (same recipe as
`flutter/scripts/build_embed.sh`), copied to `app/build/generated/embed/assets/embed`
and packaged as `assets/embed/` (about 14 MB, not committed). Needs Node 22+ and
pnpm. `-PskipEmbed=true` bundles a placeholder page instead (Rust or Kotlin
work without Node).

## Resource view (stage 2)

Tapping a row (Home, search, drive) opens `ResourceScreen`: a Compose top bar
(title, back) over ONE WebView that `EmbedController` creates once the store is
open and keeps alive. Opening is a route change, `atomicEmbed.open(subject)`;
leaving flushes pending edits (`atomicEmbed.flush`) and blanks the route. Back
(arrow or gesture) first asks the page (`atomicEmbed.back()`: overlays, in-page
history) and returns to Home when it has nothing to go back to.

```
WebView (https://appassets.androidplatform.net/embed.html, from assets, no network)
  AtomicFlutter.postMessage({id,method,args})   <- addJavascriptInterface, same name as in Flutter
  window.__atomicReply(id,ok,payload)           -> evaluateJavascript
        |                                                    ^
   EmbedBridge (Kotlin: ready/pending open, openNative/theme/opened, flush, back)
        |  embed_dispatch(method, argsJson)  UniFFI, async         | EmbedListener.on_changed(subjects)
   atomic_lib::host::embed::EmbedHost  (signs only commits of this device's agent)
```

The call contract is the Flutter embed's (`planning/flutter-resource-webview.md`,
`lib/src/host/embed.rs`); the unmodified bundle runs. The page holds no store
and no secret (the Loro WASM in the bundle is code for editing documents, not
storage). `EmbedWebViewClient` serves only bundled files and refuses every other
request (`blockNetworkLoads` too); links out of the page open in the system.
Store changes reach the page as `changed([...])`, batched (60 ms) and without the
commits the page applied itself (`embed.rs`: echo filter).

## Screenshots without an emulator

`HomeScreenshotTest` (Robolectric + Roborazzi) renders the real `HomeScreen`
composables with fake data. Output goes outside the repo:

```sh
SHOTS_DIR=/tmp/claude-0/kotlin-shots ./gradlew testDebugUnitTest -Proborazzi.test.record=true
```

## Test data in debug builds

`adb shell "echo 30 > /sdcard/Android/data/place.atomic.app.kotlin/files/perf_seed"`,
then start the app: it makes 30 documents/folders, opens each once, adds three
AI chats and three favorites (`DebugSeed`, compiled out of release).

## Account, sync and settings (stage 3)

```
Kotlin  AccountFlow (start-up, sign-in, find the drive)   SettingsModel   PairModel
           |  Backend interface (CoreBackend = UniFFI; FakeBackend in the JVM tests)
Rust    session.rs (resume)   sync/ws.rs (WebSocket, reconnects)   sync/peers.rs (Iroh, pkarr, push)
        sync/discovery.rs (home server, /server, /drive-usage)   pairing.rs   sync_api.rs (exports)
```

- **The store keeps the active drive, not the agent.** `Db::default_agent` is in
  memory, so `SessionStore` keeps the secret (AES-GCM key in the Android Keystore,
  `session/`) and `resume_session` / `resume_agent` loads it on every start. Without
  it every start was a first run with a new agent.
- Local writes (Home, the embedded page) go through the real pusher
  (`state::RealPusher`: outbox drain over WS, live peers, paired devices), not `NoPush`.
- `sync/ws.rs` and `sync/peers.rs` are copied from `flutter/rust/src/api/simple*`
  (not a dependency, see above); the WS session additionally reconnects with a 2 s to
  60 s backoff. All HTTPS goes through `atomic_lib::client`, whose TLS is
  `lib/src/client/tls.rs`.
- Screens: login (create, secret to save, sign in with a secret, sync your drive),
  settings behind the avatar (agent, workspace switcher, this device, servers, paired
  devices, sync status), pairing (own QR drawn with ZXing, camera frames read with
  CameraX + ZXing, or a pasted node id), edit profile, store recovery, store-open and
  startup failures. Components: `SettingsRow`, `AtomicDialog`, `SettingsGroup`,
  `ErrorBox`, `AtomicScaffold` (`ui/Components.kt`).
- The manifest now has INTERNET and CAMERA (it had neither); a FileProvider shares
  the damaged store file.
- The warm WebView is laid out at screen size before the page loads and gets
  MATCH_PARENT params when shown (a 0 x 0 view made `100dvh` 0 and the page body blank).

## Status (stages 1 to 3)

Done and checked only by `cargo test`, JVM tests and a successful build (nothing was
run on a device or emulator here): store init, agent persistence, first run, sign in,
drives, Home, resource view, settings, servers, pairing, profile, recovery screens.

Not built: signing in with an atomic.place account (portal, AI credits, Cloud Vault
rows), agent pictures (emoji or initial only), AI chat, native chat rooms,
conversations screens. Names of other agents come from the connected server.
