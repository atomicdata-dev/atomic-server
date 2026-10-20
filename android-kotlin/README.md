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

## Status (stage 1 and 2)

Done: store init (once per process, recovery), agent + drive first run, drives,
recents, AI chats, favorites, messages, live search, store event callback, Home
screen with Show all, tablet split layout, resource view in the warm WebView
(stage 2; only checked by JVM tests and a successful build, not run on a device
or emulator). Not built: AI chat, native chat-room screens (`openNative` answers
no, so the page draws them), settings page (`path=`), conversations, sync/server connection, settings (avatar is a
placeholder), pairing. Messages show unknown names for other agents until a
server is connected. The crate copies the store-opening glue from
`flutter/rust` because `atomic_flutter_rust` has no `rlib` and cannot be a
dependency.
