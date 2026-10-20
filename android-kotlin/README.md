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

## Test data in debug and benchmark builds

`adb shell "echo 30 > /sdcard/Android/data/place.atomic.app.kotlin/files/perf_seed"`,
then start the app: it makes 30 documents/folders, opens each once, adds three
AI chats and three favorites (`DebugSeed`, in `src/seeded`, used by the `debug` and
`benchmark` build types; the `release` source set has an empty stub).

- `perf_seed_long` with a number N: one AI chat "Perf long chat" with N entries, for
  the long-chat marks (`chat data`, `chat painted`, `chat older page`).
- `fake_ai` (any content): the AI chat answers with a scripted, streamed reply, and
  with a `semantic_search` tool call when the message contains "search" (`DebugAi`),
  so the chat can be run and timed without an account.

## Benchmark build

`./gradlew assembleBenchmark` builds `app-benchmark.apk`: the `release` type
(R8-minified, resources shrunk, not debuggable, Rust built with the `release` profile
automatically when a `*Benchmark*` task is requested) plus
`<profileable android:shell="true"/>`, the seed above, the fake AI and the `[perf]`
marks. It is signed with the debug key. Measure with it, not with the debug APK:

```sh
adb install -r app/build/outputs/apk/benchmark/app-benchmark.apk
adb shell "echo 30 > /sdcard/Android/data/place.atomic.app.kotlin/files/perf_seed"
adb shell am start -W place.atomic.app.kotlin/.MainActivity
adb logcat -d -s flutter:I | grep '\[perf\]'
```

A real `release` build has no seed and no marks (`BuildConfig.PERF_MARKS`).

### `[perf]` marks

Same names, format and logcat tag (`flutter`, priority I) as the Flutter app
(`packages/atomic_flutter/lib/src/perf.dart`), so `flutter/scripts/perf_android.sh`'s
log reading works on both: `[perf] <name> <ms> ms` is a mark since `Application.onCreate`,
`[perf] <name> <ms> ms (span)` a span the app timed. Debug and benchmark builds only.

| Mark | Where |
| --- | --- |
| `main`, `first frame` | `Perf.start()` in `onCreate`; first draw of the activity window |
| `db open`, `session restored` | store opened; signed in again from the saved secret |
| `home start`, `home <list>` (span), `home data` | `HomeViewModel`; `home data` when all five lists are in |
| `home painted` | the frame after `home data` |
| `warm ready` | the embed page said `ready` |
| `search query` (span), `search keystroke to results` (span) | Rust query; last key to the frame that shows its results |
| `resource painted warm\|cold`, `... since tap`, `resource painted in page ...` | the page's `main` shows the title (JS injected by the bridge, as in Flutter), two frames later |
| `resource revealed warm\|cold`, `... since tap` | `main[about=subject]` holds more than a loading state (JS from Flutter's `_watchReveal`) |
| `chat data N`, `chat painted N`, `chat older page N` | native chat screens: first page read, messages on screen, each older page |
| `[chat] +Nms first event` | AI chat: time to the first streamed event |

"Since tap" is the time since the last finger lifted anywhere (`MainActivity.dispatchTouchEvent`,
as Flutter's `watchTaps`). `warm` means the embed page was ready when the resource was opened.
Not marked (Flutter has them, this app has no equivalent step): `rust init`,
`documents dir`, `runApp`, `session loaded`, `resource data warm|cold`.

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

## AI chat, conversations and chat rooms (stage 4)

```
Kotlin  AiChatModel / ThreadModel (one for DMs and rooms)   ChatWindow   HostedAi   AccountClient
           |  ChatBackend / ThreadSource (CoreChatBackend = UniFFI; FakeChat in the JVM tests)
Rust    chat.rs: windowed reads, append_ai_chat_entry, conversations, rooms, sign_with_agent
```

- **AI chat** (`AiChatScreen`, Flutter's `ChatScreen`): the AI chats list on Home opens
  it; "New chat" next to the heading starts one. A new chat offers two drives and the
  latest opened as context pills, and the attach button searches for more. The chat is
  created with the first message (named after it, 40 characters) and both messages are
  saved in the web app's `ChatLog` format (`parts`, and the attached resources in `ctx`),
  so the web app reads them too. Markdown answers, tool calls as steps, Stop keeps what
  has streamed.
- **The AI route is Flutter's, the account's credits, and only that**: the Flutter app has
  no own-API-key route, so neither has this one. The active agent signs in to
  `https://atomic.place` (`POST /api/auth/agent/challenge`, then `/api/auth/agent?if_linked=true`,
  signed in Rust by `sign_with_agent` so the key never leaves it), the `session_token` cookie
  is kept sealed by the Keystore next to the agent secret (`SessionStore.accountSession`),
  `GET ai/status`, `POST ai/consent` ("Turn on AI"), then `POST /api/ai/chat/completions`
  as an SSE stream. The app runs the tools (`semantic_search`, `get_atomic_resource`) itself
  and goes on with their results, at most 8 rounds. The model gets the latest 40 messages
  (and about 24 000 characters) of a long chat.
- **Long chats** page like Flutter's `ChatWindow`: the newest 50, older pages as the list
  scrolls up, at most 500 held (the oldest drop near the bottom, the newest far up and
  come back), "Jump to latest" once scrolled up. Cursors are message ids.
- **Conversations (DMs, end-to-end encrypted) and chat rooms / meetings** (`ThreadScreen`):
  bubbles, day separators, a meeting's events as lines, a pending message while sending,
  the text back in the field when a send fails, a poll every 3 s while open, rooms can be
  renamed. Conversations are fetched onto the device when needed (`follow_conversation`).
- The page's `openNative(kind, subject, title)` opens these screens for `chatroom`,
  `conversation` and `aichat` (answers `true`, as Flutter); the page reads the resource
  again when the screen closes. Everything else stays `false`.

## Status (stages 1 to 4)

Done and checked only by `cargo test`, JVM tests and a successful build (nothing was
run on a device or emulator here): store init, agent persistence, first run, sign in,
drives, Home, resource view, settings, servers, pairing, profile, recovery screens.

Stage 4 (AI chat, conversations, rooms, perf marks, benchmark build) is also only
JVM-tested and built; see the list of what never ran below.

Not built: linking a device with a code and the account pages of the portal (credits,
billing, Cloud Vault rows), agent pictures (emoji or initial only), voice input and file
or photo attachments in the AI chat, pinning the answer's top while it streams (Flutter's
`AnswerTop` behaviour; here the list follows the end), an own-API-key AI route (Flutter has
none). Names of other agents come from the connected server.

Differences from Flutter that are deliberate or forced:
- Paging reads through the Rust crate over a whole-chat read and cuts it at the id cursor
  (`rust/src/chat.rs`): the branch's `atomic_lib` has no `read_chat_page`. Correct, but the
  read cost grows with the chat; swap it for the lib's page read when it lands.
- The resources attached to a message are kept in the entry's `ctx` as JSON with a title and
  class (Flutter drops them); the web app only reads `type` and `subject`.
