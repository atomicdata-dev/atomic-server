# Flutter app performance

> **Status:** measured and first round of fixes, 2026-10-20 (branch
> `claude/flutter-mobile-app-w8e9wz`). Emulator only so far; the numbers that
> matter are the ones still to be taken on the Xiaomi phone and Pad (below).

## How to measure

```
cd flutter
flutter build apk --profile --target-platform android-arm64 --dart-define=FAKE_AI=1
scripts/perf_android.sh -a build/app/outputs/flutter-apk/app-profile.apk [-s SERIAL] [-n 5] [-o out.md]
scripts/perf_android.sh --seed 30 --only size     # once per install: test data
```

- `FAKE_AI=1` (the chat step's canned AI) only on the emulator or a test
  phone: every reply says "FAKE AI, test build". An APK for someone's own
  phone is built without it.
- Always a **profile** build. Debug is several times slower; release prints
  no marks. Cargokit builds the Rust library `--release` for profile and
  release (`rust_builder/cargokit/build_tool/lib/src/builder.dart`).
- The app logs `[perf]` lines in debug and profile builds
  (`packages/atomic_flutter/lib/src/perf.dart`): start-up marks, the home
  lists, opens (`resource data`, `resource painted`, and `resource painted in
  page`, timed by the page itself), the first embed calls of a page, search,
  and one summary per burst of frames (janky %, build/raster p50/90/95/99).
  `dumpsys gfxinfo` does not see Flutter's surface, so the frame numbers
  come from `FrameTiming`.
- `--seed N` makes N documents/folders and 3 AI chats through a debug/profile
  hook (`flutter/lib/perf_seed.dart`, triggered by a file adb writes) and
  fills "Perf document 0" with 80 kB of text over DevTools.
- The script force-stops the app many times. Do not point it at a phone whose
  data matters (see "Store lost after a kill" below).
- Timing is not a CI check (device-bound, noisy). The embed bundle budget
  (`scripts/check_embed_size.sh`) is the deterministic part and runs in CI.

## Budgets

On a mid-range phone (Xiaomi), profile build, warm OS caches, seeded identity:

| What | Budget | Emulator now |
| --- | --- | --- |
| Cold start: process start → Home painted with data | < 1500 ms | 3260 ms (2650 ms with the dex compiled) |
| Cold start: first frame | < 800 ms | 2320 ms |
| Hot start (`am start` TotalTime) | < 200 ms | 136 ms |
| Open from Recents, warm page: tap → resource painted | < 500 ms (embed plan: 250 ms first content) | 1386 ms (page's own clock 1137 ms) |
| Open, cold page (no spare) | < 1500 ms | not captured (the spare is back within 1.5 s) |
| 80 kB document, warm page | < 800 ms | 1940 ms |
| Search: last keystroke → results drawn | < 50 ms | 24 ms (Rust query 12 ms; no debounce) |
| Tap → next frame drawn (any button, row, toggle) | < 16-50 ms | 6-28 ms |
| Scrolling Home: janky frames | < 1 % | 6.5 % (raster-bound: emulated GL) |
| App PSS after start | < 200 MB | 220 MB |
| Web view renderer PSS with the spare | < 120 MB | 158 MB |
| Rust library in the APK | < 25 MB | 23.1 MB |
| Embed first-use chunks | < 1000 kB gzip (CI) | 938 kB |

## Results (emulator)

Phone_A35 AVD (Android 15, arm64) on an M5 Pro. The host was busy for most
of the session (load 15-40 from Spotlight indexing and other builds), which
spread single runs over 2-5x; the comparisons below were run interleaved
(`baseline, change, baseline, change`) and compare medians or per-run phase
durations. Treat them as direction, not as phone numbers.

| Metric | Before | After |
| --- | --- | --- |
| Cold: Home painted (process start), quiet host, 8 interleaved runs | 3627 ms | 3261 ms |
| Cold: first frame | 2633 ms | 2320 ms |
| Cold: first frame → Home painted, busy host (8 runs each) | 2654 ms | 790-1009 ms |
| Cold: first frame → session restored, busy host | 2406 ms | 446-698 ms |
| Open document from Recents (warm), painted | 1639 ms | 1251 ms |
| Open 80 kB document (warm), painted | 2179 ms | 1942 ms |
| Page's own clock, document / 80 kB | 1328 / 1844 ms | 965 / 1382 ms |
| Rust library (arm64, stored uncompressed) | 33.2 MB | 24.2 MB (23.1 MiB) |
| APK entries (compressed) | 88.0 MB | 75.3 MB |
| Logcat lines from the app in the first 8 s | 1532 | 135 |
| Search keystroke → results | 143 ms | 157 ms (unchanged; noise) |
| Hot start | 124 ms | 136 ms (unchanged) |
| AI chat (FAKE_AI), send → first token | 401 ms | 402 ms (the fake waits 400 ms itself; its frame summary was not captured on the emulator) |

What changed (one commit each):

1. `Store open: no page walk for a store far below the compaction floor`:
   every open walked all redb pages (258 ms for 6 MiB on the emulator) to
   decide on a compaction that never happens below 256 MiB.
2. `Bridge: log at warn for the log crate, no backtrace capture for errors`:
   flutter_rust_bridge's default utils logged rustls/reqwest/iroh at Trace and
   made every `anyhow` error capture a backtrace.
3. `Bridge: resume answers before Iroh is up`: the resume waited for the Iroh
   endpoint and its relay (0.5 s online, up to the 10 s timeout when the relay
   does not answer). `start_peer` is serialized so the background start and a
   sync button share one endpoint.
4. `App start: one session resume, read once, theme read while the store
   opens`: two concurrent resumes (sign-in screen and `AtomicApp`), two secure
   storage reads, two sync-event loops.
5. `Warm page: render the latest recent once while hidden`: the spare's first
   render ran cold JS (a second render of a document in the same page took
   323-555 ms against 1.3-1.8 s); it now renders the top of Recents once,
   then goes blank, and the taker reloads that resource.
6. `Bridge: fat LTO and one codegen unit`: library 33 → 24 MB; a release
   Rust rebuild takes about 3.5 min instead of under 1 min.

## Round 2: "instant" (2026-10-20)

Goal: every tap or keystroke shows feedback within a frame, local content
within 50-100 ms where the work allows. Emulator, profile build, interleaved
with the round 1 APK as baseline.

| Metric | Before | After |
| --- | --- | --- |
| Search: last keystroke → results drawn (median, n=4-5) | 154 ms (146-219) | 24-33 ms (17-76) |
| Search: Rust query | 18 ms | 12 ms (unchanged, noise) |
| Open: the opened 80 kB document's read, page asks → answered | 200-280 ms | 2-21 ms (read on pointer-down) |
| Open, warm, tap → painted (doc / 80 kB doc) | ~1.4 / 1.6 s | 1.4 / 1.5 s (emulator-bound, see below) |
| Page slide in / out | 380 / 320 ms | 150 / 150 ms; none in the tablet detail pane |
| Tap → next frame: bar buttons, Home section toggle, + menu, rows | not measured | 6-28 ms (one 217 ms Home tap out of 3, from a settings web page) |

Commits:

1. `Perf: log tap to next frame for every tap, and time since the tap`
   (`[perf] tap ? to frame N ms`, `Perf.sinceTap`). No handler found that
   blocks the UI thread: no sync FFI or big decode on a tap path.
2. `Search: query on every keystroke, no 120 ms debounce`: one search at a
   time, the latest text next, stale answers dropped, recents kept until the
   first hits (no empty frame, no spinner).
3. `Pages slide in and out in 150 ms, the detail pane swaps at once`.
4. `Open: read the resource when the finger goes down on its row`
   (`WarmResourceWebView.prefetch`, used by the page's batch read, once, for
   1.5 s). With `adb input tap` down and up are one instant, so the emulator
   only shows the read itself vanish; a finger adds its 50-120 ms.

Tried and dropped: reading the resource the spare rendered ahead after the
opened one instead of before (no gain: the bridge runs both reads at once).

What an open still spends (emulator, screen recording at 20 fps):

- ~450 ms after the tap the screen does not change at all (the bar's icon
  changes, the page does not slide in): Flutter's own frame is built in
  <20 ms and rasterized in <20 ms, so this is the Android main thread
  attaching the web view (platform view) under emulated GL. Then the page
  is up, dark, with the web app's own loading spinner for ~0.9 s, then the
  title, then the text ~0.3 s later.
- The page asks for the opened resource 250-500 ms after `open` (its JS),
  and each reply reaches it 500-900 ms after it was answered.

To re-measure on the Xiaomi (phone and Pad):

- [ ] `scripts/perf_android.sh -s <serial> -a app-profile.apk --only open,search`
      (fresh test data on a test install only): search should be < 50 ms,
      `open ...: tap to painted` and the `[perf] embed ... delivered at` gaps.
- [ ] A screen recording of an open (`adb shell screenrecord`, frames at
      20 fps): the time from the tap to the first changed frame. If the web
      view attach freezes the screen there too, keep the warm web view
      attached (offstage) or draw the page's top bar natively first.
- [ ] `[perf] tap ? to frame` over a few minutes of use: anything > 50 ms.
- [ ] Whether the 150 ms slide feels right on the phone, and the instant
      swap on the Pad.

## Round 3: the warm web view stays attached (2026-10-20)

Changes (commits `Embed: no loader for the first second…`, `Open: keep the
warm web view attached under the pages…`):

- The ready spare is in the widget tree: `WarmPageSlot` under the shell's
  navigator (phone pages / tablet detail pane), same box and insets as a
  resource page, `Opacity(0)` + `IgnorePointer` + `ExcludeSemantics`. On
  Android the web view is a texture layer (TLHC): it is created by layout,
  so its Android view is attached and laid out before the tap and keeps
  drawing into its texture; opacity 0 only leaves the layer out.
- `ResourceView` takes the page and moves the same `GlobalKey`ed subtree in
  one frame later (the slot lets go after the take's frame; same frame would
  be a duplicate key): the platform view is not made again and not resized
  (widget tests check both, plus rotation phone ↔ tablet with the spare and
  with an open page, release after close, memory pressure).
- Until the page's `main[about=subject]` holds more than a loading state
  (posted as `revealed`, two frames later), a native `ResourceSkeleton`
  covers it: the page colour and a 36 px header with the row's title. Caps:
  2 s warm, 8 s cold. Then a 90 ms fade. No spinner in Flutter.
- The page: a centered `Spinner` in the embed waits 1 s (empty status until
  then); `?scheme=dark|light` sets the host scheme before the first render;
  the pool tells a ready spare the app's scheme.

Emulator (Phone_A35, profile, host load 5-7, interleaved with the round 2
APK). Screen recordings (only frames that change, analysed per frame from
the push frame: the bar's Home icon turning to an outline, which Flutter
logs 8-14 ms after the tap):

| Open from Recents, warm | Before | After |
| --- | --- | --- |
| Push frame → screen frozen (nothing moves) | 550-980 ms in 3 of 10 opens, else none | none in 11 opens |
| Push frame → page's title as it ends up, top row (rendered ahead) | 314-1016 ms (median 340, n=9) | 279-380 ms (median 330, n=6) |
| Push frame → title, second row | 366-447 ms (median 430, n=5) | 318-401 ms (median 380, n=5) |
| First thing on the page | a black page sliding in | the page colour with the row's title sliding in |

Logged (`perf_android.sh --only open`, 4 interleaved runs of 3-4 opens): tap
→ painted (title in `main`, after the message reaches Dart) did not move
beyond the noise: doc 1139-1585 vs 173-1310 ms medians per run, 80 kB
doc 1406-2251 vs 307-2169 ms. One quiet run gave 173 / 307 ms; the rest
are dominated by replies to the page waiting 300-1500 ms for the main
thread (the emulator's GL, see below), which the video does not show:
the title is on screen at ~330 ms while the log says 1.2 s. Renderer PSS
with the spare 143 vs 149 MB, after opens 335 vs 357 MB, app 226 vs
231 MB: no memory cost for keeping it attached.

To check on the Xiaomi (phone and Pad):

- [ ] Screen recording of opens from Recents: first changed frame after the
      tap (should be the next frame) and the title.
- [ ] `--only open,memory`: `tap to revealed` vs `tap to painted`, renderer
      PSS with the spare attached, and after 10 opens.
- [ ] Battery/CPU with the spare attached and idle (it should draw nothing).
- [ ] Rotation and split-screen with only the spare loaded, and with a page
      open; a TalkBack pass (the hidden spare must not be announced).
- [ ] The skeleton's header against the page's breadcrumb (a small jump:
      the page also shows the drive).

## Where the time goes now (and what is emulator-only)

- **Process start → Dart `main`: 1150 ms**, of which about 600 ms is the
  profile build's dex running interpreted (18 dex files, no R8): with `cmd
  package compile -m speed` `main` starts at 580 ms and Home paints at
  2650 ms. A Play install gets cloud profiles; a baseline profile for the
  app's Java side would help sideloaded builds.
- **`main` → store open: ~1100 ms of the Android main thread**, sampled with
  SIGQUIT stacks: `FlutterJNI.nativeSurfaceCreated` (Impeller on emulated
  OpenGL ES, likely much less on a phone's Vulkan), and `flutter_tts`, which
  creates a `TextToSpeech` when the engine attaches and enumerates every voice
  (`getVoices`, Java deserialization) on the main thread at every start, for a
  feature only voice mode uses. `MainActivity` now takes the plugin out of engine start-up and
  `PluginSpeechOutput` asks for it before the first utterance (unmeasured:
  check the `main` -> `documents dir` gap on the phone).
- **Opening a resource**: the page's own render is 1.0-1.4 s; on the emulator
  every web view frame also blocks the Android main thread (it waits in
  `ThreadedRenderer.syncAndDrawFrame` while the RenderThread draws the web
  view through the qemu GL pipe), and with Flutter's merged UI/platform thread
  that stalls Dart too: replies to the page took 500-800 ms to be delivered.
  On a phone this hand-over should be milliseconds; check the gap between
  `resource painted` and `resource painted in page` there.
- **Embed bundle**: the first-use set is 938 kB gzip, 543 kB of it the
  `Providers` chunk (1.7 MB raw). It loads in the hidden spare, off the tap's
  path; splitting it helps the cold path and the spare's memory. Not done.
- **Memory**: app 220 MB PSS, the web view renderer 150-160 MB with the
  spare, up to ~400 MB right after a burst of opens (cold pages and the 80 kB
  document) and back to ~160 MB within a minute; no page leak (released pages
  leave `/json`).
- **APK**: the profile APK also carries `mobile_scanner`'s barhopper for x86_64
  and armeabi-v7a (9 MB); release and profile builds now exclude them (`build.gradle`, unmeasured: check the entries with the size script).
  Gradle's incremental packaging leaves the APK file at its old length (99 MB
  on disk, 75 MB of entries): the script reports the entries.

## Found on the way

- **Store lost after a kill** (fixed): three times the redb store did not
  open after a kill (`raw_file_len >= header.layout().len()` panic, app black).
  Root cause: Android re-runs `main` in the same process when it recreates
  the activity (back out, start again), `open_db` opened a second redb handle
  on the live file (the APK's Rust is cargokit's `stable`, 1.95, whose std
  has no file lock on Android, so redb opened without one), `set_db` dropped
  it, and its drop trimmed the file under the first handle; the first
  handle's next commit wrote its longer layout into the header and the next
  kill left a file shorter than its header. Reproduced on the emulator in one
  try and with an unlocked backend on the host. Fixed: `open_db` keeps an
  open store, `RedbStore` refuses a second handle per process
  (`db::recovery::OpenFileGuard`), the open never panics, a damaged store is
  kept as `atomic.redb.corrupt-<ms>` and repaired on a copy (all three kept
  stores repair) or replaced by an empty one, the app explains it (recovery
  screen with Share) and never stays black, and it flushes on background.
  Emulator kill-loop afterwards: 50 force-stops, 25 of them after a
  same-process relaunch, 0 failures. cargokit now builds with the repo's pinned
  toolchain (`rust-toolchain.toml`), so `File::try_lock` works on Android.
- **ANRs on the emulator** while opening and leaving pages: the main thread
  waits for the RenderThread drawing the web view through emulated GL
  (stacks above). Probably emulator-only; watch for it on the phone.
- The existing `startup_compaction_shrinks_a_bloated_store_and_keeps_every_resource`
  test is flaky (the second open compacts again in about half the runs), with
  and without change 1.

## To measure on the Xiaomi phone and Pad

`scripts/perf_android.sh -s <serial>` with a profile build, on a throwaway
identity (`--seed 30` once), and note the device in the result.

- [ ] Cold start marks: is `main` → `documents dir` (main thread busy) still
      ~1 s? If so, sample it (`kill -3`) for `flutter_tts` and the surface.
- [ ] Open from Recents: `resource painted` vs `resource painted in page`
      (the hand-over), warm vs cold, and the 80 kB document.
- [ ] Scrolling Home and a streaming AI reply (`FAKE_AI=1`): janky %, raster
      p99 on real GPU.
- [ ] PSS of the app and the renderer with the spare, and after 10 opens.
- [ ] Whether a kill during use ever leaves the store unopenable there.
- [ ] Release build once: start-up without profile overhead.

## Stress test: 1000 chats (2026-10-20)

Joep: "Make a drive, give it 1000 AI chats with a lot of text, see if search
and UI are still fast." Phase 1 and 2 (Rust, on the Mac) are done; phase 3
(the app on a device) is planned below and waits for an emulator slot.

### Method

`lib/tests/stress_chats.rs`, two ignored tests, each in its own process:

```
STRESS_DIR=<scratch>/stress STRESS_TEXT_SCALE=1.5 \
  cargo test -p atomic_lib --features db-redb --profile e2e --test stress_chats -- --ignored --nocapture stress_seed
STRESS_DIR=<scratch>/stress \
  cargo test -p atomic_lib --features db-redb --profile e2e --test stress_chats -- --ignored --nocapture stress_measure
```

- **Data**: a private drive and a "Work" drive with 2000 documents and
  folders (7.6 MB of body text, nested folders), and 1000 AI chats with 20-60
  messages each (39 505 messages; user 300-2250, assistant 2250-6000 chars at
  scale 1.5): multilingual prose (en/nl/de/fr/es with a Zipf vocabulary and a
  40 000-word long tail), headings, lists and code blocks; 106 MB of message
  text. Ten chats are written one `append_entry` per message (as the app
  does while chatting), the rest with the new `host::chats::import_ai_chat`
  (one commit per 256-message page). The recents listener runs during the
  seeding, as in the app.
- **Measure**: opens the store the way the bridge's `open_db` does (file,
  search catch-up, recents load and listener), then the host calls the app
  makes, 10-20 repetitions each: first call (cold) and median/p95 of the rest.
  `STRESS_COMPACTION_CHECK=1` adds the startup compaction check,
  `STRESS_TREES=1` the per-tree size breakdown, `STRESS_REBUILD=1` a full
  search index rebuild; `stress_reopen` opens and closes the file 3x.
- **Build**: the `e2e` profile (opt-level 2, no LTO) with debug assertions
  off for redb, loro and atomic_lib (`--config
  'profile.e2e.package.<crate>.debug-assertions=false'`); with them on, redb
  walks every page at open (`mark_allocated_page_for_debug`), which a debug
  app build also does. The app ships fat-LTO opt-level 3. M-series Mac, warm
  OS cache; a mid-range phone is roughly 3-5x slower.
- **Size**: the store is 1.08 GB (775 MB on disk; the cap for this run was
  1.5 GB, so the text was not scaled down). Deleted after the run.

### Results

Host calls, ms (first = cold, then median / p95), before (`ca1be557d`) and
after the fixes (`9b773ee4f`):

| What | Before | After |
| --- | --- | --- |
| open_db: init_redb_file | 94-1025 (compaction check walks every page), once 60 733 | 12-24 (check weekly: 118) |
| RSS right after open | 870 MB | 11 MB |
| Home: `list_ai_chats(4)` after the listener lagged | 1854 (rescan) | 0.13 (rescan in the background) |
| Home: `list_ai_chats(4)` / `(50)` warm | 0.07 / 0.5 | 0.12 / 0.7 |
| "All": `list_ai_chats(1000)` (169 KB JSON) | 11 | 9.2 (86 cold) |
| Chat index rescan (no recents.json) | 1200* | 884*; 830-920 without assertions |
| search "k" / "b" / "s" (1 letter, all drives) | 8.0 / 9.9 / 11.3 | 1.6 / 2.2 / 2.0 (first 9-33) |
| search "ku" / "bu" / "se" / "be" (2 letters) | 19.0 / 20.9 / 34.6 / 30.6 | 0.5 / 1.0 / 1.0 / 1.4 |
| search "kub" / "bud" / "sea" / "ver" (3 letters) | 4.2 / 4.2 / 6.2 / 11.7 | 3.7 / 3.5 / 5.1 / 9.8 (first 10-62) |
| search full word ("budget", "vergadering") | 3.5 / 3.6 | 3.0 / 3.1 |
| search two words ("kubernetes dep") | 8.1 | 6.6 |
| search "b" in one drive / 100 hits | 15.2 / 13.7 | 3.5 / 5.6 |
| search AI chats only (isA filter in the index), "b" / "budget" | 5.7 / 2.3 | 1.4 / 2.0 |
| `read_chat` of a 60-message chat (166 KB JSON) | 1.56* | 1.23*; 1.1 without assertions |
| recents / activity / drives lists | 0.15 / 0.09 / 0.66 | 0.14 / 0.08 / 0.55 |
| seeding: `append_chat_entry` / `import_ai_chat` | 10.3 ms per message / 1838 messages/s | 7.7 ms / 2391 messages/s |

\* measured with debug assertions on (the first runs); the other numbers
without.

Targets: search keystroke → results < 50 ms (met with room: worst warm 10 ms,
worst cold first keystroke 62 ms on the Mac, so expect up to ~200 ms for the
very first keystroke after a cold start on a phone); Home < 100 ms (met);
'All' first page < 50 ms (met for the host call; the UI is not lazy, see
below); open_db < 1.5 s (met, 24 ms; but see compaction).

Store breakdown (`STRESS_TREES=1`, uncompressed values): the 113 MB of
text is held four times, in the resources' rows (154 MB; probably the last
commit's `loroUpdate`, which for a page written in one commit is the whole
snapshot), the Loro snapshots
(144 MB), the commit envelopes (182 MB) and the outbox (173 MB; this device
never synced, a connected one drains it). redb then stores 519 MB plus
503 MB of slack in the pages that hold large values. Search postings are
5.6 MB: chat text is not indexed.

### Fixes (commits)

- `7c9d8c760` Chats: a chat's pages are decoded once (was get_resource +
  export + re-import, three passes), and the recents rescan reads only the
  entry times.
- `478f299cb` Bridge: the startup compaction check (a walk of every page,
  which also fills redb's 1 GiB cache with the whole store) runs once a week
  or when the file grew by a quarter, recorded in `compaction-check` next to
  the store.
- `bcd300900` Search: typo variants from three letters on; a single one- or
  two-letter token scans titles only.
- `9bfb9adfe` Recents: after a lag the listener rescans the chats once the
  events calm down; the Home list no longer waits for it (only an empty index
  does).

### Open findings

- [ ] **Chat text is not searchable.** The index covers titles, descriptions
      and document bodies (`documentContent`); a `ChatLog` page's entries are
      not extracted, so a word that only occurs in messages finds nothing
      (`zephyrquokka`: 0 hits). Indexing it is a product decision: about
      100 MB more text in the postings for this store, and re-tokenising a
      page (up to 256 messages) on every appended message unless the indexer
      learns to add one entry's tokens.
- [ ] **Startup compaction of a big store blocks the first frame.** The very
      first measuring open of the first seeded store took 60.7 s inside
      `init_redb_file` (logs not captured; two later seeds had 1 %
      reclaimable and did not compact, and the weekly check costs 118 ms).
      A compaction of a 1 GB store, when it is due, runs before the app
      draws. Consider compacting on the phone only while charging / in the
      background, or with a time budget.
- [ ] **redb's read cache is 1 GiB** (`Database::create` defaults,
      `db::recovery::create_database`): whatever the app reads stays cached,
      up to the store's size (RSS 204 MB after Home + search + one rescan,
      870 MB after a full walk). A phone wants 32-64 MiB
      (`Builder::set_cache_size`).
- [ ] **Store size is ~10x the text** (above). The copy in the resource row
      (to confirm) and the slack of large values look like the cheap wins;
      the outbox shrinks once synced.
- [ ] The first keystroke after start reads the search trees cold (9-62 ms on
      the Mac). Warming them in the background after Home is drawn would hide
      it.
- [ ] 3-letter queries are the slowest warm case (5-10 ms): the one-edit
      neighbourhood of three letters still scans the two-letter prefixes.

### Phase 3: the same data in the app (planned, not run)

Waits for a go-ahead (emulator builds conflict with other agents and disk).

1. **Bridge**: expose `import_ai_chat(name, entries_json) -> subject` in
   `flutter/rust/src/api/assistant.rs` (calls `host::chats::import_ai_chat`;
   `entries_json` = `[{role, parts, c}]`), regenerate the bindings
   (`flutter_rust_bridge_codegen generate`).
2. **Seed hook** (`flutter/lib/perf_seed.dart`): a second flag file,
   `perf_seed_chats` containing `N [scale]`, makes N chats with the same
   generator as the Rust test (port the xorshift + vocabulary to Dart, so a
   device and the Mac get comparable data; deterministic seed), in batches of
   10 chats per `Future.wait`, then logs `[perf] perf seed chats N <ms>` and
   the store size. Debug/profile only, like the existing hook. At scale 1.0
   the store is ~700 MB: on the emulator check free space first
   (`adb shell df /data`); use `--chat-scale 0.3` for small devices.
3. **`scripts/perf_android.sh`**: `--seed-chats N [--chat-scale S]` writes
   the flag and waits for the log line (timeout 15 min). New `--only` steps:
   - `chats`: Home → "AI chats" → "All", time tap → list painted (needs a
     `Perf.span('list all painted')` mark in `chats_screen.dart`), then 8
     fling swipes down and up, `[perf] frames` janky % and raster/build p99.
   - `search` with the chat data: type `b`, `u`, `d`, `g`, `e`, `t` one
     `input text` per keystroke, 300 ms apart, and record `[perf] search
     query` and `search keystroke to results` per keystroke (the first one
     cold after start, separately); also with the "AI chats" kind.
   - `chat`: open the longest chat (60 messages), tap → messages painted,
     and scroll it.
   - `memory`: app PSS after seeding, after "All", after 20 searches, after
     opening 5 chats.
   - `cold` with the big store: start → Home painted, and once with the
     compaction check due (`run-as <pkg> rm files/compaction-check` first).
4. **UI changes these measurements will need** (packages/atomic_chat, other
   agents' files; not changed here):
   - `_ListPage` builds every row up front (`ListView(children: rows)`,
     `chats_screen.dart` ~962) and `_openAll` hands it a finished
     `List<Widget>`: make it `ListView.builder` over the data.
   - The Home loads `listAiChats(limit: 50)` and "All" shows those same rows,
     so 950 of 1000 chats are unreachable from the list. "All" should load
     its own list (1000 rows is 9 ms and 169 KB in Rust; page with an offset
     beyond a few thousand).
   - Search "AI chats" lists `api.chats()` (the same 50) before typing, and
     while typing keeps only the AI chats among the 20 global hits, so a
     query whose best 20 are documents shows no chat. Pass the class to Rust
     (`SearchOpts.filter_pairs` isA = AiChat, measured 1.4-2.0 ms) through a
     `class` parameter on the bridge's `search`.
