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
| Search: last keystroke → results drawn (incl. 120 ms debounce) | < 200 ms | 157 ms (Rust query 12 ms) |
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
  feature only voice mode uses. Lazy registration of that plugin is the next
  start-up fix if the phone shows it.
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
  and armeabi-v7a (9 MB); an app bundle or `--split-per-abi` drops them.
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
  same-process relaunch, 0 failures. Still open: cargokit builds with
  `stable`, not the repo's pinned toolchain.
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
