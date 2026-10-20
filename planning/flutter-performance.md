# Flutter app performance

> **Status:** 2026-10-20. Measured on the emulator and the Mac; the owner's
> phones still to do (below). The round-by-round logs that led here are in
> git: `git show 72d0a00:planning/flutter-performance.md`.

## How to measure

```
cd flutter
flutter build apk --profile --target-platform android-arm64 --dart-define=FAKE_AI=1
scripts/perf_android.sh -a build/app/outputs/flutter-apk/app-profile.apk [-s SERIAL] [-n 5] [-o out.md]
scripts/perf_android.sh --seed 30 --only size     # once per install: test data
scripts/perf_android.sh --seed-chats 1000 --chat-scale 0.5 --only size -n 1
scripts/perf_android.sh --seed-long 100000 --only longchat,memory
```

- Always a **profile** build. Debug is several times slower (and its Rust is
  unoptimized); release prints no marks. Cargokit builds the Rust library
  `--release` for profile and release.
- `FAKE_AI=1` (canned AI replies) only on the emulator or a test phone. An APK
  for someone's own phone is a release build without it:
  `scripts/deploy_release.sh <serial>` (installs with `-r`, never uninstalls).
- The script force-stops the app many times and seeds data: never point it at
  a phone whose data matters. Use a throwaway identity.
- The app logs `[perf]` lines in debug and profile builds
  (`packages/atomic_flutter/lib/src/perf.dart`): start-up marks, Home lists,
  opens, search, chats, and per burst of frames janky % and build/raster
  percentiles (`dumpsys gfxinfo` does not see Flutter's surface).
- Rust side, on the Mac: `lib/tests/stress_chats.rs` (ignored tests,
  `--profile e2e`, see the file's header for the env vars).
- Timing is not a CI check. The embed bundle budget
  (`scripts/check_embed_size.sh`) is the deterministic part and runs in CI.

## Budgets and current numbers

Budgets are for a mid-range phone (Xiaomi), profile build, warm OS caches.
"Now" is the Phone_A35 emulator (Android 15 arm64, M5 Pro host) unless
noted; emulated GL makes raster time and web view hand-overs slower than on
a phone.

| What | Budget | Now |
| --- | --- | --- |
| Cold start: process start → Home painted | < 1500 ms | 3.3 s (2.65 s with the dex compiled) |
| Cold start: first frame | < 800 ms | 2.3 s |
| Hot start | < 200 ms | 136 ms |
| Open from Recents, warm page: tap → title on screen | < 500 ms | ~330 ms (screen recording) |
| Search: keystroke → results drawn | < 50 ms | 16-29 ms; first after cold start 43 ms |
| Tap → next frame | < 16-50 ms | 6-28 ms |
| Scrolling: janky frames | < 1 % | 1-19 % on the emulator, raster-bound (build p90 2-5 ms) |
| App PSS after start | < 200 MB | 220-250 MB |
| Web view renderer PSS with the spare | < 120 MB | 143-158 MB |
| Rust library in the APK | < 25 MB | 23.1 MB |
| Embed first-use chunks | < 1000 kB gzip (CI) | 938 kB |

Scale, with 1000 AI chats (39 842 messages, 470 MB store) the app behaves
as with 30 documents: Home lists 79-100 ms, "All AI chats" first frame
10 ms and 34 ms per page of 50, a chat opens in under 50 ms.

Very long chats (Mac, 200 000 messages; conversation 20 000), first /
median ms:

| What | Whole read (before) | Windows of 50 (now) |
| --- | --- | --- |
| Open AI chat | 897 / 872, +762 MB | 9.8 / 1.25, +4 MB |
| Open chat room | 1273 / 1282 | 16 / 1.35 |
| Open conversation | 1198 / 497 | 101 (index build) / 2.6 |
| Append one message | ~470 / ~395 | 4.4 / 3.9 |
| Scroll up (next 50) | | 0.6-2; conversation 12-19 (decrypts) |

On the emulator a 100 000-message AI chat opens painted in 21 ms, 30 fast
flings give 1.2 % janky frames, PSS ~250 MB.

## Design notes that hold

- The startup compaction check walks every redb page; it runs once a week or
  when the file grew by a quarter (`compaction-check` next to the store).
- redb's read cache is 48 MiB in the app (`init_redb_file_with_cache`), the
  server keeps the 1 GiB default.
- Search: typo variants from three letters on; one or two letters scan titles
  only; the search trees are warmed after Home's first frame.
- Chat screens read through `ChatWindow`
  (`packages/atomic_chat/lib/src/chat_window.dart`): pages of 50 through the
  sorted index (`Db::query_page`), an opaque cursor
  `<page createdAt>|<page subject>#<entry key>`, at most ~500 messages held.
  Append and `chat_last_activity` read the newest page only. The whole-chat
  reads (`read_chat`, `ChatRooms::read`, `Conversations::read`) remain for the
  web-compatible read and AI tools.
- The warm web view stays attached (offstage) so an open does not freeze the
  screen; a native skeleton covers it until the page reveals.
- One redb handle per process (`db::recovery::OpenFileGuard`): Android re-runs
  `main` in the same process, and a second handle truncated the store.

## Where the time goes (emulator)

- Process start → Dart `main` ~1150 ms, ~600 ms of it interpreted dex in a
  sideloaded profile build. A baseline profile for the Java side would help.
- `main` → store open ~1100 ms on the Android main thread: surface creation on
  emulated GL. `flutter_tts` no longer enumerates voices at start (unmeasured
  on a phone).
- Web view frames block the Android main thread on the emulator, so replies to
  the page wait 300-1500 ms there. Check the gap between `resource painted`
  and `resource painted in page` on a phone.

## Open

- [ ] On the Xiaomi phone and Pad (throwaway identity, profile build): cold
      start marks, opens (warm/cold, 80 kB document), scrolling and a
      streaming reply (janky %, raster p99), PSS after 10 opens, a kill
      during use, and one release-build start.
- [ ] Chat text is not searchable (titles, descriptions, documents only).
      Indexing it is a product decision: ~100 MB more postings for the
      1000-chat store and re-tokenising a page per appended message.
- [ ] Compacting a big store, when due, runs before the first frame (once
      60.7 s for 1 GB). Compact in the background or with a time budget.
- [ ] Store size is ~10x the text (row copy of the last commit, Loro
      snapshot, commit envelope, outbox, redb slack).
- [ ] 3-letter queries are the slowest warm case (5-10 ms on the Mac).
- [ ] A device that does not hold a room's pages yet syncs all of them.
- [ ] Search inside a long chat, and opening a hit at its place.
- [ ] `read_*_after` does not look at older pages: an entry another device
      adds to a page that is no longer the newest here shows on reopen only.
- [ ] An unread count per chat (counting walks every page).
- [ ] The embed's `Providers` chunk (543 kB gzip) could be split.
