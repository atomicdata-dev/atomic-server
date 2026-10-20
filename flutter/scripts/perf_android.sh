#!/bin/bash
# Measures the app on an Android device or emulator and prints a markdown table
# (median, min-max and sample count per metric). Timing is NOT a CI check: the
# numbers depend on the device; compare runs on the same one. Budgets and past
# results: planning/flutter-performance.md.
#
#   scripts/perf_android.sh [-s SERIAL] [-a APK] [-n RUNS] [-o OUT.md] [--seed N]
#                           [--seed-chats N [--chat-scale S]] [--seed-long N]
#                           [--only LIST]
#
#   -s SERIAL  adb device (default emulator-5554). Never point this at a phone
#              whose data you care about: it force-stops the app, taps through
#              it and (with --seed) adds test documents.
#   -a APK     install this APK first (-r, keeps the data) and report its size.
#              Measure a PROFILE build: flutter build apk --profile
#              --target-platform android-arm64 [--dart-define=FAKE_AI=1]
#              FAKE_AI=1 only for an emulator or a test phone: its AI chat
#              is a canned fake (marked "FAKE AI" in every reply). A build
#              for someone's own phone omits it.
#              Debug builds are several times slower and say little.
#   -n RUNS    samples per timing (default 5)
#   -o OUT.md  also write the table there
#   --seed N   first make N documents and folders (+3 AI chats) in the active
#              drive through the app's perf seed hook (lib/perf_seed.dart),
#              and fill "Perf document 0" with a long text (the big document).
#              Once per install; needs a signed-in identity.
#   --seed-chats N  first make N AI chats full of text (20-60 messages of
#              200-4000 chars times --chat-scale, default 1.0) through the
#              same hook: the stress data of lib/tests/stress_chats.rs. 1000
#              chats at scale 1.0 is a ~700 MB store; check `df /data` first.
#   --seed-long N  first make one AI chat of N short messages ("Very long
#              chat", ~120 chars each; 50 000 is a ~70 MB store) for longchat.
#   --only L   comma list of steps: cold,warm,scroll,open,search,chat,memory,size,
#              allchats (All AI chats: painted, page loads, scroll jank),
#              typing (search per keystroke, cold first one, AI chats chip),
#              bigchat (open two seeded chats, scroll them),
#              longchat (open "Very long chat", fling up through its history,
#              jump to latest, send with FAKE_AI=1; not in the default list)
#
# Reads the app's `[perf]`, `[warm]` and `[chat]` lines in logcat (profile and
# debug builds print them; see packages/atomic_flutter/lib/src/perf.dart).
# The app must be signed in (Home showing) before running.
set -euo pipefail

SERIAL=emulator-5554 APK= RUNS=5 OUT= SEED=0 SEED_CHATS=0 CHAT_SCALE=1.0 SEED_LONG=0
ONLY=cold,warm,scroll,open,search,chat,memory,size,allchats,typing,bigchat
while [ $# -gt 0 ]; do
  case $1 in
    -s) SERIAL=$2; shift 2;;
    -a) APK=$2; shift 2;;
    -n) RUNS=$2; shift 2;;
    -o) OUT=$2; shift 2;;
    --seed) SEED=$2; shift 2;;
    --seed-chats) SEED_CHATS=$2; shift 2;;
    --chat-scale) CHAT_SCALE=$2; shift 2;;
    --seed-long) SEED_LONG=$2; shift 2;;
    --only) ONLY=$2; shift 2;;
    -h|--help) sed -n 2,35p "$0"; exit 0;;
    *) echo "unknown argument $1" >&2; exit 2;;
  esac
done

here="$(cd "$(dirname "$0")/.." && pwd)"
PKG=com.ontola.atomiccanvas_flutter
ACT=$PKG/.MainActivity
ADB="${ADB:-$(command -v adb || echo "$HOME/Library/Android/sdk/platform-tools/adb")}"
work="$(mktemp -d "${TMPDIR:-/tmp}/perf_android.XXXXXX")"
data="$work/data.tsv"   # metric<TAB>value
: > "$data"
echo "perf_android: logs in $work" >&2

a() { "$ADB" -s "$SERIAL" "$@"; }
step() { [[ ",$ONLY," == *",$1,"* ]]; }
put() { printf '%s\t%s\n' "$1" "$2" >> "$data"; }
note() { echo "  $*" >&2; }

# logcat of the app's flutter lines since the last clear.
log() { a logcat -d -v brief -s flutter:I 2>/dev/null | tr -d '\r'; }

# Waits until the log has a line matching $1 (ERE), at most $2 seconds.
wait_log() {
  local t=0
  while ! log | grep -Eq "$1"; do
    sleep 0.25; t=$((t + 1))
    if [ $t -ge $(( ${2:-30} * 4 )) ]; then note "timeout waiting for /$1/"; return 1; fi
  done
}

# The number in the last log line matching $1, followed by " ms".
last_ms() { log | grep -E "$1" | tail -1 | sed -E 's/.* ([0-9]+) ms.*/\1/'; }

# Taps the on-screen element whose text or description has a line equal to
# $1 (or containing it, with $2 = contains). Flutter's semantics show in the
# accessibility dump.
find_text() { # prints "x y" of the element, or nothing
  a shell uiautomator dump /sdcard/perf_ui.xml >/dev/null 2>&1 || true
  a exec-out cat /sdcard/perf_ui.xml > "$work/ui.xml"
  python3 - "$work/ui.xml" "$1" "${2:-exact}" <<'EOF'
import re, sys, html
xml, want, mode = open(sys.argv[1]).read(), sys.argv[2], sys.argv[3]
for m in re.finditer(r'<node [^>]*>', xml):
    n = m.group(0)
    get = lambda k: html.unescape((re.search(k + r'="([^"]*)"', n) or [None, ''])[1])
    lines = (get('text') + '\n' + get('content-desc')).split('\n')
    hit = any(l.strip() == want for l in lines) if mode == 'exact' else any(want in l for l in lines)
    if hit:
        x1, y1, x2, y2 = map(int, re.findall(r'\d+', get('bounds')))
        print((x1 + x2) // 2, (y1 + y2) // 2)
        break
EOF
}
tap_text() {
  local at; at=$(find_text "$@")
  if [ -z "$at" ]; then note "not on screen: $1"; return 1; fi
  a shell input tap $at
}

back() { a shell input keyevent 4; }

# find_text, scrolling the page down (up to 5 swipes) until it shows.
find_scrolling() {
  local at i
  for i in 0 1 2 3 4 5; do
    at=$(find_text "$@")
    if [ -n "$at" ]; then echo "$at"; return 0; fi
    a shell input swipe 540 1700 540 900 300; sleep 0.8
  done
  return 1
}

# One frame summary line ([perf] frames) into the table under label $1.
put_frames() {
  local line; line=$(log | grep -E '\[perf\] frames' | tail -1 || true)
  [ -n "$line" ] || return 0
  note "$line"
  put "$1: janky frames (%)" "$(sed -E 's/.*janky=([0-9.]+)%.*/\1/' <<<"$line")"
  local k v p50 p90 p95 p99
  for k in build raster; do
    v=$(sed -E "s/.* $k=([0-9.\/]+).*/\1/" <<<"$line")
    IFS=/ read -r p50 p90 p95 p99 <<<"$v"
    put "$1: $k p90 (ms)" "$p90"; put "$1: $k p99 (ms)" "$p99"
  done
}

mem_stage() { # $1 = label: app PSS now, in MB
  step memory || return 0
  sleep 2
  put "memory: app PSS $1 (MB)" "$(pss_of $PKG | awk '{printf "%.0f", $1/1024}')"
}
# The home, whatever page is open (the bar's Home button pops back to it);
# the app brought back to the front when it is not (never a blind back,
# which leaves the app from its home).
go_home() {
  tap_text Home 2>/dev/null || { a shell am start -n $ACT >/dev/null; sleep 2; tap_text Home 2>/dev/null || true; }
  sleep 1
}

start_cold() {
  a shell am force-stop $PKG
  sleep 1
  a logcat -c
  a shell am start -W -n $ACT > "$work/start.txt"
}

home_ready() { wait_log '\[perf\] home painted' 40 && wait_log '\[perf\] warm ready' 40; }

pss_of() { # pid or package -> total PSS in kB
  a shell dumpsys meminfo "$1" 2>/dev/null | tr -d '\r' |
    sed -nE 's/^ *TOTAL PSS: *([0-9]+).*/\1/p; s/^ *TOTAL +([0-9]+) .*/\1/p' | head -1
}
renderer_pss() { # the web view's renderer processes (the app's pages; the
  # system's webview_service and webview_zygote are shared, not counted)
  local total=0 pid p
  for pid in $(a shell ps -A -o PID,NAME | tr -d '\r' | awk '/webview:sandboxed_process/ {print $1}'); do
    p=$(pss_of "$pid"); total=$((total + ${p:-0}))
  done
  echo $total
}

# ── Device ────────────────────────────────────────────────────────────────
model=$(a shell getprop ro.product.model | tr -d '\r')
release=$(a shell getprop ro.build.version.release | tr -d '\r')
abi=$(a shell getprop ro.product.cpu.abi | tr -d '\r')
qemu=$(a shell getprop ro.kernel.qemu | tr -d '\r')
device="$model, Android $release, $abi$([ "$qemu" = 1 ] && echo ", emulator on $(uname -sm) $(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)")"
note "device: $device"

if [ -n "$APK" ]; then
  note "installing $APK"
  a install -r "$APK" >/dev/null
  # The first start after an install extracts and verifies the dex: not a
  # start anyone measures twice.
  a shell am start -W -n $ACT >/dev/null; sleep 15; a shell am force-stop $PKG
  if step size; then
    # The entries, not the file: Gradle's incremental packaging leaves the
    # file at its old size with holes (a clean build is about this size).
    put "APK size, compressed entries (MB)" "$(unzip -lv "$APK" | tail -1 | awk '{printf "%.1f", $2/1048576}')"
    put "APK: Rust library (MB)" "$(unzip -lv "$APK" | awk '/libatomic_flutter_rust.so/ {printf "%.1f", $1/1048576}')"
  fi
fi
if step size && [ -f "$here/assets/embed/embed.html" ]; then
  "$here/scripts/check_embed_size.sh" > "$work/embed_size.txt" 2>&1 || true
  put "embed bundle total (MB)" "$(du -sk "$here/assets/embed" | awk '{printf "%.1f", $1/1024}')"
  gz=$(sed -nE 's/^First-use chunks: [0-9]+, raw [0-9.]+ kB, gzip ([0-9.]+) kB.*/\1/p' "$work/embed_size.txt" | head -1)
  [ -n "$gz" ] && put "embed first-use gzip (kB)" "$gz"
fi

# ── Seed ──────────────────────────────────────────────────────────────────
if [ "$SEED" -gt 0 ]; then
  note "seeding $SEED items"
  a shell mkdir -p /sdcard/Android/data/$PKG/files
  a shell "echo $SEED > /sdcard/Android/data/$PKG/files/perf_seed"
  start_cold
  wait_log '\[perf\] perf seed' 300
  home_ready || true
  # The big document: "Perf document 0", filled through the editor.
  start_cold; home_ready
  a shell input keyevent 3; sleep 1; a shell am start -n $ACT >/dev/null; sleep 2
  # Search finds it wherever it is in Recents.
  tap_text Search; sleep 1
  a shell input text "Perf%sdocument%s0"; sleep 2
  back; sleep 0.5
  tap_text "Perf document 0"
  wait_log '\[perf\] resource painted' 30; sleep 2
  pid=$(a shell pidof $PKG | tr -d '\r')
  a forward tcp:9339 localabstract:webview_devtools_remote_$pid >/dev/null
  node --input-type=module - "$work" <<'EOF'
const pages = await (await fetch('http://127.0.0.1:9339/json')).json();
const run = (url, expression) => new Promise((ok, fail) => {
  const ws = new WebSocket(url);
  ws.onopen = () => ws.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate',
    params: { expression, returnByValue: true, awaitPromise: true } }));
  ws.onmessage = (m) => { ws.close(); ok(JSON.parse(m.data).result?.result?.value); };
  ws.onerror = fail;
});
const para = (i) => `<h2>Section ${i}</h2><p>${'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. '.repeat(4)}</p><ul><li>point ${i}a</li><li>point ${i}b</li></ul>`;
const html = Array.from({ length: 150 }, (_, i) => para(i)).join('');
let done = false;
for (const p of pages.filter((p) => p.webSocketDebuggerUrl)) {
  const r = await run(p.webSocketDebuggerUrl, `(() => {
    const el = document.querySelector('.ProseMirror');
    if (!el || !el.editor) return 'no editor';
    el.editor.commands.setContent(${JSON.stringify(html)}, true);
    return 'filled ' + el.editor.getText().length + ' chars';
  })()`);
  console.error('  big document: ' + r);
  if (String(r).startsWith('filled')) { done = true; break; }
}
if (!done) process.exit(1);
EOF
  a forward --remove tcp:9339 || true
  sleep 4; back; sleep 4
fi

# ── Seed AI chats ─────────────────────────────────────────────────────────
if [ "$SEED_CHATS" -gt 0 ]; then
  note "seeding $SEED_CHATS AI chats at scale $CHAT_SCALE"
  a shell mkdir -p /sdcard/Android/data/$PKG/files
  a shell "echo $SEED_CHATS $CHAT_SCALE > /sdcard/Android/data/$PKG/files/perf_seed_chats"
  start_cold
  # Progress every 100 chats; the whole run can take minutes.
  wait_log '\[perf\] perf seed chats' 1800 || true
  log | grep -E '\[perf\] (seeding chats|seeded)' | while read -r l; do note "$l"; done
  put "seed: $SEED_CHATS chats (ms)" "$(last_ms '\[perf\] perf seed chats')"
  put "seed: store after seeding (MB)" "$(log | sed -nE 's/.*\[perf\] seeded .* store ([0-9]+) MB.*/\1/p' | tail -1)"
  sleep 3
fi

if [ "$SEED_LONG" -gt 0 ]; then
  note "seeding one AI chat of $SEED_LONG messages"
  a shell mkdir -p /sdcard/Android/data/$PKG/files
  a shell "echo $SEED_LONG > /sdcard/Android/data/$PKG/files/perf_seed_long"
  start_cold
  wait_log '\[perf\] perf seed long' 1800 || true
  log | grep -E '\[perf\] seeded long' | while read -r l; do note "$l"; done
  put "seed: long chat of $SEED_LONG (ms)" "$(last_ms '\[perf\] perf seed long')"
  put "seed: store after the long chat (MB)" "$(log | sed -nE 's/.*\[perf\] seeded long.* store ([0-9]+) MB.*/\1/p' | tail -1)"
  sleep 3
fi

# ── Cold start ────────────────────────────────────────────────────────────
marks=("main" "rust init" "documents dir" "db open" "runApp" "first frame" "session loaded" "session restored" "home data" "home painted" "warm ready")
if step cold || step memory; then
  for i in $(seq "$RUNS"); do
    start_cold
    home_ready || continue
    put "cold: am start TotalTime" "$(sed -nE 's/^TotalTime: ([0-9]+).*/\1/p' "$work/start.txt")"
    put "cold: am start WaitTime" "$(sed -nE 's/^WaitTime: ([0-9]+).*/\1/p' "$work/start.txt")"
    # Milliseconds since the process started (ActivityManager's "Start proc"
    # line), from the log's own timestamps.
    a logcat -d -v epoch > "$work/cold_epoch.txt"
    python3 - "$work/cold_epoch.txt" "$PKG" "${marks[@]}" <<'EOF2' > "$work/cold_marks.tsv"
import re, sys
lines, pkg, marks = open(sys.argv[1], errors='replace').read().splitlines(), sys.argv[2], sys.argv[3:]
t0 = next((float(l.split()[0]) for l in lines if re.search(r'Start proc \d+:' + re.escape(pkg) + r'/', l)), None)
if t0 is None: sys.exit()
for m in marks:
    hit = next((l for l in lines if re.search(r'\[perf\] ' + re.escape(m) + r' \d+ ms$', l)), None)
    if hit: print(f'{m}\t{round((float(hit.split()[0]) - t0) * 1000)}')
EOF2
    while IFS=$'\t' read -r m v; do put "cold: $m (ms since process start)" "$v"; done < "$work/cold_marks.tsv"
    for l in drives chats recents favorites conversations activity notifications; do
      v=$(last_ms "\[perf\] home $l [0-9]+ ms")
      [ -n "$v" ] && put "cold: home list $l (ms)" "$v"
    done
    log > "$work/cold_$i.log"
    if step memory && [ "$i" = 1 ]; then
      sleep 3
      put "memory: app PSS after start (MB)" "$(pss_of $PKG | awk '{printf "%.0f", $1/1024}')"
      put "memory: web view renderers PSS after start, spare loaded (MB)" "$(renderer_pss | awk '{printf "%.0f", $1/1024}')"
    fi
  done
fi

# ── Warm (hot) start ──────────────────────────────────────────────────────
if step warm; then
  start_cold; home_ready || true
  for i in $(seq "$RUNS"); do
    a shell input keyevent 3; sleep 2
    a shell am start -W -n $ACT > "$work/hot.txt"
    put "hot start: am start TotalTime" "$(sed -nE 's/^TotalTime: ([0-9]+).*/\1/p' "$work/hot.txt")"
    sleep 1
  done
fi

# ── Scrolling ─────────────────────────────────────────────────────────────
if step scroll; then
  start_cold; home_ready || true
  sleep 3
  a shell dumpsys gfxinfo $PKG reset >/dev/null
  for i in $(seq "$RUNS"); do
    a logcat -c
    for _ in 1 2 3 4; do
      a shell input swipe 540 1900 540 700 150
      a shell input swipe 540 700 540 1900 150
    done
    wait_log '\[perf\] frames' 10 || continue
    line=$(log | grep -E '\[perf\] frames' | tail -1 || true)
    note "$line"
    put "scroll Home: janky frames (%)" "$(sed -E 's/.*janky=([0-9.]+)%.*/\1/' <<<"$line")"
    for k in build raster; do
      v=$(sed -E "s/.* $k=([0-9.\/]+).*/\1/" <<<"$line")
      IFS=/ read -r p50 p90 p95 p99 <<<"$v"
      put "scroll Home: $k p90 (ms)" "$p90"; put "scroll Home: $k p99 (ms)" "$p99"
    done
  done
  a shell dumpsys gfxinfo $PKG > "$work/gfxinfo.txt"
  put "scroll Home: gfxinfo janky (%, Android views only)" "$(sed -nE 's/^Janky frames: [0-9]+ \(([0-9.]+)%\).*/\1/p' "$work/gfxinfo.txt" | head -1)"
fi

# ── Opening resources from Recents (warm pool vs cold) ───────────────────
open_one() { # $1 = "x y" to tap, $2 = label; records the open's numbers
  a logcat -c
  a shell input tap $1
  wait_log '\[perf\] resource painted' 30 || { back; return 1; }
  local path; path=$(log | grep -Eo 'resource painted (warm|cold)' | head -1 | awk '{print $3}')
  put "open $2 ($path): data in page (ms)" "$(last_ms '\[perf\] resource data')"
  put "open $2 ($path): painted (ms)" "$(last_ms '\[perf\] resource painted (warm|cold) [0-9]')"
  put "open $2 ($path): painted, page's own clock (ms)" "$(last_ms '\[perf\] resource painted in page')"
  put "open $2 ($path): tap to painted (ms)" "$(last_ms '\[perf\] resource painted (warm|cold) since tap')"
  # The web view shown (its placeholder gone); builds before 2026-10-20 have none.
  put "open $2 ($path): tap to revealed (ms)" "$(last_ms '\[perf\] resource revealed (warm|cold) since tap')"
  log >> "$work/open.log"
}
if step open || step memory; then
  start_cold; home_ready || true
  for i in $(seq "$RUNS"); do
    for doc in "Perf document 28:doc" "Perf document 0:big doc"; do
      go_home; sleep 4
      # The spare is ready: a warm open.
      at=$(find_text "${doc%%:*}"); [ -n "$at" ] || { note "not on screen: ${doc%%:*}"; continue; }
      open_one "$at" "${doc#*:}" || true; back; sleep 2
      # Cold: take the spare and leave at once, then open the same row (now
      # on top of Recents) again before the next spare is up.
      at=$(find_text "${doc%%:*}"); [ -n "$at" ] || continue
      a shell input tap $at; sleep 0.6; back; sleep 0.8
      open_one "$at" "${doc#*:}" || true; back
    done
  done
  if step memory; then
    sleep 3
    put "memory: app PSS after opening resources (MB)" "$(pss_of $PKG | awk '{printf "%.0f", $1/1024}')"
    put "memory: web view renderers PSS after opening resources (MB)" "$(renderer_pss | awk '{printf "%.0f", $1/1024}')"
  fi
fi

# ── Search ────────────────────────────────────────────────────────────────
if step search; then
  start_cold; home_ready || true
  queries=(perf document folder chat perf%s1)
  for i in $(seq "$RUNS"); do
    go_home; tap_text Search || break
    sleep 1.5
    a logcat -c
    a shell input text "${queries[$(( (i - 1) % ${#queries[@]} ))]}"
    wait_log '\[perf\] search keystroke to results' 10 || { back; back; continue; }
    sleep 0.5
    put "search: Rust query (ms)" "$(last_ms '\[perf\] search query')"
    put "search: last keystroke to results drawn (ms)" "$(last_ms '\[perf\] search keystroke to results')"
    back; sleep 0.5; back; sleep 1
  done
fi

# ── All AI chats: the paged, lazy list ────────────────────────────────────
if step allchats; then
  start_cold; home_ready || true
  mem_stage "after start"
  for i in $(seq "$RUNS"); do
    go_home; sleep 1
    at=$(find_scrolling "All AI chats") || { note "no All AI chats button"; break; }
    a logcat -c
    a shell input tap $at
    wait_log '\[perf\] chats all painted' 10 || { back; continue; }
    put "All chats: tap to list painted (ms, page clock)" "$(last_ms '\[perf\] chats all painted')"
    sleep 1
    # Fling through the list: every swipe pages in more chats.
    for _ in 1 2 3 4 5 6 7 8; do a shell input swipe 540 1900 540 400 120; sleep 0.3; done
    for _ in 1 2 3 4; do a shell input swipe 540 400 540 1900 120; sleep 0.3; done
    wait_log '\[perf\] frames' 10 || true
    put_frames "All chats scroll"
    v=$(log | grep -E '\[perf\] chats page' | sed -E 's/.* ([0-9]+) ms.*/\1/' | sort -n | tail -1)
    [ -n "$v" ] && put "All chats: slowest page load (ms)" "$v"
    put "All chats: rows loaded after scrolling" "$(log | grep -Eo 'chats page [0-9]+\+[0-9]+' | tail -1 | awk -F'[ +]' '{print $3 + $4}')"
    [ "$i" = 1 ] && mem_stage "after scrolling All chats"
    back; sleep 1
  done
fi

# ── Search, one keystroke at a time ───────────────────────────────────────
type_word() { # $1 = word, $2 = label; one keystroke every 400 ms
  local w=$1 k
  for ((k = 0; k < ${#w}; k++)); do
    a logcat -c
    a shell input text "${w:$k:1}"
    if wait_log '\[perf\] search keystroke to results' 5; then
      put "$2 key $((k + 1)) ('${w:0:$((k + 1))}'): Rust query (ms)" "$(last_ms '\[perf\] search query')"
      put "$2 key $((k + 1)) ('${w:0:$((k + 1))}'): keystroke to drawn (ms)" "$(last_ms '\[perf\] search keystroke to results')"
    fi
    sleep 0.4
  done
}
if step typing; then
  for i in $(seq "$RUNS"); do
    # The very first search after a cold start reads the index from disk.
    start_cold; home_ready || true
    tap_text Search || break
    sleep 1.5
    type_word budget "search (all)"
    back; sleep 0.5; back; sleep 0.5
    # The AI chats chip: the section's own search.
    go_home
    at=$(find_scrolling "Search AI chats") || { note "no Search AI chats button"; continue; }
    a shell input tap $at; sleep 1.5
    type_word kubernetes "search (AI chats)"
    back; sleep 0.5; back; sleep 0.5
  done
  mem_stage "after searching"
fi

# ── Opening seeded chats, and scrolling them ──────────────────────────────
if step bigchat; then
  start_cold; home_ready || true
  for i in $(seq "$RUNS"); do
    go_home
    at=$(find_scrolling "All AI chats") || break
    a shell input tap $at; sleep 1.5
    # Past the newest chats (the ones made by hand today are short), into
    # the seeded ones, then two rows there.
    a shell input swipe 540 1900 540 400 600; sleep 1
    for y in 900 1200; do
      a logcat -c
      a shell input tap 540 $y
      if wait_log '\[perf\] chat painted' 10; then
        n=$(log | grep -Eo 'chat painted [0-9]+' | tail -1 | awk '{print $3}')
        put "open chat ($n messages): data (ms)" "$(last_ms '\[perf\] chat data')"
        put "open chat ($n messages): painted (ms)" "$(last_ms '\[perf\] chat painted')"
        sleep 1
        for _ in 1 2 3 4 5 6; do a shell input swipe 540 600 540 1900 120; sleep 0.3; done
        wait_log '\[perf\] frames' 10 || true
        put_frames "chat scroll"
        back; sleep 1
      fi
    done
    [ "$i" = 1 ] && mem_stage "after opening chats"
    back; sleep 1
  done
fi

# ── One very long chat: open, fling up through history, jump back ───────
if step longchat; then
  start_cold; home_ready || true
  mem_stage "after start (long chat)"
  for i in $(seq "$RUNS"); do
    go_home
    at=$(find_scrolling "Very long chat" contains) || { note "no Very long chat"; break; }
    a logcat -c
    a shell input tap $at
    wait_log '\[perf\] chat painted' 15 || { back; continue; }
    n=$(log | grep -Eo 'chat painted [0-9]+' | tail -1 | awk '{print $3}')
    put "long chat: open, data (ms; $n messages in the window)" "$(last_ms '\[perf\] chat data')"
    put "long chat: open, painted (ms)" "$(last_ms '\[perf\] chat painted')"
    sleep 1
    # Fast flings up through the history (finger down): every few pages
    # an older page is read.
    a logcat -c
    for _ in $(seq 30); do a shell input swipe 540 500 540 2000 80; sleep 0.15; done
    sleep 1
    wait_log '\[perf\] frames' 10 || true
    put_frames "long chat fling up"
    v=$(log | grep -E '\[perf\] chat older page' | sed -E 's/.* ([0-9]+) ms.*/\1/' | sort -n)
    if [ -n "$v" ]; then
      put "long chat: older pages read while flinging" "$(wc -l <<<"$v" | tr -d ' ')"
      put "long chat: older page read, median (ms)" "$(awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}' <<<"$v")"
      put "long chat: older page read, slowest (ms)" "$(tail -1 <<<"$v")"
      put "long chat: messages held after flinging" "$(log | grep -Eo 'chat older page [0-9]+' | tail -1 | awk '{print $4}')"
    fi
    [ "$i" = 1 ] && mem_stage "after flinging up a long chat"
    if at=$(find_text "Jump to latest"); then
      a logcat -c
      a shell input tap $at; sleep 1.5
      put_frames "long chat jump to latest" || true
    else
      note "no Jump to latest button"
    fi
    # Send (FAKE_AI=1): the reply streams in at the bottom.
    send=$(find_text Send || true)
    if [ -n "$send" ]; then
      a shell input tap $(( ${send% *} - 450 )) ${send#* }; sleep 0.5
      a shell input text "long%schat%s$i"
      a logcat -c
      a shell input tap $send
      if wait_log '\[chat\] .*stream done' 30; then
        sleep 2
        put "long chat (fake AI): send to first token (ms)" "$(log | grep -E '\[chat\] \+[0-9]+ms first event' | tail -1 | sed -E 's/.*\+([0-9]+)ms.*/\1/')"
        put_frames "long chat streaming reply"
      fi
    fi
    back; sleep 0.5; back; sleep 1
  done
  mem_stage "after the long chat"
fi

# ── AI chat (FAKE_AI=1 builds) ────────────────────────────────────────────
if step chat; then
  start_cold; home_ready || true
  for i in $(seq "$RUNS"); do
    go_home
    tap_text "New chat" || break
    sleep 1.5
    send=$(find_text Send)
    [ -n "$send" ] || break
    # The message field is left of the Send button.
    a shell input tap $(( ${send% *} - 450 )) ${send#* }
    sleep 0.5
    a shell input text "hello%sthere%s$i"
    a logcat -c
    a shell input tap $send
    if ! wait_log '\[chat\] .*stream done' 30; then note "no AI reply (not a FAKE_AI=1 build?)"; back; back; break; fi
    sleep 3
    put "AI chat (fake, waits 400 ms itself): send to first token (ms)" "$(log | grep -E '\[chat\] \+[0-9]+ms first event' | tail -1 | sed -E 's/.*\+([0-9]+)ms.*/\1/')"
    line=$(log | grep -E '\[perf\] frames' | tail -1 || true)
    if [ -n "$line" ]; then
      put "AI chat (fake): janky frames while streaming (%)" "$(sed -E 's/.*janky=([0-9.]+)%.*/\1/' <<<"$line")"
      v=$(sed -E "s/.* build=([0-9.\/]+).*/\1/" <<<"$line"); IFS=/ read -r _ p90 _ p99 <<<"$v"
      put "AI chat (fake): build p90 (ms)" "$p90"; put "AI chat (fake): build p99 (ms)" "$p99"
    fi
    back; sleep 0.5; back; sleep 1
  done
fi

a shell am force-stop $PKG || true

# ── Table ─────────────────────────────────────────────────────────────────
table=$(python3 - "$data" "$device" "$RUNS" <<'EOF'
import sys, statistics
rows, order = {}, []
for line in open(sys.argv[1]):
    k, _, v = line.rstrip('\n').partition('\t')
    try: x = float(v)
    except ValueError: continue
    if k not in rows: rows[k] = []; order.append(k)
    rows[k].append(x)
fmt = lambda x: f'{x:.1f}'.rstrip('0').rstrip('.')
print(f'Device: {sys.argv[2]}\n')
print('| Metric | Median | Min-max | n |\n| --- | --- | --- | --- |')
for k in order:
    v = rows[k]
    print(f'| {k} | {fmt(statistics.median(v))} | {fmt(min(v))}-{fmt(max(v))} | {len(v)} |')
EOF
)
echo "$table"
[ -n "$OUT" ] && echo "$table" > "$OUT"
echo "perf_android: raw logs in $work" >&2
