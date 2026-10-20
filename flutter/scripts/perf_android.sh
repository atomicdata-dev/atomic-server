#!/bin/bash
# Measures the app on an Android device or emulator and prints a markdown table
# (median, min-max and sample count per metric). Timing is NOT a CI check: the
# numbers depend on the device; compare runs on the same one. Budgets and past
# results: planning/flutter-performance.md.
#
#   scripts/perf_android.sh [-s SERIAL] [-a APK] [-n RUNS] [-o OUT.md] [--seed N] [--only LIST]
#
#   -s SERIAL  adb device (default emulator-5554). Never point this at a phone
#              whose data you care about: it force-stops the app, taps through
#              it and (with --seed) adds test documents.
#   -a APK     install this APK first (-r, keeps the data) and report its size.
#              Measure a PROFILE build: flutter build apk --profile
#              --target-platform android-arm64 [--dart-define=FAKE_AI=1]
#              Debug builds are several times slower and say little.
#   -n RUNS    samples per timing (default 5)
#   -o OUT.md  also write the table there
#   --seed N   first make N documents and folders (+3 AI chats) in the active
#              drive through the app's perf seed hook (lib/perf_seed.dart),
#              and fill "Perf document 0" with a long text (the big document).
#              Once per install; needs a signed-in identity.
#   --only L   comma list of steps: cold,warm,scroll,open,search,chat,memory,size
#
# Reads the app's `[perf]`, `[warm]` and `[chat]` lines in logcat (profile and
# debug builds print them; see packages/atomic_flutter/lib/src/perf.dart).
# The app must be signed in (Home showing) before running.
set -euo pipefail

SERIAL=emulator-5554 APK= RUNS=5 OUT= SEED=0 ONLY=cold,warm,scroll,open,search,chat,memory,size
while [ $# -gt 0 ]; do
  case $1 in
    -s) SERIAL=$2; shift 2;;
    -a) APK=$2; shift 2;;
    -n) RUNS=$2; shift 2;;
    -o) OUT=$2; shift 2;;
    --seed) SEED=$2; shift 2;;
    --only) ONLY=$2; shift 2;;
    -h|--help) sed -n 2,27p "$0"; exit 0;;
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
renderer_pss() { # every web view renderer process (the app's pages)
  local total=0 pid p
  for pid in $(a shell ps -A -o PID,NAME | tr -d '\r' | awk '/sandboxed_process|webview_service|:privileged_process/ {print $1}'); do
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
  if step size; then put "APK size (MB)" "$(du -k "$APK" | awk '{printf "%.1f", $1/1024}')"; fi
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
    line=$(log | grep -E '\[perf\] frames' | tail -1)
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
  put "open $2 ($path): painted (ms)" "$(last_ms '\[perf\] resource painted')"
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
    put "search: last keystroke to results drawn, incl. 120 ms debounce (ms)" "$(last_ms '\[perf\] search keystroke to results')"
    back; sleep 0.5; back; sleep 1
  done
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
    sleep 2
    put "AI chat (fake): send to first token (ms)" "$(log | grep -E '\[chat\] \+[0-9]+ms first event' | tail -1 | sed -E 's/.*\+([0-9]+)ms.*/\1/')"
    line=$(log | grep -E '\[perf\] frames' | tail -1)
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
