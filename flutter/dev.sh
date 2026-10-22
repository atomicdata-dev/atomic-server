#!/bin/bash
# Usage: ./dev.sh web | ./dev.sh android
# Hot reload from any terminal: make reload-web / make reload-android
FLUTTER="$HOME/.local/share/mise/installs/flutter/3.22.1-stable/bin/flutter"
DART="$HOME/.local/share/mise/installs/flutter/3.22.1-stable/bin/dart"
ANDROID1_ID="92f5edcb"   # xiaomi tablet (23043RP34G)
ANDROID2_ID="456cb10b"   # xiaomi phone (24129PN74G)
ANDROID3_ID="R52X80AC5CY" # samsung tablet s9plus

TARGET=$1
case $TARGET in
  web)      DEVICE="chrome" ;;
  tablet)   DEVICE="$ANDROID1_ID" ;;
  phone)    DEVICE="$ANDROID2_ID" ;;
  emu)      DEVICE="emulator-5554" ;;
  *) echo "Usage: $0 web|tablet|phone|emu"; exit 1 ;;
esac

FIFO="/tmp/atomic_app_${TARGET}_pipe"
WRITER_PID_FILE="/tmp/atomic_app_${TARGET}_writer.pid"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Clean up from any previous run
kill "$(cat "$WRITER_PID_FILE" 2>/dev/null)" 2>/dev/null || true
rm -f "$FIFO"
mkfifo "$FIFO"

# Keep the write end of the FIFO open so flutter run never sees EOF
sleep 86400 > "$FIFO" &
echo $! > "$WRITER_PID_FILE"

echo ""
echo "  Hot reload:  make reload-$TARGET"
echo "  Hot restart: make restart-$TARGET"
echo "  Quit:        Ctrl+C"

EXTRA_ARGS=""
APK="build/app/outputs/flutter-apk/app-debug.apk"
# Reuse a recent APK to skip Gradle/cargokit when iterating (both devices share one build).
if [ -f "$APK" ] && { [ "$TARGET" = "phone" ] || [ "$TARGET" = "tablet" ]; }; then
  EXTRA_ARGS="--use-application-binary=$APK"
  echo "  Using existing APK (skip rebuild): $APK"
fi

# For web, start the COOP/COEP proxy (needed for SharedArrayBuffer / WASM threads)
if [ "$TARGET" = "web" ]; then
  FLUTTER_PORT=65423
  PROXY_PORT=8080
  PROXY_PID_FILE="/tmp/atomic_app_web_proxy.pid"
  kill "$(cat "$PROXY_PID_FILE" 2>/dev/null)" 2>/dev/null || true
  "$DART" run "$SCRIPT_DIR/web_proxy.dart" "$FLUTTER_PORT" "$PROXY_PORT" &
  echo $! > "$PROXY_PID_FILE"
  EXTRA_ARGS="--web-port=$FLUTTER_PORT --web-launch-url=http://localhost:$PROXY_PORT"
  echo "  App: http://localhost:$PROXY_PORT (with COOP/COEP headers)"
fi

# Log file for this target
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/${TARGET}.log"
: > "$LOG_FILE"  # truncate on start
echo "  Log file: $LOG_FILE"
echo ""

# Run flutter with auto-retry on failure
while true; do
  "$FLUTTER" run -d "$DEVICE" $EXTRA_ARGS < "$FIFO" 2>&1 | tee -a "$LOG_FILE"
  EXIT_CODE=$?
  if [ $EXIT_CODE -eq 0 ]; then
    break
  fi
  echo ""
  echo "  Flutter exited with code $EXIT_CODE. Retrying in 2s... (Ctrl+C to stop)"
  echo ""

  # Recreate FIFO (flutter consumed the old one)
  kill "$(cat "$WRITER_PID_FILE" 2>/dev/null)" 2>/dev/null || true
  rm -f "$FIFO"
  mkfifo "$FIFO"
  sleep 86400 > "$FIFO" &
  echo $! > "$WRITER_PID_FILE"

  sleep 2
done

# Cleanup on exit
kill "$(cat "$WRITER_PID_FILE" 2>/dev/null)" 2>/dev/null || true
kill "$(cat /tmp/atomic_app_web_proxy.pid 2>/dev/null)" 2>/dev/null || true
rm -f "$FIFO" "$WRITER_PID_FILE" /tmp/atomic_app_web_proxy.pid
