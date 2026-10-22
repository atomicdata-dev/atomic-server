#!/bin/bash
# Builds the release APK (arm64) and installs it on one or more devices,
# keeping the app's data (`adb install -r`), then starts it.
#
#   scripts/deploy_release.sh [--no-build] SERIAL...
#
# The release build is signed with the debug key (android/app/build.gradle),
# so it replaces a debug install in place. When a device has the app signed
# with another key, `adb install -r` fails with INSTALL_FAILED_UPDATE_
# INCOMPATIBLE; this script never uninstalls (that would wipe the device's
# store and identity): sort that out by hand.
#
# Serials: `adb devices -l` (wireless ones look like
# adb-XXXX._adb-tls-connect._tcp or 192.168.x.y:port).
set -euo pipefail

cd "$(dirname "$0")/.."
BUILD=1
if [ "${1:-}" = "--no-build" ]; then BUILD=0; shift; fi
if [ $# -eq 0 ]; then sed -n 2,14p "$0"; exit 2; fi

APP=io.ontola.atomic
APK=build/app/outputs/flutter-apk/app-release.apk
ADB=${ADB:-adb}

if [ $BUILD = 1 ]; then
  # Cargokit builds the Rust library with `--release` (rust/Cargo.toml's
  # [profile.release]: fat LTO, one codegen unit); arm64 only.
  CARGO_INCREMENTAL=0 mise exec flutter@3.44 -- \
    flutter build apk --release --target-platform android-arm64
fi
[ -f "$APK" ] || { echo "no $APK" >&2; exit 1; }
if unzip -l "$APK" | grep -q kernel_blob.bin; then
  echo "$APK is a debug build (kernel_blob.bin)" >&2; exit 1
fi
ls -l "$APK"

status=0
for s in "$@"; do
  echo "== $s ($($ADB -s "$s" shell getprop ro.product.model | tr -d '\r'))"
  if ! $ADB -s "$s" install -r "$APK"; then
    echo "   install failed on $s (nothing was uninstalled)" >&2
    status=1
    continue
  fi
  $ADB -s "$s" shell am force-stop $APP
  $ADB -s "$s" shell am start -n $APP/com.ontola.atomiccanvas_flutter.MainActivity >/dev/null
  if $ADB -s "$s" shell dumpsys package $APP | grep -q 'flags=.*DEBUGGABLE'; then
    echo "   still DEBUGGABLE on $s" >&2
    status=1
  else
    echo "   release installed and started"
  fi
done
exit $status
