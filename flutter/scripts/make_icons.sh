#!/usr/bin/env bash
# Regenerates the launcher icons that brand/generate.mjs does not cover, from
# the same source mark (brand/src/place-mark.svg):
#   - macOS AppIcon.appiconset (rounded tile with the usual padding + shadow)
#   - Android adaptive icon (foreground + monochrome layers, background colour)
#   - assets/icon/app-icon.png, the 1024 master
# iOS, web/PWA and the legacy Android mipmaps come from `node brand/generate.mjs`.
# Needs rsvg-convert and ImageMagick 7 (brew install librsvg imagemagick).
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=../brand/src/place-mark.svg
TILE='#111111'
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
STRIP=(-strip -define png:exclude-chunk=date,time)

# Mark without its tile, shrunk to sit inside the adaptive safe zone (66/108 dp).
grep -v '<rect ' "$SRC" | sed 's/scale(1.05)/scale(0.92)/' > "$TMP/fg.svg"
# Themed icons (Android 13) use only the alpha channel: orb becomes solid white.
sed 's|fill="url(#placeInsideOrb)"|fill="#fff"|' "$TMP/fg.svg" > "$TMP/mono.svg"

mkdir -p assets/icon
rsvg-convert -w 1024 -h 1024 "$SRC" -o "$TMP/master.png"
magick "$TMP/master.png" "${STRIP[@]}" assets/icon/app-icon.png

# Android adaptive icon: 108 dp canvas per density.
RES=android/app/src/main/res
for d in mdpi:108 hdpi:162 xhdpi:216 xxhdpi:324 xxxhdpi:432; do
  dir=$RES/mipmap-${d%%:*}; px=${d##*:}
  rsvg-convert -w "$px" -h "$px" "$TMP/fg.svg" -o "$TMP/o.png"
  magick "$TMP/o.png" "${STRIP[@]}" "$dir/ic_launcher_foreground.png"
  rsvg-convert -w "$px" -h "$px" "$TMP/mono.svg" -o "$TMP/o.png"
  magick "$TMP/o.png" "${STRIP[@]}" "$dir/ic_launcher_monochrome.png"
done
mkdir -p $RES/mipmap-anydpi-v26
cat > $RES/mipmap-anydpi-v26/ic_launcher.xml <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@mipmap/ic_launcher_foreground" />
    <monochrome android:drawable="@mipmap/ic_launcher_monochrome" />
</adaptive-icon>
XML
cat > $RES/values/ic_launcher_background.xml <<XML
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="ic_launcher_background">$TILE</color>
</resources>
XML

# macOS: artwork is 824 of 1024 px, centred, with a soft drop shadow.
MAC=macos/Runner/Assets.xcassets/AppIcon.appiconset
rsvg-convert -w 824 -h 824 "$SRC" -o "$TMP/art.png"
magick -size 1024x1024 xc:none \( "$TMP/art.png" -background black -shadow 40x12+0+10 \) \
  -gravity center -compose over -composite "$TMP/art.png" -gravity center -composite \
  "$TMP/mac1024.png"
for s in 16 32 64 128 256 512 1024; do
  magick "$TMP/mac1024.png" -filter Lanczos -resize ${s}x${s} "${STRIP[@]}" "$MAC/app_icon_$s.png"
done
