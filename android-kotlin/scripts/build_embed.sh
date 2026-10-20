#!/bin/bash
# Builds the embedded renderer (browser/data-browser, embed.html, the repo's own
# vite.embed.config.ts) into a directory the Gradle build bundles as app assets.
# Gradle runs it (task `buildEmbed`); run it by hand to look at the bundle.
#
#   android-kotlin/scripts/build_embed.sh [out-dir]
#
# out-dir defaults to android-kotlin/app/build/generated/embed/assets/embed
# (build output, gitignored). Needs Node 22+ and pnpm. Same bundle as the
# Flutter app (flutter/scripts/build_embed.sh); the only difference is where it goes.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
browser="$here/../browser"
dest="${1:-$here/app/build/generated/embed/assets/embed}"

(cd "$browser" && pnpm install --frozen-lockfile \
  && pnpm --filter @tomic/lib --filter @tomic/react --filter @tomic/service-ui \
          --filter @tomic/edit-mode --filter @tomic/form-renderer --filter @tomic/plugin run build)
# TAURI=1: no service worker or CSP nonces (they only make sense on a web origin).
# SKIP_WASM_BUILD=1: the page keeps no WASM store; the host answers every read.
(cd "$browser/data-browser" && TAURI=1 SKIP_WASM_BUILD=1 pnpm exec vite build -c vite.embed.config.ts)

rm -rf "$dest"
mkdir -p "$dest/assets"
cp "$browser/data-browser/dist-embed/embed.html" "$dest/"
cp -R "$browser/data-browser/dist-embed/assets/." "$dest/assets/"
# Only what the page itself loads: not the web app's icons, robots.txt, etc.
echo "embed: $(du -sh "$dest" | cut -f1) in $dest"
