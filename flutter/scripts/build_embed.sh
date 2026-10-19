#!/bin/bash
# Builds the embedded renderer (browser/data-browser, embed.html) and puts it
# into flutter/assets/embed, where the app ships it. Run before `flutter build`
# or `flutter run`, and again after a change in browser/.
#
#   ./scripts/build_embed.sh
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
browser="$here/../browser"

(cd "$browser" && pnpm install --frozen-lockfile && pnpm --filter @tomic/lib --filter @tomic/react --filter @tomic/service-ui --filter @tomic/edit-mode --filter @tomic/form-renderer --filter @tomic/plugin run build)
(cd "$browser/data-browser" && TAURI=1 SKIP_WASM_BUILD=1 pnpm exec vite build -c vite.embed.config.ts)

dest="$here/assets/embed"
find "$dest" -type f ! -name '.gitkeep' -delete
cp "$browser/data-browser/dist-embed/embed.html" "$dest/"
cp -R "$browser/data-browser/dist-embed/assets/." "$dest/assets/"
# Only what the page itself loads: not the web app's icons, robots.txt, etc.
echo "embed: $(du -sh "$dest" | cut -f1) in $dest"
