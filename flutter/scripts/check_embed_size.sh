#!/bin/bash
# Size budget for the embedded renderer. Fails when the chunks that load for the
# FIRST resource (embed.html's module script and modulepreload links, plus their
# static imports, transitively; lazy import() calls are not followed) exceed a
# gzip budget, or when the whole directory exceeds a total budget.
#
#   ./scripts/check_embed_size.sh [dir]     # default: flutter/assets/embed
#   ./scripts/check_embed_size.sh ../browser/data-browser/dist-embed
#
# Budgets (env-overridable), bytes:
#   FIRST_USE_GZIP_BYTES  default 1000000  (measured 926 kB gzip: 45 chunks, entry + modulepreloads + Providers)
#   TOTAL_BYTES           default 16777216
# Appends a markdown summary to $GITHUB_STEP_SUMMARY when set.
set -euo pipefail

FIRST_USE_GZIP_BYTES="${FIRST_USE_GZIP_BYTES:-1000000}"
TOTAL_BYTES="${TOTAL_BYTES:-16777216}"

here="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-$here/assets/embed}"
[ -f "$dir/embed.html" ] || { echo "check_embed_size: $dir/embed.html not found (build the embed first)" >&2; exit 2; }

export EMBED_DIR="$dir" FIRST_USE_GZIP_BYTES TOTAL_BYTES
exec node --input-type=commonjs -e '
const fs = require("fs"), path = require("path"), zlib = require("zlib");
const dir = process.env.EMBED_DIR;
const budgetGz = Number(process.env.FIRST_USE_GZIP_BYTES);
const budgetTotal = Number(process.env.TOTAL_BYTES);

const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
const files = walk(dir).filter((f) => path.basename(f) !== ".gitkeep");
const total = files.reduce((n, f) => n + fs.statSync(f).size, 0);
const gz = (f) => zlib.gzipSync(fs.readFileSync(f), { level: 9 }).length;

// Entry set: embed.html scripts and modulepreloads.
const html = fs.readFileSync(path.join(dir, "embed.html"), "utf8");
const seen = new Set();
const queue = [];
for (const m of html.matchAll(/<(?:script|link)\b[^>]*?(?:src|href)="([^"]+\.js)"[^>]*>/g)) {
  if (/<script\b/.test(m[0]) && !/type="module"/.test(m[0])) continue;
  queue.push(path.resolve(dir, m[1]));
}
// Static imports only: import{..}from"./x.js", import"./x.js", export..from"./x.js".
// import("./x.js") has a paren after import and does not match.
const re = /(?:^|[;}\s])(?:import|export)\s*(?:[\w$*{][^"\x27;()]*?\s*from\s*)?["\x27](\.[^"\x27]+\.js)["\x27]/g;
while (queue.length) {
  const f = queue.pop();
  if (seen.has(f) || !fs.existsSync(f)) continue;
  seen.add(f);
  const src = fs.readFileSync(f, "utf8");
  for (const m of src.matchAll(re)) queue.push(path.resolve(path.dirname(f), m[1]));
}

const rel = (f) => path.relative(dir, f);
const first = [...seen].map((f) => ({ f, raw: fs.statSync(f).size, gz: gz(f) }));
const firstGz = first.reduce((n, c) => n + c.gz, 0);
const firstRaw = first.reduce((n, c) => n + c.raw, 0);

const jsFiles = files.filter((f) => /\.(js|css)$/.test(f));
const biggest = files.map((f) => ({ f, raw: fs.statSync(f).size }))
  .sort((a, b) => b.raw - a.raw).slice(0, 10)
  .map((c) => ({ ...c, gz: gz(c.f), first: seen.has(c.f) }));

const kb = (n) => (n / 1000).toFixed(1).padStart(9) + " kB";
const lines = [];
lines.push("Biggest 10 files in " + dir);
lines.push("  " + "file".padEnd(52) + "      raw       gzip  first-use");
for (const c of biggest)
  lines.push("  " + rel(c.f).slice(-52).padEnd(52) + kb(c.raw) + kb(c.gz) + "  " + (c.first ? "yes" : ""));
lines.push("");
lines.push("First-use chunks: " + first.length + ", raw " + kb(firstRaw).trim() + ", gzip " + kb(firstGz).trim() + " (budget " + kb(budgetGz).trim() + ")");
lines.push("Total directory:  " + kb(total).trim() + " (budget " + kb(budgetTotal).trim() + ")");
const okGz = firstGz <= budgetGz, okTotal = total <= budgetTotal;
lines.push("Verdict: " + (okGz && okTotal ? "OK" : "OVER BUDGET" + (okGz ? "" : " (first-use gzip)") + (okTotal ? "" : " (total)")));
console.log(lines.join("\n"));

if (process.env.GITHUB_STEP_SUMMARY) {
  const md = [];
  md.push("### Flutter embed size: " + (okGz && okTotal ? "OK" : "OVER BUDGET"), "");
  md.push("| Metric | Measured | Budget |", "|---|---:|---:|");
  md.push("| First-use gzip (" + first.length + " chunks) | " + kb(firstGz).trim() + " | " + kb(budgetGz).trim() + " |");
  md.push("| Total directory | " + kb(total).trim() + " | " + kb(budgetTotal).trim() + " |", "");
  md.push("| Biggest files | raw | gzip | first-use |", "|---|---:|---:|:-:|");
  for (const c of biggest) md.push("| `" + rel(c.f) + "` | " + kb(c.raw).trim() + " | " + kb(c.gz).trim() + " | " + (c.first ? "yes" : "") + " |");
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md.join("\n") + "\n");
}
process.exit(okGz && okTotal ? 0 : 1);
'
