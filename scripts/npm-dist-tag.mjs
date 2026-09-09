#!/usr/bin/env node
/**
 * Dist-tag for a release version. Used by the release.yml npm job so a
 * pre-release cannot accidentally become `latest`.
 *
 *   node scripts/npm-dist-tag.mjs 0.41.0-beta.4   → beta
 *   node scripts/npm-dist-tag.mjs v0.41.0-rc.1    → rc
 *   node scripts/npm-dist-tag.mjs 0.41.0          → latest
 *
 * `--check` runs the cases below and exits non-zero on a mismatch. No
 * network, no npm — this is the bit that used to live as untested bash
 * and is the only decision the publish job makes on its own.
 */
const CASES = [
  ['0.41.0', 'latest'],
  ['v0.41.0', 'latest'],
  ['0.41.0-beta.4', 'beta'],
  ['v0.41.0-beta.4', 'beta'],
  ['0.41.0-beta', 'beta'],
  ['0.41.0-rc.1', 'rc'],
  ['0.41.0-alpha.0', 'alpha'],
  ['1.0.0-rc.12', 'rc'],
];

export function npmDistTag(raw) {
  const version = String(raw).replace(/^v/, '');
  if (!version.includes('-')) {
    return 'latest';
  }
  const pre = version.slice(version.indexOf('-') + 1);
  const id = pre.split(/[.-]/, 1)[0];
  return id || 'beta';
}

const args = process.argv.slice(2);
if (args[0] === '--check') {
  let failed = 0;
  for (const [input, expected] of CASES) {
    const got = npmDistTag(input);
    if (got !== expected) {
      console.error(`fail: ${input} → ${got} (expected ${expected})`);
      failed += 1;
    }
  }
  if (failed) {
    process.exit(1);
  }
  console.log(`ok: ${CASES.length} dist-tag cases`);
  process.exit(0);
}

if (args.length !== 1 || args[0].startsWith('-')) {
  console.error('Usage: node scripts/npm-dist-tag.mjs <version>');
  console.error('       node scripts/npm-dist-tag.mjs --check');
  process.exit(1);
}

console.log(npmDistTag(args[0]));
