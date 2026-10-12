import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';
import {
  pinnedEnvironment,
  pnpmPinVersion,
  verifyPlaywright,
} from './toolchain.mjs';

const pin = JSON.parse(
  readFileSync(new URL('../../package.json', import.meta.url)),
).packageManager;
const pinVersion = pnpmPinVersion(pin);

function hasCorepack() {
  try {
    execFileSync('corepack', ['--version'], { stdio: 'ignore' });

    return true;
  } catch {
    return false;
  }
}

test('a pinned pnpm on PATH is used without Corepack', () => {
  const root = mkdtempSync(join(tmpdir(), 'atomic-toolchain-'));

  try {
    writeFileSync(
      join(root, 'package.json'),
      JSON.stringify({ packageManager: pin }),
    );
    const bin = join(root, 'bin');
    mkdirSync(bin);
    writeFileSync(join(bin, 'pnpm'), `#!/bin/sh\nprintf "${pinVersion}\\n"\n`, {
      mode: 0o755,
    });
    // Only the fake pnpm and the shell are reachable: no Corepack.
    const env = pinnedEnvironment(root, root, { ...process.env, PATH: bin });
    assert.equal(env.CI, 'true');
    assert.equal(env.PATH, bin);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test(
  'nested pnpm ignores an older PATH executable and installation is noninteractive',
  {
    skip: !hasCorepack() && 'Corepack is not installed',
  },
  () => {
    const root = mkdtempSync(join(tmpdir(), 'atomic-toolchain-'));

    try {
      writeFileSync(
        join(root, 'package.json'),
        JSON.stringify({ packageManager: pin }),
      );
      const oldBin = join(root, 'old-bin');
      mkdirSync(oldBin);
      writeFileSync(join(oldBin, 'pnpm'), '#!/bin/sh\nprintf "8.15.0\\n"\n', {
        mode: 0o755,
      });
      const env = pinnedEnvironment(root, root, {
        ...process.env,
        PATH: `${oldBin}${delimiter}${process.env.PATH}`,
      });
      assert.equal(env.CI, 'true');
      const actual = execFileSync('pnpm', ['exec', 'pnpm', '--version'], {
        cwd: root,
        env,
        encoding: 'utf8',
      }).trim();
      // pnpm 11 may print install progress before the command output.
      assert.equal(actual.split('\n').pop(), pinVersion);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);

test('an installed Playwright version different from the manifest fails closed', () => {
  const root = mkdtempSync(join(tmpdir(), 'atomic-playwright-'));

  try {
    mkdirSync(join(root, 'e2e/node_modules/@playwright/test'), {
      recursive: true,
    });
    writeFileSync(
      join(root, 'e2e/package.json'),
      JSON.stringify({ devDependencies: { '@playwright/test': '1.63.0' } }),
    );
    writeFileSync(
      join(root, 'e2e/node_modules/@playwright/test/package.json'),
      JSON.stringify({ version: '1.60.0' }),
    );
    assert.throws(() => verifyPlaywright(root), /Playwright mismatch/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a Corepack pin with a hash suffix is accepted and ranges are rejected', () => {
  assert.equal(pnpmPinVersion('pnpm@11.10.0'), '11.10.0');
  assert.equal(pnpmPinVersion('pnpm@11.10.0+sha512.0b7f8b98ab12'), '11.10.0');
  for (const bad of [
    'pnpm@^11.10.0',
    'pnpm@11',
    'pnpm@11.10.0+sha512.',
    'pnpm@11.10.0+sha512.XYZ',
    'pnpm@11.10.0+md5.abcd',
    'npm@11.10.0',
    undefined,
  ])
    assert.throws(() => pnpmPinVersion(bad), /exact pnpm pin/);
});
