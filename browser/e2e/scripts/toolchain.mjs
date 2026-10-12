import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { createRequire } from 'node:module';

/** Private Corepack shims also pin nested pnpm calls in package scripts. */
export function pinnedEnvironment(browser, output, inherited = process.env) {
  const { packageManager } = JSON.parse(
    readFileSync(join(browser, 'package.json'), 'utf8'),
  );

  const wanted = pnpmPinVersion(packageManager);

  // The pnpm already on PATH is fine when it is the pinned one. Node 25
  // stopped bundling Corepack, so only reach for it on a mismatch.
  if (pnpmVersion(browser, inherited) === wanted)
    return { ...inherited, CI: 'true' };

  const bin = join(output, 'toolchain-bin');
  mkdirSync(bin, { recursive: true });

  try {
    execFileSync('corepack', ['enable', '--install-directory', bin, 'pnpm'], {
      cwd: browser,
      env: inherited,
      stdio: 'pipe',
    });
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    throw new Error(
      `pnpm on PATH is not ${packageManager} and Corepack is not installed. Install ${packageManager} or Corepack (npm install -g corepack).`,
    );
  }

  const env = {
    ...inherited,
    CI: 'true',
    PATH: `${bin}${delimiter}${inherited.PATH}`,
  };
  const actual = pnpmVersion(browser, env);

  if (actual !== wanted) {
    throw new Error(
      `Package manager mismatch: expected ${packageManager}, got pnpm@${actual}`,
    );
  }

  return env;
}

/**
 * The version of an exact pnpm pin. Corepack writes `pnpm@X.Y.Z` and, once it
 * has verified the download, `pnpm@X.Y.Z+sha512.<hex>`. Ranges are rejected.
 */
export function pnpmPinVersion(packageManager) {
  const match =
    /^pnpm@(\d+\.\d+\.\d+)(?:\+sha(?:224|256|384|512)\.[0-9a-f]+)?$/.exec(
      String(packageManager),
    );

  if (!match) {
    throw new Error(`Expected an exact pnpm pin, got ${packageManager}`);
  }

  return match[1];
}

function pnpmVersion(cwd, env) {
  try {
    return execFileSync('pnpm', ['--version'], {
      cwd,
      env,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return undefined;
  }
}

export function verifyPlaywright(browser) {
  const path = join(browser, 'e2e', 'package.json');
  const manifest = JSON.parse(readFileSync(path, 'utf8'));
  const expected = manifest.devDependencies['@playwright/test'];
  const require = createRequire(path);
  const actual = require('@playwright/test/package.json').version;

  if (actual !== expected) {
    throw new Error(
      `Playwright mismatch: expected ${expected}, got ${actual}. Run the pinned frozen install.`,
    );
  }

  return actual;
}
