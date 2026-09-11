#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';

const root = execFileSync('git', ['rev-parse', '--show-toplevel'], {
  encoding: 'utf8',
}).trim();
const changed = execFileSync('git', ['diff', '--cached', '--name-only', '-z'], {
  cwd: root,
  encoding: 'utf8',
})
  .split('\0')
  .filter(Boolean);
const browser = changed.some(file => file.startsWith('browser/'));
// Match CI's main Rust workspace; Flutter and desktop have separate toolchains.
const rust = changed.some(
  file =>
    !file.startsWith('flutter/') &&
    !file.startsWith('desktop/') &&
    (/\.rs$/.test(file) ||
      /(^|\/)Cargo\.(toml|lock)$/.test(file) ||
      file.startsWith('.cargo/') ||
      /^rust-toolchain(\.toml)?$/.test(file)),
);

if (!browser && !rust) process.exit(0);

const snapshot = mkdtempSync(join(tmpdir(), 'atomic-pre-commit-'));

try {
  // Check exactly what Git will commit, including partially staged files.
  // No stash/reset: the user's index and working tree are never modified.
  execFileSync(
    'git',
    ['checkout-index', '--all', `--prefix=${snapshot}${sep}`],
    {
      cwd: root,
      stdio: 'inherit',
    },
  );
  // Git exports these during a commit. They must not make subprocesses inspect
  // the original checkout instead of the staged snapshot.
  const env = { ...process.env };
  for (const key of execFileSync('git', ['rev-parse', '--local-env-vars'], {
    cwd: root,
    encoding: 'utf8',
  })
    .trim()
    .split('\n'))
    delete env[key];

  if (browser) {
    const browserRoot = join(root, 'browser');

    if (!existsSync(join(browserRoot, 'node_modules'))) {
      throw new Error(
        'Browser dependencies missing. Run: cd browser && pnpm install',
      );
    }

    // Reuse installed dependencies, but lint only staged source/configuration.
    const directories = [
      '',
      ...readdirSync(join(snapshot, 'browser'), {
        withFileTypes: true,
      })
        .filter(entry => entry.isDirectory())
        .map(entry => entry.name),
    ];

    for (const directory of directories) {
      const modules = join(browserRoot, directory, 'node_modules');

      if (existsSync(modules)) {
        symlinkSync(
          modules,
          join(snapshot, 'browser', directory, 'node_modules'),
          'dir',
        );
      }
    }

    console.log('pre-commit: linting staged browser snapshot');
    execFileSync('pnpm', ['run', 'lint'], {
      cwd: join(snapshot, 'browser'),
      env: {
        ...env,
        // This snapshot borrows node_modules through symlinks. Never let pnpm
        // repair/install them. Export both names for nested `pnpm run` calls:
        // pnpm 11 reads pnpm_config_*; older versions use npm_config_*.
        pnpm_config_verify_deps_before_run: 'false',
        npm_config_verify_deps_before_run: 'false',
      },
      stdio: 'inherit',
    });
  }

  if (rust) {
    console.log('pre-commit: checking staged Rust snapshot with Clippy');
    execFileSync(
      'cargo',
      [
        'clippy',
        '--workspace',
        '--exclude',
        'atomic-server-tauri',
        '--no-deps',
        '--all-targets',
        '--no-default-features',
        '--features',
        'light',
        '--',
        '-D',
        'warnings',
      ],
      {
        cwd: snapshot,
        env: {
          ...env,
          CARGO_TARGET_DIR: resolve(root, env.CARGO_TARGET_DIR || 'target'),
        },
        stdio: 'inherit',
      },
    );
  }
} catch (error) {
  console.error(`pre-commit: commit blocked. ${error.message}`);
  process.exitCode = 1;
} finally {
  rmSync(snapshot, { recursive: true, force: true });
}
