import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scripts = dirname(fileURLToPath(import.meta.url));
const oxlint = resolve(scripts, '../browser/node_modules/.bin/oxlint');

const version = '11.10.0';
test(`pnpm ${version}: Git commits lint the index, preserve local edits, and fail closed`, () => {
  const root = mkdtempSync(join(tmpdir(), 'atomic-hook-test-'));
  // Do not inherit an outer commit's Git index/worktree or Husky bypass.
  const env = { ...process.env };

  for (const key of Object.keys(env)) {
    if (key.startsWith('GIT_') || key === 'HUSKY') delete env[key];
  }

  const run = (command, args) =>
    spawnSync(command, args, {
      cwd: root,
      env,
      encoding: 'utf8',
      timeout: 30_000,
    });

  const git = (...args) => {
    const result = run('git', args);
    assert.equal(result.status, 0, result.stdout + result.stderr);

    return result.stdout;
  };

  const write = (file, contents) => writeFileSync(join(root, file), contents);

  const commit = (expected, diagnostic) => {
    const before = git('diff', '--cached', '--binary');
    const working = readFileSync(
      join(root, 'browser/src/with spaces.js'),
      'utf8',
    );
    const modules = join(root, 'browser/node_modules');
    const metadata = existsSync(modules)
      ? readFileSync(join(modules, '.modules.yaml'), 'utf8')
      : null;
    const result = run('git', ['commit', '-m', 'fixture']);
    if (metadata !== null) {
      assert.equal(
        readFileSync(join(modules, '.modules.yaml'), 'utf8'),
        metadata,
      );
      assert.equal(
        readFileSync(join(modules, 'sentinel'), 'utf8'),
        'preserve installed dependencies\n',
      );
    }
    assert.equal(result.status === 0, expected, result.stdout + result.stderr);
    if (diagnostic) assert.match(result.stdout + result.stderr, diagnostic);
    assert.equal(
      readFileSync(join(root, 'browser/src/with spaces.js'), 'utf8'),
      working,
    );
    if (!expected) assert.equal(git('diff', '--cached', '--binary'), before);
  };

  try {
    git('init', '-q');
    git('config', 'user.name', 'Hook test');
    git('config', 'user.email', 'hook-test@example.invalid');
    git('config', 'commit.gpgsign', 'false');
    git('config', 'core.hooksPath', '.hooks');
    mkdirSync(join(root, '.hooks'));
    mkdirSync(join(root, 'scripts'));
    mkdirSync(join(root, 'browser/src'), { recursive: true });
    mkdirSync(join(root, 'browser/node_modules/.bin'), { recursive: true });
    mkdirSync(join(root, 'pnpm-tools'));
    writeFileSync(
      join(root, 'pnpm-tools/pnpm'),
      `#!/bin/sh\nexec corepack pnpm@${version} "$@"\n`,
      { mode: 0o755 },
    );
    env.PATH = `${join(root, 'pnpm-tools')}:${env.PATH}`;
    // A real pnpm 11 workspace with linked, incompatible installed metadata.
    // Any automatic install must fail without a TTY, never purge the modules.
    delete env.CI;
    delete env.pnpm_config_verify_deps_before_run;
    write(
      'browser/pnpm-workspace.yaml',
      'packages: [src]\nverifyDepsBeforeRun: install\n',
    );
    write(
      'browser/node_modules/.modules.yaml',
      'layoutVersion: 5\nstoreDir: /nonexistent-hook-test-store\n',
    );
    write('browser/node_modules/sentinel', 'preserve installed dependencies\n');
    symlinkSync(oxlint, join(root, 'browser/node_modules/.bin/oxlint'));
    symlinkSync(
      resolve(scripts, '../browser/node_modules/oxlint'),
      join(root, 'browser/node_modules/oxlint'),
    );
    write(
      'browser/src/package.json',
      JSON.stringify({
        name: 'hook-lint-fixture',
        scripts: { lint: 'oxlint --deny no-debugger .' },
      }),
    );
    write('.gitignore', 'node_modules/\npnpm-tools/\n');
    copyFileSync(
      join(scripts, 'pre-commit.mjs'),
      join(root, 'scripts/pre-commit.mjs'),
    );
    writeFileSync(
      join(root, '.hooks/pre-commit'),
      '#!/bin/sh\nnode scripts/pre-commit.mjs\n',
      {
        mode: 0o755,
      },
    );
    write(
      'browser/package.json',
      JSON.stringify({
        private: true,
        packageManager: `pnpm@${version}`,
        scripts: { lint: 'pnpm run -r lint' },
      }),
    );
    write('browser/src/with spaces.js', 'debugger;\n');
    git('add', '.');
    // An unstaged fix must not conceal a staged error (including first commit).
    write('browser/src/with spaces.js', 'console.log("fixed");\n');
    commit(false, /no-debugger/);
    git('add', 'browser/src/with spaces.js');
    // Unstaged errors must not block a clean staged snapshot.
    write('browser/src/with spaces.js', 'debugger;\n');
    commit(true);
    // Documentation-only commits skip browser lint, even with local errors.
    write('README.md', 'documentation\n');
    git('add', 'README.md');
    commit(true);
    // Verify Clippy dispatch/failure without compiling a Rust workspace.
    mkdirSync(join(root, 'fake-tools'));
    writeFileSync(
      join(root, 'fake-tools/cargo'),
      `#!/bin/sh
test "$1" = clippy || exit 90
test "$PWD" != "$HOOK_TEST_ROOT" || exit 91
test "$(cat Cargo.toml)" = staged-manifest || exit 92
printf '%s\\n' "$@" > "$HOOK_TEST_ROOT/clippy-args"
exit "$HOOK_TEST_CARGO_STATUS"
`,
      { mode: 0o755 },
    );
    env.PATH = `${join(root, 'fake-tools')}:${env.PATH}`;
    env.HOOK_TEST_ROOT = root;
    env.HOOK_TEST_CARGO_STATUS = '1';
    write('Cargo.toml', 'staged-manifest\n');
    git('add', 'Cargo.toml');
    write('Cargo.toml', 'unstaged-manifest\n');
    commit(false);
    assert.match(
      readFileSync(join(root, 'clippy-args'), 'utf8'),
      /--features\nlight\n--\n-D\nwarnings\n/,
    );
    env.HOOK_TEST_CARGO_STATUS = '0';
    commit(true);
    assert.equal(
      readFileSync(join(root, 'Cargo.toml'), 'utf8'),
      'unstaged-manifest\n',
    );
    // Missing dependencies cannot silently skip checks.
    rmSync(join(root, 'browser/node_modules'), { recursive: true });
    write('browser/src/with spaces.js', 'console.log("another fix");\n');
    git('add', 'browser/src/with spaces.js');
    commit(false, /Browser dependencies missing/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
