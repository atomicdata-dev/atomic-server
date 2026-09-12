import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  readSync,
  openSync,
  closeSync,
  readdirSync,
  statSync,
  existsSync,
} from 'node:fs';
import { join, relative } from 'node:path';

export function digestFiles(root, files) {
  const digest = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1024);

  for (const file of [...files].sort()) {
    digest.update(file).update('\0');
    const fd = openSync(join(root, file), 'r');

    try {
      let size;
      while ((size = readSync(fd, buffer, 0, buffer.length, null)) > 0)
        digest.update(buffer.subarray(0, size));
    } finally {
      closeSync(fd);
    }

    digest.update('\0');
  }

  return digest.digest('hex');
}

export function buildKey(root, env, toolVersions, scope = 'all') {
  const git = args =>
    execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
  // Include untracked product inputs too: a new module need not be committed
  // before local E2E can validate it. Generated outputs are git-ignored.
  const files = git([
    'ls-files',
    '--cached',
    '--others',
    '--exclude-standard',
    '-z',
  ])
    .split('\0')
    .filter(
      file =>
        file &&
        existsSync(join(root, file)) &&
        !/^(browser\/e2e\/|planning\/|docs\/|\.github\/|\.dagger\/)/.test(
          file,
        ) &&
        !file.endsWith('.md'),
    );
  for (const localInput of [
    'browser/data-browser/.env',
    'browser/data-browser/.env.local',
    'browser/data-browser/.env.production',
    'browser/data-browser/.env.production.local',
    '.cargo/config',
    '.cargo/config.toml',
    '.npmrc',
    'browser/.npmrc',
  ])
    if (existsSync(join(root, localInput))) files.push(localInput);
  const scopedFiles =
    scope === 'wasm'
      ? files.filter(file =>
          /^(lib\/|wasm\/|\.cargo\/|Cargo\.(toml|lock)$|rust-toolchain(?:\.toml)?$|browser\/(?:data-browser\/)?package\.json$)/.test(
            file,
          ),
        )
      : files;
  const tools =
    toolVersions ??
    ['node', 'pnpm', 'rustc', 'cargo'].map(command =>
      execFileSync(command, ['--version'], {
        cwd: root,
        env,
        encoding: 'utf8',
      }).trim(),
    );
  const buildEnv = Object.fromEntries(
    Object.entries(env)
      .filter(([key]) =>
        key === 'ATOMIC_E2E_CARGO_PROFILE'
          ? scope !== 'wasm'
          : /^(VITE_|CARGO_|RUST|BINARYEN_|NODE_|TAURI$|SOURCEMAP$|ATOMICSERVER_|CC$|CXX$|CFLAGS$|CXXFLAGS$|LDFLAGS$)/.test(
              key,
            ),
      )
      .sort(([a], [b]) => a.localeCompare(b)),
  );

  return createHash('sha256')
    .update(
      JSON.stringify({
        ...(scope === 'wasm' ? { scope } : {}),
        files: digestFiles(root, [...new Set(scopedFiles)]),
        tools,
        buildEnv,
      }),
    )
    .digest('hex');
}

export function artifactDigest(root, binary) {
  const files = [];

  const walk = directory => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) files.push(relative(root, path));
    }
  };

  for (const directory of [
    'lib/dist',
    'react/dist',
    'svelte/dist',
    'cli/bin',
    'create-template/bin',
    'data-browser/dist',
    'data-browser/public/wasm',
  ])
    walk(join(root, 'browser', directory));
  if (!statSync(binary).isFile()) throw new Error('Server binary is missing');
  files.push(relative(root, binary));

  return digestFiles(root, files);
}

export function wasmArtifactDigest(root) {
  return digestFiles(root, [
    'browser/data-browser/public/wasm/atomic_wasm.js',
    'browser/data-browser/public/wasm/atomic_wasm_bg.wasm',
  ]);
}
