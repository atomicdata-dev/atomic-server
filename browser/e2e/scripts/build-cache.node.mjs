import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  buildKey,
  artifactDigest,
  wasmArtifactDigest,
} from './build-cache.mjs';

test('cache invalidates product changes and corrupted outputs but permits spec-only edits', () => {
  const root = mkdtempSync(join(tmpdir(), 'e2e-build-cache-'));
  const git = args => execFileSync('git', args, { cwd: root, stdio: 'ignore' });

  try {
    git(['init']);
    mkdirSync(join(root, 'browser/e2e'), { recursive: true });
    writeFileSync(join(root, 'browser/product.ts'), 'export const value = 1;');
    writeFileSync(join(root, 'browser/e2e/spec.ts'), '// first test');
    git(['add', '.']);
    git([
      '-c',
      'user.name=Test',
      '-c',
      'user.email=test@example.invalid',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '-m',
      'fixture',
    ]);
    const versions = ['node-test', 'pnpm-test', 'rustc-test', 'cargo-test'];
    const before = buildKey(root, process.env, versions);
    const wasmBefore = buildKey(root, process.env, versions, 'wasm');
    const optimizedEnv = { ...process.env, ATOMIC_E2E_CARGO_PROFILE: 'e2e' };
    const debugEnv = { ...process.env, ATOMIC_E2E_CARGO_PROFILE: 'dev' };
    assert.notEqual(
      buildKey(root, optimizedEnv, versions),
      buildKey(root, debugEnv, versions),
    );
    assert.equal(
      buildKey(root, optimizedEnv, versions, 'wasm'),
      buildKey(root, debugEnv, versions, 'wasm'),
    );

    writeFileSync(join(root, 'browser/e2e/spec.ts'), '// another test');
    assert.equal(buildKey(root, process.env, versions), before);
    git(['add', '.']);
    git([
      '-c',
      'user.name=Test',
      '-c',
      'user.email=test@example.invalid',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '-m',
      'spec-only change',
    ]);
    assert.equal(buildKey(root, process.env, versions), before);
    writeFileSync(join(root, 'browser/product.ts'), 'export const value = 2;');
    assert.notEqual(buildKey(root, process.env, versions), before);
    assert.equal(buildKey(root, process.env, versions, 'wasm'), wasmBefore);
    mkdirSync(join(root, 'lib/src'), { recursive: true });
    writeFileSync(join(root, 'lib/src/source.rs'), '// changed Rust input');
    assert.notEqual(buildKey(root, process.env, versions, 'wasm'), wasmBefore);
    rmSync(join(root, 'lib'), { recursive: true });
    writeFileSync(join(root, 'browser/product.ts'), 'export const value = 1;');
    assert.notEqual(
      buildKey(root, { ...process.env, VITE_E2E: 'changed' }, versions),
      before,
    );
    writeFileSync(
      join(root, 'browser/new-module.ts'),
      '// untracked product source',
    );
    assert.notEqual(buildKey(root, process.env, versions), before);
    assert.notEqual(
      buildKey(root, process.env, ['different tool version']),
      before,
    );
    const binary = join(root, 'server-binary');
    assert.throws(() => artifactDigest(root, binary));
    for (const directory of [
      'lib/dist',
      'react/dist',
      'svelte/dist',
      'cli/bin',
      'create-template/bin',
      'data-browser/dist',
      'data-browser/public/wasm',
    ])
      mkdirSync(join(root, 'browser', directory), { recursive: true });
    assert.throws(() => wasmArtifactDigest(root));
    const wasmJs = join(
      root,
      'browser/data-browser/public/wasm/atomic_wasm.js',
    );
    writeFileSync(wasmJs, 'glue');
    writeFileSync(
      join(root, 'browser/data-browser/public/wasm/atomic_wasm_bg.wasm'),
      'wasm',
    );
    const wasmArtifacts = wasmArtifactDigest(root);
    writeFileSync(wasmJs, 'changed glue');
    assert.notEqual(wasmArtifactDigest(root), wasmArtifacts);
    writeFileSync(binary, 'compiled');
    const artifacts = artifactDigest(root, binary);
    writeFileSync(binary, 'different build');
    assert.notEqual(artifactDigest(root, binary), artifacts);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
