import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const dir = realpathSync(mkdtempSync(join(tmpdir(), 'react-compiler-cli-')));
const script = fileURLToPath(
  new URL('../scripts/check-react-compiler.mjs', import.meta.url),
);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

function fixture(name: string, source: string) {
  writeFileSync(join(dir, name), source);

  return name;
}

function run(...files: string[]) {
  return spawnSync(process.execPath, [script, ...files], {
    cwd: dir,
    encoding: 'utf8',
  });
}

describe('React Compiler CLI', () => {
  it('reports memoization using paths relative to the caller', () => {
    const result = run(
      fixture(
        'clean.tsx',
        'export function Greeting({name}) { return <p>{name}</p>; }',
      ),
    );

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no diagnostics; memoization emitted');
    expect(result.stderr).toBe('');
  });

  it('fails on a bailout even when another function is memoized', () => {
    const result = run(
      fixture(
        'bailout.tsx',
        `
        import { useState } from 'react';
        export function Greeting({name}) { return <p>{name}</p>; }
        export function useBroken() {
          const [value] = useState(0);
          return async () => {
            try {
              if (value) { throw new Error('oops'); }
              return value;
            } catch { return 'error'; }
          };
        }
      `,
      ),
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('bailout.tsx:');
    expect(result.stderr).toContain('ThrowStatement');
    expect(result.stderr).toMatch(/bailout\.tsx:8:28 — /);
    expect(result.stderr.trim().split('\n')).toHaveLength(1);

    const verbose = run('--verbose', 'bailout.tsx');
    expect(verbose.status).toBe(1);
    expect(verbose.stderr).toContain('throw new Error');
  });

  it('does not claim memoization for an explicit opt-out', () => {
    const result = run(
      fixture(
        'opt-out.tsx',
        `export function Greeting({name}) {
        'use no memo';
        return <p>{name}</p>;
      }`,
      ),
    );

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no memoization emitted');
  });

  it('continues after an unreadable file while keeping a failure exit code', () => {
    const result = run(
      'missing.tsx',
      fixture('plain.ts', 'export const value = 1;'),
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('missing.tsx');
    expect(result.stdout).toContain(`OK ${join(dir, 'plain.ts')}`);
  });
});
