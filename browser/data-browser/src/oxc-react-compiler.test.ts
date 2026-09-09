import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { transformSync } from 'oxc-transform-react';

const srcDir = fileURLToPath(new URL('.', import.meta.url));

function compile(filename: string, source: string) {
  return transformSync(filename, source, {
    jsx: { runtime: 'automatic' },
    reactCompiler: { target: '19' },
  });
}

function walkTsx(dir: string, acc: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const stat = statSync(path);

    if (stat.isDirectory()) {
      walkTsx(path, acc);
    } else if (/\.[jt]sx$/.test(name) && !name.includes('.test.')) {
      acc.push(path);
    }
  }

  return acc;
}

describe('oxc-transform-react', () => {
  it('does not evaluate TipTap command getters while rendering the node menu', () => {
    const filename = join(srcDir, 'chunks/RTE/NodeSelectMenu.tsx');
    const result = compile(filename, readFileSync(filename, 'utf8'));
    expect(result.fatal).toBe(false);
    const component = result.code.slice(
      result.code.indexOf('function NodeSelectMenu'),
    );
    expect(component).not.toContain('.commands');
  });

  it('outlines captured callbacks into the enclosing function, not module scope', () => {
    // Regression for oxc#25536 (fixed in 0.145). The community
    // oxc-plugin-react-compiler@0.2 and oxc-transform-react@0.144 hoisted
    // `_temp` to module scope, so `mounts` became a ReferenceError.
    const result = compile(
      'probe.tsx',
      `
        import { useEffect } from 'react';
        export function makeProbe() {
          let mounts = 0;
          function MountCounter() {
            useEffect(() => {
              mounts += 1;
            }, []);
            return null;
          }
          return { MountCounter, read: () => mounts };
        }
      `,
    );

    expect(result.fatal).toBe(false);
    expect(result.code).toMatch(/function makeProbe[\s\S]*function _temp/);
    expect(result.code).not.toMatch(/^function _temp/m);
    expect(result.code).toContain('react/compiler-runtime');
  });

  it('memoises multiple components in one file without clashing helpers', () => {
    const result = compile(
      'multi.tsx',
      `
        import { useState } from 'react';
        export function A({ name }: { name: string }) {
          const [n, setN] = useState(0);
          return <button onClick={() => setN(n + 1)}>{name}{n}</button>;
        }
        export function B({ name }: { name: string }) {
          const [n, setN] = useState(0);
          return <button onClick={() => setN(n + 1)}>{name}{n}</button>;
        }
      `,
    );

    expect(result.fatal).toBe(false);
    expect(result.code).toContain('react/compiler-runtime');
    expect(result.code.match(/export function A[\s\S]*_c\(/)).not.toBeNull();
    expect(result.code.match(/export function B[\s\S]*_c\(/)).not.toBeNull();

    const temps = [...result.code.matchAll(/function (_temp\d*)\s*\(/g)].map(
      match => match[1],
    );
    expect(new Set(temps).size).toBe(temps.length);
  });

  it('honours "use no memo"', () => {
    const result = compile(
      'opt-out.tsx',
      `
        import { useState } from 'react';
        export function OptOut() {
          'use no memo';
          const [n, setN] = useState(0);
          return <button onClick={() => setN(n + 1)}>{n}</button>;
        }
      `,
    );

    expect(result.fatal).toBe(false);
    expect(result.code).not.toContain('react/compiler-runtime');
  });

  it('compiles the AI sidebar without a fatal error', () => {
    const file = join(srcDir, 'chunks/AI/AISidebar.tsx');
    const result = compile(file, readFileSync(file, 'utf8'));

    expect(result.fatal).toBe(false);
    expect(result.errors).toEqual([]);
    expect(result.code).toContain('react/compiler-runtime');
  });

  it('transforms every app TSX/JSX file without a fatal error', () => {
    const fatals: string[] = [];
    let compiled = 0;

    for (const file of walkTsx(srcDir)) {
      const result = compile(file, readFileSync(file, 'utf8'));

      if (result.fatal) {
        fatals.push(
          `${file}: ${result.errors.map(error => error.message).join('; ')}`,
        );
      }

      if (result.code.includes('react/compiler-runtime')) {
        compiled += 1;
      }
    }

    expect(fatals).toEqual([]);
    expect(compiled).toBeGreaterThan(400);
    // Every TSX file in the app goes through the compiler here: about two
    // seconds on a workstation, nine on a two-core hosted runner, so the
    // default five-second budget is what failed, not the transform.
  }, 60_000);
});
