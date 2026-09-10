import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { transformSync } from 'oxc-transform-react';

const require = createRequire(import.meta.url);

export const compilerVersion =
  require('oxc-transform-react/package.json').version;

export function checkSource(filename, source, verbose = false) {
  // Match the production transform in oxcReactCompilerPlugin.ts.
  const result = transformSync(filename, source, {
    jsx: { runtime: 'automatic' },
    reactCompiler: { target: '19' },
  });
  const diagnostics = result.errors.map(diagnostic => {
    if (verbose && diagnostic.codeframe) return diagnostic.codeframe;

    // Oxc labels are UTF-8 byte offsets, not JavaScript string offsets.
    const offset = diagnostic.labels[0]?.start;
    let location = filename;

    if (offset !== undefined) {
      const prefix = Buffer.from(source).subarray(0, offset).toString('utf8');
      const lines = prefix.split('\n');
      const column = [...lines[lines.length - 1]].length + 1;
      location += `:${lines.length}:${column}`;
    }

    return `${location} — ${diagnostic.message.replace(/\s+/g, ' ').trim()}`;
  });

  if (result.fatal && diagnostics.length === 0) {
    diagnostics.push(`${filename} — Fatal compiler transform failure.`);
  }

  return {
    diagnostics,
    memoized: result.code.includes('react/compiler-runtime'),
  };
}

export function checkFile(filename, verbose = false) {
  return checkSource(filename, readFileSync(filename, 'utf8'), verbose);
}
