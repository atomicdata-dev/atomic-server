// Usage: node --experimental-strip-types scripts/generate-export-bindings.mjs <manifest.json> <out.ts>
import { readFileSync, writeFileSync } from 'node:fs';
import { generateExportBindings } from '../src/exportBindings.ts';

const [manifestPath, outPath] = process.argv.slice(2);

if (!manifestPath || !outPath) {
  console.error('Usage: generate-export-bindings <manifest.json> <out.ts>');
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
writeFileSync(outPath, generateExportBindings(manifest));
