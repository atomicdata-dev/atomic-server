import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { root, discover } from './certify.mjs';
import { assessEvidence } from './evidence.mjs';
// Generates a repository asset only. No network publication or release promotion.
const input = process.argv[2];
if (!input)
  throw new Error(
    'Usage: node integrations/tooling/publish-evidence.mjs report.json',
  );
const report = JSON.parse(readFileSync(resolve(input), 'utf8'));
for (const p of discover()) {
  const hash = createHash('sha256')
    .update(readFileSync(resolve(root, p.path, 'plugin.js')))
    .digest('hex');
  const evidence = assessEvidence(report, p.id, hash);
  const item = report.integrations?.find(i => i.id === p.id);
  if (
    !evidence ||
    evidence.stale ||
    item.version !== p.version ||
    item.owner !== p.owner ||
    item.apiVersion !== p.apiVersion ||
    !p.sandboxTests.every(t =>
      item.checks.some(c => c.name === t && c.status === 'passed'),
    )
  )
    throw new Error(`${p.id}: current complete evidence is required`);
}
writeFileSync(
  resolve(root, 'integrations/evidence.json'),
  JSON.stringify(report, null, 2) + '\n',
);
console.log('Updated repository evidence asset; no external publication');
