// @wc-ignore-file
import github from '../../../../../integrations/github-issues/plugin.js?raw';
import notion from '../../../../../integrations/notion/plugin.js?raw';
import clockify from '../../../../../integrations/clockify/plugin.js?raw';
import mt940 from '../../../../../integrations/mt940/plugin.js?raw';
import pets from '../../../../../integrations/pets/plugin.js?raw';
import report from '../../../../../integrations/evidence.json';
import { assessEvidence } from '../../../../../integrations/tooling/evidence.mjs';

const sources = { 'github-issues': github, notion, clockify, mt940, pets };

export type BundledEvidenceId = keyof typeof sources;
export async function loadEvidence(id: BundledEvidenceId) {
  const source = sources[id];
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(source),
  );
  const hash = Array.from(new Uint8Array(digest), byte =>
    byte.toString(16).padStart(2, '0'),
  ).join('');

  return assessEvidence(report, id, hash);
}
