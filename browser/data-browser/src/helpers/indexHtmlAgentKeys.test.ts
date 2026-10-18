import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AGENT_FALLBACK_KEY, AGENT_IDB_KEY } from './agentStorage';

// index.html reads the agent straight from IndexedDB before the bundle loads,
// so it hard-codes what agentStorage.ts and idb-keyval define.
describe('index.html agent preread', () => {
  const html = readFileSync(resolve(__dirname, '../../index.html'), 'utf8');

  it.each([
    ['AGENT_IDB_KEY', AGENT_IDB_KEY],
    ['AGENT_FALLBACK_KEY', AGENT_FALLBACK_KEY],
    ['idb-keyval database', 'keyval-store'],
    ['idb-keyval store', 'keyval'],
  ])('uses the %s name', (_, name) => {
    expect(html).toContain(`'${name}'`);
  });
});
