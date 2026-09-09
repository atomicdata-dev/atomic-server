import { expect, it } from 'vitest';
import { grantIdentity } from './grantIdentity';

it('never shares consent across accounts, servers, drives or installations', () => {
  const base = ['https://server', 'drive', 'alice', 'installation'] as const;
  const original = grantIdentity(...base);

  for (let i = 0; i < base.length; i++) {
    const other: [string, string, string, string] = [...base];
    other[i] = 'other';
    expect(grantIdentity(...other)).not.toBe(original);
  }

  expect(original).not.toBe('atomic.plugins.ui.namespace.plugin');
  expect(grantIdentity('a', 'b,c', 'd', 'e')).not.toBe(
    grantIdentity('a,b', 'c', 'd', 'e'),
  );
});
