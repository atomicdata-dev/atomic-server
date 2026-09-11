import { setupError } from './setupError';
import { expect, it } from 'vitest';
import { listAppSetups, getAppSetup } from './registry';
import {
  setup,
  credentialLink,
} from '../../../../../integrations/github-issues/setup';
import { validateSetupArguments } from '@tomic/lib';

it('exposes the same non-secret schema to the form and assistant', () => {
  const adapter = getAppSetup('github-issues');
  const declaration = listAppSetups().find(a => a.id === adapter.id)!;
  expect(declaration.inputSchema).toEqual(adapter.declaration.inputSchema);
  expect(Object.keys(declaration.inputSchema.properties)).toEqual([
    'repository',
    'destination',
  ]);
  expect(JSON.stringify(declaration)).not.toContain('credential');
  expect(() =>
    validateSetupArguments(declaration, {
      repository: 'ontola/atomic-server',
      token: 'private',
    }),
  ).toThrow('Unknown setup argument');
  expect(() => getAppSetup('untrusted-source')).toThrow();
});
it('normalizes setup before any installation and rejects malformed repositories', () => {
  expect(setup({ repository: ' ontola/atomic-server ' })).toEqual({
    repository: 'ontola/atomic-server',
    destination: '',
  });

  for (const repository of [
    'https://github.com/a/b',
    'a/b/c',
    '../b',
    'a b/repo',
  ]) {
    expect(() => setup({ repository })).toThrow();
  }
});
it('uses only a valid repository owner in the host credential link', () => {
  const url = new URL(credentialLink('ontola/atomic-server'));
  expect(url.origin).toBe('https://github.com');
  expect(url.searchParams.get('target_name')).toBe('ontola');
  expect(url.searchParams.get('issues')).toBe('write');
  expect(
    new URL(credentialLink('https://evil.test')).searchParams.has(
      'target_name',
    ),
  ).toBe(false);
});

it('redacts credential values from reported host errors', () => {
  expect(
    setupError(new Error('Failed using my-token then my-token'), 'my-token'),
  ).toBe('Failed using [redacted] then [redacted]');
});
