import { expect, it } from 'vitest';
import { proxyTransport } from './proxy.mjs';

it('serializes rotating codes, preserves query strings and checkpoints successful writes', async () => {
  let code = 'first';
  const seen = [];
  const journal = {};
  let saves = 0;
  const call = proxyTransport({
    url: 'https://proxy.example',
    repository: 'owner/repo',
    journal,
    getCode: () => code,
    setCode: c => {
      code = c;
    },
    save: async () => {
      saves++;
    },
    fetcher: async (url, opts) => {
      seen.push({ url, ...opts });
      return new Response('{"id":1}', {
        headers: { 'X-Connection-Code': `next-${seen.length}` },
      });
    },
  });
  await Promise.all([
    call('list_issues', { page: 2 }, 'read'),
    call('create_comment', { number: 1, body: 'Hello' }, 'write'),
  ]);
  expect(seen[0].url).toContain(
    '/proxy/github-issues/repos/owner/repo/issues?state=all&per_page=100&page=2',
  );
  expect(seen.map(r => r.headers.Authorization)).toEqual([
    'Bearer first',
    'Bearer next-1',
  ]);
  expect(code).toBe('next-2');
  expect(saves).toBe(2);
  await call('create_comment', { number: 1, body: 'Hello' }, 'write');
  expect(seen).toHaveLength(2);
  await expect(
    call('create_comment', { number: 1, body: 'Changed' }, 'write'),
  ).rejects.toThrow('different arguments');
});

it('never retries an uncertain create after a lost response or restart', async () => {
  const journal = {};
  let writes = 0;
  let code = 'first';
  const options = {
    url: 'https://proxy.example',
    repository: 'owner/repo',
    journal,
    getCode: () => code,
    setCode: c => {
      code = c;
    },
    save: async () => {},
    fetcher: async () => {
      writes++;
      throw new Error('network');
    },
  };
  await expect(
    proxyTransport(options)('create_issue', { title: 'Title' }, 'create'),
  ).rejects.toThrow('Proxy request failed');
  code = 'reconnected';
  await expect(
    proxyTransport(options)('create_issue', { title: 'Title' }, 'create'),
  ).rejects.toThrow('Uncertain GitHub write');
  expect(writes).toBe(1);
});

it('retains rotated codes on provider errors and identifies missing exposed headers', async () => {
  let code = 'first';
  const options = {
    url: 'https://proxy.example',
    repository: 'owner/repo',
    journal: {},
    getCode: () => code,
    setCode: c => {
      code = c;
    },
    save: async () => {},
    fetcher: async () =>
      new Response('{}', {
        status: 403,
        headers: { 'X-Connection-Code': 'rotated' },
      }),
  };
  expect(
    (await proxyTransport(options)('get_issue', { number: 1 }, 'read')).status,
  ).toBe(403);
  expect(code).toBe('rotated');
  options.fetcher = async () => new Response('{}');
  await expect(
    proxyTransport(options)('get_issue', { number: 1 }, 'read'),
  ).rejects.toThrow('expose X-Connection-Code');
});
