import { afterEach, describe, expect, it } from 'vitest';
import {
  inviteNodeCandidates,
  pickInviteNode,
  serverFromEntryUrl,
} from './inviteNode';
import { rememberOriginWithoutNode } from './originNode';

describe('inviteNodeCandidates', () => {
  afterEach(() => rememberOriginWithoutNode(undefined));

  it('prefers the origin the link was opened on over a saved server', () => {
    expect(
      inviteNodeCandidates({
        locationOrigin: 'https://node1.atomicserver.eu',
        storedServer: 'https://app.atomic.place',
      }),
    ).toEqual(['https://node1.atomicserver.eu', 'https://app.atomic.place']);
  });

  it('prefers ?server= over everything and drops duplicates', () => {
    expect(
      inviteNodeCandidates({
        serverParam: 'https://node1.atomicserver.eu/anything',
        locationOrigin: 'https://node1.atomicserver.eu',
        storedServer: 'https://node1.atomicserver.eu',
      }),
    ).toEqual(['https://node1.atomicserver.eu']);
  });

  it('ignores the page origin on the dev server', () => {
    expect(
      inviteNodeCandidates({
        locationOrigin: 'http://localhost:6747',
        storedServer: 'http://localhost:9883',
        dev: true,
      }),
    ).toEqual(['http://localhost:9883']);
  });

  it('skips values that are not http(s) origins', () => {
    expect(
      inviteNodeCandidates({
        serverParam: 'javascript:alert(1)',
        locationOrigin: 'tauri://localhost',
        storedServer: 'not a url',
      }),
    ).toEqual([]);
  });

  it('picks the first candidate that is not an origin without a node', () => {
    rememberOriginWithoutNode('https://app.atomic.place');

    expect(
      pickInviteNode([
        'https://app.atomic.place',
        'https://node1.atomicserver.eu',
      ]),
    ).toBe('https://node1.atomicserver.eu');
    expect(pickInviteNode(['https://app.atomic.place'])).toBeUndefined();
  });
});

describe('entry URL signing destination', () => {
  it.each([
    '/app/invite',
    '/APP/INVITE/',
    '/app/%69nvite',
    '/app/show?token=x',
  ])('never adopts an invitation origin at %s', path => {
    const url = new URL(path, 'https://app.example');
    url.searchParams.set('server', 'https://untrusted.example');
    expect(serverFromEntryUrl(url.href)).toBeUndefined();
  });
  it('keeps ordinary server deep links and rejects credentials', () => {
    expect(
      serverFromEntryUrl(
        'https://app.example/app/show?server=https://node.example',
      ),
    ).toBe('https://node.example');
    expect(
      serverFromEntryUrl(
        'https://app.example/app/show?server=https://user:pass@node.example',
      ),
    ).toBeUndefined();
  });
});
