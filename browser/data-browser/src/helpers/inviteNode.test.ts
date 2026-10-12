import { afterEach, describe, expect, it } from 'vitest';
import { inviteNodeCandidates, pickInviteNode } from './inviteNode';
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
