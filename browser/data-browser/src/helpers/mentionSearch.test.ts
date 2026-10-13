import { describe, expect, it } from 'vitest';
import { core, type Store } from '@tomic/react';
import { findMemberSubjects } from './mentionSearch';

const fakeResource = (props: Record<string, unknown>) => ({
  get: (prop: string) => props[prop],
});

const fakeStore = (resources: Record<string, Record<string, unknown>>) =>
  ({
    getResource: async (subject: string) => fakeResource(resources[subject]),
  }) as unknown as Store;

describe('findMemberSubjects', () => {
  const store = fakeStore({
    drive: {
      [core.properties.write]: ['did:ad:agent:alice', 'did:ad:agent:bob'],
      [core.properties.read]: ['did:ad:agent:bob', 'did:ad:agent:carol'],
    },
    'did:ad:agent:alice': { [core.properties.name]: 'Alice Jansen' },
    'did:ad:agent:bob': { [core.properties.shortname]: 'bobby' },
    'did:ad:agent:carol': { [core.properties.name]: 'Carol' },
  });

  it('matches drive members by name or shortname, once each', async () => {
    expect(await findMemberSubjects(store, 'drive', 'ali')).toEqual([
      'did:ad:agent:alice',
    ]);
    expect(await findMemberSubjects(store, 'drive', 'BOB')).toEqual([
      'did:ad:agent:bob',
    ]);
  });

  it('offers no members for an empty query', async () => {
    expect(await findMemberSubjects(store, 'drive', '  ')).toEqual([]);
  });
});
