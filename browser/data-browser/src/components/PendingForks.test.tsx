import { describe, expect, it, vi } from 'vitest';
import type { Resource } from '@tomic/react';
import { PendingForks } from './PendingForks';

const state = vi.hoisted(() => ({ candidates: new Map<string, Resource>() }));
vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  useDrive: () => ['did:ad:drive'],
  useCollection: () => ({ collection: {}, ready: true }),
  useCollectionPage: () => [...state.candidates.keys()],
  useResources: () => state.candidates,
}));
vi.mock('../views/ResourceInline/ResourceInline', () => ({
  ResourceInline: 'a',
}));

const original = { subject: 'did:ad:original', isFork: false } as Resource;

function candidate(
  subject: string,
  isFork: boolean,
  target?: string,
  loading = false,
): Resource {
  return { subject, isFork, loading, get: () => target } as unknown as Resource;
}

describe('pending fork banner validates query candidates', () => {
  it('does not label ordinary drive contents as proposals', () => {
    state.candidates = new Map([
      ['did:ad:document', candidate('did:ad:document', false)],
      ['did:ad:folder', candidate('did:ad:folder', false)],
    ]);
    expect(PendingForks({ resource: original })).toBeNull();
  });

  it('does not carry proposals from a previous resource or an unresolved candidate', () => {
    state.candidates = new Map([
      [
        'did:ad:other-fork',
        candidate('did:ad:other-fork', true, 'did:ad:other'),
      ],
      [
        'did:ad:loading',
        candidate('did:ad:loading', true, original.subject, true),
      ],
    ]);
    expect(PendingForks({ resource: original })).toBeNull();
  });

  it('shows a verified fork of this resource', () => {
    state.candidates = new Map([
      ['did:ad:fork', candidate('did:ad:fork', true, original.subject)],
    ]);
    expect(PendingForks({ resource: original })).not.toBeNull();
  });
});
