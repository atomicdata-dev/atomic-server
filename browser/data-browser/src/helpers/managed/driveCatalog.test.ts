import { describe, it, expect, vi } from 'vitest';
import {
  catalogSubjects,
  DriveCatalogSync,
  catalogCacheKey,
  readCatalogCache,
} from './driveCatalog';
const identity = { email: 'one@example.com', agent: 'did:ad:agent:one' };
const remote = {
  drives: [{ drive_subject: 'did:ad:remote' }],
  removed: ['did:ad:removed'],
};

describe('account drive catalog', () => {
  it('shows both indexes, deduplicates, and never resurrects removed entries', () => {
    expect(
      catalogSubjects(
        ['did:ad:local', 'did:ad:remote', 'did:ad:removed'],
        remote,
      ),
    ).toEqual(['did:ad:local', 'did:ad:remote']);
  });
  it('keeps last successful data through an offline failure and retries', async () => {
    const send = vi.fn().mockResolvedValue(remote);
    const sync = new DriveCatalogSync({
      identity: async () => identity,
      send,
      changed: vi.fn(),
    });
    await sync.refresh([]);
    send.mockRejectedValueOnce(new Error('offline'));
    await expect(sync.refresh([])).rejects.toThrow('offline');
    expect(sync.snapshot?.drives).toEqual(remote.drives);
    await sync.refresh([{ drive_subject: 'did:ad:new' }]);
    expect(send).toHaveBeenLastCalledWith([{ drive_subject: 'did:ad:new' }]);
  });
  it('discards a response after logout', async () => {
    let resolve!: (value: unknown) => void;
    const send = vi.fn(
      () =>
        new Promise(r => {
          resolve = r;
        }),
    );
    const sync = new DriveCatalogSync({
      identity: async () => identity,
      send,
      changed: vi.fn(),
    });
    const pending = sync.refresh([]);
    await vi.waitFor(() => expect(send).toHaveBeenCalled());
    sync.reset();
    resolve(remote);
    await pending;
    expect(sync.snapshot).toBeNull();
  });
  it('does not mix identities when accounts change during an upload', async () => {
    const who = vi
      .fn()
      .mockResolvedValueOnce(identity)
      .mockResolvedValueOnce({ ...identity, email: 'two@example.com' });
    const sync = new DriveCatalogSync({
      identity: who,
      send: async () => remote,
      changed: vi.fn(),
    });
    await sync.refresh([]);
    expect(sync.snapshot).toBeNull();
  });
});

it('restores an offline cache only for its bound account and agent', () => {
  const storage = {
    getItem: (key: string) =>
      key === catalogCacheKey(identity) ? JSON.stringify(remote) : null,
  };
  expect(readCatalogCache(identity, storage)?.drives).toEqual(remote.drives);
  expect(
    readCatalogCache({ ...identity, email: 'other@example.com' }, storage),
  ).toBeNull();
  expect(readCatalogCache({ ...identity, agent: 'other' }, storage)).toBeNull();
});
