import { afterEach, describe, expect, it, vi } from 'vitest';
import { core } from './ontologies/core.js';
import { testStore } from './test-store.js';
import { RequestCancelledError } from './error.js';
import { BLOCK_AFTER_FAILURES } from './local-outbox.js';

afterEach(() => vi.restoreAllMocks());

describe('explicit save acknowledgement', () => {
  it.each([
    'Unauthorized: no write rights in parent',
    'Property content missing. Is required in class Message',
    'is_genesis: true, but the resource already exists',
  ])('rejects a server refusal: %s', async message => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
      propVals: { [core.properties.name]: 'Rejected' },
    });
    const error = new Error(message);
    postCommitSpy.mockRejectedValue(error);

    await expect(doc.save()).rejects.toBe(error);
    expect(doc.commitError).toBe(error);
    store.setServerConnected(false);
  });

  it('does not report a backed-off retry as persisted', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    const error = new Error('server temporarily unavailable');
    postCommitSpy.mockRejectedValue(error);
    await doc.save().catch(() => undefined);
    const attempts = postCommitSpy.mock.calls.length;

    await expect(doc.save()).rejects.toBe(error);
    expect(postCommitSpy).toHaveBeenCalledTimes(attempts);
    store.setServerConnected(false);
  });

  it('keeps transport failures queued and returns offline', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    postCommitSpy.mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(doc.save()).resolves.toBe('offline');
    expect(store.outbox.hasPending(doc.subject)).toBe(true);
    expect(store.serverConnected).toBe(false);
  });
  it('clears the error after a successful retry', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    const error = new Error('temporary refusal');
    postCommitSpy.mockRejectedValueOnce(error);
    await expect(doc.save()).rejects.toBe(error);
    store.outbox.getEntry(doc.subject)!.lastAttemptAt = 0;

    await expect(doc.save()).resolves.toBe('persisted');
    expect(doc.commitError).toBeUndefined();
    expect(store.outbox.hasPending(doc.subject)).toBe(false);
    store.setServerConnected(false);
  });

  it('rejects a blocked entry without posting again', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    const error = new Error('Unauthorized: no write rights in parent');
    postCommitSpy.mockRejectedValue(error);
    await expect(doc.save()).rejects.toBe(error);
    const entry = store.outbox.getEntry(doc.subject)!;
    entry.failures = BLOCK_AFTER_FAILURES;
    entry.blocked = true;
    const attempts = postCommitSpy.mock.calls.length;

    await expect(doc.save()).rejects.toBe(error);
    expect(postCommitSpy).toHaveBeenCalledTimes(attempts);
    store.setServerConnected(false);
  });

  it('does not let an unrelated failure reject an acknowledged save', async () => {
    const { store, postCommitSpy } = await testStore();
    const rejected = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    const accepted = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    postCommitSpy.mockRejectedValueOnce(new Error('temporary refusal'));
    await rejected.save().catch(() => undefined);

    await expect(accepted.save()).resolves.toBe('persisted');
    expect(store.outbox.hasPending(rejected.subject)).toBe(true);
    store.setServerConnected(false);
  });

  it('rejects cancellation without losing the queued write', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    const error = new RequestCancelledError();
    postCommitSpy.mockRejectedValue(error);

    await expect(doc.save()).rejects.toBe(error);
    expect(store.outbox.hasPending(doc.subject)).toBe(true);
    store.setServerConnected(false);
  });

  it('allows an acknowledged save while a newer edit remains dirty', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    await doc.save();
    await doc.set(core.properties.name, 'Saved edit', false);
    postCommitSpy.mockImplementationOnce(async commit => {
      await doc.set(core.properties.name, 'Newer edit', false);

      return {
        ...commit,
        id: `https://example.com/commits/${commit.signature}`,
      };
    });

    await expect(doc.save()).resolves.toBe('persisted');
    expect(doc.get(core.properties.name)).toBe('Newer edit');
    expect(doc.hasOpsPastSaveCursor()).toBe(true);
    store.setServerConnected(false);
  });

  it('rejects a failed update to an existing resource', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    await doc.save();
    await doc.set(core.properties.name, 'Rejected update', false);
    const error = new Error('Unauthorized: no write rights');
    postCommitSpy.mockRejectedValue(error);

    await expect(doc.save()).rejects.toBe(error);
    expect(doc.hasOpsPastSaveCursor()).toBe(true);
    expect(store.outbox.hasPending(doc.subject)).toBe(true);
    store.setServerConnected(false);
  });
});
