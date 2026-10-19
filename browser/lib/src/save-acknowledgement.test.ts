import { afterEach, describe, expect, it, vi } from 'vitest';
import { core } from './ontologies/core.js';
import { Resource } from './resource.js';
import { testStore } from './test-store.js';
import { AtomicError, ErrorType, RequestCancelledError } from './error.js';
import { BLOCK_AFTER_FAILURES } from './local-outbox.js';
import { ErrorCode } from './ws-v2.js';
import { StoreEvents } from './store.js';

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
  it('still reports a save the server acknowledged when the local mirror fails', async () => {
    const { store } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    vi.spyOn(Resource.prototype, 'persistToClientDb').mockRejectedValue(
      new Error('ClientDb unavailable: parked'),
    );

    await expect(doc.save()).resolves.toBe('persisted');
    expect(doc.commitError).toBeUndefined();
    store.setServerConnected(false);
  });

  it('does not hold an acknowledged save on a local mirror that never answers', async () => {
    const { store } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    vi.spyOn(Resource.prototype, 'persistToClientDb').mockReturnValue(
      new Promise(() => {}),
    );

    await expect(doc.save()).resolves.toBe('persisted');
    store.setServerConnected(false);
  }, 10_000);

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

  it('re-arms a write parked for a missing parent when its drive finishes a resync', async () => {
    const { store, postCommitSpy } = await testStore();
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    const refusal =
      'Parent of atomic:a (atomic:b) not found: Resource not found.';
    postCommitSpy.mockRejectedValue(new Error(refusal));
    await doc.save().catch(() => undefined);
    const entry = store.outbox.getEntry(doc.subject)!;
    entry.failures = BLOCK_AFTER_FAILURES;
    entry.blocked = true;
    entry.lastAttemptError = refusal;

    // Another drive finishing its sync says nothing about this one's parent.
    store.finishDriveSync('did:ad:some-other-drive', 1, Date.now());
    expect(entry.blocked).toBe(true);

    store.finishDriveSync(doc.subject, 1, Date.now());
    expect(entry.blocked).toBe(false);
    expect(entry.failures).toBe(0);
    store.setServerConnected(false);
  });

  it("keeps each drive's finished sync, so another drive finishing later does not hide it", async () => {
    const { store } = await testStore();
    const ontola = 'did:ad:ontola';
    store.finishDriveSync(ontola, 5, 100);
    store.finishDriveSync('did:ad:own', 2, 200);
    store.setDrive(ontola);
    expect(store.getSyncStatus().lastDriveSync?.drive).toBe(ontola);
    expect(store.getSyncStatus().lastDriveSync?.timestamp).toBe(100);
    store.setServerConnected(false);
  });

  it('reports writes refused for a missing parent once per drive', async () => {
    const { store } = await testStore();
    const drive = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    const refusal =
      'Parent of atomic:a (atomic:b) not found: Resource not found.';
    const errors: string[] = [];
    store.on(StoreEvents.Error, e => errors.push(e.message));
    const notify = (subject: string) =>
      (
        store as unknown as {
          notifyBlockedSync(subject: string, message: string): void;
        }
      ).notifyBlockedSync(subject, refusal);

    notify(drive.subject);
    notify(drive.subject);
    notify(drive.subject);

    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('drive');
    expect(errors[0]).not.toContain('Not retrying; edit again');
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

describe('terminal drops are classified by error code, not message text', () => {
  // The server's structured `code` (WS `ERROR` frame or the `errorCode`
  // property on the HTTP `/commit` error body) decides whether a refusal is
  // terminal and whether the drop is benign. Message matching only covers
  // code-less responses from older servers, so a wording change on the server
  // cannot turn a terminal refusal into infinite retries.
  const LEGACY_GENESIS =
    'Commit for did:ad:abc has is_genesis: true, but the resource already exists.';

  async function saveRejectedWith(error: Error) {
    const { store, postCommitSpy } = await testStore();
    const notify = vi
      .spyOn(store, 'notifyError')
      .mockImplementation(() => undefined);
    const doc = await store.newResource({
      isA: 'https://atomicdata.dev/classes/Drive',
      noParent: true,
    });
    postCommitSpy.mockRejectedValue(error);
    await expect(doc.save()).rejects.toBe(error);
    const pending = store.outbox.hasPending(doc.subject);
    store.setServerConnected(false);

    return { pending, notified: notify.mock.calls.length };
  }

  it.each([ErrorCode.GENESIS_COLLISION, ErrorCode.IMMUTABLE_COMMIT])(
    'code %s with an unrelated message drops the entry silently',
    async code => {
      const { pending, notified } = await saveRejectedWith(
        new AtomicError(
          'refused, in words this client has never seen',
          ErrorType.Server,
          code,
        ),
      );
      expect(pending).toBe(false);
      expect(notified).toBe(0);
    },
  );

  it('a code-less legacy genesis-collision message still drops silently', async () => {
    const { pending, notified } = await saveRejectedWith(
      new Error(LEGACY_GENESIS),
    );
    expect(pending).toBe(false);
    expect(notified).toBe(0);
  });

  it("the HTTP error body's errorCode is honoured over its description", async () => {
    // `Client.postCommit` wraps a non-200 body in `AtomicError(body)`, whose
    // constructor reads `errorCode` off the JSON-AD error resource.
    const body = JSON.stringify({
      'https://atomicdata.dev/properties/description': 'unrelated wording',
      'https://atomicdata.dev/properties/errorCode':
        ErrorCode.GENESIS_COLLISION,
    });
    const { pending, notified } = await saveRejectedWith(
      new AtomicError(body, ErrorType.Server),
    );
    expect(pending).toBe(false);
    expect(notified).toBe(0);
  });

  it('another code keeps the entry even when the message has the legacy phrase', async () => {
    const { pending } = await saveRejectedWith(
      new AtomicError(
        LEGACY_GENESIS,
        ErrorType.Server,
        ErrorCode.UNAUTHORIZED_WRITE,
      ),
    );
    expect(pending).toBe(true);
  });

  it('a lost-write terminal code drops the entry and tells the user', async () => {
    const { pending, notified } = await saveRejectedWith(
      new AtomicError(
        'unrelated wording',
        ErrorType.Server,
        ErrorCode.MISSING_REQUIRED_PROPERTY,
      ),
    );
    expect(pending).toBe(false);
    expect(notified).toBe(1);
  });
});
