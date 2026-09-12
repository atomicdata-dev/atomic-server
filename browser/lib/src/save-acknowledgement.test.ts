import { expect, it, vi } from 'vitest';
import { testStore } from './test-store.js';
import { core } from './ontologies/core.js';

it('does not report server persistence when the outbox retained a failed genesis', async () => {
  const { store, postCommitSpy } = await testStore();
  const drive = await store.createDrive('Home');
  const app = await store.newResource({
    parent: drive.subject,
    isA: [core.classes.folder],
    propVals: { [core.properties.name]: 'Pending app' },
  });
  const acknowledge = postCommitSpy.getMockImplementation()!;
  const subject = app.subject;
  postCommitSpy.mockRejectedValue(new Error('Temporary server failure'));
  expect(await app.save()).toBe('offline');
  expect(store.outbox.hasPending(app.subject)).toBe(true);
  // A second save during backoff is still pending, not an acknowledgement.
  expect(await app.save()).toBe('offline');
  postCommitSpy.mockImplementation(acknowledge);
  const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 60_000);

  try {
    expect(await app.save()).toBe('persisted');
    expect(store.outbox.hasPending(subject)).toBe(false);
    expect(app.subject).toBe(subject);
  } finally {
    clock.mockRestore();
  }
});
