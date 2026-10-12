import { afterEach, describe, expect, it, vi } from 'vitest';
import { isSettledDestroyErrorMessage } from './local-outbox.js';
import { Resource } from './resource.js';
import { isNewPlaceholderSubject } from './subject.js';
import { testStore } from './test-store.js';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
  // `test-setup.ts` relies on this flag to keep the Store off a real WS.
  localStorage.setItem('ws-disconnected', '1');
});

const PLACEHOLDERS = [
  '_new:01m370mvgky7aszw76azkqxtxn',
  'internal:/_new:01m370mvgky7aszw76azkqxtxn',
  'https://atomic.example.de/_new:01m370mvgky7aszw76azkqxtxn',
];

describe('Resource.destroy() of a placeholder that never reached the server', () => {
  it.each(PLACEHOLDERS)(
    'drops %s locally and queues nothing, even when `new` is false',
    async subject => {
      const { store, postCommitSpy } = await testStore();
      // A placeholder that lost its `new` flag, e.g. one refetched under the
      // spelling the server normalized it to.
      const ghost = new Resource(subject, false);
      store.addResource(ghost);

      await expect(ghost.destroy()).resolves.toBeUndefined();

      expect(postCommitSpy).not.toHaveBeenCalled();
      expect(store.outbox.hasPending(subject)).toBe(false);
      expect(store.hasPendingDestroy(subject)).toBe(false);
      expect(store.resources.has(subject)).toBe(false);
    },
  );

  it('recognises placeholders in every spelling and nothing else', () => {
    for (const subject of PLACEHOLDERS) {
      expect(isNewPlaceholderSubject(subject)).toBe(true);
    }

    expect(isNewPlaceholderSubject('https://example.com/doc/_new')).toBe(false);
    expect(isNewPlaceholderSubject('did:ad:abc')).toBe(false);
    expect(isNewPlaceholderSubject('https://example.com/a_new:b')).toBe(false);
  });

  it('treats the server saying there is nothing to destroy as settled', () => {
    expect(
      isSettledDestroyErrorMessage(
        'Destroy commit for internal:/_new:x has no such resource to destroy on this node',
      ),
    ).toBe(true);
  });
});
