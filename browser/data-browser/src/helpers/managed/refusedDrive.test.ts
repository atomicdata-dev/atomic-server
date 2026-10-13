import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { conversations, core } from '@tomic/react';
import { healRefusedDrive } from './refusedDrive';
import { setManagedDeviceToken } from './api';
import { noteManagedSessionChanged } from './session';

const DRIVE = 'did:ad:W2Q3';
const ME = 'did:ad:agent:me';
const OTHER = 'did:ad:agent:other';

/** What `store.getResource` resolves for a drive, as far as the decision reads. */
function resource(
  classes: string[] = [],
  error?: Error,
  ready = true,
  read?: unknown,
) {
  return {
    error,
    isReady: () => ready,
    get: (property: string) =>
      property === core.properties.read ? read : undefined,
    hasClasses: (...wanted: string[]) =>
      wanted.every(klass => classes.includes(klass)),
  };
}

function setup(local = false, found: unknown = resource()) {
  return {
    getResource: vi.fn(async () => found as never),
    getAgent: () => ({ subject: ME }) as never,
    isLocalOnlyDrive: vi.fn(() => local),
    normalizeSubject: (subject: string) =>
      subject.replace(/^did:ad:/, 'atomic:'),
    makeDriveLocal: vi.fn(async () => {}),
  };
}

describe('a drive the node refuses as not enrolled', () => {
  // The session answer is cached; a signed-out answer from one test must not
  // stand in for the next test's control plane.
  beforeEach(() => noteManagedSessionChanged());

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it('moves to this browser when the account hosts nothing for it', async () => {
    const store = setup();

    expect(await healRefusedDrive(store, DRIVE, async () => [])).toBe(true);
    expect(store.makeDriveLocal).toHaveBeenCalledExactlyOnceWith(DRIVE);
  });

  it('ignores enrollments of other drives and disabled ones', async () => {
    const store = setup();

    expect(
      await healRefusedDrive(store, DRIVE, async () => [
        { drive_subject: 'did:ad:other', status: 'Active' },
        { drive_subject: DRIVE, status: 'Disabled' },
      ]),
    ).toBe(true);
    expect(store.makeDriveLocal).toHaveBeenCalledOnce();
  });

  it.each(['Active', 'Pending', 'Suspended', 'Error'])(
    'does not move a drive with a %s enrollment, wherever it is hosted',
    async status => {
      const store = setup();

      expect(
        await healRefusedDrive(store, DRIVE, async () => [
          // Spelled the other way: the refusal and the account may differ.
          { drive_subject: 'atomic:W2Q3', status },
        ]),
      ).toBe(false);
      expect(store.makeDriveLocal).not.toHaveBeenCalled();
    },
  );

  it('does not move a drive when the enrollment lookup fails', async () => {
    const store = setup();

    expect(
      await healRefusedDrive(store, DRIVE, async () => {
        throw new Error('Could not check Cloud Server hosting.');
      }),
    ).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
  });

  it('does not move a drive when nobody is signed in', async () => {
    vi.stubEnv('VITE_MANAGED_API_BASE', 'https://portal.example/api');
    setManagedDeviceToken(null);
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith('/me'))
        return new Response(null, { status: 401 });

      throw new Error(`Unexpected fetch: ${String(input)}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    const store = setup();

    expect(await healRefusedDrive(store, DRIVE)).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it('asks the control plane when signed in, and moves a drive it does not list', async () => {
    vi.stubEnv('VITE_MANAGED_API_BASE', 'https://portal.example/api');
    setManagedDeviceToken(null);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);

        if (url.endsWith('/me')) return Response.json({ email: 'a@b.c' });
        if (url.endsWith('/sync-enrollments'))
          return Response.json([
            { drive_subject: 'did:ad:other', status: 'Active' },
          ]);

        throw new Error(`Unexpected fetch: ${url}`);
      }),
    );
    const store = setup();

    expect(await healRefusedDrive(store, DRIVE)).toBe(true);
    expect(store.makeDriveLocal).toHaveBeenCalledOnce();
    vi.unstubAllGlobals();
  });

  it('does not move a drive when the control plane cannot be reached', async () => {
    vi.stubEnv('VITE_MANAGED_API_BASE', 'https://portal.example/api');
    setManagedDeviceToken(null);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);

        if (url.endsWith('/me')) return Response.json({ email: 'a@b.c' });

        return new Response('oops', { status: 502 });
      }),
    );
    const store = setup();

    expect(await healRefusedDrive(store, DRIVE)).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it('leaves the refusal to be reported when the local copy cannot be verified', async () => {
    const store = setup();
    store.makeDriveLocal.mockRejectedValue(new Error('Sign in first'));
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect(await healRefusedDrive(store, DRIVE, async () => [])).toBe(false);
  });

  it('never moves an encrypted conversation, whatever the account hosts', async () => {
    const store = setup(false, resource([conversations.classes.conversation]));
    const lookup = vi.fn(async () => []);

    expect(await healRefusedDrive(store, DRIVE, lookup)).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
    expect(lookup).not.toHaveBeenCalled();
  });

  it('moves a conversation with only yourself, a note to self', async () => {
    const store = setup(
      false,
      resource([conversations.classes.conversation], undefined, true, [ME]),
    );

    expect(await healRefusedDrive(store, DRIVE, async () => [])).toBe(true);
    expect(store.makeDriveLocal).toHaveBeenCalledExactlyOnceWith(DRIVE);
  });

  it('still asks what the account hosts before moving a note to self', async () => {
    const store = setup(
      false,
      resource([conversations.classes.conversation], undefined, true, [ME]),
    );

    expect(
      await healRefusedDrive(store, DRIVE, async () => [
        { drive_subject: DRIVE, status: 'Active' },
      ]),
    ).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
  });

  it.each([
    ['with someone else', [ME, OTHER]],
    ['of someone else only', [OTHER]],
    ['whose members are unreadable', undefined],
    ['with no members', []],
  ])('does not move a conversation %s', async (_, read) => {
    const store = setup(
      false,
      resource([conversations.classes.conversation], undefined, true, read),
    );
    const lookup = vi.fn(async () => []);

    expect(await healRefusedDrive(store, DRIVE, lookup)).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
    expect(lookup).not.toHaveBeenCalled();
  });

  it('does not move a note to self when nobody is signed in', async () => {
    const store = {
      ...setup(
        false,
        resource([conversations.classes.conversation], undefined, true, [ME]),
      ),
      getAgent: () => undefined,
    };

    expect(await healRefusedDrive(store, DRIVE, async () => [])).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
  });

  it('does not move a conversation that cannot be read here, even one of yours', async () => {
    const store = setup(
      false,
      resource(
        [conversations.classes.conversation],
        new Error('Not found'),
        true,
        [ME],
      ),
    );

    expect(await healRefusedDrive(store, DRIVE, async () => [])).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
  });

  it('moves a plain drive that is readable here', async () => {
    const store = setup(
      false,
      resource(['https://atomicdata.dev/classes/Drive']),
    );

    expect(await healRefusedDrive(store, DRIVE, async () => [])).toBe(true);
    expect(store.getResource).toHaveBeenCalledWith(DRIVE);
    expect(store.makeDriveLocal).toHaveBeenCalledOnce();
  });

  it.each([
    ['carries an error', resource([], new Error('Not found'))],
    ['is not ready', resource([], undefined, false)],
  ])('does not move a drive whose resource %s', async (_, found) => {
    const store = setup(false, found);

    expect(await healRefusedDrive(store, DRIVE, async () => [])).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
  });

  it('does not move a drive whose resource cannot be read', async () => {
    const store = setup();
    store.getResource.mockRejectedValue(new Error('timed out'));

    expect(await healRefusedDrive(store, DRIVE, async () => [])).toBe(false);
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
  });

  it('has nothing to do for a drive that is already browser-only', async () => {
    const store = setup(true);
    const lookup = vi.fn(async () => []);

    expect(await healRefusedDrive(store, DRIVE, lookup)).toBe(true);
    expect(lookup).not.toHaveBeenCalled();
    expect(store.makeDriveLocal).not.toHaveBeenCalled();
  });
});
