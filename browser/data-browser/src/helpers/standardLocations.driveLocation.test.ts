// @wc-ignore-file
import { describe, expect, it, vi } from 'vitest';
import { AtomicError, ErrorType, notifications, type Store } from '@tomic/lib';
import { getOrCreateDriveLocation } from './standardLocations';

/**
 * The Inbox is found through a pointer on the private drive. A second device
 * starts with a partial local copy: the drive may predate the pointer, and the
 * Inbox itself may not have arrived. Neither is a reason to make a new Inbox.
 */
const DRIVE = 'did:ad:private';
const INBOX = 'did:ad:inbox';
const POINTER = notifications.properties.inbox;
const missing = () => new AtomicError('Missing', ErrorType.NotFound);

type Fake = { subject: string; error?: Error; get: (p: string) => unknown };

function device(opts: {
  localDrive: Record<string, unknown>;
  serverDrive: Record<string, unknown>;
  localInbox?: boolean;
  serverInbox?: boolean;
  connected?: boolean;
}) {
  const fake = (subject: string, props: Record<string, unknown>): Fake => ({
    subject,
    get: (p: string) => props[p],
  });
  const created = vi.fn(async () => ({
    subject: 'did:ad:new-inbox',
    save: vi.fn(async () => {}),
  }));
  const driveSet = vi.fn();
  const store = {
    getIdentityGeneration: () => 0,
    serverConnected: opts.connected ?? true,
    isLocalOnlySubject: () => false,
    getResource: vi.fn(async (subject: string) => {
      if (subject === DRIVE) {
        return {
          ...fake(DRIVE, opts.localDrive),
          set: driveSet,
          save: vi.fn(),
        };
      }

      return opts.localInbox
        ? fake(INBOX, {})
        : { subject, error: missing(), get: () => undefined };
    }),
    fetchResourceFromServer: vi.fn(async (subject: string) => {
      if (subject === DRIVE) {
        return {
          ...fake(DRIVE, opts.serverDrive),
          set: driveSet,
          save: vi.fn(),
        };
      }

      return opts.serverInbox
        ? fake(INBOX, {})
        : { subject, error: missing(), get: () => undefined };
    }),
    newResource: created,
    notifyResourceManuallyCreated: vi.fn(),
  };

  return { store: store as unknown as Store, created, driveSet };
}

const locate = (store: Store) =>
  getOrCreateDriveLocation(store, DRIVE, POINTER, {
    isA: notifications.classes.inbox,
    name: 'Inbox',
  });

describe('getOrCreateDriveLocation on a device with a partial local copy', () => {
  it('shares concurrent first use in the location owner', async () => {
    const { store, created, driveSet } = device({
      localDrive: {},
      serverDrive: {},
    });
    expect(await Promise.all([locate(store), locate(store)])).toEqual([
      'did:ad:new-inbox',
      'did:ad:new-inbox',
    ]);
    expect(created).toHaveBeenCalledOnce();
    expect(driveSet).toHaveBeenCalledOnce();
  });

  it('retries a failed creation instead of retaining its rejected promise', async () => {
    const { store, created } = device({ localDrive: {}, serverDrive: {} });
    created.mockRejectedValueOnce(new Error('storage unavailable'));
    await expect(locate(store)).rejects.toThrow('storage unavailable');
    expect(await locate(store)).toBe('did:ad:new-inbox');
    expect(created).toHaveBeenCalledTimes(2);
  });

  it('does not share a pending creation with a new identity session', async () => {
    const { store, created } = device({ localDrive: {}, serverDrive: {} });
    let generation = 0;
    vi.spyOn(store, 'getIdentityGeneration').mockImplementation(
      () => generation,
    );
    const first = locate(store);
    const rejected = expect(first).rejects.toThrow(/session changed/i);
    generation++;
    expect(await locate(store)).toBe('did:ad:new-inbox');
    await rejected;
    expect(created).toHaveBeenCalledOnce();
  });

  it('uses the pointer another device set after this one loaded the drive', async () => {
    const { store, created } = device({
      localDrive: {},
      serverDrive: { [POINTER]: INBOX },
      serverInbox: true,
    });

    expect(await locate(store)).toBe(INBOX);
    expect(created).not.toHaveBeenCalled();
  });

  it('uses an Inbox that is not stored locally yet', async () => {
    const { store, created } = device({
      localDrive: { [POINTER]: INBOX },
      serverDrive: { [POINTER]: INBOX },
      serverInbox: true,
    });

    expect(await locate(store)).toBe(INBOX);
    expect(created).not.toHaveBeenCalled();
  });

  it('does not replace an Inbox it merely failed to read', async () => {
    const { store, created, driveSet } = device({
      localDrive: { [POINTER]: INBOX },
      serverDrive: { [POINTER]: INBOX },
      connected: false,
    });

    await expect(locate(store)).rejects.toBeDefined();
    expect(created).not.toHaveBeenCalled();
    expect(driveSet).not.toHaveBeenCalled();
  });

  it('still makes an Inbox when the server confirms there is none', async () => {
    const { store, created } = device({ localDrive: {}, serverDrive: {} });

    expect(await locate(store)).toBe('did:ad:new-inbox');
    expect(created).toHaveBeenCalledOnce();
  });

  it('replaces a pointer to an Inbox the server no longer has', async () => {
    const { store, created } = device({
      localDrive: { [POINTER]: INBOX },
      serverDrive: { [POINTER]: INBOX },
    });

    expect(await locate(store)).toBe('did:ad:new-inbox');
    expect(created).toHaveBeenCalledOnce();
  });
});
