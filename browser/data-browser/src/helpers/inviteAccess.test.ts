// @wc-ignore-file
import { expect, it, vi } from 'vitest';
import {
  alreadyHasInviteAccess,
  readInviteGrant,
  type AccessResource,
} from './inviteAccess';

const token = (data: Record<string, unknown>) => btoa(JSON.stringify(data));
const grant = (write: boolean, signer = 'atomic:agent:inviter') => ({
  target: 'atomic:drive',
  write,
  signer,
});

function storeWith(resource: AccessResource | Promise<never>) {
  return { getResource: vi.fn(() => Promise.resolve(resource)) };
}

it('reads the target, write flag and signer from a token', () => {
  expect(
    readInviteGrant(
      token({
        'https://atomicdata.dev/properties/invite/target': 'atomic:drive',
        'https://atomicdata.dev/properties/invite/write': true,
        'https://atomicdata.dev/properties/signer': 'atomic:agent:me',
      }),
    ),
  ).toEqual({ target: 'atomic:drive', write: true, signer: 'atomic:agent:me' });
  expect(readInviteGrant('not base64 json')).toBeUndefined();
  expect(readInviteGrant(token({}))).toBeUndefined();
});

it('opens your own invite without asking anything', async () => {
  const store = storeWith({
    error: new Error('unreachable'),
    canWrite: vi.fn(),
  });

  expect(
    await alreadyHasInviteAccess(
      store,
      'atomic:agent:me',
      grant(true, 'atomic:agent:me'),
    ),
  ).toBe(true);
  expect(store.getResource).not.toHaveBeenCalled();
});

it('a view invite needs only that the resource reads', async () => {
  const readable = storeWith({ canWrite: async () => [false, 'no'] });
  const unreadable = storeWith({ error: new Error('401'), canWrite: vi.fn() });

  expect(
    await alreadyHasInviteAccess(readable, 'atomic:agent:me', grant(false)),
  ).toBe(true);
  expect(
    await alreadyHasInviteAccess(unreadable, 'atomic:agent:me', grant(false)),
  ).toBe(false);
});

it('an edit invite needs write rights already', async () => {
  const viewer = storeWith({ canWrite: async () => [false, 'no'] });
  const editor = storeWith({ canWrite: async () => [true, undefined] });

  expect(
    await alreadyHasInviteAccess(viewer, 'atomic:agent:me', grant(true)),
  ).toBe(false);
  expect(
    await alreadyHasInviteAccess(editor, 'atomic:agent:me', grant(true)),
  ).toBe(true);
});

it('shows the invite when signed out or when the check stalls', async () => {
  const editor = storeWith({ canWrite: async () => [true, undefined] });
  const stalled = { getResource: () => new Promise<never>(() => {}) };

  expect(await alreadyHasInviteAccess(editor, undefined, grant(true))).toBe(
    false,
  );
  expect(
    await alreadyHasInviteAccess(stalled, 'atomic:agent:me', grant(false), 10),
  ).toBe(false);
});

it('forgets a failed read, so a drive that arrives later can load', async () => {
  const store = {
    ...storeWith({ error: new Error('not found'), canWrite: vi.fn() }),
    evictResource: vi.fn(),
  };

  expect(
    await alreadyHasInviteAccess(store, 'atomic:agent:me', grant(true)),
  ).toBe(false);
  expect(store.evictResource).toHaveBeenCalledWith('atomic:drive');
});
