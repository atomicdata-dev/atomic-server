import { beforeEach, expect, it, vi } from 'vitest';
import type { Agent, Store } from '@tomic/react';

const saved = vi.hoisted(() => ({ saveAgentToIDB: vi.fn() }));
const env = vi.hoisted(() => ({
  portal: undefined as string | undefined,
  noNode: false,
}));

vi.mock('./managed/cloudSync', () => ({
  getManagedPortalUrl: () => env.portal,
}));
vi.mock('./originNode', () => ({ isOriginWithoutNode: () => env.noNode }));
vi.mock('./tauri', () => ({ isRunningInTauri: () => false }));

vi.mock('./agentStorage', () => saved);

import { startLocalIdentity } from './startLocalIdentity';

const calls: string[] = [];

function fakeStore(failDrive = false) {
  const resource = {
    set: vi.fn(async () => undefined),
    save: vi.fn(async () => {
      calls.push('save-agent-resource');
    }),
  };
  const store = {
    getServerUrl: () => 'https://node.example',
    setAgent: vi.fn((agent?: Agent) => {
      calls.push(agent ? 'setAgent' : 'clearAgent');
    }),
    registerLocalOnlyDrive: vi.fn((subject: string) => {
      calls.push(`local-only:${subject}`);
    }),
    getResourceLoading: vi.fn(() => resource),
    ensurePrivateDrive: vi.fn(async () => {
      calls.push('ensurePrivateDrive');

      if (failDrive) throw new Error('no drive');

      return { subject: 'did:ad:home' };
    }),
  };

  return { store, resource };
}

beforeEach(() => {
  calls.length = 0;
  saved.saveAgentToIDB.mockReset();
  env.portal = undefined;
  env.noNode = false;
});

it.each([
  ['a portal origin', 'https://portal.example', false],
  ['an origin without a node', undefined, true],
])('keeps agent and drive local-only on %s', async (_name, portal, noNode) => {
  env.portal = portal;
  env.noNode = noNode;
  const { store } = fakeStore();
  const { agent, drive } = await startLocalIdentity(store as unknown as Store);

  expect(drive).toBe('did:ad:home');
  expect(agent.subject).toMatch(/agent:/);
  // Registered before any awaited work, so nothing fetches the agent first.
  expect(calls.slice(0, 2)).toEqual([
    'setAgent',
    `local-only:${agent.subject}`,
  ]);
  expect(store.ensurePrivateDrive).toHaveBeenCalledWith(undefined, {
    localOnly: true,
  });
});

it('makes the identity on the server when a node is behind the app', async () => {
  const { store } = fakeStore();
  await startLocalIdentity(store as unknown as Store);

  expect(store.registerLocalOnlyDrive).not.toHaveBeenCalled();
  expect(store.ensurePrivateDrive).toHaveBeenCalledWith(undefined, {
    localOnly: false,
  });
});

it('stores the key as the account identity, not a disposable guest', async () => {
  const { store } = fakeStore();
  const { agent } = await startLocalIdentity(store as unknown as Store);

  expect(saved.saveAgentToIDB).toHaveBeenCalledTimes(1);
  // No `adoptOnDevice: false`: that is what marks the demo's throwaway guest.
  expect(saved.saveAgentToIDB.mock.calls[0]).toHaveLength(1);
  expect(store.setAgent).toHaveBeenLastCalledWith(agent);
});

it('leaves no half-made identity when the drive cannot be made', async () => {
  const { store } = fakeStore(true);

  await expect(startLocalIdentity(store as unknown as Store)).rejects.toThrow(
    'no drive',
  );
  expect(store.setAgent).toHaveBeenLastCalledWith(undefined);
  expect(saved.saveAgentToIDB).not.toHaveBeenCalled();
});
