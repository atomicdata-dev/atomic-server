import { describe, expect, it, vi } from 'vitest';
import type { Store } from '@tomic/react';

vi.mock('./DemoDirector', () => ({ DemoDirector: class {} }));
vi.mock('./demoWorkspace', () => ({
  createDemoWorkspace: vi.fn(),
  saveDemoManifest: vi.fn(),
}));
vi.mock('./guestAgent', () => ({ ensureAgentForDemo: vi.fn() }));

const { cleanupDemoDrive, demoOutlivesAgentChange } =
  await import('./startDemo');

const GUEST = 'atomic:agent:guest';
const DRIVE = 'atomic:demo-drive';
const TEAM = 'atomic:team-table';
const ROW = 'atomic:team-row';

/** A store whose local database holds a demo drive, its team table, a
 *  teammate row and the guest's own profile row (the agent resource). */
function demoStore() {
  const children: Record<string, string[]> = {
    [DRIVE]: [TEAM],
    [TEAM]: [ROW, GUEST],
  };
  const removed: string[] = [];
  const store = {
    getAgent: () => ({ subject: GUEST }),
    queryLocalDb: async ({ value }: { property: string; value: string }) => ({
      subjects: children[value] ?? [],
    }),
    removeResource: (subject: string) => removed.push(subject),
    unregisterLocalOnlyDrive: vi.fn(),
    getResource: async () => ({ get: () => undefined }),
  };

  return { store: store as unknown as Store, removed };
}

describe('cleanupDemoDrive', () => {
  it('removes the demo drive and what it holds, but not the guest identity', async () => {
    const { store, removed } = demoStore();

    await cleanupDemoDrive(store, DRIVE);

    expect(removed.sort()).toEqual([DRIVE, ROW, TEAM].sort());
    expect(removed).not.toContain(GUEST);
    expect(store.unregisterLocalOnlyDrive).toHaveBeenCalledWith(DRIVE);
  });
});

describe('demoOutlivesAgentChange', () => {
  it('keeps playing for the same guest', () => {
    expect(demoOutlivesAgentChange(GUEST, { subject: GUEST })).toBe(true);
  });

  it('stops when another identity signs in or the guest becomes an account', () => {
    expect(demoOutlivesAgentChange(GUEST, { subject: 'atomic:agent:me' })).toBe(
      false,
    );
    expect(
      demoOutlivesAgentChange(GUEST, {
        subject: GUEST,
        privateDrive: 'atomic:home',
      }),
    ).toBe(false);
    expect(demoOutlivesAgentChange(GUEST, undefined)).toBe(false);
  });
});
