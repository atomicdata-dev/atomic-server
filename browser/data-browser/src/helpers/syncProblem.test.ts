import { describe, expect, it } from 'vitest';
import type { StoreSyncStatus } from '@tomic/react';
import { describeSyncProblem } from './syncProblem';

const DRIVE = 'did:ad:drive';

function status(patch: Partial<StoreSyncStatus> = {}): StoreSyncStatus {
  return {
    serverConnected: true,
    syncInProgress: false,
    pendingDirtyCount: 0,
    blockedCount: 0,
    serverUrl: 'https://n.example',
    drive: DRIVE,
    clientDbReady: true,
    clientDbAttached: true,
    ...patch,
  };
}

const base = {
  status: status(),
  refusedByServer: false,
  entries: [],
  serverName: 'n.example',
};

describe('describeSyncProblem', () => {
  it('says nothing when nothing is wrong', () => {
    expect(describeSyncProblem(base)).toBeNull();
  });

  it('asks the person to act when the server refuses the workspace', () => {
    const problem = describeSyncProblem({ ...base, refusedByServer: true });

    expect(problem?.cause).toBe('you');
    expect(problem?.actions).toEqual(['connect-device', 'review-sync']);
  });

  it('calls a connection error a state, with a way to retry', () => {
    const problem = describeSyncProblem({
      ...base,
      status: status({
        serverConnected: false,
        serverConnectionError: 'Connection refused',
      }),
    });

    expect(problem?.cause).toBe('offline');
    expect(problem?.actions).toEqual(['try-again']);
  });

  it('owns an unexplained refused sync, and has not reported it yet', () => {
    const problem = describeSyncProblem({
      ...base,
      status: status({
        lastDriveSyncError: { drive: DRIVE, message: 'boom', timestamp: 1 },
      }),
    });

    expect(problem).toMatchObject({
      cause: 'ours',
      reported: false,
      actions: ['try-again'],
    });
  });

  it('ignores a sync error that belongs to another workspace', () => {
    expect(
      describeSyncProblem({
        ...base,
        status: status({
          lastDriveSyncError: {
            drive: 'did:ad:other',
            message: 'boom',
            timestamp: 1,
          },
        }),
      }),
    ).toBeNull();
  });

  it('points a full plan at storage', () => {
    const problem = describeSyncProblem({
      ...base,
      status: status({
        lastDriveSyncError: {
          drive: DRIVE,
          message: 'Drive has reached its storage quota on this node',
          timestamp: 1,
        },
      }),
    });

    expect(problem?.actions).toEqual(['storage']);
  });

  it('names missing write access without blaming us', () => {
    const problem = describeSyncProblem({
      ...base,
      status: status({ blockedCount: 1 }),
      entries: [
        {
          subject: 'a',
          blocked: true,
          lastAttemptError: '401 Unauthorized: no write right',
        },
      ],
    });

    expect(problem).toMatchObject({ cause: 'you', key: 'no-access' });
  });

  it('treats parked changes with an unknown error as ours, already reported', () => {
    const problem = describeSyncProblem({
      ...base,
      status: status({ blockedCount: 1 }),
      entries: [{ subject: 'a', blocked: true, lastAttemptError: 'weird' }],
    });

    expect(problem).toMatchObject({ cause: 'ours', reported: true });
  });

  it('notices changes that keep failing while connected', () => {
    const problem = describeSyncProblem({
      ...base,
      status: status({ pendingDirtyCount: 1 }),
      entries: [{ subject: 'a', failures: 5, lastAttemptError: 'weird' }],
    });

    expect(problem).toMatchObject({ key: 'failing', reported: true });
  });

  it('leaves a first failed attempt alone', () => {
    expect(
      describeSyncProblem({
        ...base,
        status: status({ pendingDirtyCount: 1 }),
        entries: [{ subject: 'a', failures: 1, lastAttemptError: 'x' }],
      }),
    ).toBeNull();
  });

  describe('a refused workspace', () => {
    const OTHER = 'atomic:otherdrive';
    const refused = (drive: string) =>
      `Drive ${drive} is not enrolled for sync on this node`;
    const blockedEntry = (message: string) => [
      {
        subject: 'atomic:somedoc',
        blocked: true,
        failures: 5,
        lastAttemptError: message,
      },
    ];

    it('keeps the plain wording for the workspace in view', () => {
      const problem = describeSyncProblem({
        ...base,
        entries: blockedEntry(refused(DRIVE)),
        driveOf: () => DRIVE,
      });

      expect(problem?.title).toBe('This server does not have this workspace');
      expect(problem?.otherDrive).toBeUndefined();
      expect(problem?.actions).toEqual(['connect-device', 'review-sync']);
    });

    it('names another workspace by its title, and is not offered the viewed switch', () => {
      const problem = describeSyncProblem({
        ...base,
        entries: blockedEntry(refused('did:ad:otherdrive')),
        driveTitle: () => 'Team notes',
      });

      expect(problem?.title).toBe('This server does not have “Team notes”');
      expect(problem?.body).toContain('not the workspace you are viewing');
      expect(problem?.otherDrive).toBe(OTHER);
      expect(problem?.actions).toEqual(['connect-device']);
      expect(problem?.detail).toContain('is not enrolled');
    });

    it('falls back to a neutral phrase when the title cannot be loaded', () => {
      const problem = describeSyncProblem({
        ...base,
        entries: blockedEntry(refused(OTHER)),
        driveTitle: () => undefined,
      });

      expect(problem?.title).toBe(
        'This server does not have another workspace on this device',
      );
      expect(problem?.title).not.toContain(OTHER);
    });

    it('finds the workspace from the entry when the message names none', () => {
      const problem = describeSyncProblem({
        ...base,
        entries: blockedEntry('Parent of atomic:x not found'),
        driveOf: () => OTHER,
        driveTitle: () => 'Team notes',
      });

      expect(problem?.otherDrive).toBe(OTHER);
    });
  });
});
