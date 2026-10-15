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

  describe('scoped to the viewed workspace', () => {
    const OTHER = 'did:ad:otherdrive';
    const entry = (message: string, subject: string) => [
      {
        subject,
        blocked: true,
        failures: 5,
        lastAttemptError: message,
      },
    ];
    const driveOf = (subject: string) =>
      subject.startsWith('other:') ? OTHER : DRIVE;
    const missing = 'Parent of atomic:ktCV (atomic:Xlqr) not found';

    it('ignores changes of another workspace', () => {
      expect(
        describeSyncProblem({
          ...base,
          status: status({ blockedCount: 1 }),
          entries: entry(missing, 'other:doc'),
          driveOf,
        }),
      ).toBeNull();
    });

    it('ignores another workspace that keeps failing', () => {
      expect(
        describeSyncProblem({
          ...base,
          entries: [
            { subject: 'other:doc', failures: 9, lastAttemptError: 'x' },
          ],
          driveOf,
        }),
      ).toBeNull();
    });

    it('still reports changes of the viewed workspace', () => {
      const problem = describeSyncProblem({
        ...base,
        entries: [
          ...entry(missing, 'other:doc'),
          ...entry(missing, 'mine:doc'),
        ],
        driveOf,
      });

      expect(problem?.title).toBe('This server does not have this workspace');
      expect(problem?.actions).toEqual(['connect-device', 'review-sync']);
      expect(problem?.detail).toBe(missing);
    });

    it('compares spellings of the same workspace as equal', () => {
      const problem = describeSyncProblem({
        ...base,
        entries: entry('weird', 'mine:doc'),
        driveOf: () => DRIVE.replace('did:ad:', 'atomic:'),
      });

      expect(problem?.key).toBe('blocked');
    });

    it('scopes the same way when the viewed workspace is a top-level resource', () => {
      const dm = 'did:ad:dm';
      const problem = describeSyncProblem({
        ...base,
        status: status({ drive: dm }),
        entries: [...entry('weird', 'drive:doc'), ...entry(missing, 'dm:doc')],
        driveOf: s => (s.startsWith('dm:') ? dm : DRIVE),
      });

      expect(problem?.key).toBe('not-hosted');
    });
  });
});
