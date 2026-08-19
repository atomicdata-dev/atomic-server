import { RequestCancelledError } from './error.js';
import { describe, it, beforeEach, vi } from 'vitest';
import {
  LocalOutbox,
  isTerminalCommitErrorMessage,
  isUnrecoverableCommitErrorMessage,
  isTerminalCommitError,
  isUnrecoverableCommitError,
  isCommitSubject,
  drainBackoffMs,
  groupTiers,
  runBounded,
  BLOCK_AFTER_FAILURES,
  type OutboxEntry,
} from './local-outbox.js';
import { commitToJsonADObject, type Commit } from './commit.js';
import { ErrorCode } from './ws-v2.js';

function fakeCommit(
  subject: string,
  signature = 'fakesig==',
  signer = 'did:ad:agent:fake=',
): Commit {
  return {
    subject,
    signer,
    createdAt: 0,
    signature,
    isA: ['https://atomicdata.dev/classes/Commit'],
    previousCommit: undefined,
    set: { 'https://atomicdata.dev/properties/name': 'x' },
  } as unknown as Commit;
}

/** A persisted `signedGenesis` value (JSON-AD object), built through the real
 *  serializer so `signerOfPersisted` (parseCommitJSON) can read its signer. */
function fakeCommitJsonAd(subject: string, signer: string): unknown {
  return commitToJsonADObject(fakeCommit(subject, 'fakesig==', signer));
}

const SUBJECT = 'did:ad:fakeresource';

describe('isTerminalCommitErrorMessage', () => {
  it('flags genesis-collision errors', ({ expect }) => {
    expect(
      isTerminalCommitErrorMessage(
        'Commit for did:ad:abc has is_genesis: true, but the resource already exists.',
      ),
    ).toBe(true);
  });

  it('flags required-property validation failures', ({ expect }) => {
    expect(
      isTerminalCommitErrorMessage(
        'Property https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/property/content missing. Is required in class https://atomicdata.dev/01jtjxtsa9syxmfca2zx5gcnmj/class/ai-message ',
      ),
    ).toBe(true);
  });

  it('flags a write aimed at an immutable Commit', ({ expect }) => {
    // A `<server>/commits/<sig>` subject (imported from another server) once
    // reached the outbox and retried this rejection on backoff forever.
    expect(isTerminalCommitErrorMessage('Commits cannot be edited.')).toBe(
      true,
    );
  });

  it("doesn't flag normal errors", ({ expect }) => {
    expect(isTerminalCommitErrorMessage('Invalid signature')).toBe(false);
    expect(isTerminalCommitErrorMessage('Network timeout')).toBe(false);
    expect(isTerminalCommitErrorMessage('')).toBe(false);
  });

  it('flags edits to a commit', ({ expect }) => {
    expect(isTerminalCommitErrorMessage('Commits cannot be edited.')).toBe(
      true,
    );
  });
});

describe('commit subjects never queue', () => {
  const HTTP_COMMIT =
    'https://staging.atomicdata.dev/commits//Ybe1N6CuUMUowBWeFYEjuP20Mp4MiTI2ELtuXveh2UnegO2mCdqucz8dG+J7Ldq9cxSzvo6JMdMNqn+VWqrDg==';

  it('recognises both commit subject forms', ({ expect }) => {
    expect(isCommitSubject('did:ad:commit:abc=')).toBe(true);
    expect(isCommitSubject(HTTP_COMMIT)).toBe(true);
    expect(isCommitSubject('https://example.com/commits')).toBe(false);
    expect(isCommitSubject('https://example.com/folder/commits/x')).toBe(false);
    expect(isCommitSubject(SUBJECT)).toBe(false);
    expect(isCommitSubject('_new:abc')).toBe(false);
  });

  it('markDirty ignores them', ({ expect }) => {
    const outbox = new LocalOutbox();
    outbox.markDirty(HTTP_COMMIT);
    outbox.markDirty('did:ad:commit:abc=');
    outbox.markDirty(SUBJECT);
    expect(outbox.size).toBe(1);
  });

  it('entries persisted by an older build are dropped on hydrate', ({
    expect,
  }) => {
    if (typeof localStorage === 'undefined') return;
    localStorage.clear();
    // Same shape an older build wrote (anonymous namespace); it had no
    // commit guard.
    localStorage.setItem(
      'atomic.outbox.__anonymous__',
      JSON.stringify([
        { subject: SUBJECT, enqueuedAt: 1 },
        { subject: HTTP_COMMIT, enqueuedAt: 2 },
      ]),
    );

    const rehydrated = new LocalOutbox();
    expect(rehydrated.size).toBe(1);
  });
});

describe('LocalOutbox.drain', () => {
  beforeEach(() => {
    if (typeof localStorage !== 'undefined') localStorage.clear();
  });

  it('keeps cancelled work queued without failure backoff', async ({
    expect,
  }) => {
    const outbox = new LocalOutbox();
    outbox.markDirty(SUBJECT);
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await outbox.drain({
      sort: entries => [...entries],
      drainSubject: async () => {
        throw new RequestCancelledError('Disconnected');
      },
    });
    expect(outbox.getEntry(SUBJECT)).toBeDefined();
    expect(outbox.getEntry(SUBJECT)?.failures ?? 0).toBe(0);
    expect(warning).not.toHaveBeenCalled();
    warning.mockRestore();
  });

  it('drops entries on terminal error + calls onTerminalDrop', async ({
    expect,
  }) => {
    const outbox = new LocalOutbox();
    outbox.markDirty(SUBJECT);

    const onTerminalDrop = vi.fn();

    await outbox.drain({
      sort: e => [...e],
      drainSubject: async () => {
        throw new Error(
          'Commit for did:ad:abc has is_genesis: true, but the resource already exists.',
        );
      },
      isTerminalError: (_entry, e) =>
        isTerminalCommitErrorMessage(e instanceof Error ? e.message : ''),
      onTerminalDrop,
    });

    expect(outbox.size).toBe(0);
    expect(onTerminalDrop).toHaveBeenCalledOnce();
    expect(onTerminalDrop.mock.calls[0][0].subject).toBe(SUBJECT);
  });

  it('a signedGenesis envelope survives drain failure and stays queued', async ({
    expect,
  }) => {
    // Under sign-at-drain the only signed envelope the outbox holds
    // is a `signedGenesis` for DID-derived subjects. If the drain
    // throws non-terminally the genesis must remain queued for the
    // next drain attempt.
    const outbox = new LocalOutbox();
    const genesis = fakeCommit(SUBJECT, 'sig-genesis');
    outbox.setGenesisCommit(SUBJECT, genesis);

    await outbox.drain({
      sort: e => [...e],
      drainSubject: async () => {
        throw new Error('Temporary network failure');
      },
    });

    expect(outbox.size).toBe(1);
    const entry = outbox.getEntry(SUBJECT) as OutboxEntry;
    expect(entry.signedGenesis?.signature).toBe('sig-genesis');
    expect(entry.lastAttemptError).toContain('Temporary network failure');
  });

  it('keeps entries queued on non-terminal error', async ({ expect }) => {
    const outbox = new LocalOutbox();
    outbox.markDirty(SUBJECT);

    const onTerminalDrop = vi.fn();

    await outbox.drain({
      sort: e => [...e],
      drainSubject: async () => {
        throw new Error('Temporary network failure');
      },
      isTerminalError: (_entry, e) =>
        isTerminalCommitErrorMessage(e instanceof Error ? e.message : ''),
      onTerminalDrop,
    });

    expect(outbox.size).toBe(1);
    expect(onTerminalDrop).not.toHaveBeenCalled();
    const entry = outbox.getEntry(SUBJECT) as OutboxEntry;
    expect(entry.lastAttemptError).toContain('Temporary network failure');
  });

  it('clearDirty removes an entry but keeps signedGenesis pending', ({
    expect,
  }) => {
    const outbox = new LocalOutbox();
    outbox.setGenesisCommit(SUBJECT, fakeCommit(SUBJECT, 'sig-genesis'));
    outbox.markDirty(SUBJECT);
    expect(outbox.size).toBe(1);

    // clearDirty on an entry with a signedGenesis keeps the entry —
    // genesis still needs to POST.
    outbox.clearDirty(SUBJECT);
    expect(outbox.size).toBe(1);
    expect(outbox.getEntry(SUBJECT)?.signedGenesis?.signature).toBe(
      'sig-genesis',
    );

    // After genesis acks, clearGenesis drops the envelope. The entry
    // then has neither a dirty bit nor a pending genesis and clears
    // on the next dirty-clear.
    outbox.clearGenesis(SUBJECT);
    outbox.clearDirty(SUBJECT);
    expect(outbox.size).toBe(0);
  });
});

describe('LocalOutbox drain re-entrancy (planning/completed/outbox-drain-data-loss-race.md)', () => {
  beforeEach(() => {
    if (typeof localStorage !== 'undefined') localStorage.clear();
  });

  it('drains a subject marked dirty mid-drain before a late caller’s await resolves', async ({
    expect,
  }) => {
    // The data-loss race: a drain pass is in flight (snapshotted [r1]);
    // `save()` marks r2 dirty and awaits drain(). Sharing the in-flight
    // promise alone resolves that await with r2 still un-POSTed — save()
    // reports 'persisted' for a write the server never saw.
    const outbox = new LocalOutbox();
    const drained: string[] = [];
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>(r => (releaseFirst = r));

    const ctx = {
      sort: (e: readonly OutboxEntry[]) => [...e],
      drainSubject: async (subject: string) => {
        // Hold r1's "POST" open so the second caller arrives mid-flight.
        if (subject === 'did:ad:r1') await firstGate;
        drained.push(subject);
        outbox.clearDirty(subject);
      },
    };

    outbox.markDirty('did:ad:r1');
    const first = outbox.drain(ctx);

    // While r1's POST is in flight: a save() on r2.
    outbox.markDirty('did:ad:r2');
    const second = outbox.drain(ctx);

    releaseFirst();
    await second;

    expect(drained).toContain('did:ad:r2');
    expect(outbox.hasPending('did:ad:r2')).toBe(false);
    await first;
  });

  it('keeps awaiting when the SAME subject is re-dirtied during its own POST', async ({
    expect,
  }) => {
    // Variant: r1's V1 delta is mid-POST when a new edit (V2) lands on r1.
    // The store's drainSubject leaves the entry dirty (caughtUp=false →
    // markDirty). A caller that awaited drain() after the V2 edit must not
    // resolve until a follow-up pass re-drains r1.
    const outbox = new LocalOutbox();
    let attempts = 0;
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>(r => (releaseFirst = r));

    const ctx = {
      sort: (e: readonly OutboxEntry[]) => [...e],
      drainSubject: async (subject: string) => {
        attempts++;

        if (attempts === 1) {
          // First attempt: POST in flight while V2 lands; entry stays dirty.
          await firstGate;
          outbox.markDirty(subject);
        } else {
          outbox.clearDirty(subject);
        }
      },
    };

    outbox.markDirty(SUBJECT);
    const first = outbox.drain(ctx);

    // V2 edit mid-POST, then a save() awaits the drain.
    const second = outbox.drain(ctx);

    releaseFirst();
    await second;

    expect(attempts).toBe(2);
    expect(outbox.hasPending(SUBJECT)).toBe(false);
    await first;
  });

  it('a drain() call during the follow-up pass chains another follow-up', async ({
    expect,
  }) => {
    const outbox = new LocalOutbox();
    const drained: string[] = [];
    const gates = new Map<string, () => void>();
    const gatePromise = (subject: string) =>
      new Promise<void>(r => gates.set(subject, r));
    const held = new Map([
      ['did:ad:r1', gatePromise('did:ad:r1')],
      ['did:ad:r2', gatePromise('did:ad:r2')],
    ]);

    const ctx = {
      sort: (e: readonly OutboxEntry[]) => [...e],
      drainSubject: async (subject: string) => {
        const gate = held.get(subject);
        if (gate) await gate;
        drained.push(subject);
        outbox.clearDirty(subject);
      },
    };

    outbox.markDirty('did:ad:r1');
    void outbox.drain(ctx);

    // Mid-pass-1: dirty r2, join → chains follow-up (pass 2).
    outbox.markDirty('did:ad:r2');
    void outbox.drain(ctx);
    gates.get('did:ad:r1')!();

    // Wait until pass 2 has started (it's holding r2's gate now).
    await new Promise<void>(resolve => {
      const poll = () =>
        drained.includes('did:ad:r1') ? resolve() : setTimeout(poll, 0);
      poll();
    });

    // Mid-pass-2: dirty r3, join → must chain pass 3 (flag was reset).
    outbox.markDirty('did:ad:r3');
    const third = outbox.drain(ctx);
    gates.get('did:ad:r2')!();

    await third;
    expect(drained).toEqual(['did:ad:r1', 'did:ad:r2', 'did:ad:r3']);
    expect(outbox.size).toBe(0);
  });
});

describe('isUnrecoverableCommitErrorMessage', () => {
  it('flags the server "no write right" 401', ({ expect }) => {
    expect(
      isUnrecoverableCommitErrorMessage(
        'Unauthorized. No https://atomicdata.dev/properties/write right has been found for did:ad:agent:Qmfp=',
      ),
    ).toBe(true);
  });

  it("doesn't flag unrelated or read 401s", ({ expect }) => {
    expect(
      isUnrecoverableCommitErrorMessage(
        'Unauthorized. This resource is not publicly readable. Try signing in',
      ),
    ).toBe(false);
    expect(isUnrecoverableCommitErrorMessage('Network timeout')).toBe(false);
    expect(isUnrecoverableCommitErrorMessage('')).toBe(false);
  });
});

describe('isTerminalCommitError (F5: code-first, planning/unified-sync.md)', () => {
  it('trusts a recognized code even with unrelated message text', ({
    expect,
  }) => {
    expect(
      isTerminalCommitError(
        'some unrelated wording',
        ErrorCode.GENESIS_COLLISION,
      ),
    ).toBe(true);
    expect(
      isTerminalCommitError(
        'some unrelated wording',
        ErrorCode.MISSING_REQUIRED_PROPERTY,
      ),
    ).toBe(true);
  });

  it('a non-terminal recognized code overrides a terminal-looking message', ({
    expect,
  }) => {
    // Proves the code wins over string matching, not just "code is checked
    // too" — this message would match the terminal string pattern, but the
    // server explicitly classified it as UNAUTHORIZED_WRITE, not terminal.
    expect(
      isTerminalCommitError(
        'is_genesis: true, but the resource already exists',
        ErrorCode.UNAUTHORIZED_WRITE,
      ),
    ).toBe(false);
  });

  it('falls back to string matching when code is UNKNOWN or absent', ({
    expect,
  }) => {
    expect(
      isTerminalCommitError(
        'Commit for did:ad:abc has is_genesis: true, but the resource already exists.',
        ErrorCode.UNKNOWN,
      ),
    ).toBe(true);
    expect(
      isTerminalCommitError(
        'Commit for did:ad:abc has is_genesis: true, but the resource already exists.',
        undefined,
      ),
    ).toBe(true);
    expect(isTerminalCommitError('Network timeout', undefined)).toBe(false);
  });
});

describe('a commit naming a class the server lacks', () => {
  // Verbatim from the field: every row of a shared table was refused with this,
  // the rows rendered as though saved, and the outbox retried each one forever
  // because nothing classified the failure.
  const MESSAGE =
    'Failed getting class did:ad:ViKExaq3nm6tVE5UCaCzEQhe7lwOrd. Resource not found. ' +
    'DID Resource did:ad:ViKExaq3nm6tVE5UCaCzEQhe7lwOrd not found locally';

  it('blocks, so the entry stops retrying and stays visible', ({ expect }) => {
    expect(isUnrecoverableCommitError(MESSAGE, ErrorCode.MISSING_CLASS)).toBe(
      true,
    );
  });

  it('is NOT terminal — the row is good and must not be discarded', ({
    expect,
  }) => {
    // The class can still arrive, and the same commit would then apply.
    // Dropping the entry would throw away a write the user believes they made.
    expect(isTerminalCommitError(MESSAGE, ErrorCode.MISSING_CLASS)).toBe(false);
  });

  it('blocks on the message alone, for a server too old to send the code', ({
    expect,
  }) => {
    expect(isUnrecoverableCommitError(MESSAGE, undefined)).toBe(true);
    expect(isUnrecoverableCommitError(MESSAGE, ErrorCode.UNKNOWN)).toBe(true);
  });
});

describe('isUnrecoverableCommitError (F5: code-first, planning/unified-sync.md)', () => {
  it('trusts a recognized code even with unrelated message text', ({
    expect,
  }) => {
    expect(
      isUnrecoverableCommitError(
        'some unrelated wording',
        ErrorCode.UNAUTHORIZED_WRITE,
      ),
    ).toBe(true);
  });

  it('a non-blocking recognized code overrides a blocking-looking message', ({
    expect,
  }) => {
    expect(
      isUnrecoverableCommitError(
        'No https://atomicdata.dev/properties/write right has been found',
        ErrorCode.GENESIS_COLLISION,
      ),
    ).toBe(false);
  });

  it('falls back to string matching when code is UNKNOWN or absent', ({
    expect,
  }) => {
    expect(
      isUnrecoverableCommitError(
        'Unauthorized. No https://atomicdata.dev/properties/write right has been found for did:ad:agent:Qmfp=',
        ErrorCode.UNKNOWN,
      ),
    ).toBe(true);
    expect(isUnrecoverableCommitError('Network timeout', undefined)).toBe(
      false,
    );
  });
});

describe('unrecognized codes fall back to string matching (F5 fallback bug)', () => {
  // A pre-F5 server's ERROR frame has no code field; a post-F5 client's
  // `decodeError` still reads 2 bytes for `code` and gets the message's
  // first 2 UTF-8 bytes instead. For a message starting "Commit for...",
  // that's 'C' (0x43) + 'o' (0x6F) = 0x436F — an arbitrary NONZERO value
  // that isn't `ErrorCode.UNKNOWN` (0) and isn't in the known set either.
  // Before the fix, `code !== undefined && code !== ErrorCode.UNKNOWN` took
  // this as "recognized" and matched it against none of the known codes —
  // returning false (not terminal / not blocking) even for a message that
  // string-matching would correctly flag as terminal. That silently
  // converts a genesis-collision from an old server into an infinite retry
  // loop — exactly the ingest-flood failure mode F5 exists to prevent.
  const GARBLED_CODE = 0x436f; // 'C' + 'o', see comment above

  it('a garbled nonzero code does not suppress a terminal string match', ({
    expect,
  }) => {
    expect(
      isTerminalCommitError(
        'Commit for did:ad:abc has is_genesis: true, but the resource already exists.',
        GARBLED_CODE,
      ),
    ).toBe(true);
  });

  it('a garbled nonzero code does not suppress a blocking string match', ({
    expect,
  }) => {
    expect(
      isUnrecoverableCommitError(
        'Unauthorized. No https://atomicdata.dev/properties/write right has been found for did:ad:agent:Qmfp=',
        GARBLED_CODE,
      ),
    ).toBe(true);
  });

  it('a garbled code still correctly reports false for a non-matching message', ({
    expect,
  }) => {
    expect(isTerminalCommitError('Network timeout', GARBLED_CODE)).toBe(false);
    expect(isUnrecoverableCommitError('Network timeout', GARBLED_CODE)).toBe(
      false,
    );
  });
});

describe('LocalOutbox blocking', () => {
  beforeEach(() => {
    if (typeof localStorage !== 'undefined') localStorage.clear();
  });

  const blockingCtx = (
    drainSubject: () => Promise<void>,
    onBlocked = vi.fn(),
  ) => ({
    sort: (e: readonly OutboxEntry[]) => [...e],
    drainSubject,
    isBlockingError: (_e: OutboxEntry, err: unknown) =>
      isUnrecoverableCommitErrorMessage(
        err instanceof Error ? err.message : '',
      ),
    onBlocked,
  });

  const alwaysUnauthorized = () =>
    vi.fn(async () => {
      throw new Error(
        'Unauthorized. No https://atomicdata.dev/properties/write right has been found for did:ad:agent:x=',
      );
    });

  /** Drain repeatedly, advancing past each backoff window, until the entry
   *  racks up enough failures to be parked as blocked. */
  async function drainUntilBlocked(
    outbox: LocalOutbox,
    ctx: ReturnType<typeof blockingCtx>,
  ) {
    let now = 0;
    vi.setSystemTime(now);

    for (let i = 1; i <= BLOCK_AFTER_FAILURES; i++) {
      await outbox.drain(ctx);
      now += drainBackoffMs(i) + 1;
      vi.setSystemTime(now);
    }
  }

  it('retries a blocking error first, then parks after sustained failures', async ({
    expect,
  }) => {
    vi.useFakeTimers();

    try {
      const outbox = new LocalOutbox();
      outbox.markDirty(SUBJECT);
      const drainSubject = alwaysUnauthorized();
      const onBlocked = vi.fn();
      const ctx = blockingCtx(drainSubject, onBlocked);

      // A 401 is NOT blocked on the first failure — it's retried under backoff
      // (it's usually a transient ordering race: parent not yet synced).
      vi.setSystemTime(0);
      await outbox.drain(ctx);
      expect(outbox.getEntry(SUBJECT)?.blocked).toBeFalsy();
      expect(outbox.getEntry(SUBJECT)?.failures).toBe(1);

      // Only after BLOCK_AFTER_FAILURES sustained failures does it park.
      await drainUntilBlocked(outbox, ctx);
      expect(drainSubject).toHaveBeenCalledTimes(BLOCK_AFTER_FAILURES);
      expect(outbox.getEntry(SUBJECT)?.blocked).toBe(true);
      expect(outbox.blockedCount).toBe(1);
      expect(outbox.size).toBe(1); // kept (visible), not dropped
      expect(onBlocked).toHaveBeenCalledTimes(1);
      expect(outbox.nextDueAt()).toBeUndefined();

      // Once blocked, further drains do NOT re-attempt it.
      vi.setSystemTime(60_000);
      await outbox.drain(ctx);
      expect(drainSubject).toHaveBeenCalledTimes(BLOCK_AFTER_FAILURES);
    } finally {
      vi.useRealTimers();
    }
  });

  it('a successful retry clears the failure streak before blocking', async ({
    expect,
  }) => {
    vi.useFakeTimers();

    try {
      const outbox = new LocalOutbox();
      outbox.markDirty(SUBJECT);
      let fail = true;
      const drainSubject = vi.fn(async () => {
        if (fail)
          throw new Error(
            'Unauthorized. No https://atomicdata.dev/properties/write right has been found for did:ad:agent:x=',
          );
      });
      const ctx = blockingCtx(drainSubject);

      // Two failures, then the parent syncs and the retry succeeds (the
      // ordering race resolves) — the entry drains, never blocking.
      vi.setSystemTime(0);
      await outbox.drain(ctx);
      vi.setSystemTime(drainBackoffMs(1) + 1);
      await outbox.drain(ctx);
      expect(outbox.getEntry(SUBJECT)?.failures).toBe(2);

      fail = false;
      vi.setSystemTime(drainBackoffMs(1) + drainBackoffMs(2) + 2);
      await outbox.drain(ctx);
      // drainSubject resolved → entry stays only if not cleared by caller; here
      // there's no clearDirty, so it remains with failures reset to 0.
      expect(outbox.getEntry(SUBJECT)?.failures).toBe(0);
      expect(outbox.getEntry(SUBJECT)?.blocked).toBeFalsy();
    } finally {
      vi.useRealTimers();
    }
  });

  it('markDirty re-arms a blocked entry for another attempt', async ({
    expect,
  }) => {
    vi.useFakeTimers();

    try {
      const outbox = new LocalOutbox();
      outbox.markDirty(SUBJECT);
      const drainSubject = alwaysUnauthorized();
      const ctx = blockingCtx(drainSubject);

      await drainUntilBlocked(outbox, ctx);
      expect(outbox.getEntry(SUBJECT)?.blocked).toBe(true);

      // Fresh local edit clears the block + failure streak...
      outbox.markDirty(SUBJECT);
      expect(outbox.getEntry(SUBJECT)?.blocked).toBe(false);
      expect(outbox.getEntry(SUBJECT)?.failures).toBe(0);
      expect(outbox.nextDueAt()).toBe(0); // failures reset → due immediately

      // ...so the next drain attempts again.
      await outbox.drain(ctx);
      expect(drainSubject).toHaveBeenCalledTimes(BLOCK_AFTER_FAILURES + 1);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('LocalOutbox identity scoping (rebind)', () => {
  const AGENT_A = 'did:ad:agent:aaa=';
  const AGENT_B = 'did:ad:agent:bbb=';

  beforeEach(() => {
    if (typeof localStorage !== 'undefined') localStorage.clear();
  });

  it("a new agent does not see the previous agent's queue", ({ expect }) => {
    const outbox = new LocalOutbox();
    outbox.rebind(AGENT_A);
    outbox.markDirty('did:ad:resourceA');
    expect(outbox.size).toBe(1);

    // Switch identity → B starts with an empty, isolated queue.
    outbox.rebind(AGENT_B);
    expect(outbox.size).toBe(0);
    expect(outbox.hasPending('did:ad:resourceA')).toBe(false);

    // B's own work stays in B's namespace.
    outbox.markDirty('did:ad:resourceB');
    expect(outbox.size).toBe(1);

    // Returning to A restores A's preserved queue (not lost on switch).
    outbox.rebind(AGENT_A);
    expect(outbox.size).toBe(1);
    expect(outbox.hasPending('did:ad:resourceA')).toBe(true);
    expect(outbox.hasPending('did:ad:resourceB')).toBe(false);
  });

  it('rebind to the same agent is a no-op (keeps the queue)', ({ expect }) => {
    const outbox = new LocalOutbox();
    outbox.rebind(AGENT_A);
    outbox.markDirty('did:ad:resourceA');
    outbox.rebind(AGENT_A);
    expect(outbox.size).toBe(1);
  });

  it('persists per-agent across instances (reload survives identity)', ({
    expect,
  }) => {
    const first = new LocalOutbox();
    first.rebind(AGENT_A);
    first.markDirty('did:ad:resourceA');
    first.flush();

    // Fresh instance (a reload) bound to A sees A's entry; bound to B sees none.
    const second = new LocalOutbox();
    second.rebind(AGENT_B);
    expect(second.size).toBe(0);
    second.rebind(AGENT_A);
    expect(second.hasPending('did:ad:resourceA')).toBe(true);
  });

  it('migrates the legacy flat queue by owner, dropping unattributable entries', ({
    expect,
  }) => {
    // Seed the pre-scoping shared key with one owned (genesis) entry for A and
    // one dirty-only entry that can't be attributed.
    const owned = {
      subject: 'did:ad:ownedByA',
      enqueuedAt: 1,
      signedGenesis: fakeCommitJsonAd('did:ad:ownedByA', AGENT_A),
    };
    const orphan = { subject: 'did:ad:noOwner', enqueuedAt: 2 };
    localStorage.setItem('atomic.outbox', JSON.stringify([owned, orphan]));

    // Construction runs the one-shot migration.
    const outbox = new LocalOutbox();
    // Flat key is consumed.
    expect(localStorage.getItem('atomic.outbox')).toBeNull();

    // A's namespace now holds the owned entry; the orphan was dropped.
    outbox.rebind(AGENT_A);
    expect(outbox.hasPending('did:ad:ownedByA')).toBe(true);
    expect(outbox.hasPending('did:ad:noOwner')).toBe(false);
  });
});

describe('outbox backoff', () => {
  it('drainBackoffMs is exponential, capped at 30s', ({ expect }) => {
    expect(drainBackoffMs(0)).toBe(0);
    expect(drainBackoffMs(1)).toBe(1000);
    expect(drainBackoffMs(2)).toBe(2000);
    expect(drainBackoffMs(3)).toBe(4000);
    expect(drainBackoffMs(20)).toBe(30_000); // capped
  });

  it('skips a failed entry within its backoff window, retries when due', async ({
    expect,
  }) => {
    vi.useFakeTimers();
    vi.setSystemTime(0);

    try {
      const outbox = new LocalOutbox();
      outbox.markDirty(SUBJECT);
      const drainSubject = vi.fn(async () => {
        throw new Error('Temporary network failure');
      });
      const ctx = { sort: (e: readonly OutboxEntry[]) => [...e], drainSubject };

      // First attempt fails → failures=1, due at t=1000.
      await outbox.drain(ctx);
      expect(drainSubject).toHaveBeenCalledTimes(1);
      expect(outbox.getEntry(SUBJECT)?.failures).toBe(1);
      expect(outbox.nextDueAt()).toBe(1000);

      // Re-drain still at t=0 → inside the backoff window → skipped entirely.
      await outbox.drain(ctx);
      expect(drainSubject).toHaveBeenCalledTimes(1);

      // Past the window → attempted again; backoff grows to 2s (due at 3001).
      vi.setSystemTime(1001);
      await outbox.drain(ctx);
      expect(drainSubject).toHaveBeenCalledTimes(2);
      expect(outbox.getEntry(SUBJECT)?.failures).toBe(2);
      expect(outbox.nextDueAt()).toBe(1001 + 2000);
    } finally {
      vi.useRealTimers();
    }
  });

  it('resets the failure counter after a successful drain', async ({
    expect,
  }) => {
    vi.useFakeTimers();
    vi.setSystemTime(0);

    try {
      const outbox = new LocalOutbox();
      // A genesis envelope keeps the entry around after a "successful" drain
      // that doesn't clear it, so we can observe `failures` reset.
      outbox.setGenesisCommit(SUBJECT, {
        subject: SUBJECT,
        signer: 'did:ad:agent:fake=',
        createdAt: 0,
        signature: 'sig',
      } as unknown as Commit);

      let shouldFail = true;
      const drainSubject = vi.fn(async () => {
        if (shouldFail) throw new Error('Temporary network failure');
      });
      const ctx = { sort: (e: readonly OutboxEntry[]) => [...e], drainSubject };

      await outbox.drain(ctx);
      expect(outbox.getEntry(SUBJECT)?.failures).toBe(1);

      shouldFail = false;
      vi.setSystemTime(2000); // past the 1s backoff window
      await outbox.drain(ctx);
      expect(outbox.getEntry(SUBJECT)?.failures).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('LocalOutbox.drain tiers (pipelined COMMITs)', () => {
  beforeEach(() => {
    if (typeof localStorage !== 'undefined') localStorage.clear();
  });

  const subjects = (n: number, prefix: string) =>
    Array.from({ length: n }, (_, i) => `did:ad:${prefix}${i}`);

  it('groups sorted entries into runs of equal tier', ({ expect }) => {
    const entries = ['a', 'b', 'c', 'd'].map(s => ({
      subject: s,
      enqueuedAt: 1,
    }));
    const tier = (e: { subject: string }) => (e.subject < 'c' ? '0' : '1');

    expect(groupTiers(entries, tier).map(t => t.map(e => e.subject))).toEqual([
      ['a', 'b'],
      ['c', 'd'],
    ]);
    // No tierOf: strictly sequential, one entry per tier.
    expect(groupTiers(entries).map(t => t.length)).toEqual([1, 1, 1, 1]);
  });

  it('runBounded never has more than `limit` tasks in flight', async ({
    expect,
  }) => {
    let inFlight = 0;
    let peak = 0;
    const started: number[] = [];

    await runBounded([1, 2, 3, 4, 5, 6, 7], 3, async item => {
      started.push(item);
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise(r => setTimeout(r, 1));
      inFlight--;
    });

    expect(peak).toBe(3);
    expect(started).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it('drains a tier concurrently and barriers between tiers', async ({
    expect,
  }) => {
    const outbox = new LocalOutbox();
    const parents = subjects(2, 'parent');
    const children = subjects(6, 'child');
    for (const s of [...parents, ...children]) outbox.markDirty(s);

    let inFlight = 0;
    let peak = 0;
    const order: string[] = [];
    const release = new Map<string, () => void>();

    const drainSubject = (subject: string) =>
      new Promise<void>(resolve => {
        order.push(subject);
        inFlight++;
        peak = Math.max(peak, inFlight);
        release.set(subject, () => {
          inFlight--;
          outbox.clearDirty(subject);
          resolve();
        });
      });

    const drain = outbox.drain({
      sort: e => [...e].sort((a, b) => a.subject.localeCompare(b.subject)),
      tierOf: e => (e.subject.includes('parent') ? 'parents' : 'children'),
      concurrency: 4,
      drainSubject,
    });

    // Sorted: children come before parents alphabetically; the first tier
    // is the six children, of which four are in flight at once.
    await new Promise(r => setTimeout(r, 0));
    expect(order).toHaveLength(4);
    expect(order.every(s => s.includes('child'))).toBe(true);
    expect(peak).toBe(4);

    // No parent starts until every child settled — the tier barrier.
    for (const s of children) release.get(s)?.();
    await new Promise(r => setTimeout(r, 0));
    for (const s of children) release.get(s)?.();
    await new Promise(r => setTimeout(r, 0));
    expect(order.filter(s => s.includes('parent'))).toHaveLength(2);
    expect(order.slice(0, 6).every(s => s.includes('child'))).toBe(true);

    for (const s of parents) release.get(s)?.();
    await drain;
    expect(outbox.size).toBe(0);
    expect(peak).toBe(4);
  });

  it('without tierOf the drain stays sequential', async ({ expect }) => {
    const outbox = new LocalOutbox();
    for (const s of subjects(3, 's')) outbox.markDirty(s);
    let inFlight = 0;
    let peak = 0;

    await outbox.drain({
      sort: e => [...e],
      drainSubject: async subject => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise(r => setTimeout(r, 1));
        inFlight--;
        outbox.clearDirty(subject);
      },
    });

    expect(peak).toBe(1);
    expect(outbox.size).toBe(0);
  });

  it('a failing subject does not strand the rest of its tier', async ({
    expect,
  }) => {
    const outbox = new LocalOutbox();
    for (const s of subjects(3, 's')) outbox.markDirty(s);

    await outbox.drain({
      sort: e => [...e],
      tierOf: () => 'one',
      drainSubject: async subject => {
        if (subject.endsWith('1')) throw new Error('boom');
        outbox.clearDirty(subject);
      },
    });

    expect(outbox.size).toBe(1);
    expect(outbox.getEntry('did:ad:s1')?.failures).toBe(1);
  });
});
