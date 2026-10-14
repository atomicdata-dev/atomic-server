import { RequestCancelledError } from './error.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ClientDbOutboxWrite } from './client-db.js';
import { commitToJsonADObject, type Commit } from './commit.js';
import { LocalOutbox, type OutboxDatabase } from './local-outbox.js';

const AGENT = 'did:ad:agent:outbox-db=';
const OTHER = 'did:ad:agent:someone-else=';

function fakeCommit(subject: string, extra: Partial<Commit> = {}): Commit {
  return {
    subject,
    signer: AGENT,
    createdAt: 1,
    signature: `sig-${subject}`,
    isA: ['https://atomicdata.dev/classes/Commit'],
    ...extra,
  } as unknown as Commit;
}

/**
 * The outbox half of the client database: rows per agent and subject, and a
 * copy of what was durable at the last flush, which is what a crash or a
 * reload finds.
 */
class FakeDatabase implements OutboxDatabase {
  rows = new Map<string, Map<string, string>>();
  durableRows = new Map<string, Map<string, string>>();
  writes: Array<ClientDbOutboxWrite & { durable: boolean }> = [];
  failNext = false;
  /** Resolve `outboxEntries` by hand, to act in the gap while it reads. */
  gate: Promise<void> | undefined;

  async outboxEntries(agent: string): Promise<string[]> {
    if (this.gate) await this.gate;

    return [...(this.rows.get(agent)?.values() ?? [])];
  }

  async outboxWrite(
    write: ClientDbOutboxWrite,
    durable: boolean,
  ): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error('disk unavailable');
    }

    this.writes.push({ ...write, durable });
    const rows = this.rows.get(write.agent) ?? new Map<string, string>();
    for (const subject of write.deletes) rows.delete(subject);
    for (const { subject, value } of write.puts) rows.set(subject, value);
    this.rows.set(write.agent, rows);

    if (durable) this.persist();
  }

  /** The worker's flush: everything written so far becomes durable. */
  persist(): void {
    this.durableRows = new Map(
      [...this.rows].map(([agent, rows]) => [agent, new Map(rows)]),
    );
  }

  /** A reload: only durable rows survive. */
  reopen(): FakeDatabase {
    const next = new FakeDatabase();
    next.rows = new Map(
      [...this.durableRows].map(([agent, rows]) => [agent, new Map(rows)]),
    );
    next.durableRows = this.durableRows;

    return next;
  }

  subjects(agent = AGENT): string[] {
    return [...(this.rows.get(agent)?.keys() ?? [])].sort();
  }
}

/** A fresh tab: the outbox as `Store` sets it up when a database is coming. */
async function reload(db: FakeDatabase, agent = AGENT): Promise<LocalOutbox> {
  const outbox = new LocalOutbox();
  outbox.expectDatabase();
  outbox.rebind(agent);
  await outbox.attachDatabase(agent, db);

  return outbox;
}

const tick = () => new Promise(resolve => setTimeout(resolve, 0));

beforeEach(() => localStorage.clear());

afterEach(() => {
  localStorage.clear();
  localStorage.setItem('ws-disconnected', '1');
});

describe('LocalOutbox in the client database', () => {
  it('imports the localStorage queue once, durably, then removes the key', async () => {
    // What an older build left behind: a dirty bit with an offline cursor,
    // a parked genesis and a parked destroy.
    const legacy = [
      { subject: 'did:ad:edited', enqueuedAt: 5, baseVersion: 'AAEC' },
      {
        subject: 'did:ad:created',
        enqueuedAt: 6,
        signedGenesis: commitToJsonADObject(fakeCommit('did:ad:created')),
      },
      {
        subject: 'did:ad:deleted',
        enqueuedAt: 7,
        signedDestroy: commitToJsonADObject(
          fakeCommit('did:ad:deleted', { destroy: true }),
        ),
      },
    ];
    localStorage.setItem(`atomic.outbox.${AGENT}`, JSON.stringify(legacy));
    // Another agent's queue is not this database's to take.
    localStorage.setItem(
      `atomic.outbox.${OTHER}`,
      JSON.stringify([{ subject: 'did:ad:theirs', enqueuedAt: 1 }]),
    );

    const db = new FakeDatabase();
    const outbox = new LocalOutbox();
    outbox.expectDatabase();
    outbox.rebind(AGENT);
    // Visible at once, before the database is there.
    expect(outbox.size).toBe(3);
    await outbox.attachDatabase(AGENT, db);

    expect(db.subjects()).toEqual([
      'did:ad:created',
      'did:ad:deleted',
      'did:ad:edited',
    ]);
    expect(db.writes).toHaveLength(1);
    expect(db.writes[0].durable).toBe(true);
    expect(localStorage.getItem(`atomic.outbox.${AGENT}`)).toBeNull();
    expect(localStorage.getItem(`atomic.outbox.${OTHER}`)).not.toBeNull();

    // A reload reads the same queue back from the database alone.
    const reloaded = await reload(db.reopen());
    expect(reloaded.getEntry('did:ad:edited')?.baseVersion).toBe('AAEC');
    expect(reloaded.getEntry('did:ad:edited')?.enqueuedAt).toBe(5);
    expect(reloaded.getEntry('did:ad:created')?.signedGenesis?.signature).toBe(
      'sig-did:ad:created',
    );
    expect(reloaded.getEntry('did:ad:deleted')?.signedDestroy?.destroy).toBe(
      true,
    );
  });

  it('keeps the localStorage copy when the import write fails', async () => {
    localStorage.setItem(
      `atomic.outbox.${AGENT}`,
      JSON.stringify([{ subject: 'did:ad:edited', enqueuedAt: 5 }]),
    );
    const db = new FakeDatabase();
    db.failNext = true;
    const outbox = new LocalOutbox();
    outbox.rebind(AGENT);
    await outbox.attachDatabase(AGENT, db);

    expect(localStorage.getItem(`atomic.outbox.${AGENT}`)).not.toBeNull();
    expect(outbox.hasPending('did:ad:edited')).toBe(true);

    // The next write repeats the row it could not store.
    outbox.markDirty('did:ad:other');
    await tick();
    expect(db.subjects()).toEqual(['did:ad:edited', 'did:ad:other']);
  });

  it('writes to the database after attaching, never to localStorage', async () => {
    const db = new FakeDatabase();
    const outbox = await reload(db);

    outbox.markDirty('did:ad:a');
    await tick();
    expect(db.subjects()).toEqual(['did:ad:a']);
    // A plain dirty bit waits for the periodic flush.
    expect(db.writes.at(-1)?.durable).toBe(false);

    outbox.setGenesisCommit('did:ad:b', fakeCommit('did:ad:b'));
    await tick();
    // A signed envelope cannot be rebuilt after a crash: durable at once.
    expect(db.writes.at(-1)?.durable).toBe(true);
    expect(db.writes.at(-1)?.puts.map(p => p.subject)).toEqual(['did:ad:b']);

    outbox.clearDirty('did:ad:a');
    await tick();
    expect(db.subjects()).toEqual(['did:ad:b']);
    expect(db.writes.at(-1)?.deletes).toEqual(['did:ad:a']);
    expect(localStorage.getItem(`atomic.outbox.${AGENT}`)).toBeNull();

    // An unchanged queue writes nothing.
    const writes = db.writes.length;
    outbox.markDirty('did:ad:b');
    await tick();
    expect(db.writes).toHaveLength(writes);
  });

  it('is not hydrated until the expected database attaches', async () => {
    const db = new FakeDatabase();
    const first = await reload(db);
    first.setBaseVersion('did:ad:offline', 'AAEC');
    await first.flush();

    const outbox = new LocalOutbox();
    outbox.expectDatabase();
    outbox.rebind(AGENT);
    expect(outbox.hydrated).toBe(false);
    // Unknown yet: a guard must not treat the subject as clean.
    expect(outbox.mayHavePending('did:ad:offline')).toBe(true);

    let hydrated = false;
    const waiting = outbox.whenHydrated().then(() => (hydrated = true));
    await tick();
    expect(hydrated).toBe(false);

    await outbox.attachDatabase(AGENT, db.reopen());
    await waiting;
    expect(outbox.hasPending('did:ad:offline')).toBe(true);
    expect(outbox.mayHavePending('did:ad:elsewhere')).toBe(false);
  });

  it('falls back to localStorage when no database comes', async () => {
    const outbox = new LocalOutbox();
    outbox.expectDatabase();
    outbox.rebind(AGENT);
    outbox.databaseUnavailable(AGENT);
    expect(outbox.hydrated).toBe(true);

    outbox.markDirty('did:ad:a');
    await outbox.flush();
    const stored = JSON.parse(
      localStorage.getItem(`atomic.outbox.${AGENT}`) ?? '[]',
    );
    expect(stored.map((e: { subject: string }) => e.subject)).toEqual([
      'did:ad:a',
    ]);
  });

  it('lets edits made while the rows load win over the stored rows', async () => {
    const db = new FakeDatabase();
    const first = await reload(db);
    first.markDirty('did:ad:cleared');
    first.markDirty('did:ad:destroyed');
    first.markDirty('did:ad:untouched');
    await first.flush();

    const outbox = new LocalOutbox();
    outbox.rebind(AGENT);
    let open!: () => void;
    const reopened = db.reopen();
    reopened.gate = new Promise(resolve => (open = resolve));
    const attached = outbox.attachDatabase(AGENT, reopened);

    // While the rows are read: one subject is synced and cleared, another
    // deleted. Neither knew about the stored rows.
    outbox.markDirty('did:ad:cleared');
    outbox.clearDirty('did:ad:cleared');
    outbox.setDestroyCommit(
      'did:ad:destroyed',
      fakeCommit('did:ad:destroyed', { destroy: true }),
    );
    open();
    await attached;

    expect(outbox.hasPending('did:ad:cleared')).toBe(false);
    expect(outbox.getEntry('did:ad:destroyed')?.signedDestroy).toBeTruthy();
    expect(outbox.hasPending('did:ad:untouched')).toBe(true);
    expect(reopened.subjects()).toEqual([
      'did:ad:destroyed',
      'did:ad:untouched',
    ]);
  });

  it("does not load one agent's rows after switching to another", async () => {
    const db = new FakeDatabase();
    const first = await reload(db);
    first.markDirty('did:ad:mine');
    await first.flush();

    const outbox = new LocalOutbox();
    outbox.expectDatabase();
    outbox.rebind(AGENT);
    let open!: () => void;
    db.gate = new Promise(resolve => (open = resolve));
    const attached = outbox.attachDatabase(AGENT, db);
    outbox.rebind(OTHER);
    open();
    await attached;

    expect(outbox.size).toBe(0);
    // The new agent's database has not attached yet.
    expect(outbox.hydrated).toBe(false);
  });

  it('writes an offline save with its snapshot, then updates memory', async () => {
    const db = new FakeDatabase();
    const onChange = vi.fn();
    const outbox = new LocalOutbox(onChange);
    outbox.expectDatabase();
    outbox.rebind(AGENT);
    await outbox.attachDatabase(AGENT, db);
    onChange.mockClear();

    let passed: ClientDbOutboxWrite | undefined;
    await outbox.recordOfflineSave(
      'did:ad:note',
      { baseVersion: 'AAEC', dirty: true },
      async write => {
        passed = write;
        // Nothing is queued in memory while the snapshot write is running,
        // so `pendingDirtyCount` cannot rise ahead of it.
        expect(outbox.hasPending('did:ad:note')).toBe(false);
        expect(onChange).not.toHaveBeenCalled();
        // The worker writes the row and the snapshot, then flushes once.
        await db.outboxWrite(write!, true);

        return true;
      },
    );

    expect(passed?.agent).toBe(AGENT);
    expect(passed?.puts.map(p => p.subject)).toEqual(['did:ad:note']);
    expect(JSON.parse(passed!.puts[0].value).baseVersion).toBe('AAEC');
    expect(outbox.getEntry('did:ad:note')?.baseVersion).toBe('AAEC');
    expect(onChange).toHaveBeenCalled();

    // Already stored with the snapshot: no second write for the same row.
    const writes = db.writes.length;
    await tick();
    expect(db.writes).toHaveLength(writes);

    // A later offline save keeps the first cursor: it is still the last
    // version the server has.
    await outbox.recordOfflineSave(
      'did:ad:note',
      { baseVersion: 'BBBB', dirty: true },
      async write => {
        expect(JSON.parse(write!.puts[0].value).baseVersion).toBe('AAEC');

        return false;
      },
    );
    expect(outbox.getEntry('did:ad:note')?.baseVersion).toBe('AAEC');
  });

  it('passes no row without a database, and queues through localStorage', async () => {
    const outbox = new LocalOutbox();
    outbox.rebind(AGENT);
    let passed: ClientDbOutboxWrite | undefined | 'unset' = 'unset';
    await outbox.recordOfflineSave(
      'did:ad:note',
      { baseVersion: 'AAEC', dirty: true },
      async write => {
        passed = write;

        return false;
      },
    );
    await tick();

    expect(passed).toBeUndefined();
    expect(localStorage.getItem(`atomic.outbox.${AGENT}`)).toContain(
      'did:ad:note',
    );
  });

  it('retains cancelled writes for a later flush after a leader handoff', async () => {
    const db = new FakeDatabase();
    const outbox = await reload(db);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const write = vi.spyOn(db, 'outboxWrite');
    write.mockRejectedValueOnce(new RequestCancelledError('leader changed'));
    outbox.markDirty('did:ad:a');
    await tick();
    expect(outbox.hasPending('did:ad:a')).toBe(true);
    expect(db.reopen().subjects()).toEqual([]);
    expect(warn).not.toHaveBeenCalled();
    await outbox.flush();
    expect(db.reopen().subjects()).toEqual(['did:ad:a']);
    warn.mockRestore();
  });

  it('a flush makes a plain dirty bit durable', async () => {
    const db = new FakeDatabase();
    const outbox = await reload(db);
    outbox.markDirty('did:ad:a');
    await tick();
    expect(db.reopen().subjects()).toEqual([]);

    await outbox.flush();
    expect(db.reopen().subjects()).toEqual(['did:ad:a']);
  });
});
