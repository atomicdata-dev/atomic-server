import { describe, expect, it, vi } from 'vitest';
import {
  applyPlan,
  type ApplyHost,
  type CreateRequest,
} from './plugin-apply.js';
import type { PlannedChange, RunPlan } from './plugin-plan.js';
import type { JSONValue } from './value.js';

const plan = (changes: PlannedChange[], blocked = false): RunPlan => ({
  changes,
  problems: [],
  minted: {},
  blocked,
});

const create = (
  subject: string,
  over: Partial<PlannedChange> = {},
): PlannedChange => ({
  op: 'create',
  subject,
  localId: subject.split('/').pop(),
  parent: 'https://x/drive',
  isA: ['https://x/Thing'],
  properties: [],
  problems: [],
  ...over,
});

const set = (
  subject: string,
  properties: PlannedChange['properties'],
): PlannedChange => ({ op: 'set', subject, properties, problems: [] });

interface HostLog {
  creates: CreateRequest[];
  sets: Array<[string, Record<string, JSONValue>]>;
  removes: Array<[string, string[]]>;
  destroys: string[];
}

const makeHost = (
  over: Partial<ApplyHost> = {},
): { host: ApplyHost; log: HostLog } => {
  const log: HostLog = { creates: [], sets: [], removes: [], destroys: [] };
  let n = 0;

  const host: ApplyHost = {
    create: vi.fn(async (request: CreateRequest) => {
      log.creates.push(request);

      return `did:ad:real-${++n}`;
    }),
    set: vi.fn(async (subject, propVals) => {
      log.sets.push([subject, propVals]);
    }),
    remove: vi.fn(async (subject, properties) => {
      log.removes.push([subject, properties]);
    }),
    destroy: vi.fn(async subject => {
      log.destroys.push(subject);
    }),
    ...over,
  };

  return { host, log };
};

describe('applyPlan', () => {
  it('refuses a blocked plan instead of writing part of it', async () => {
    const { host } = makeHost();

    await expect(
      applyPlan(plan([create('_new:a')], true), host),
    ).rejects.toThrow(/blocked plan/);
    expect(host.create).not.toHaveBeenCalled();
  });

  it('reports the subject a create actually got', async () => {
    const { host } = makeHost();

    const report = await applyPlan(plan([create('_new:a')]), host);

    expect(report.applied).toBe(1);
    expect(report.outcomes[0]).toMatchObject({
      planned: '_new:a',
      subject: 'did:ad:real-1',
      status: 'applied',
    });
    expect(report.subjects).toEqual({ '_new:a': 'did:ad:real-1' });
  });

  it('points later references at the subject the store minted', async () => {
    const { host, log } = makeHost();

    await applyPlan(
      plan([
        create('_new:org'),
        set('https://x/contact', [
          { property: 'https://x/employer', to: '_new:org' },
        ]),
      ]),
      host,
    );

    expect(log.sets[0][1]).toEqual({
      'https://x/employer': 'did:ad:real-1',
    });
  });

  it('creates a parent before its child', async () => {
    const { host, log } = makeHost();

    await applyPlan(
      plan([
        create('_new:child', { parent: '_new:folder' }),
        create('_new:folder'),
      ]),
      host,
    );

    expect(log.creates[0].parent).toBe('https://x/drive');
    expect(log.creates[1].parent).toBe('did:ad:real-1');
  });

  it('sends only properties that have a value', async () => {
    const { host, log } = makeHost();

    await applyPlan(
      plan([
        set('https://x/a', [
          { property: 'https://x/name', from: 'old', to: 'new' },
          { property: 'https://x/gone', from: 'x' },
        ]),
      ]),
      host,
    );

    expect(log.sets[0][1]).toEqual({ 'https://x/name': 'new' });
  });

  it('removes and destroys', async () => {
    const { host, log } = makeHost();

    await applyPlan(
      plan([
        {
          op: 'remove',
          subject: 'https://x/a',
          properties: [{ property: 'https://x/name', from: 'old' }],
          problems: [],
        },
        { op: 'destroy', subject: 'https://x/b', properties: [], problems: [] },
      ]),
      host,
    );

    expect(log.removes).toEqual([['https://x/a', ['https://x/name']]]);
    expect(log.destroys).toEqual(['https://x/b']);
  });

  it('skips a change with nothing to write', async () => {
    const { host } = makeHost();

    const report = await applyPlan(plan([set('https://x/a', [])]), host);

    expect(report.skipped).toBe(1);
    expect(host.set).not.toHaveBeenCalled();
  });
});

describe('links between resources this run creates', () => {
  const linkedCreate = (subject: string, to: string): PlannedChange => ({
    ...create(subject),
    properties: [{ property: 'https://x/employer', to }],
  });

  it('creates the target before the resource that links to it', async () => {
    const { host, log } = makeHost();

    // The linking resource comes first and is not the target's child, so
    // ordering by parent alone would have written a link to `_new:org`.
    await applyPlan(
      plan([linkedCreate('_new:person', '_new:org'), create('_new:org')]),
      host,
    );

    expect(log.creates[0].propVals).toEqual({});
    expect(log.creates[1].propVals).toEqual({
      'https://x/employer': 'did:ad:real-1',
    });
  });

  it('follows links nested in arrays', async () => {
    const { host, log } = makeHost();

    await applyPlan(
      plan([
        {
          ...create('_new:person'),
          properties: [{ property: 'https://x/tags', to: ['_new:tag'] }],
        },
        create('_new:tag'),
      ]),
      host,
    );

    expect(log.creates[1].propVals).toEqual({
      'https://x/tags': ['did:ad:real-1'],
    });
  });

  it('refuses to write a link to a create that never happened', async () => {
    const { host } = makeHost();

    // Two creates naming each other: no order satisfies both.
    const report = await applyPlan(
      plan([
        linkedCreate('_new:a', '_new:b'),
        linkedCreate('_new:b', '_new:a'),
      ]),
      host,
      { continueOnError: true },
    );

    expect(report.failed).toBeGreaterThan(0);

    const failure = report.outcomes.find(o => o.status === 'failed')!;
    expect(failure.error).toContain('link to nothing');
  });
});

describe('failures', () => {
  it('stops so dependents do not link to something that failed', async () => {
    const { host } = makeHost({
      create: vi.fn(async () => {
        throw new Error('offline');
      }),
    });

    const report = await applyPlan(
      plan([
        create('_new:org'),
        set('https://x/a', [
          { property: 'https://x/employer', to: '_new:org' },
        ]),
      ]),
      host,
    );

    expect(report.failed).toBe(1);
    expect(report.stoppedEarly).toBe(true);
    expect(report.outcomes[1].status).toBe('not-attempted');
    expect(host.set).not.toHaveBeenCalled();
  });

  it('records why a change failed', async () => {
    const { host } = makeHost({
      destroy: vi.fn(async () => {
        throw new Error('not allowed');
      }),
    });

    const report = await applyPlan(
      plan([
        { op: 'destroy', subject: 'https://x/a', properties: [], problems: [] },
      ]),
      host,
    );

    expect(report.outcomes[0]).toMatchObject({
      status: 'failed',
      error: 'Error: not allowed',
    });
  });

  it('keeps going when told to', async () => {
    let calls = 0;
    const { host } = makeHost({
      destroy: vi.fn(async () => {
        if (++calls === 1) throw new Error('gone');
      }),
    });

    const report = await applyPlan(
      plan([
        { op: 'destroy', subject: 'https://x/a', properties: [], problems: [] },
        { op: 'destroy', subject: 'https://x/b', properties: [], problems: [] },
      ]),
      host,
      { continueOnError: true },
    );

    expect(report.failed).toBe(1);
    expect(report.applied).toBe(1);
    expect(report.stoppedEarly).toBe(false);
  });

  it('does not claim it stopped early when the last change failed', async () => {
    const { host } = makeHost({
      destroy: vi.fn(async () => {
        throw new Error('gone');
      }),
    });

    const report = await applyPlan(
      plan([
        { op: 'destroy', subject: 'https://x/a', properties: [], problems: [] },
      ]),
      host,
    );

    expect(report.stoppedEarly).toBe(false);
    expect(report.failed).toBe(1);
  });
});
