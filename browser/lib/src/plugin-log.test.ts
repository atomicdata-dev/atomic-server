import { describe, expect, it, vi } from 'vitest';
import { pluginSchema, recordRun, runStatus } from './plugin-log.js';
import { ensureSchema } from './plugin-schema.js';
import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import type { ApplyReport } from './plugin-apply.js';
import type { RunPlan } from './plugin-plan.js';
import type { JSONValue } from './value.js';

const DRIVE = 'https://x/drive';
const ONTOLOGY = 'https://x/drive/ontology';

interface Stored {
  subject: string;
  isA: string[];
  props: Record<string, JSONValue>;
}

/** A store just real enough to see whether the schema is reused or recreated. */
const makeStore = (seed: Record<string, Stored> = {}) => {
  const world: Record<string, Stored> = {
    [DRIVE]: {
      subject: DRIVE,
      isA: [],
      props: { [server.properties.defaultOntology]: ONTOLOGY },
    },
    [ONTOLOGY]: { subject: ONTOLOGY, isA: [], props: {} },
    ...seed,
  };

  let n = 0;

  const wrap = (stored: Stored) => ({
    subject: stored.subject,
    get: (property: string) => stored.props[property],
    set: async (property: string, value: JSONValue) => {
      stored.props[property] = value;
    },
    save: async () => undefined,
  });

  const store = {
    world,
    getResource: vi.fn(async (subject: string) => {
      world[subject] ??= { subject, isA: [], props: {} };

      return wrap(world[subject]);
    }),
    newResource: vi.fn(
      async (opts: {
        parent: string;
        isA: string[];
        propVals: Record<string, JSONValue>;
      }) => {
        const subject = `${opts.parent}/created-${++n}`;
        world[subject] = {
          subject,
          isA: opts.isA,
          props: { ...opts.propVals },
        };

        return wrap(world[subject]);
      },
    ),
  };

  return store;
};

const plan = (over: Partial<RunPlan> = {}): RunPlan => ({
  changes: [],
  problems: [],
  minted: {},
  blocked: false,
  ...over,
});

const report = (over: Partial<ApplyReport> = {}): ApplyReport => ({
  outcomes: [],
  applied: 0,
  skipped: 0,
  failed: 0,
  subjects: {},
  stoppedEarly: false,
  ...over,
});

describe('ensureSchema', () => {
  it('creates the classes and properties a spec asks for', async () => {
    const store = makeStore();

    const schema = await ensureSchema(store, DRIVE, pluginSchema());

    expect(Object.keys(schema.properties)).toHaveLength(
      pluginSchema().properties.length,
    );
    expect(schema.classes['plugin-script']).toBeDefined();
    expect(schema.classes['plugin-run']).toBeDefined();

    const created = store.world[schema.classes['plugin-run']];
    expect(created.isA).toEqual([core.classes.class]);
    expect(created.props[core.properties.requires]).toEqual([
      schema.properties.trigger,
      schema.properties['started-at'],
      schema.properties['run-status'],
    ]);
  });

  it('registers what it created on the ontology', async () => {
    const store = makeStore();

    const schema = await ensureSchema(store, DRIVE, pluginSchema());

    expect(store.world[ONTOLOGY].props[core.properties.classes]).toEqual([
      schema.classes['plugin-script'],
      schema.classes['plugin-run'],
      schema.classes.app,
      schema.classes['plugin-grant'],
    ]);
    expect(
      store.world[ONTOLOGY].props[core.properties.properties],
    ).toHaveLength(pluginSchema().properties.length);
  });

  it('reuses what is already there instead of making a parallel set', async () => {
    const store = makeStore();

    const first = await ensureSchema(store, DRIVE, pluginSchema());
    const createdAfterFirst = store.newResource.mock.calls.length;

    const second = await ensureSchema(store, DRIVE, pluginSchema());

    expect(second).toEqual(first);
    expect(store.newResource.mock.calls.length).toBe(createdAfterFirst);
  });

  it('says so when the drive has nowhere to put a schema', async () => {
    const store = makeStore();
    store.world[DRIVE].props = {};

    await expect(ensureSchema(store, DRIVE, pluginSchema())).rejects.toThrow(
      /no default ontology/,
    );
  });
});

describe('runStatus', () => {
  it('reads blocked, applied, partial and failed off the report', () => {
    expect(runStatus(plan({ blocked: true }))).toBe('blocked');
    expect(runStatus(plan())).toBe('blocked');
    expect(runStatus(plan(), report({ applied: 3 }))).toBe('applied');
    expect(runStatus(plan(), report({ applied: 2, failed: 1 }))).toBe(
      'partial',
    );
    expect(runStatus(plan(), report({ applied: 0, failed: 2 }))).toBe('failed');
  });
});

describe('recordRun', () => {
  const trigger = { kind: 'manual' as const, at: 1_700_000_000_000 };

  it('records a run that wrote', async () => {
    const store = makeStore();

    const subject = await recordRun(store, {
      parent: 'https://x/plugin',
      drive: DRIVE,
      trigger,
      plan: plan(),
      report: report({ applied: 2, outcomes: [] }),
    });

    const record = store.world[subject];
    const schema = await ensureSchema(store, DRIVE, pluginSchema());

    expect(record.props[schema.properties['run-status']]).toBe('applied');
    expect(record.props[schema.properties['started-at']]).toBe(trigger.at);
    expect(record.props[schema.properties.trigger]).toBe('manual');
  });

  it('records a blocked run, so a refusal is not indistinguishable from silence', async () => {
    const store = makeStore();

    const subject = await recordRun(store, {
      parent: 'https://x/plugin',
      drive: DRIVE,
      trigger,
      plan: plan({
        blocked: true,
        problems: [{ severity: 'error', message: 'no property foo exists' }],
      }),
    });

    const schema = await ensureSchema(store, DRIVE, pluginSchema());
    const record = store.world[subject];

    expect(record.props[schema.properties['run-status']]).toBe('blocked');
    expect(record.props[schema.properties['run-problems']]).toEqual([
      { severity: 'error', message: 'no property foo exists' },
    ]);
  });

  it('tags a change problem with the subject it concerns', async () => {
    const store = makeStore();

    const subject = await recordRun(store, {
      parent: 'https://x/plugin',
      drive: DRIVE,
      trigger,
      plan: plan({
        changes: [
          {
            op: 'set',
            subject: 'https://x/a',
            properties: [],
            problems: [
              { severity: 'warning', message: 'already has this value' },
            ],
          },
        ],
      }),
      report: report({ applied: 1 }),
    });

    const schema = await ensureSchema(store, DRIVE, pluginSchema());

    expect(
      store.world[subject].props[schema.properties['run-problems']],
    ).toEqual([
      {
        severity: 'warning',
        message: 'already has this value',
        subject: 'https://x/a',
      },
    ]);
  });

  it('keeps the cursor only when something was actually written', async () => {
    const store = makeStore();
    const schema = await ensureSchema(store, DRIVE, pluginSchema());
    const cursorProp = schema.properties['run-cursor'];

    const wrote = await recordRun(store, {
      parent: 'https://x/plugin',
      drive: DRIVE,
      trigger,
      plan: plan({ cursor: 'page-2' }),
      report: report({ applied: 1 }),
    });

    const wroteNothing = await recordRun(store, {
      parent: 'https://x/plugin',
      drive: DRIVE,
      trigger,
      plan: plan({ cursor: 'page-2' }),
      report: report({ applied: 0, failed: 1 }),
    });

    expect(store.world[wrote].props[cursorProp]).toBe('page-2');
    expect(store.world[wroteNothing].props[cursorProp]).toBeUndefined();
  });
});
