import { describe, expect, it, vi } from 'vitest';
import { planVerdict, type PlanHost } from './plugin-plan.js';
import { Datatype } from './datatypes.js';
import type { Property } from './store.js';
import type { Verdict } from './plugin-run.js';
import type { JSONValue } from './value.js';

const NAME = 'https://x/name';
const AGE = 'https://x/age';
const LINK = 'https://x/employer';

const property = (subject: string, datatype: Datatype): Property => ({
  subject,
  datatype,
  shortname: subject.split('/').pop()!,
  description: '',
});

const SCHEMA: Record<string, Property> = {
  [NAME]: property(NAME, Datatype.STRING),
  [AGE]: property(AGE, Datatype.INTEGER),
  [LINK]: property(LINK, Datatype.ATOMIC_URL),
};

interface HostOpts {
  resources?: Record<string, Record<string, JSONValue>>;
}

const makeHost = ({ resources = {} }: HostOpts = {}) => {
  let n = 0;

  const host: PlanHost = {
    createSubject: vi.fn((parent?: string) => `${parent}/new-${++n}`),
    getProperty: vi.fn(async (subject: string) => {
      const found = SCHEMA[subject];

      if (!found) throw new Error(`Property ${subject} is not found`);

      return found;
    }),
    readResource: vi.fn(async (subject: string) => resources[subject]),
  };

  return host;
};

const verdict = (over: Partial<Verdict> = {}): Verdict => ({
  intents: [],
  problems: [],
  ...over,
});

describe('minting subjects', () => {
  it('mints under the given parent and records the mapping', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          {
            op: 'create',
            localId: 'org',
            parent: 'https://x/drive',
            isA: ['https://x/Org'],
            set: { [NAME]: 'Acme' },
          },
        ],
      }),
      makeHost(),
    );

    expect(plan.blocked).toBe(false);
    expect(plan.minted.org).toBe('https://x/drive/new-1');
    expect(plan.changes[0]).toMatchObject({
      op: 'create',
      subject: 'https://x/drive/new-1',
      localId: 'org',
      isA: ['https://x/Org'],
    });
  });

  it('mints a child under the parent created in the same run', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          {
            op: 'create',
            localId: 'child',
            parent: 'local:folder',
            isA: [],
            set: {},
          },
          {
            op: 'create',
            localId: 'folder',
            parent: 'https://x/drive',
            isA: [],
            set: {},
          },
        ],
      }),
      makeHost(),
    );

    expect(plan.minted.child.startsWith(plan.minted.folder)).toBe(true);
  });

  it('rewrites local references onto the minted subject', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          {
            op: 'create',
            localId: 'org',
            parent: 'https://x/drive',
            isA: [],
            set: {},
          },
          {
            op: 'set',
            subject: 'https://x/contact',
            set: { [LINK]: 'local:org' },
          },
        ],
      }),
      makeHost({ resources: { 'https://x/contact': {} } }),
    );

    expect(plan.changes[1].properties[0].to).toBe(plan.minted.org);
  });

  it('refuses creates that parent each other instead of hanging', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          { op: 'create', localId: 'a', parent: 'local:b', isA: [], set: {} },
          { op: 'create', localId: 'b', parent: 'local:a', isA: [], set: {} },
        ],
      }),
      makeHost(),
    );

    expect(plan.blocked).toBe(true);
    expect(plan.problems[0].message).toContain('a, b');
    expect(plan.changes).toEqual([]);
  });
});

describe('schema checks', () => {
  it('blocks a value whose property does not exist', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          {
            op: 'create',
            localId: 'a',
            parent: 'https://x/drive',
            isA: ['https://x/Org'],
            set: { 'https://x/nope': 'value' },
          },
        ],
      }),
      makeHost(),
    );

    expect(plan.blocked).toBe(true);
    expect(plan.changes[0].problems[0].message).toContain('nowhere to go');
  });

  it('blocks a value of the wrong datatype', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          {
            op: 'create',
            localId: 'a',
            parent: 'https://x/drive',
            isA: ['https://x/Org'],
            set: { [AGE]: 'forty' },
          },
        ],
      }),
      makeHost(),
    );

    expect(plan.blocked).toBe(true);
    expect(plan.changes[0].problems[0]).toMatchObject({
      severity: 'error',
      property: AGE,
    });
    expect(plan.changes[0].problems[0].message).toContain('age');
  });

  it('looks each property up once however many intents use it', async () => {
    const host = makeHost({
      resources: { 'https://x/a': {}, 'https://x/b': {} },
    });

    await planVerdict(
      verdict({
        intents: [
          { op: 'set', subject: 'https://x/a', set: { [NAME]: 'one' } },
          { op: 'set', subject: 'https://x/b', set: { [NAME]: 'two' } },
        ],
      }),
      host,
    );

    expect(host.getProperty).toHaveBeenCalledTimes(1);
  });

  it('warns about a create with no class rather than blocking it', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          {
            op: 'create',
            localId: 'a',
            parent: 'https://x/drive',
            isA: [],
            set: {},
          },
        ],
      }),
      makeHost(),
    );

    expect(plan.blocked).toBe(false);
    expect(plan.changes[0].problems[0].severity).toBe('warning');
  });
});

describe('existing resources', () => {
  it('blocks a change to a resource that is not there', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          { op: 'set', subject: 'https://x/ghost', set: { [NAME]: 'x' } },
        ],
      }),
      makeHost(),
    );

    expect(plan.blocked).toBe(true);
    expect(plan.changes[0].problems[0].message).toContain('does not exist');
  });

  it('shows the value being replaced', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          { op: 'set', subject: 'https://x/a', set: { [NAME]: 'new' } },
        ],
      }),
      makeHost({ resources: { 'https://x/a': { [NAME]: 'old' } } }),
    );

    expect(plan.changes[0].properties[0]).toMatchObject({
      property: NAME,
      shortname: 'name',
      from: 'old',
      to: 'new',
    });
  });

  it('skips a write that would change nothing', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [
          { op: 'set', subject: 'https://x/a', set: { [NAME]: 'same' } },
        ],
      }),
      makeHost({ resources: { 'https://x/a': { [NAME]: 'same' } } }),
    );

    expect(plan.changes[0].properties).toEqual([]);
    expect(plan.changes[0].problems[0].severity).toBe('warning');
    expect(plan.blocked).toBe(false);
  });

  it('plans a remove of a property that is set', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [{ op: 'remove', subject: 'https://x/a', properties: [NAME] }],
      }),
      makeHost({ resources: { 'https://x/a': { [NAME]: 'old' } } }),
    );

    expect(plan.changes[0].properties).toEqual([
      { property: NAME, from: 'old' },
    ]);
  });

  it('warns when removing a property that is not set', async () => {
    const plan = await planVerdict(
      verdict({
        intents: [{ op: 'remove', subject: 'https://x/a', properties: [NAME] }],
      }),
      makeHost({ resources: { 'https://x/a': {} } }),
    );

    expect(plan.changes[0].properties).toEqual([]);
    expect(plan.changes[0].problems[0].severity).toBe('warning');
  });

  it('plans a destroy of a resource that exists', async () => {
    const plan = await planVerdict(
      verdict({ intents: [{ op: 'destroy', subject: 'https://x/a' }] }),
      makeHost({ resources: { 'https://x/a': { [NAME]: 'x' } } }),
    );

    expect(plan.blocked).toBe(false);
    expect(plan.changes[0]).toMatchObject({ op: 'destroy', properties: [] });
  });
});

describe('problems from the run', () => {
  it('carries the verdict problems into the plan', async () => {
    const plan = await planVerdict(
      verdict({
        problems: [{ severity: 'warning', message: 'row 4 had no date' }],
      }),
      makeHost(),
    );

    expect(plan.problems).toHaveLength(1);
    expect(plan.blocked).toBe(false);
  });

  it('blocks when the run itself reported an error', async () => {
    const plan = await planVerdict(
      verdict({
        problems: [{ severity: 'error', message: 'name is required' }],
      }),
      makeHost(),
    );

    expect(plan.blocked).toBe(true);
  });
});
