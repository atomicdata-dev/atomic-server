import { describe, expect, it, vi } from 'vitest';
import { testStore } from './test-store.js';
import { parseVerdict } from './plugin-run.js';
import { planHostFromStore, planVerdict } from './plugin-plan.js';
import { applyHostFromStore, applyPlan } from './plugin-apply.js';
import { Datatype } from './datatypes.js';
import { core } from './ontologies/core.js';
import type { Property } from './store.js';

/**
 * The whole `run` path against a real Store: a verdict is parsed, planned,
 * applied, and the resulting commits are inspected. Everything else is tested
 * against fakes; this is the one that would catch a store contract the rest of
 * the chain only assumes.
 */

const NAME = core.properties.name;
const DESCRIPTION = core.properties.description;
const THING = 'https://x/Thing';

const schema: Record<string, Property> = {
  [NAME]: {
    subject: NAME,
    datatype: Datatype.STRING,
    shortname: 'name',
    description: '',
  },
  [DESCRIPTION]: {
    subject: DESCRIPTION,
    datatype: Datatype.MARKDOWN,
    shortname: 'description',
    description: '',
  },
};

const withSchema = (store: { getProperty: unknown }) => {
  store.getProperty = vi.fn(async (subject: string) => {
    const found = schema[subject];

    if (!found) throw new Error(`Property ${subject} is not found`);

    return found;
  });
};

describe('a run, end to end', () => {
  it('creates linked resources and commits real subjects', async () => {
    const { store, posted } = await testStore();
    withSchema(store as unknown as { getProperty: unknown });

    // What a plugin would have returned: a folder, a child inside it, and a
    // link from the child to the folder — all three referring to resources
    // that do not exist yet.
    const verdict = parseVerdict({
      intents: [
        {
          op: 'create',
          localId: 'child',
          parent: 'local:folder',
          isA: [THING],
          set: { [NAME]: 'Child', [DESCRIPTION]: 'lives in local:folder' },
        },
        {
          op: 'create',
          localId: 'folder',
          parent: 'https://example.com',
          isA: [THING],
          set: { [NAME]: 'Folder' },
        },
      ],
      problems: [],
    });

    expect(verdict.problems).toEqual([]);

    const plan = await planVerdict(verdict, planHostFromStore(store));

    expect(plan.blocked).toBe(false);
    expect(plan.changes).toHaveLength(2);

    const report = await applyPlan(plan, applyHostFromStore(store));

    expect(report.failed).toBe(0);
    expect(report.applied).toBe(2);

    const folder = report.outcomes.find(o => o.localId === 'folder')!;
    const child = report.outcomes.find(o => o.localId === 'child')!;

    // The store minted DIDs of its own; the planner's placeholders are gone.
    expect(folder.subject).toMatch(/^did:ad:/);
    expect(folder.subject).not.toBe(folder.planned);

    // The child landed under the subject the folder actually got.
    const created = await store.getResource(child.subject);
    expect(created.get(core.properties.parent)).toBe(folder.subject);
    expect(created.get(NAME)).toBe('Child');

    // And every write reached the wire.
    expect(posted.length).toBeGreaterThanOrEqual(2);
    expect(posted.some(c => c.subject === folder.subject)).toBe(true);
    expect(posted.some(c => c.subject === child.subject)).toBe(true);
  });

  it('edits an existing resource and shows what it replaced', async () => {
    const { store } = await testStore();
    withSchema(store as unknown as { getProperty: unknown });

    const existing = await store.newResource({
      parent: 'https://example.com',
      isA: [THING],
      propVals: { [NAME]: 'Before' },
    });
    await existing.save();

    const plan = await planVerdict(
      parseVerdict({
        intents: [
          { op: 'set', subject: existing.subject, set: { [NAME]: 'After' } },
        ],
      }),
      planHostFromStore(store),
    );

    expect(plan.blocked).toBe(false);
    expect(plan.changes[0].properties[0]).toMatchObject({
      from: 'Before',
      to: 'After',
    });

    await applyPlan(plan, applyHostFromStore(store));

    const reread = await store.getResource(existing.subject);
    expect(reread.get(NAME)).toBe('After');
  });

  it('blocks a run whose property does not exist, writing nothing', async () => {
    const { store, posted } = await testStore();
    withSchema(store as unknown as { getProperty: unknown });

    const before = posted.length;

    const plan = await planVerdict(
      parseVerdict({
        intents: [
          {
            op: 'create',
            localId: 'a',
            parent: 'https://example.com',
            isA: [THING],
            set: { 'https://x/not-a-property': 'value' },
          },
        ],
      }),
      planHostFromStore(store),
    );

    expect(plan.blocked).toBe(true);

    await expect(applyPlan(plan, applyHostFromStore(store))).rejects.toThrow(
      /blocked plan/,
    );

    expect(posted.length).toBe(before);
  });
});
