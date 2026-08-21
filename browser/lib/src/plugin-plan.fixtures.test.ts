import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { planVerdict, type PlanHost } from './plugin-plan.js';
import { parseVerdict } from './plugin-run.js';
import type { Datatype } from './datatypes.js';
import type { Property } from './store.js';
import type { JSONValue } from './value.js';

/**
 * The shared plan corpus, run against the TypeScript planner.
 *
 * The same files are run against the Rust planner the server uses. Two
 * implementations exist because neither can do the other's job — the browser
 * plans offline against a local store, the server plans for runs nobody is
 * watching — and a planner that disagrees with the one that drew the preview
 * means the approved changes are not the changes made.
 *
 * See `testdata/plugin-plans/README.md`.
 */

interface Fixture {
  name: string;
  schema: Record<string, { datatype: string; shortname: string }>;
  resources: Record<string, Record<string, JSONValue>>;
  verdict: unknown;
  expect: {
    blocked: boolean;
    problems: string[];
    changes: Array<{
      op: string;
      localId?: string;
      subject?: string;
      properties: Array<{
        property: string;
        from?: JSONValue;
        to?: JSONValue;
        /** The subject minted for this create, which no fixture can name. */
        toMintedFor?: string;
      }>;
    }>;
  };
}

const DIR = join(import.meta.dirname, '../../../testdata/plugin-plans');

const fixtures = readdirSync(DIR)
  .filter(file => file.endsWith('.json'))
  .map(file => ({
    file,
    fixture: JSON.parse(readFileSync(join(DIR, file), 'utf8')) as Fixture,
  }));

const hostFor = (fixture: Fixture): PlanHost => {
  let n = 0;

  return {
    createSubject: (parent?: string) => `${parent}/minted-${++n}`,
    getProperty: async (subject: string): Promise<Property> => {
      const found = fixture.schema[subject];

      if (!found) throw new Error(`Property ${subject} is not found`);

      return {
        subject,
        datatype: found.datatype as Datatype,
        shortname: found.shortname,
        description: '',
      };
    },
    readResource: async (subject: string) => fixture.resources[subject],
  };
};

describe('the shared plan corpus', () => {
  it('has fixtures to run', () => {
    // A corpus that silently found nothing would report success for having
    // pinned nothing at all.
    expect(fixtures.length).toBeGreaterThan(0);
  });

  for (const { file, fixture } of fixtures) {
    it(`${file}: ${fixture.name}`, async () => {
      const plan = await planVerdict(
        parseVerdict(fixture.verdict),
        hostFor(fixture),
      );

      expect(plan.blocked).toBe(fixture.expect.blocked);

      const problems = [
        ...plan.problems,
        ...plan.changes.flatMap(c => c.problems),
      ].map(p => p.message);

      for (const expected of fixture.expect.problems) {
        expect(problems.join('\n')).toContain(expected);
      }

      expect(plan.changes).toHaveLength(fixture.expect.changes.length);

      fixture.expect.changes.forEach((expectedChange, index) => {
        const change = plan.changes[index];

        expect(change.op).toBe(expectedChange.op);

        if (expectedChange.localId !== undefined) {
          expect(change.localId).toBe(expectedChange.localId);
        }

        if (expectedChange.subject !== undefined) {
          expect(change.subject).toBe(expectedChange.subject);
        }

        expect(change.properties).toHaveLength(
          expectedChange.properties.length,
        );

        expectedChange.properties.forEach((expectedProperty, i) => {
          const property = change.properties[i];

          expect(property.property).toBe(expectedProperty.property);

          if (expectedProperty.from !== undefined) {
            expect(property.from).toEqual(expectedProperty.from);
          }

          if (expectedProperty.toMintedFor !== undefined) {
            // The subject is minted, so the fixture pins that it points at the
            // right create rather than at a literal.
            expect(property.to).toBe(plan.minted[expectedProperty.toMintedFor]);
          } else if (expectedProperty.to !== undefined) {
            expect(property.to).toEqual(expectedProperty.to);
          }
        });
      });
    });
  }
});
