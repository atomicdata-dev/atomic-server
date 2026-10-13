import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Datatype } from './datatypes.js';
import type { OntologyInput } from './ontology-input.js';
import { ensureOntology } from './plugin-schema.js';
import { ontologyFromJsonSchema } from './schema-json-schema.js';
import {
  checkLockfile,
  lockfileFromEnsured,
  lockfileFromInput,
  parseLockfile,
  serializeLockfile,
} from './schema-lockfile.js';
import { makeSchemaStore, TEST_DRIVE } from './schema-test-store.js';

interface Fixture {
  cases: Array<{
    name: string;
    ontology: string;
    classes: Record<string, string>;
    plan?: OntologyInput;
    jsonSchema?: unknown;
    fingerprint: string;
    lockfile: string;
  }>;
}

// Shared with lib/src/schema/lockfile.rs: the same bytes in both languages.
const fixture: Fixture = JSON.parse(
  readFileSync(
    new URL(
      '../../../lib/tests/fixtures/schema-lockfile.json',
      import.meta.url,
    ),
    'utf8',
  ),
);

const inputOf = (c: Fixture['cases'][number]): OntologyInput =>
  c.jsonSchema !== undefined
    ? ontologyFromJsonSchema(c.jsonSchema)
    : (c.plan as OntologyInput);

describe('schema lockfile', () => {
  for (const c of fixture.cases) {
    it(`writes the same bytes as Rust: ${c.name}`, () => {
      const lock = lockfileFromInput(inputOf(c), c.ontology, c.classes);

      expect(lock.fingerprint).toBe(c.fingerprint);
      expect(serializeLockfile(lock)).toBe(c.lockfile);
      expect(parseLockfile(c.lockfile)).toEqual(lock);
      expect(checkLockfile(lock, inputOf(c))).toEqual([]);
    });
  }

  it('is what ensureOntology pins', async () => {
    const { store } = makeSchemaStore();
    const input = inputOf(fixture.cases[0]);
    const ensured = await ensureOntology(store, TEST_DRIVE, input);
    const lock = lockfileFromEnsured(ensured, input);

    expect(lock).toEqual(
      lockfileFromInput(input, ensured.ontology, ensured.classes),
    );
    expect(checkLockfile(lock, input)).toEqual([]);
  });

  it('names a changed datatype', () => {
    const input = inputOf(fixture.cases[0]);
    const lock = lockfileFromInput(input, fixture.cases[0].ontology);
    const changed: OntologyInput = structuredClone(input);

    changed.classes[1].properties![1].datatype = Datatype.INTEGER;

    const problems = checkLockfile(lock, changed);

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("property 'total'");
    expect(problems[0]).toContain('shortname or datatype makes a new property');
  });

  it('reports added and removed properties and classes', () => {
    const input = inputOf(fixture.cases[0]);
    const lock = lockfileFromInput(input, fixture.cases[0].ontology, {
      gone: 'did:ad:gone',
    });
    const grown: OntologyInput = structuredClone(input);

    grown.properties = [{ shortname: 'extra', datatype: Datatype.STRING }];

    const problems = checkLockfile(lock, grown).join('\n');

    expect(problems).toContain('not in the lockfile');
    expect(problems).toContain("class 'gone' is in the lockfile");
  });

  it('reports a changed contract, and ignores cosmetic edits and order', () => {
    const input = inputOf(fixture.cases[0]);
    const lock = lockfileFromInput(input, fixture.cases[0].ontology);
    const cosmetic: OntologyInput = structuredClone(input);

    cosmetic.name = 'Renamed';
    cosmetic.classes[0].description = 'Reworded';
    cosmetic.classes.reverse();
    cosmetic.classes[0].properties!.reverse();

    expect(checkLockfile(lock, cosmetic)).toEqual([]);

    const tighter: OntologyInput = structuredClone(input);

    tighter.classes[0].requires!.push('email');

    expect(checkLockfile(lock, tighter).join('\n')).toContain(
      'changed since it was locked',
    );
  });

  it('reads and writes a lockfile without a fingerprint unchanged', () => {
    const text =
      '{\n  "classes": {},\n  "ontology": "x",\n  "properties": {}\n}\n';

    expect(serializeLockfile(parseLockfile(text))).toBe(text);
  });

  it('rejects unknown fields', () => {
    expect(() =>
      parseLockfile('{"ontology":"x","properties":{},"extra":1}'),
    ).toThrow(/Not a valid lockfile/);
  });
});
