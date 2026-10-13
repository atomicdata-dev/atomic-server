import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ensureOntology } from './plugin-schema.js';
import {
  ontologyFromJsonSchema,
  ontologyToJsonSchema,
  type JsonSchemaImportOptions,
} from './schema-json-schema.js';
import { makeSchemaStore, TEST_DRIVE } from './schema-test-store.js';
import type { OntologyInput } from './ontology-input.js';
import { isPropertyId } from './property-identity.js';
import { core } from './ontologies/core.js';

interface Fixture {
  cases: Array<{
    name: string;
    schema: unknown;
    options?: JsonSchemaImportOptions;
    plan: OntologyInput;
    /** What the ontology exports as, when that is not the schema itself. */
    export?: Record<string, unknown>;
  }>;
  rejected: Array<{
    name: string;
    schema: unknown;
    options?: JsonSchemaImportOptions;
    pointer: string;
    message: string;
  }>;
}

const fixture = JSON.parse(
  readFileSync(
    new URL(
      '../../../lib/tests/fixtures/json-schema-interop.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as Fixture;

/** The subjects an export adds are Atomic's, not the schema's. */
const withoutSubjects = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(withoutSubjects);

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([k]) => k !== 'x-atomic-subject' && k !== 'x-atomic-property')
        .map(([k, v]) => [k, withoutSubjects(v)]),
    );
  }

  return value;
};

describe('JSON Schema interop fixture', () => {
  it('has cases', () => {
    expect(fixture.cases.length).toBeGreaterThan(5);
    expect(fixture.rejected.length).toBeGreaterThan(20);
  });

  describe.each(fixture.cases.map(c => [c.name, c] as const))('%s', (_n, c) => {
    it('imports to the plan', () => {
      expect(ontologyFromJsonSchema(c.schema, c.options)).toEqual(c.plan);
    });

    it('round-trips through ensureOntology', async () => {
      const { store } = makeSchemaStore();
      const plan = ontologyFromJsonSchema(c.schema, c.options);
      const ensured = await ensureOntology(store, TEST_DRIVE, plan);
      const exported = await ontologyToJsonSchema(store, ensured.ontology);

      expect(withoutSubjects(exported)).toEqual(c.export ?? c.schema);

      // The export is a fixed point: importing it gives the same ontology.
      const again = await makeSchemaStore();
      const second = await ensureOntology(
        again.store,
        TEST_DRIVE,
        ontologyFromJsonSchema(exported),
      );

      expect(
        withoutSubjects(
          await ontologyToJsonSchema(again.store, second.ontology),
        ),
      ).toEqual(c.export ?? c.schema);
    });

    it('carries each property subject', async () => {
      const { store } = makeSchemaStore();
      const ensured = await ensureOntology(
        store,
        TEST_DRIVE,
        ontologyFromJsonSchema(c.schema, c.options),
      );
      const exported = (await ontologyToJsonSchema(
        store,
        ensured.ontology,
      )) as {
        $defs: Record<
          string,
          { properties: Record<string, Record<string, string>> }
        >;
      };
      const subjects = Object.values(exported.$defs).flatMap(def =>
        Object.values(def.properties).map(p => p['x-atomic-property']),
      );

      expect(subjects.every(s => isPropertyId(s))).toBe(true);
      expect(new Set(subjects)).toEqual(
        new Set(Object.values(ensured.properties)),
      );
    });
  });

  it.each(fixture.rejected.map(r => [r.name, r] as const))(
    'rejects %s',
    (_n, r) => {
      let message = '';

      try {
        ontologyFromJsonSchema(r.schema, r.options);
      } catch (e) {
        message = (e as Error).message;
      }

      expect(message).toContain(`JSON Schema at ${r.pointer || '/'}:`);
      expect(message).toContain(r.message);
    },
  );
});

describe('import and ensureOntology together', () => {
  const shop = fixture.cases[0];

  it('stores the constraints on the class, keyed by property subject', async () => {
    const { store, world } = makeSchemaStore();
    const ensured = await ensureOntology(
      store,
      TEST_DRIVE,
      ontologyFromJsonSchema(shop.schema),
    );
    const invoice = world[ensured.classes.invoice].props;
    const constraints = invoice[core.properties.constraints] as Record<
      string,
      Record<string, unknown>
    >;

    expect(constraints[ensured.properties.customer]).toEqual({
      class: ensured.classes.customer,
    });
    expect(constraints[ensured.properties.amount]).toEqual({
      minimum: 0,
      exclusiveMaximum: 100000,
    });
    expect(invoice[core.properties.requires]).toEqual([
      ensured.properties.number,
      ensured.properties.customer,
    ]);
  });

  it('writes nothing on a second run', async () => {
    const { store, world, saves } = makeSchemaStore();
    const plan = ontologyFromJsonSchema(shop.schema);
    const first = await ensureOntology(store, TEST_DRIVE, plan);
    const before = JSON.stringify(world);
    const written = saves.length;
    const second = await ensureOntology(store, TEST_DRIVE, plan);

    expect(second).toEqual(first);
    expect(JSON.stringify(world)).toBe(before);
    expect(saves.length).toBe(written);
  });
});
