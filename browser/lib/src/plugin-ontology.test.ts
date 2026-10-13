import { describe, expect, it } from 'vitest';
import { Datatype } from './datatypes.js';
import { core } from './ontologies/core.js';
import { ensureOntology } from './plugin-schema.js';
import { propertyId } from './property-identity.js';
import { makeSchemaStore, TEST_DRIVE } from './schema-test-store.js';
import type { OntologyInput } from './ontology-input.js';

const input: OntologyInput = {
  shortname: 'crm',
  description: 'Contacts.',
  classes: [
    {
      shortname: 'person',
      properties: [
        { shortname: 'name', datatype: Datatype.STRING },
        { shortname: 'age', datatype: Datatype.INTEGER },
        { shortname: 'employer', datatype: Datatype.ATOMIC_URL },
      ],
      requires: ['name'],
      constraints: {
        age: { minimum: 0 },
        employer: { class: 'company' },
      },
    },
    {
      shortname: 'company',
      properties: [{ shortname: 'name', datatype: Datatype.STRING }],
      requires: ['name'],
    },
  ],
};

describe('ensureOntology', () => {
  it('creates the ontology, content-addressed properties and classes', async () => {
    const { store, world } = makeSchemaStore();
    const ensured = await ensureOntology(store, TEST_DRIVE, input);

    expect(world[ensured.ontology].props[core.properties.parent]).toBe(
      TEST_DRIVE,
    );
    expect(ensured.properties.name).toBe(
      propertyId(ensured.ontology, 'name', Datatype.STRING),
    );
    expect(ensured.properties.age).toBe(
      propertyId(ensured.ontology, 'age', Datatype.INTEGER),
    );
    expect(Object.keys(ensured.classes)).toEqual(['person', 'company']);
    expect(world[ensured.ontology].props[core.properties.properties]).toEqual([
      ensured.properties.name,
      ensured.properties.age,
      ensured.properties.employer,
    ]);
    expect(world[ensured.ontology].props[core.properties.classes]).toEqual([
      ensured.classes.person,
      ensured.classes.company,
    ]);
  });

  it('gives the same subjects in another store', async () => {
    const a = makeSchemaStore();
    const b = makeSchemaStore();
    const first = await ensureOntology(a.store, TEST_DRIVE, input);
    const second = await ensureOntology(b.store, TEST_DRIVE, input);

    // A property's subject depends only on ontology, shortname and datatype.
    expect(Object.keys(first.properties)).toEqual(
      Object.keys(second.properties),
    );
    expect(first.properties.name).toBe(second.properties.name);
  });

  it('is idempotent: a second run writes nothing', async () => {
    const { store, world, saves } = makeSchemaStore();
    const first = await ensureOntology(store, TEST_DRIVE, input);
    const before = JSON.stringify(world);
    const written = saves.length;

    expect(await ensureOntology(store, TEST_DRIVE, input)).toEqual(first);
    expect(JSON.stringify(world)).toBe(before);
    expect(saves.length).toBe(written);
  });

  it('resolves a class constraint to the class subject', async () => {
    const { store, world } = makeSchemaStore();
    const ensured = await ensureOntology(store, TEST_DRIVE, input);
    const constraints = world[ensured.classes.person].props[
      core.properties.constraints
    ] as Record<string, unknown>;

    expect(constraints).toEqual({
      [ensured.properties.age]: { minimum: 0 },
      [ensured.properties.employer]: { class: ensured.classes.company },
    });
  });

  it('shares a property declared by two classes', async () => {
    const { store, world } = makeSchemaStore();
    const ensured = await ensureOntology(store, TEST_DRIVE, input);

    expect(
      world[ensured.classes.company].props[core.properties.requires],
    ).toEqual([ensured.properties.name]);
    expect(
      (
        world[ensured.ontology].props[core.properties.properties] as string[]
      ).filter(s => s === ensured.properties.name),
    ).toHaveLength(1);
  });

  it('brings requires and constraints of an existing class back in line', async () => {
    const { store, world } = makeSchemaStore();
    const first = await ensureOntology(store, TEST_DRIVE, input);
    const changed: OntologyInput = {
      ...input,
      classes: [
        {
          ...input.classes[0],
          requires: ['name', 'age'],
          constraints: { age: { minimum: 18 } },
        },
        input.classes[1],
      ],
    };
    const second = await ensureOntology(store, TEST_DRIVE, changed);
    const person = world[second.classes.person].props;

    expect(second).toEqual(first);
    expect(person[core.properties.requires]).toEqual([
      first.properties.name,
      first.properties.age,
    ]);
    expect(person[core.properties.constraints]).toEqual({
      [first.properties.age]: { minimum: 18 },
    });
  });

  it('leaves constraints alone when the input has none, clears them for {}', async () => {
    const { store, world } = makeSchemaStore();
    const first = await ensureOntology(store, TEST_DRIVE, input);
    const person = input.classes[0];

    await ensureOntology(store, TEST_DRIVE, {
      ...input,
      classes: [{ ...person, constraints: undefined }, input.classes[1]],
    });
    expect(
      Object.keys(
        world[first.classes.person].props[
          core.properties.constraints
        ] as object,
      ),
    ).toHaveLength(2);

    await ensureOntology(store, TEST_DRIVE, {
      ...input,
      classes: [{ ...person, constraints: {} }, input.classes[1]],
    });
    expect(
      world[first.classes.person].props[core.properties.constraints],
    ).toEqual({});
  });

  it.each([
    [
      'a property with two datatypes',
      {
        ...input,
        classes: [
          ...input.classes,
          {
            shortname: 'pet',
            properties: [{ shortname: 'name', datatype: Datatype.INTEGER }],
          },
        ],
      },
      /cannot hold two properties/,
    ],
    [
      'an undeclared required property',
      {
        ...input,
        classes: [{ shortname: 'a', requires: ['missing'] }],
      },
      /not a declared property/,
    ],
    [
      'a constraint on a property the class does not have',
      {
        ...input,
        classes: [
          { ...input.classes[1], constraints: { age: { minimum: 1 } } },
        ],
      },
      /neither requires nor recommends/,
    ],
    [
      'an unknown constraint keyword',
      {
        ...input,
        classes: [
          { ...input.classes[1], constraints: { name: { minimun: 1 } } },
        ],
      },
      /Unknown constraint keyword/,
    ],
    [
      'a class constraint naming no class',
      {
        ...input,
        classes: [
          { ...input.classes[0], constraints: { employer: { class: 'nope' } } },
        ],
      },
      /not in this ontology/,
    ],
  ])('refuses %s before writing anything', async (_name, bad, error) => {
    const { store, saves } = makeSchemaStore();

    await expect(ensureOntology(store, TEST_DRIVE, bad)).rejects.toThrow(error);
    expect(saves).toEqual([]);
  });
});
