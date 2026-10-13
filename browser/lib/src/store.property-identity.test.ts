import { describe, it, expect } from 'vitest';
import { testStore } from './test-store.js';
import { core } from './ontologies/core.js';
import { propertyId } from './property-identity.js';

const GENESIS = 'https://atomicdata.dev/properties/genesis';
const ONTOLOGY = 'atomic:ontologyGenesis';
const STRING = 'https://atomicdata.dev/datatypes/string';
const VECTOR =
  'atomic:prop:5a939a7ca63806573c204c88e8994252ef6e14f125f8bd258bce672344b2ba74';

const propVals = {
  [core.properties.shortname]: 'name',
  [core.properties.datatype]: STRING,
};

describe('newResource({ contentAddressedProperty })', () => {
  it('uses the content-addressed ID as subject, without a genesis cert', async () => {
    const { store } = await testStore();

    const prop = await store.newResource({
      isA: core.classes.property,
      parent: ONTOLOGY,
      propVals,
      contentAddressedProperty: true,
    });

    expect(prop.subject).toBe(VECTOR);
    expect(prop.subject).toBe(propertyId(ONTOLOGY, 'name', STRING));
    expect(prop.get(GENESIS)).toBeUndefined();
  });

  it.each([
    ['parent', { propVals }],
    [
      'shortname',
      {
        parent: ONTOLOGY,
        propVals: { [core.properties.datatype]: STRING },
      },
    ],
    [
      'datatype',
      {
        parent: ONTOLOGY,
        propVals: { [core.properties.shortname]: 'name' },
      },
    ],
  ])('throws when %s is missing', async (_name, opts) => {
    const { store } = await testStore();

    await expect(
      store.newResource({
        isA: core.classes.property,
        contentAddressedProperty: true,
        ...opts,
      }),
    ).rejects.toThrow();
  });

  it('returns the existing resource for the same inputs', async () => {
    const { store } = await testStore();
    const opts = {
      isA: core.classes.property,
      parent: ONTOLOGY,
      propVals,
      contentAddressedProperty: true,
    };

    const first = await store.newResource(opts);
    const second = await store.newResource(opts);

    expect(second.subject).toBe(first.subject);
    expect(second).toBe(first);
  });

  it('stores a did:ad:prop: key under its atomic:prop: key', async () => {
    const { store } = await testStore();
    const hex = 'a'.repeat(64);
    const res = await store.newResource({ isA: core.classes.property });

    await res.set(`did:ad:prop:${hex}`, 'hello', false, undefined);

    expect(res.get(`atomic:prop:${hex}`)).toBe('hello');
    expect(
      Object.keys(res.getPropVals()).some(k => k.startsWith('did:ad:prop:')),
    ).toBe(false);
  });
});
