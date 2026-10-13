import { describe, expect, it } from 'vitest';
import { core, propertyId, type Store } from '@tomic/lib';
import { ensureOntologyFromJsonSchema, findSchemas } from './schemaTools';

const DRIVE = 'https://x/drive';

type Props = Record<string, unknown>;

/** In-memory store with just what ensureOntology and the schema export read. */
function makeStore() {
  const world: Record<string, Props> = { [DRIVE]: {} };
  const pending: Record<string, Props> = {};
  const saves: string[] = [];
  let n = 0;

  const wrap = (subject: string, props: Props) => {
    let dirty = false;

    return {
      subject,
      get: (p: string) => props[p],
      set: async (p: string, v: unknown) => {
        if (JSON.stringify(props[p]) === JSON.stringify(v)) return;
        props[p] = v;
        dirty = true;
      },
      save: async () => {
        if (pending[subject]) {
          world[subject] = pending[subject];
          delete pending[subject];
          saves.push(subject);
        } else if (dirty) {
          saves.push(subject);
        }

        dirty = false;
      },
    };
  };

  const store = {
    findByLocalId: async (_d: string, parent: string, localId: string) => {
      const hit = Object.entries(world).find(
        ([, r]) =>
          r[core.properties.parent] === parent &&
          r[core.properties.localId] === localId,
      );

      return hit ? wrap(hit[0], hit[1]) : undefined;
    },
    getResource: async (subject: string) => {
      const props = world[subject] ?? pending[subject];

      if (!props) throw new Error(`unknown resource ${subject}`);

      return wrap(subject, props);
    },
    newResource: async (opts: {
      parent: string;
      isA: string[];
      propVals: Props;
      contentAddressedProperty?: boolean;
    }) => {
      const subject = opts.contentAddressedProperty
        ? propertyId(
            opts.parent,
            String(opts.propVals[core.properties.shortname]),
            String(opts.propVals[core.properties.datatype]),
          )
        : `${opts.parent}/created-${++n}`;

      if (world[subject]) return wrap(subject, world[subject]);

      pending[subject] = {
        ...opts.propVals,
        [core.properties.parent]: opts.parent,
        [core.properties.isA]: opts.isA,
      };

      return wrap(subject, pending[subject]);
    },
  };

  return { store: store as unknown as Store, world, saves };
}

const shop = {
  title: 'Shop',
  $defs: {
    customer: {
      type: 'object',
      description: 'Someone who buys things',
      properties: { name: { type: 'string', minLength: 1 } },
      required: ['name'],
    },
    invoice: {
      type: 'object',
      properties: {
        amount: { type: 'number', minimum: 0 },
        customer: { $ref: '#/$defs/customer' },
      },
    },
  },
};

describe('ensureOntologyFromJsonSchema', () => {
  it('creates the ontology and returns the subjects', async () => {
    const { store, world } = makeStore();
    const result = await ensureOntologyFromJsonSchema(store, DRIVE, {
      schema: shop,
    });

    expect(result).toMatchObject({ shortname: 'shop' });
    if ('error' in result) throw new Error(result.error);
    expect(Object.keys(result.classes).sort()).toEqual(['customer', 'invoice']);
    expect(Object.keys(result.properties).sort()).toEqual([
      'amount',
      'customer',
      'name',
    ]);
    expect(world[result.classes.invoice]).toBeDefined();
  });

  it('is idempotent', async () => {
    const { store, saves } = makeStore();
    const first = await ensureOntologyFromJsonSchema(store, DRIVE, {
      schema: shop,
    });
    const savedAfterFirst = saves.length;
    const second = await ensureOntologyFromJsonSchema(store, DRIVE, {
      schema: shop,
    });

    expect(second).toEqual(first);
    expect(saves.length).toBe(savedAfterFirst);
  });

  it('uses the given shortname', async () => {
    const { store } = makeStore();
    const result = await ensureOntologyFromJsonSchema(store, DRIVE, {
      schema: shop,
      shortname: 'webshop',
    });

    expect(result).toMatchObject({ shortname: 'webshop' });
  });

  it('returns import errors verbatim with their JSON pointer', async () => {
    const { store, saves } = makeStore();
    const result = await ensureOntologyFromJsonSchema(store, DRIVE, {
      schema: {
        title: 'Bad',
        $defs: {
          Invoice: {
            type: 'object',
            properties: { status: { oneOf: [{ type: 'string' }] } },
          },
        },
      },
    });

    expect(result).toHaveProperty('error');
    expect((result as { error: string }).error).toContain(
      '/$defs/Invoice/properties/status/oneOf',
    );
    expect(saves).toEqual([]);
  });

  it('reports a missing ontology name', async () => {
    const { store } = makeStore();
    const result = await ensureOntologyFromJsonSchema(store, DRIVE, {
      schema: { $defs: { a: { type: 'object', properties: {} } } },
    });

    expect(result).toHaveProperty('error');
  });
});

describe('findSchemas', () => {
  it('finds a class by words and returns its JSON Schema', async () => {
    const { store } = makeStore();
    const ensured = await ensureOntologyFromJsonSchema(store, DRIVE, {
      schema: shop,
    });
    if ('error' in ensured) throw new Error(ensured.error);

    const subjects = Object.values(ensured.classes);
    const { matches, total } = await findSchemas(store, subjects, 'invoice');

    expect(total).toBe(1);
    expect(matches[0]).toMatchObject({
      class: ensured.classes.invoice,
      shortname: 'invoice',
      ontology: { subject: ensured.ontology, shortname: 'shop' },
    });
    expect(matches[0].jsonSchema).toMatchObject({
      type: 'object',
      properties: { amount: { type: 'number', minimum: 0 } },
    });
  });

  it('matches on the description and the ontology, and lists all for an empty query', async () => {
    const { store } = makeStore();
    const ensured = await ensureOntologyFromJsonSchema(store, DRIVE, {
      schema: shop,
    });
    if ('error' in ensured) throw new Error(ensured.error);

    const subjects = Object.values(ensured.classes);

    expect((await findSchemas(store, subjects, 'buys')).total).toBe(1);
    expect((await findSchemas(store, subjects, 'shop')).total).toBe(2);
    expect((await findSchemas(store, subjects, 'nothing-like')).total).toBe(0);
    expect((await findSchemas(store, subjects, '')).total).toBe(2);
    expect((await findSchemas(store, subjects, '', 1)).matches).toHaveLength(1);
  });
});
