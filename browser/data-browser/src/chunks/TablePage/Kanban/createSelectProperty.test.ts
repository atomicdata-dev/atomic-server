import { describe, expect, it, vi } from 'vitest';
import {
  Datatype,
  type JSONValue,
  type Resource,
  type Store,
  core,
  dataBrowser,
} from '@tomic/react';

// `createSelectProperty.ts` only wants the color palette, but the real
// `@components/Tag/tagColours` module drags in the whole app shell (routes,
// providers, bugsnag's `window` access), which doesn't survive import outside
// a browser. Stub it so this file can test the plain creation logic in Node.
vi.mock('@components/Tag/tagColours', () => ({
  tagColours: ['blue', 'red', 'green'],
}));

const { createOptionTags, createPropertyOnClass, createSelectPropertyOnClass } =
  await import('./createSelectProperty');

/**
 * A minimal in-memory double of `@tomic/lib`'s `Store`/`Resource`, just
 * enough surface (`get`/`set`/`push`/`save`/`hasClasses`/`newResource`/
 * `getResource`/`buildUniqueSubjectFromParts`) for the creation functions
 * under test — no network, no CRDT signing, no real ontology validation.
 */
function fakeStore() {
  const resources = new Map<
    string,
    { classes: Set<string>; props: Map<string, JSONValue> }
  >();
  let counter = 0;

  function makeResource(subject: string): Resource {
    const record = resources.get(subject);

    if (!record) {
      throw new Error(`fakeStore: no such resource ${subject}`);
    }

    return {
      subject,
      get title() {
        return String(record.props.get(core.properties.name) ?? subject);
      },
      get: (prop: string) => record.props.get(prop),
      set: async (prop: string, value: JSONValue) => {
        record.props.set(prop, value);
      },
      push: (prop: string, values: JSONValue[], unique?: boolean) => {
        const existing = (record.props.get(prop) as JSONValue[]) ?? [];
        const next = unique
          ? [...new Set([...existing, ...values])]
          : [...existing, ...values];
        record.props.set(prop, next);
      },
      save: async () => 'persisted',
      hasClasses: (...classSubjects: string[]) =>
        classSubjects.some(c => record.classes.has(c)),
    } as unknown as Resource;
  }

  const store = {
    getServerUrl: () => 'https://localhost',
    getResource: async (subject: string) => makeResource(subject),
    getResourceLoading: (subject: string) =>
      resources.has(subject)
        ? { ...makeResource(subject), isReady: () => true }
        : { isReady: () => false, get: () => undefined },
    newResource: async (opts: {
      subject?: string;
      parent?: string;
      isA?: string | string[];
      propVals?: Record<string, JSONValue>;
    }) => {
      const subject = opts.subject ?? `test:${++counter}`;
      const isA = opts.isA
        ? Array.isArray(opts.isA)
          ? opts.isA
          : [opts.isA]
        : [];
      const props = new Map<string, JSONValue>(
        Object.entries(opts.propVals ?? {}),
      );

      if (opts.parent) {
        props.set(core.properties.parent, opts.parent);
      }

      resources.set(subject, { classes: new Set(isA), props });

      return makeResource(subject);
    },
    buildUniqueSubjectFromParts: async (parts: string[], parent: string) =>
      `${parent}/${parts.join('-')}`,
  } as unknown as Store;

  return store;
}

/** An ontology and two row classes parented under it — the shared shape every
 *  "two tables on the same drive" scenario in this file starts from. */
async function twoTablesOnOneOntology(store: Store) {
  const ontology = await store.newResource({
    isA: core.classes.ontology,
    propVals: { [core.properties.properties]: [] },
  });
  const rowClassA = await store.newResource({
    isA: core.classes.class,
    parent: ontology.subject,
  });
  const rowClassB = await store.newResource({
    isA: core.classes.class,
    parent: ontology.subject,
  });

  return { ontology, rowClassA, rowClassB };
}

const STATUS_TAGS = [{ name: 'Todo' }, { name: 'Doing' }, { name: 'Done' }];

describe('table column creation dedupes ontology shortnames', () => {
  it('reuses an existing select property instead of creating a duplicate shortname', async () => {
    const store = fakeStore();
    const { ontology, rowClassA, rowClassB } =
      await twoTablesOnOneOntology(store);

    const first = await createSelectPropertyOnClass(store, rowClassA, {
      name: 'Status',
      tags: STATUS_TAGS,
    });
    const second = await createSelectPropertyOnClass(store, rowClassB, {
      name: 'Status',
      tags: STATUS_TAGS,
    });

    expect(second.subject).toBe(first.subject);
    // Each table gets Tags of its own for the shared property.
    expect(Object.keys(second.tags)).toEqual(Object.keys(first.tags));

    const refreshedOntology = await store.getResource(ontology.subject);
    const properties = (refreshedOntology.get(core.properties.properties) ??
      []) as string[];
    expect(
      properties.filter(subject => subject === first.subject),
    ).toHaveLength(1);

    const property = await store.getResource(first.subject);
    expect(property.get(core.properties.shortname)).toBe('status');
  });

  it('reuses an existing plain property instead of creating a duplicate shortname', async () => {
    const store = fakeStore();
    const { rowClassA, rowClassB } = await twoTablesOnOneOntology(store);

    const first = await createPropertyOnClass(store, rowClassA, {
      name: 'Priority',
      datatype: Datatype.INTEGER,
    });
    const second = await createPropertyOnClass(store, rowClassB, {
      name: 'Priority',
      datatype: Datatype.INTEGER,
    });

    expect(second).toBe(first);
  });

  it('disambiguates the shortname when an existing property is incompatible', async () => {
    const store = fakeStore();
    const { rowClassA, rowClassB } = await twoTablesOnOneOntology(store);

    await createPropertyOnClass(store, rowClassA, {
      name: 'Status',
      datatype: Datatype.INTEGER,
    });
    const select = await createSelectPropertyOnClass(store, rowClassB, {
      name: 'Status',
      tags: STATUS_TAGS,
    });

    const property = await store.getResource(select.subject);
    expect(property.get(core.properties.shortname)).toBe('status-2');
    expect(property.hasClasses(dataBrowser.classes.selectProperty)).toBe(true);
  });

  it('shares the property but gives each class its own options', async () => {
    const store = fakeStore();
    const { rowClassA, rowClassB } = await twoTablesOnOneOntology(store);

    const first = await createSelectPropertyOnClass(store, rowClassA, {
      name: 'Status',
      tags: STATUS_TAGS,
    });

    // A reading list's "Status" (Want to read / Reading) is the same property
    // as a task's, but the options are the class's, not the property's.
    const second = await createSelectPropertyOnClass(store, rowClassB, {
      name: 'Status',
      tags: [{ name: 'Todo' }, { name: 'Blocked' }],
    });

    expect(second.subject).toBe(first.subject);
    expect(Object.keys(second.tags).sort()).toEqual(['Blocked', 'Todo']);

    const constraintsOf = (klass: Resource) =>
      klass.get(core.properties.constraints) as Record<
        string,
        { enum: string[] }
      >;

    expect(constraintsOf(rowClassA)[first.subject].enum).toEqual(
      Object.values(first.tags),
    );
    expect(constraintsOf(rowClassB)[first.subject].enum).toEqual(
      Object.values(second.tags),
    );
  });

  it('writes options and a single pick to the class, not the property', async () => {
    const store = fakeStore();
    const { rowClassA } = await twoTablesOnOneOntology(store);

    const created = await createSelectPropertyOnClass(store, rowClassA, {
      name: 'Priority',
      tags: [{ name: 'Low' }, { name: 'High' }],
      max: 1,
    });
    const property = await store.getResource(created.subject);

    expect(property.get(core.properties.allowsOnly)).toEqual([]);
    expect(property.get(dataBrowser.properties.max)).toBeUndefined();
    expect(rowClassA.get(core.properties.constraints)).toEqual({
      [created.subject]: {
        enum: Object.values(created.tags),
        maxItems: 1,
      },
    });
  });

  it('keeps options on the property for forms (constraintsOn: property)', async () => {
    const store = fakeStore();
    const { rowClassA } = await twoTablesOnOneOntology(store);

    const created = await createSelectPropertyOnClass(store, rowClassA, {
      name: 'Choice',
      tags: [{ name: 'A' }, { name: 'B' }],
      max: 1,
      constraintsOn: 'property',
    });
    const property = await store.getResource(created.subject);

    expect(property.get(core.properties.allowsOnly)).toEqual(
      Object.values(created.tags),
    );
    expect(property.get(dataBrowser.properties.max)).toBe(1);
    expect(rowClassA.get(core.properties.constraints)).toBeUndefined();
  });

  it('writes the linked class of a plain column to the class map', async () => {
    const store = fakeStore();
    const { rowClassA } = await twoTablesOnOneOntology(store);

    const subject = await createPropertyOnClass(store, rowClassA, {
      name: 'Customer',
      datatype: Datatype.ATOMIC_URL,
      classtype: 'https://example.com/Customer',
    });
    const property = await store.getResource(subject);

    expect(property.get(core.properties.classtype)).toBeUndefined();
    expect(rowClassA.get(core.properties.constraints)).toEqual({
      [subject]: { class: 'https://example.com/Customer' },
    });
  });

  it('does not dedupe when the row classes have no shared ontology', async () => {
    const store = fakeStore();
    const drive = await store.newResource({});
    const rowClassA = await store.newResource({
      isA: core.classes.class,
      parent: drive.subject,
    });
    const rowClassB = await store.newResource({
      isA: core.classes.class,
      parent: drive.subject,
    });

    const first = await createPropertyOnClass(store, rowClassA, {
      name: 'Priority',
      datatype: Datatype.INTEGER,
    });
    const second = await createPropertyOnClass(store, rowClassB, {
      name: 'Priority',
      datatype: Datatype.INTEGER,
    });

    // No shared ontology to collide on — each class gets its own property.
    expect(second).not.toBe(first);
  });
});

describe('column properties are content-addressed', () => {
  it('creates plain and select properties with contentAddressedProperty', async () => {
    const store = fakeStore();
    const spy = vi.spyOn(store, 'newResource');
    const { rowClassA } = await twoTablesOnOneOntology(store);
    spy.mockClear();

    await createPropertyOnClass(store, rowClassA, {
      name: 'Title',
      datatype: Datatype.STRING,
    });
    await createSelectPropertyOnClass(store, rowClassA, {
      name: 'Status',
      tags: STATUS_TAGS,
    });

    const propertyCalls = spy.mock.calls.filter(([opts]) =>
      [opts?.isA].flat().includes(core.classes.property),
    );

    expect(propertyCalls).toHaveLength(2);
    expect(
      propertyCalls.every(([opts]) => opts?.contentAddressedProperty === true),
    ).toBe(true);
  });

  it('mints a new column under a disambiguated shortname when asked not to reuse', async () => {
    const store = fakeStore();
    const { rowClassA } = await twoTablesOnOneOntology(store);

    const first = await createPropertyOnClass(store, rowClassA, {
      name: 'Price',
      datatype: Datatype.STRING,
    });
    const second = await createPropertyOnClass(store, rowClassA, {
      name: 'Price',
      datatype: Datatype.STRING,
      reuse: false,
    });

    expect(second).not.toBe(first);
    expect(
      (await store.getResource(second)).get(core.properties.shortname),
    ).toBe('price-2');
  });
});

describe('option tags of a hosted property', () => {
  it('are not parented to a property this server does not host', async () => {
    const store = fakeStore();
    const parents: (string | undefined)[] = [];
    const subjects: (string | undefined)[] = [];
    const original = store.newResource;
    store.newResource = (async (opts: {
      subject?: string;
      parent?: string;
    }) => {
      parents.push(opts.parent);
      subjects.push(opts.subject);

      return original(opts as Parameters<typeof original>[0]);
    }) as typeof original;

    await createOptionTags(
      store as unknown as Store,
      'https://atomicdata.dev/task/v1/status',
      [{ name: 'Todo' }],
      'atomic:row-class',
    );

    // The server refuses a subject under a domain it does not own, and a child
    // of a resource the agent cannot append to.
    expect(parents).toEqual(['atomic:row-class']);
    expect(subjects).toEqual([undefined]);
  });
});
