import { describe, expect, it } from 'vitest';
import {
  getEffectiveConstraint,
  setClassConstraint,
} from './effective-constraint.js';
import { Resource } from './resource.js';
import type { Store } from './store.js';

const P = 'https://atomicdata.dev/properties/';
const status = 'atomic:prop:status';
const other = 'atomic:prop:other';

function fakeStore(
  resources: Record<string, Record<string, unknown>>,
): Pick<Store, 'getResourceLoading'> {
  return {
    getResourceLoading: (subject: string) => {
      const props = resources[subject] ?? {};

      return {
        isReady: () => subject in resources,
        get: (p: string) => props[p],
      };
    },
  } as unknown as Pick<Store, 'getResourceLoading'>;
}

describe('getEffectiveConstraint', () => {
  it('reads the class map', () => {
    const store = fakeStore({
      'https://x/Task': {
        [`${P}constraints`]: { [status]: { enum: ['a', 'b'], maxItems: 1 } },
      },
      [status]: {},
    });

    expect(getEffectiveConstraint(store, ['https://x/Task'], status)).toEqual({
      enum: ['a', 'b'],
      maxItems: 1,
    });
  });

  it('falls back per keyword to the legacy property, class map wins', () => {
    const store = fakeStore({
      'https://x/Task': {
        [`${P}constraints`]: { [status]: { enum: ['a'] } },
      },
      [status]: {
        [`${P}allowsOnly`]: ['legacy'],
        [`${P}classtype`]: 'https://x/Tag',
        [`${P}datatype`]: 'https://atomicdata.dev/datatypes/resourceArray',
        [`${P}max`]: 1,
      },
    });

    expect(getEffectiveConstraint(store, ['https://x/Task'], status)).toEqual({
      enum: ['a'],
      class: 'https://x/Tag',
      maxItems: 1,
    });
  });

  it('maps legacy min and max by datatype', () => {
    const store = fakeStore({
      n: {
        [`${P}datatype`]: 'https://atomicdata.dev/datatypes/integer',
        [`${P}min`]: 1,
        [`${P}max`]: 5,
      },
      t: {
        [`${P}datatype`]: 'https://atomicdata.dev/datatypes/string',
        [`${P}max`]: 5,
      },
    });

    expect(getEffectiveConstraint(store, [], 'n')).toEqual({
      minimum: 1,
      maximum: 5,
    });
    expect(getEffectiveConstraint(store, [], 't')).toEqual({ maxLength: 5 });
  });

  it('tightens across classes', () => {
    const store = fakeStore({
      A: {
        [`${P}constraints`]: {
          [status]: { enum: ['a', 'b'], maximum: 10, minimum: 1 },
        },
      },
      B: {
        [`${P}constraints`]: {
          [status]: { enum: ['b', 'c'], maximum: 5, minimum: 2 },
        },
      },
      [status]: {},
    });

    expect(getEffectiveConstraint(store, ['A', 'B'], status)).toEqual({
      enum: ['b'],
      maximum: 5,
      minimum: 2,
    });
  });

  it('ignores classes that are not loaded or do not parse', () => {
    const store = fakeStore({
      Bad: { [`${P}constraints`]: { [status]: { nope: 1 } } },
      [status]: { [`${P}classtype`]: 'https://x/Tag' },
    });

    expect(getEffectiveConstraint(store, ['Missing', 'Bad'], status)).toEqual({
      class: 'https://x/Tag',
    });
  });
});

describe('setClassConstraint', () => {
  const read = (r: Resource) => r.get(`${P}constraints`);

  it('merges keywords, removes undefined ones and empty entries', async () => {
    const klass = new Resource('https://x/Task');

    await setClassConstraint(klass, status, { enum: ['a'], maxItems: 1 });
    expect(read(klass)).toEqual({ [status]: { enum: ['a'], maxItems: 1 } });

    await setClassConstraint(klass, status, {
      maxItems: undefined,
      minimum: 2,
    });
    expect(read(klass)).toEqual({ [status]: { enum: ['a'], minimum: 2 } });

    await setClassConstraint(klass, other, { pattern: '^a' });
    expect(read(klass)).toEqual({
      [status]: { enum: ['a'], minimum: 2 },
      [other]: { pattern: '^a' },
    });

    await setClassConstraint(klass, status, {
      enum: undefined,
      minimum: undefined,
    });
    expect(read(klass)).toEqual({ [other]: { pattern: '^a' } });

    await setClassConstraint(klass, other, undefined);
    expect(read(klass)).toBeUndefined();
  });

  it('rejects invalid patches without touching the class', async () => {
    const klass = new Resource('https://x/Task');
    await setClassConstraint(klass, status, { maxItems: 1 });

    await expect(
      setClassConstraint(klass, status, { maxItems: -1 }),
    ).rejects.toThrow();
    expect(read(klass)).toEqual({ [status]: { maxItems: 1 } });
  });

  it('folds did:ad: keys into the canonical one', async () => {
    const klass = new Resource('https://x/Task');
    await klass.set(
      `${P}constraints`,
      { 'did:ad:prop:status': { maxItems: 1 } },
      false,
    );
    await setClassConstraint(klass, status, { minItems: 1 });

    expect(read(klass)).toEqual({ [status]: { maxItems: 1, minItems: 1 } });
  });
});
