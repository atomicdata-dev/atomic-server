import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import { testStore } from './test-store.js';
import { core } from './ontologies/core.js';
import { Datatype } from './datatypes.js';
import { ensureLens } from './lens-ensure.js';
import {
  LensIndex,
  isLensId,
  lensId,
  parseTransform,
  verifyLensId,
} from './lens.js';
import type { JSONValue } from './value.js';

interface FixtureCase {
  name: string;
  lenses: { from: string; to: string; transform: unknown }[];
  doc: Record<string, JSONValue>;
  expected: Record<string, JSONValue>;
}

const { cases } = JSON.parse(
  readFileSync(
    new URL('../../../lib/tests/fixtures/lenses.json', import.meta.url),
    'utf8',
  ),
) as { cases: FixtureCase[] };

describe('lenses fixture (shared with atomic_lib)', () => {
  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(25);
  });

  it.each(cases.map(c => [c.name, c] as const))('%s', (_name, c) => {
    const index = new LensIndex();

    c.lenses.forEach((lens, n) =>
      index.insert({
        id: `atomic:lens:${String(n).padStart(64, '0')}`,
        from: lens.from,
        to: lens.to,
        transform: parseTransform(lens.transform),
        parent: 'atomic:ontology',
      }),
    );

    const cache = structuredClone(c.doc);

    index.apply(cache);

    expect(cache).toEqual(c.expected);
  });
});

const A = `atomic:prop:${'a'.repeat(64)}`;
const B = `atomic:prop:${'b'.repeat(64)}`;

describe('lens identity', () => {
  it.each([
    [
      A,
      B,
      { op: 'rename' },
      'ba1b06696c9786de8f0b78189d69c3aa84d59181b8eba91b7678de5959d07fcb',
    ],
    [
      A.replace('atomic:', 'did:ad:'),
      B,
      { op: 'rename' },
      'ba1b06696c9786de8f0b78189d69c3aa84d59181b8eba91b7678de5959d07fcb',
    ],
    [
      A,
      B,
      { op: 'wrap' },
      '0e8670cccd962e1352793444a88fb841c27c39b7e74bce6b58fafbaea1056825',
    ],
    [
      A,
      B,
      { op: 'map', values: { todo: 'open', done: 'closed' } },
      'cfbe882e5669613c8eed6dfdcaaeda204b2a5dd4d264528875911d394d2d80a5',
    ],
    [
      A,
      B,
      { op: 'convert', to: Datatype.INTEGER },
      '0201a75d08b29edddb2131fd8143349db2f8f1a3a2ab2d605a0aea9ba9262170',
    ],
  ])('matches the spec vector %#', (from, to, transform, hex) => {
    expect(lensId(from, to, transform)).toBe(`atomic:lens:${hex}`);
  });

  it('verifies both prefixes and rejects a mismatch', () => {
    const id = lensId(A, B, { op: 'rename' });

    expect(isLensId(id)).toBe(true);
    expect(verifyLensId(id, A, B, { op: 'rename' })).toBe(true);
    expect(
      verifyLensId(id.replace('atomic:', 'did:ad:'), A, B, { op: 'rename' }),
    ).toBe(true);
    expect(verifyLensId(id, B, A, { op: 'rename' })).toBe(false);
    expect(verifyLensId(id, A, B, { op: 'wrap' })).toBe(false);
    expect(isLensId('atomic:lens:')).toBe(false);
  });

  it('rejects bad input', () => {
    expect(() => lensId(A, A, { op: 'rename' })).toThrow();
    expect(() => lensId('', B, { op: 'rename' })).toThrow();
    expect(() => lensId(A, B, { op: 'teleport' })).toThrow();
    expect(() => lensId(A, B, { op: 'rename', extra: 1 })).toThrow();
    expect(() => lensId(A, B, { op: 'convert' })).toThrow();
    expect(() => lensId(A, B, { op: 'map', values: { a: 1 } })).toThrow();
  });
});

describe('lenses in a store', () => {
  const STRING = Datatype.STRING;
  const ONTOLOGY = 'atomic:ontologyGenesis';

  async function twoProperties(
    store: Awaited<ReturnType<typeof testStore>>['store'],
  ) {
    const make = (shortname: string) =>
      store.newResource({
        isA: core.classes.property,
        parent: ONTOLOGY,
        propVals: {
          [core.properties.shortname]: shortname,
          [core.properties.datatype]: STRING,
        },
        contentAddressedProperty: true,
      });

    return [(await make('title')).subject, (await make('name')).subject];
  }

  it('derives values when a lens arrives, and real values win', async () => {
    const { store } = await testStore();
    const [title, name] = await twoProperties(store);

    const doc = await store.newResource({ isA: core.classes.property });

    await doc.set(title, 'Hello', false, undefined);
    expect(doc.get(name)).toBeUndefined();

    const lens = await ensureLens(store, {
      from: title,
      to: name,
      transform: { op: 'rename' },
    });

    expect(lens.subject).toBe(lensId(title, name, { op: 'rename' }));
    expect(lens.get(core.properties.parent)).toBe(ONTOLOGY);
    await vi_waitFor(() => store.lenses.size === 1);

    // The loaded resource follows without a reload.
    expect(doc.get(name)).toBe('Hello');

    // An edit of the old property moves the derived value.
    await doc.set(title, 'Hi', false, undefined);
    expect(doc.get(name)).toBe('Hi');

    // A real value of the new property wins.
    await doc.set(name, 'Real', false, undefined);
    await doc.set(title, 'Again', false, undefined);
    expect(doc.get(name)).toBe('Real');
    expect(doc.get(title)).toBe('Again');
  });

  it('ignores a lens whose parent does not own its target', async () => {
    const { store } = await testStore();
    const [title, name] = await twoProperties(store);
    const transform = { op: 'rename' };
    const lens = await store.newResource({
      isA: core.classes.lens,
      parent: 'atomic:someoneelse',
      propVals: {
        [core.properties.lensFrom]: title,
        [core.properties.lensTo]: name,
        [core.properties.lensTransform]: transform,
      },
      contentAddressedLens: true,
    });

    await lens.save();
    await new Promise(r => setTimeout(r, 20));

    expect(store.lenses.size).toBe(0);
  });

  it('ensureLens returns the same lens twice', async () => {
    const { store } = await testStore();
    const [title, name] = await twoProperties(store);
    const input = { from: title, to: name, transform: { op: 'wrap' as const } };
    const first = await ensureLens(store, input);
    const second = await ensureLens(store, input);

    expect(second.subject).toBe(first.subject);
  });
});

async function vi_waitFor(check: () => boolean): Promise<void> {
  for (let i = 0; i < 100; i++) {
    if (check()) return;

    await new Promise(r => setTimeout(r, 10));
  }

  throw new Error('condition never became true');
}
