import { describe, expect, it } from 'vitest';
import {
  DRAFT_KEY_PREFIX,
  DRAFT_TTL_MS,
  DRAFT_VERSION,
  decodeDraft,
  draftKey,
  encodeDraft,
  readDraft,
  removeDraft,
  writeDraft,
  type StoredDraft,
} from './draft.js';
import type { FieldType, FormDefinition } from './types.js';

const NAME = 'https://example.com/properties/name';
const AGE = 'https://example.com/properties/age';

function definition(
  fields: Array<{ mapsTo: string; type: FieldType }> = [
    { mapsTo: NAME, type: 'short-text' },
    { mapsTo: AGE, type: 'number' },
  ],
  pageCount = 1,
): FormDefinition {
  const blocks = fields.map(({ mapsTo, type }) => ({
    kind: 'field' as const,
    mapsTo,
    label: mapsTo,
    type,
    required: false,
    options: {},
  }));

  return {
    version: 1,
    id: 'abc123',
    name: 'Test form',
    settings: {},
    styling: {},
    honeypotField: 'hp',
    // Every field on the first page; later pages exist only so the
    // pageIndex clamp has something to clamp against.
    pages: Array.from({ length: pageCount }, (_, i) => ({
      blocks: i === 0 ? blocks : [],
    })),
  };
}

/** In-memory stand-in for `localStorage`, so these run under vitest's node
 * environment. `throwOn` simulates the browsers that refuse storage. */
function fakeStorage(throwOn?: 'get' | 'set' | 'remove'): Storage {
  const map = new Map<string, string>();

  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    key: (i: number) => [...map.keys()][i] ?? null,
    getItem: (k: string) => {
      if (throwOn === 'get') throw new Error('blocked');

      return map.get(k) ?? null;
    },
    setItem: (k: string, v: string) => {
      if (throwOn === 'set') throw new Error('quota');

      map.set(k, v);
    },
    removeItem: (k: string) => {
      if (throwOn === 'remove') throw new Error('blocked');

      map.delete(k);
    },
  } as Storage;
}

describe('draftKey', () => {
  it('namespaces by form id', () => {
    expect(draftKey('abc123')).toBe(`${DRAFT_KEY_PREFIX}abc123`);
  });

  it('scopes invite codes apart, so one private link never resumes another', () => {
    expect(draftKey('abc123', 'CODE1')).not.toBe(draftKey('abc123', 'CODE2'));
    expect(draftKey('abc123', 'CODE1')).toBe(`${DRAFT_KEY_PREFIX}abc123:CODE1`);
  });
});

describe('encodeDraft', () => {
  it('stores answered values with the type they were answered as', () => {
    const raw = encodeDraft(definition(), { [NAME]: 'Ada' }, 0, 1000);
    const parsed = JSON.parse(raw!) as StoredDraft;

    expect(parsed).toEqual({
      v: DRAFT_VERSION,
      savedAt: 1000,
      pageIndex: 0,
      types: { [NAME]: 'short-text' },
      values: { [NAME]: 'Ada' },
    });
  });

  it('is undefined when nothing has been answered', () => {
    expect(encodeDraft(definition(), {}, 0)).toBeUndefined();
    // Empty strings/arrays/objects are "unanswered", same as in conditions.
    expect(
      encodeDraft(definition(), { [NAME]: '', [AGE]: undefined }, 0),
    ).toBeUndefined();
  });

  it('drops values for questions the form no longer has', () => {
    const raw = encodeDraft(
      definition([{ mapsTo: NAME, type: 'short-text' }]),
      { [NAME]: 'Ada', [AGE]: 36 },
      0,
    );

    expect(JSON.parse(raw!).values).toEqual({ [NAME]: 'Ada' });
  });
});

describe('decodeDraft', () => {
  const roundTrip = (
    def: FormDefinition,
    values: Record<string, unknown>,
    pageIndex = 0,
    savedAt = 1000,
    now = 1000,
    readWith = def,
  ) => decodeDraft(encodeDraft(def, values, pageIndex, savedAt), readWith, now);

  it('round-trips answers and the page the visitor was on', () => {
    expect(roundTrip(definition(undefined, 3), { [NAME]: 'Ada' }, 2)).toEqual({
      values: { [NAME]: 'Ada' },
      pageIndex: 2,
      savedAt: 1000,
    });
  });

  it('ignores anything unparseable, empty or foreign', () => {
    const def = definition();
    expect(decodeDraft(undefined, def)).toBeUndefined();
    expect(decodeDraft('', def)).toBeUndefined();
    expect(decodeDraft('not json', def)).toBeUndefined();
    expect(decodeDraft('null', def)).toBeUndefined();
    expect(decodeDraft('[1,2]', def)).toBeUndefined();
    expect(decodeDraft(JSON.stringify({ v: 99 }), def)).toBeUndefined();
  });

  it('expires after the TTL', () => {
    const def = definition();
    const values = { [NAME]: 'Ada' };

    expect(roundTrip(def, values, 0, 0, DRAFT_TTL_MS)).toBeDefined();
    expect(roundTrip(def, values, 0, 0, DRAFT_TTL_MS + 1)).toBeUndefined();
  });

  it('drops a value whose question was retyped since', () => {
    // Saved while `age` was a text question, read back after it became a
    // number one: the stored string would not render in a number input.
    const saved = definition([{ mapsTo: AGE, type: 'short-text' }]);
    const now = definition([{ mapsTo: AGE, type: 'number' }]);

    expect(roundTrip(saved, { [AGE]: 'thirty' }, 0, 1000, 1000, now)).toBe(
      undefined,
    );
  });

  it('keeps the still-valid answers when one question changed', () => {
    const saved = definition([
      { mapsTo: NAME, type: 'short-text' },
      { mapsTo: AGE, type: 'short-text' },
    ]);
    const now = definition([
      { mapsTo: NAME, type: 'short-text' },
      { mapsTo: AGE, type: 'number' },
    ]);

    expect(
      roundTrip(saved, { [NAME]: 'Ada', [AGE]: 'thirty' }, 0, 1000, 1000, now)
        ?.values,
    ).toEqual({ [NAME]: 'Ada' });
  });

  it('clamps a page index the form no longer reaches', () => {
    const saved = definition(undefined, 5);
    const now = definition(undefined, 2);

    expect(
      roundTrip(saved, { [NAME]: 'Ada' }, 4, 1000, 1000, now)?.pageIndex,
    ).toBe(1);
  });
});

describe('storage wrappers', () => {
  it('write, read back, and remove', () => {
    const storage = fakeStorage();
    const def = definition();
    const key = draftKey('abc123');

    writeDraft(storage, key, def, { [NAME]: 'Ada' }, 0);
    expect(readDraft(storage, key, def)?.values).toEqual({ [NAME]: 'Ada' });

    removeDraft(storage, key);
    expect(readDraft(storage, key, def)).toBeUndefined();
  });

  it('removes rather than writing an empty draft', () => {
    const storage = fakeStorage();
    const def = definition();
    const key = draftKey('abc123');

    writeDraft(storage, key, def, { [NAME]: 'Ada' }, 0);
    // What "Start over" (and clearing the last field) does.
    writeDraft(storage, key, def, {}, 0);

    expect(storage.getItem(key)).toBeNull();
  });

  it('is inert when storage is unavailable or refuses', () => {
    const def = definition();
    const key = draftKey('abc123');

    expect(() =>
      writeDraft(undefined, key, def, { [NAME]: 'a' }, 0),
    ).not.toThrow();
    expect(readDraft(undefined, key, def)).toBeUndefined();
    expect(() => removeDraft(undefined, key)).not.toThrow();

    expect(() =>
      writeDraft(fakeStorage('set'), key, def, { [NAME]: 'a' }, 0),
    ).not.toThrow();
    expect(readDraft(fakeStorage('get'), key, def)).toBeUndefined();
    expect(() => removeDraft(fakeStorage('remove'), key)).not.toThrow();
  });
});
