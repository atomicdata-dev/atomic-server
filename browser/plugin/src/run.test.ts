import { describe, expect, it } from 'vitest';
import { hasBlockingProblems, parseVerdict } from './run.js';

const errors = (raw: unknown) =>
  parseVerdict(raw).problems.filter(p => p.severity === 'error');

describe('parseVerdict', () => {
  it('keeps a well formed verdict intact', () => {
    const verdict = parseVerdict({
      intents: [
        {
          op: 'create',
          localId: 'acme',
          parent: 'https://x/drive',
          isA: ['https://x/Organization'],
          set: { 'https://x/name': 'Acme' },
        },
        {
          op: 'set',
          subject: 'https://x/contact-1',
          set: { 'https://x/employer': 'local:acme' },
        },
      ],
      problems: [],
      cursor: 'page-2',
    });

    expect(verdict.problems).toEqual([]);
    expect(verdict.intents).toHaveLength(2);
    expect(verdict.cursor).toBe('page-2');
  });

  it('reports what run() returned when it is not an object', () => {
    for (const raw of [undefined, null, 'nope', 42, [1, 2]]) {
      expect(errors(raw)).toHaveLength(1);
      expect(parseVerdict(raw).intents).toEqual([]);
    }
  });

  it('treats a missing intents array as nothing to do, not an error', () => {
    expect(parseVerdict({ problems: [] })).toEqual({
      intents: [],
      problems: [],
    });
  });
});

describe('malformed intents', () => {
  const bad = (intent: unknown) => errors({ intents: [intent] });

  it('drops intents with an unknown op', () => {
    expect(bad({ op: 'yolo', subject: 'https://x/a' })).toHaveLength(1);
  });

  it('requires localId and parent on create', () => {
    expect(bad({ op: 'create', parent: 'https://x/d' })).toHaveLength(1);
    expect(bad({ op: 'create', localId: 'a' })).toHaveLength(1);
  });

  it('rejects a reused localId rather than guessing which one a ref means', () => {
    const problems = errors({
      intents: [
        { op: 'create', localId: 'dup', parent: 'https://x/d' },
        { op: 'create', localId: 'dup', parent: 'https://x/d' },
      ],
    });

    expect(problems).toHaveLength(1);
    expect(problems[0].message).toContain('dup');
  });

  it('requires a subject', () => {
    expect(bad({ op: 'set', set: { a: 1 } })).toHaveLength(1);
    expect(bad({ op: 'remove', properties: ['a'] })).toHaveLength(1);
    expect(bad({ op: 'destroy' })).toHaveLength(1);
  });

  it('requires remove to name at least one property', () => {
    expect(bad({ op: 'remove', subject: 'https://x/a' })).toHaveLength(1);
    expect(
      bad({ op: 'remove', subject: 'https://x/a', properties: [] }),
    ).toHaveLength(1);
  });

  it('rejects values that are not JSON', () => {
    expect(
      bad({ op: 'set', subject: 'https://x/a', set: { f: () => 1 } }),
    ).toHaveLength(1);
    expect(
      bad({ op: 'set', subject: 'https://x/a', set: { n: NaN } }),
    ).toHaveLength(1);
  });

  it('keeps the intents around a malformed one', () => {
    const verdict = parseVerdict({
      intents: [
        { op: 'destroy', subject: 'https://x/a' },
        { op: 'nonsense' },
        { op: 'destroy', subject: 'https://x/b' },
      ],
    });

    expect(verdict.intents).toHaveLength(2);
    expect(verdict.problems).toHaveLength(1);
  });
});

describe('optional properties', () => {
  it('drops undefined values so an absent column is not a malformed intent', () => {
    const verdict = parseVerdict({
      intents: [
        {
          op: 'set',
          subject: 'https://x/a',
          set: { 'https://x/name': 'Jo', 'https://x/email': undefined },
        },
      ],
    });

    expect(verdict.problems).toEqual([]);
    expect(verdict.intents[0]).toMatchObject({
      set: { 'https://x/name': 'Jo' },
    });
  });

  it('warns instead of committing a set that ended up empty', () => {
    const verdict = parseVerdict({
      intents: [{ op: 'set', subject: 'https://x/a', set: { e: undefined } }],
    });

    expect(verdict.intents).toEqual([]);
    expect(verdict.problems).toEqual([
      expect.objectContaining({ severity: 'warning', subject: 'https://x/a' }),
    ]);
    expect(hasBlockingProblems(verdict)).toBe(false);
  });
});

describe('local references', () => {
  it('finds references nested in arrays and objects', () => {
    const verdict = parseVerdict({
      intents: [
        {
          op: 'set',
          subject: 'https://x/a',
          set: { tags: [{ to: 'local:missing' }] },
        },
      ],
    });

    expect(verdict.intents).toEqual([]);
    expect(verdict.problems[0].message).toContain('local:missing');
  });

  it('accepts a create whose parent is another create', () => {
    const verdict = parseVerdict({
      intents: [
        { op: 'create', localId: 'folder', parent: 'https://x/drive' },
        { op: 'create', localId: 'child', parent: 'local:folder' },
      ],
    });

    expect(verdict.problems).toEqual([]);
    expect(verdict.intents).toHaveLength(2);
  });

  it('does not care whether the referenced create comes first', () => {
    const verdict = parseVerdict({
      intents: [
        { op: 'set', subject: 'https://x/a', set: { link: 'local:later' } },
        { op: 'create', localId: 'later', parent: 'https://x/drive' },
      ],
    });

    expect(verdict.problems).toEqual([]);
    expect(verdict.intents).toHaveLength(2);
  });
});

describe('limits', () => {
  it('refuses the whole batch rather than silently planning a prefix', () => {
    const intents = Array.from({ length: 5 }, (_, i) => ({
      op: 'destroy',
      subject: `https://x/${i}`,
    }));

    const verdict = parseVerdict({ intents }, { maxIntents: 3 });

    expect(verdict.intents).toEqual([]);
    expect(verdict.problems).toHaveLength(1);
    expect(verdict.problems[0].message).toContain('5');
    expect(verdict.problems[0].message).toContain('3');
  });
});

describe('problems reported by the plugin', () => {
  it('defaults to error so a validator is not downgraded by a typo', () => {
    const verdict = parseVerdict({
      problems: [
        { message: 'name is required' },
        { message: 'x', severity: 'nope' },
      ],
    });

    expect(verdict.problems.every(p => p.severity === 'error')).toBe(true);
    expect(hasBlockingProblems(verdict)).toBe(true);
  });

  it('passes warnings through without blocking', () => {
    const verdict = parseVerdict({
      problems: [
        {
          severity: 'warning',
          message: 'row 4 had no date',
          subject: 'https://x/a',
          property: 'https://x/date',
        },
      ],
    });

    expect(hasBlockingProblems(verdict)).toBe(false);
    expect(verdict.problems[0]).toMatchObject({
      subject: 'https://x/a',
      property: 'https://x/date',
    });
  });

  it('reports entries that are not problems', () => {
    expect(errors({ problems: ['just a string'] })).toHaveLength(1);
    expect(errors({ problems: 'not an array' })).toHaveLength(1);
  });
});

describe('cursor', () => {
  it('rejects a non-string cursor rather than persisting garbage', () => {
    const verdict = parseVerdict({ cursor: { page: 2 } });

    expect(verdict.cursor).toBeUndefined();
    expect(verdict.problems).toHaveLength(1);
  });

  it('treats a null cursor as absent', () => {
    expect(parseVerdict({ cursor: null }).problems).toEqual([]);
  });
});
