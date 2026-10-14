import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  checkResourceConstraints,
  checkValue,
  constraintViolations,
  ConstraintError,
  parseConstraint,
  parseConstraints,
} from './class-constraints.js';

interface FixtureCase {
  constraint: Record<string, unknown>;
  value: unknown;
  valid: boolean;
  rule?: string;
  /** JSON pointer of the failing value, when the case pins it. */
  path?: string;
  /** The constraint itself must be refused by the parser. */
  rejected?: boolean;
}

const cases = JSON.parse(
  readFileSync(
    new URL(
      '../../../lib/tests/fixtures/class-constraints.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as FixtureCase[];

describe('class constraints fixture', () => {
  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(50);
  });

  it.each(cases.map((c, i) => [i, c] as const))('case %i', (_i, c) => {
    if (c.rejected) {
      expect(() => parseConstraint(c.constraint)).toThrow();

      return;
    }

    const constraint = parseConstraint(c.constraint);

    if (c.valid) {
      expect(() => checkValue(constraint, c.value)).not.toThrow();

      return;
    }

    try {
      checkValue(constraint, c.value);
      expect.fail('expected a ConstraintError');
    } catch (e) {
      expect(e).toBeInstanceOf(ConstraintError);
      expect((e as ConstraintError).keyword).toBe(c.rule);

      if (c.path !== undefined)
        expect((e as ConstraintError).path).toBe(c.path);
    }
  });
});

describe('parseConstraints', () => {
  it.each([
    { p: { minimun: 1 } },
    { p: { minimum: '1' } },
    { p: { minLength: -1 } },
    { p: { enum: 'a' } },
    { p: { pattern: '(' } },
    { p: { class: 1 } },
    { p: 1 },
    [],
  ])('rejects %j', bad => {
    expect(() => parseConstraints(bad)).toThrow();
  });

  it('canonicalizes property keys and accepts a JSON string', () => {
    const map = parseConstraints('{"did:ad:prop:x":{"maxItems":1}}');

    expect(map.has('atomic:prop:x')).toBe(true);
  });
});

describe('checkResourceConstraints', () => {
  const classSubject = 'https://example.com/Task';
  const nameProp = 'https://atomicdata.dev/properties/name';
  const store = new Map<string, Record<string, unknown>>([
    [
      classSubject,
      {
        'https://atomicdata.dev/properties/shortname': 'task',
        'https://atomicdata.dev/properties/constraints': {
          [nameProp]: { maxLength: 3 },
        },
      },
    ],
    [nameProp, { 'https://atomicdata.dev/properties/shortname': 'name' }],
  ]);

  const getLocal = (subject: string) => {
    const props = store.get(subject);

    return (
      props && { subject, getClasses: () => [], get: (p: string) => props[p] }
    );
  };

  const instance = (name: string, classes = [classSubject]) => ({
    subject: 'https://example.com/t1',
    getClasses: () => classes,
    get: (p: string) => (p === nameProp ? name : undefined),
  });

  it('passes and fails with the documented message', () => {
    expect(() =>
      checkResourceConstraints(instance('abc'), getLocal),
    ).not.toThrow();
    expect(() => checkResourceConstraints(instance('abcd'), getLocal)).toThrow(
      /^Value for name breaks maxLength on class task: /,
    );
  });

  it('names the nested path in the message', () => {
    const nested = new Map(store);

    nested.set(classSubject, {
      'https://atomicdata.dev/properties/shortname': 'task',
      'https://atomicdata.dev/properties/constraints': {
        [nameProp]: {
          type: 'object',
          properties: { tune: { type: 'number', maximum: 24 } },
        },
      },
    });

    const getNested = (subject: string) => {
      const props = nested.get(subject);

      return (
        props && { subject, getClasses: () => [], get: (p: string) => props[p] }
      );
    };

    const withValue = (value: unknown) => ({
      subject: 'https://example.com/t1',
      getClasses: () => [classSubject],
      get: (p: string) => (p === nameProp ? value : undefined),
    });

    expect(() =>
      checkResourceConstraints(withValue({ tune: 24 }), getNested),
    ).not.toThrow();
    expect(() =>
      checkResourceConstraints(withValue({ tune: 25 }), getNested),
    ).toThrow(/^Value for name breaks maximum on class task at \/tune: /);
  });

  it('skips classes that are not loaded', () => {
    expect(() =>
      checkResourceConstraints(
        instance('abcd', ['https://example.com/Other']),
        getLocal,
      ),
    ).not.toThrow();
  });

  it('reports every violation, none for a valid or unknown-class resource', () => {
    const descProp = 'https://atomicdata.dev/properties/description';
    const two = new Map(store);

    two.set(classSubject, {
      'https://atomicdata.dev/properties/shortname': 'task',
      'https://atomicdata.dev/properties/constraints': {
        [nameProp]: { maxLength: 3 },
        [descProp]: { maxLength: 5 },
      },
    });

    const getTwo = (subject: string) => {
      const props = two.get(subject);

      return (
        props && { subject, getClasses: () => [], get: (p: string) => props[p] }
      );
    };

    const withProps = (
      name: string,
      description: string,
      classes = [classSubject],
    ) => ({
      subject: 'https://example.com/t1',
      getClasses: () => classes,
      get: (p: string) =>
        p === nameProp ? name : p === descProp ? description : undefined,
    });

    expect(constraintViolations(getTwo, withProps('abc', 'short'))).toEqual([]);

    const found = constraintViolations(getTwo, withProps('abcd', 'too long'));

    expect(found.map(v => [v.property, v.keyword, v.classSubject])).toEqual([
      [nameProp, 'maxLength', classSubject],
      [descProp, 'maxLength', classSubject],
    ]);
    expect(found[0].message).toMatch(
      /^Value for name breaks maxLength on class task: /,
    );
    expect(() =>
      checkResourceConstraints(withProps('abcd', 'too long'), getTwo),
    ).toThrow(found[0].message);
    expect(
      constraintViolations(
        getTwo,
        withProps('abcdefgh', 'too long', ['https://example.com/Missing']),
      ),
    ).toEqual([]);
  });
});
