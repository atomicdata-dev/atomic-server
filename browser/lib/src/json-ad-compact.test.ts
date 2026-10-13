import { describe, expect, it } from 'vitest';
import { Datatype } from './datatypes.js';
import {
  addPropertyToContext,
  coerceValueIn,
  compactValueOut,
  createEmptyContext,
  describeClassCompact,
  resolveKey,
  type ClassContext,
  type CompactPropertyInfo,
} from './json-ad-compact.js';

const statusProperty: CompactPropertyInfo = {
  subject: 'https://example.com/props/status',
  shortname: 'status',
  name: 'Status',
  datatype: Datatype.RESOURCEARRAY,
  classtype: 'https://atomicdata.dev/classes/Tag',
  tags: {
    Lead: 'https://example.com/tags/lead',
    Qualified: 'https://example.com/tags/qualified',
  },
  tagNames: {
    'https://example.com/tags/lead': 'Lead',
    'https://example.com/tags/qualified': 'Qualified',
  },
};

const dueDateProperty: CompactPropertyInfo = {
  subject: 'https://example.com/props/due-date',
  shortname: 'due-date',
  name: 'Due date',
  datatype: Datatype.TIMESTAMP,
};

const valueProperty: CompactPropertyInfo = {
  subject: 'https://example.com/props/value',
  shortname: 'value',
  datatype: Datatype.INTEGER,
};

const buildContext = (): ClassContext => {
  const ctx = createEmptyContext();
  addPropertyToContext(ctx, statusProperty);
  addPropertyToContext(ctx, dueDateProperty);
  addPropertyToContext(ctx, valueProperty);

  return ctx;
};

describe('resolveKey', () => {
  it('resolves shortnames case-insensitively', () => {
    const ctx = buildContext();
    expect(resolveKey(ctx, 'Status').subject).toBe(statusProperty.subject);
    expect(resolveKey(ctx, 'status').subject).toBe(statusProperty.subject);
  });

  it('resolves display names', () => {
    const ctx = buildContext();
    expect(resolveKey(ctx, 'Due date').subject).toBe(dueDateProperty.subject);
  });

  it('passes full URLs through without requiring context', () => {
    const ctx = buildContext();
    expect(resolveKey(ctx, 'https://example.com/props/unknown').subject).toBe(
      'https://example.com/props/unknown',
    );
  });

  it('throws on unknown shortnames, listing available properties', () => {
    const ctx = buildContext();
    expect(() => resolveKey(ctx, 'nonexistent')).toThrow(/status/);
  });

  it('throws on ambiguous shortnames, listing candidates', () => {
    const ctx = buildContext();
    addPropertyToContext(ctx, {
      subject: 'https://example.com/props/other-status',
      shortname: 'other-status',
      name: 'Status',
      datatype: Datatype.STRING,
    });
    expect(() => resolveKey(ctx, 'Status')).toThrow(/Ambiguous/);
  });
});

describe('coerceValueIn', () => {
  it('maps tag names to subjects and wraps single values', () => {
    expect(coerceValueIn(statusProperty, 'Lead')).toEqual([
      'https://example.com/tags/lead',
    ]);
  });

  it('accepts tag subjects directly', () => {
    expect(
      coerceValueIn(statusProperty, ['https://example.com/tags/qualified']),
    ).toEqual(['https://example.com/tags/qualified']);
  });

  it('throws on unknown tag names, listing allowed tags', () => {
    expect(() => coerceValueIn(statusProperty, 'Wat')).toThrow(/Lead/);
  });

  it('parses ISO strings into millisecond timestamps', () => {
    expect(coerceValueIn(dueDateProperty, '2026-07-08T00:00:00.000Z')).toBe(
      Date.parse('2026-07-08T00:00:00.000Z'),
    );
  });

  it('rejects unparseable timestamps', () => {
    expect(() => coerceValueIn(dueDateProperty, 'tomorrow-ish')).toThrow(
      /timestamp/,
    );
  });

  it('parses numeric strings for number datatypes', () => {
    expect(coerceValueIn(valueProperty, '50000')).toBe(50000);
  });
});

describe('compactValueOut', () => {
  it('maps tag subjects back to names', () => {
    expect(
      compactValueOut(statusProperty, ['https://example.com/tags/lead']),
    ).toEqual(['Lead']);
  });

  it('renders timestamps as ISO strings', () => {
    const ms = Date.parse('2026-07-08T00:00:00.000Z');
    expect(compactValueOut(dueDateProperty, ms)).toBe(
      '2026-07-08T00:00:00.000Z',
    );
  });
});

describe('describeClassCompact', () => {
  it('renders a one-line signature with tags and datatypes', () => {
    const ctx = buildContext();
    ctx.classNames.set('https://example.com/classes/deal', 'deal');
    const line = describeClassCompact(ctx, 'https://example.com/classes/deal');
    expect(line).toContain('deal:');
    expect(line).toContain('status(Lead|Qualified)');
    expect(line).toContain('due-date [timestamp]');
    expect(line).toContain('value [integer]');
  });
});
