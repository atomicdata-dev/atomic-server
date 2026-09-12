import {
  reviewImportResolution,
  IMPORT_RESOLUTION,
} from './import-resolution.js';
import { describe, it, expect } from 'vitest';
import {
  importRecords,
  claimImportIdentity,
  resolveImportConflict,
  IMPORT_BASELINE,
  IMPORT_LOCAL_ID,
  type ImportRecord,
} from './import-records.js';
const parent = 'https://test/table',
  klass = 'https://test/row',
  name = 'https://test/name';
const row: ImportRecord = {
  localId: 'row',
  sourceId: 'provider:1',
  parent,
  isA: [klass],
  values: { [name]: 'Source' },
};
const host = (saved: Record<string, Record<string, unknown>> = {}) => ({
  query: (property: string, value: string) =>
    Object.keys(saved).filter(key => saved[key][property] === value),
  read: (subject: string) => saved[subject],
});
const savedRow = (value = 'Source', source = 'Source') => ({
  'https://atomicdata.dev/properties/parent': parent,
  'https://atomicdata.dev/properties/isA': [klass],
  [IMPORT_LOCAL_ID]: row.sourceId,
  [name]: value,
  [IMPORT_BASELINE]: { values: { [name]: source }, previous: {} },
});
describe('shared import records', () => {
  it('persists native localId and a signed source baseline', () => {
    expect(importRecords(host(), [row]).intents[0]).toMatchObject({
      op: 'create',
      set: {
        [IMPORT_LOCAL_ID]: row.sourceId,
        [IMPORT_BASELINE]: { values: row.values, previous: {} },
      },
    });
  });
  it('skips identical imports and preserves local edits when source is unchanged', () => {
    for (const value of ['Source', 'Local'])
      expect(
        importRecords(host({ existing: savedRow(value) }), [row]).summary
          .unchanged,
      ).toBe(1);
  });
  it('updates clean records and blocks divergent edits', () => {
    const changed = { ...row, values: { [name]: 'Updated' } };
    expect(
      importRecords(host({ existing: savedRow() }), [changed]).intents[0],
    ).toMatchObject({ op: 'set', set: { [name]: 'Updated' } });
    expect(
      importRecords(host({ existing: savedRow('Local') }), [changed])
        .problems[0].severity,
    ).toBe('error');
  });
  it('rejects changed append-only source even when a local edit matches it', () => {
    expect(
      importRecords(host({ existing: savedRow('Updated') }), [
        { ...row, mode: 'append', values: { [name]: 'Updated' } },
      ]).problems,
    ).toHaveLength(1);
  });
  it('scopes identities to the immediate parent and rejects ambiguous matches', () => {
    expect(
      importRecords(
        host({
          existing: {
            ...savedRow(),
            'https://atomicdata.dev/properties/parent': 'https://test/other',
          },
        }),
        [row],
      ).summary.created,
    ).toBe(1);
    const collision = importRecords(
      host({ first: savedRow(), second: savedRow() }),
      [row],
    );
    expect(collision.intents).toEqual([]);
    expect(collision.problems[0].importCollision).toEqual(['first', 'second']);
    expect(
      importRecords(
        host({ second: savedRow('Other local edit'), first: savedRow() }),
        [row],
      ).problems[0].importCollision,
    ).toEqual(['first', 'second']);
  });
  it('updates only the reviewed primary and binds new links to it', () => {
    const rows: Record<string, Record<string, unknown>> = {
      first: savedRow(),
      second: savedRow('Other local edit'),
    };
    rows.first[IMPORT_RESOLUTION] = reviewImportResolution(
      rows,
      'first',
      'review',
    );
    const result = importRecords(host(rows), [
      { ...row, values: { [name]: 'Next source' } },
    ]);
    expect(result.problems).toEqual([]);
    expect(result.intents).toHaveLength(1);
    expect(result.intents[0]).toMatchObject({ op: 'set', subject: 'first' });
    expect(rows.second[name]).toBe('Other local edit');
    rows.second[name] = 'Offline change';
    expect(
      importRecords(host(rows), [row]).problems[0].importCollision,
    ).toEqual(['first', 'second']);
  });
  it('resolves references to existing imported resources', () => {
    const other = {
      ...row,
      localId: 'second',
      sourceId: 'provider:2',
      values: { link: 'local:row' },
    };
    expect(
      importRecords(host({ existing: savedRow() }), [row, other]).intents[0],
    ).toMatchObject({ set: { link: 'existing' } });
  });
  it('replans an interrupted linked batch without recreating completed records', () => {
    const child = {
      ...row,
      localId: 'child',
      sourceId: 'provider:child',
      parent: 'local:row',
      values: { link: 'local:row' },
    };
    const result = importRecords(host({ existing: savedRow() }), [child, row]);
    expect(result.summary).toEqual({ created: 1, updated: 0, unchanged: 1 });
    expect(result.intents[0]).toMatchObject({
      op: 'create',
      parent: 'existing',
      set: { link: 'existing' },
    });
  });
  it('adopts matching legacy records but never guesses baselines for edited rows', () => {
    const legacy = savedRow();
    delete legacy[IMPORT_LOCAL_ID];
    delete legacy[IMPORT_BASELINE];
    Object.assign(legacy, { legacy: 'id' });
    const record = { ...row, legacy: { property: 'legacy', value: 'id' } };
    expect(
      importRecords(host({ existing: legacy }), [record]).summary.updated,
    ).toBe(1);
    expect(
      importRecords(host({ existing: { ...legacy, [name]: 'Edited' } }), [
        record,
      ]).problems,
    ).toHaveLength(1);
  });
});

describe('reviewed import resolution', () => {
  it('records the exact observed value and advances the source baseline', () => {
    const existingRow = savedRow('Local');
    const keep = resolveImportConflict(existingRow, name, 'Remote', 'local');
    expect(keep).not.toHaveProperty(name);
    expect(keep[IMPORT_BASELINE]).toMatchObject({
      values: { [name]: 'Remote' },
      resolution: {
        [name]: { present: true, value: 'Local', choice: 'local' },
      },
    });
    expect(
      resolveImportConflict(existingRow, name, 'Remote', 'source')[name],
    ).toBe('Remote');
  });
  it('retains conflict details through verdict parsing', async () => {
    const { parseVerdict } = await import('./plugin-run.js');
    const result = importRecords(host({ existing: savedRow('Local') }), [
      { ...row, values: { [name]: 'Remote' } },
    ]);
    expect(parseVerdict(result).problems[0].importConflict).toEqual({
      current: 'Local',
      previous: 'Source',
      source: 'Remote',
      appendOnly: false,
    });
  });
});

it('claims native sync identity without replacing the sync baseline', () => {
  expect(
    claimImportIdentity(host(), parent, 'github:org/repo:issue:1'),
  ).toEqual({ [IMPORT_LOCAL_ID]: 'github:org/repo:issue:1' });
  expect(() =>
    claimImportIdentity(host({ existing: savedRow() }), parent, row.sourceId),
  ).toThrow('already exists');
  expect(
    claimImportIdentity(
      host({ existing: savedRow() }),
      parent,
      row.sourceId,
      'existing',
    ),
  ).toEqual({ [IMPORT_LOCAL_ID]: row.sourceId });
  expect(() =>
    claimImportIdentity(
      host({ existing: savedRow() }),
      parent,
      'different',
      'existing',
    ),
  ).toThrow('another');
});
