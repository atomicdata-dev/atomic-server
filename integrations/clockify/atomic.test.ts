import { beforeEach, expect, it, vi } from 'vitest';
import {
  core,
  findSchema,
  readConnectionSubjects,
  timeTrackingSchema,
  type Store,
} from '../../browser/lib/src/index.js';
import { timeTrackerTables } from './atomic.js';
vi.mock('../../browser/lib/src/index.js', async () => ({
  ...(await import('../../browser/lib/src/ontologies/core.js')),
  ...(await import('../../browser/lib/src/ontologies/dataBrowser.js')),
  ...(await import('../../browser/lib/src/time-tracking-schema.js')),
  findSchema: vi.fn(),
  readConnectionSubjects: vi.fn(),
}));
const spec = timeTrackingSchema();
const terms = Object.fromEntries(
  spec.properties.map(p => [p.shortname, `https://test/${p.shortname}`]),
);
const classes = {
  'work-project': 'https://test/Project',
  'work-person': 'https://test/Person',
};
let values: Map<string, Record<string, unknown>>;
const store = {
  getResource: async (subject: string) => ({
    title: 'Renamed timesheet',
    get: (p: string) => values.get(subject)?.[p],
  }),
} as unknown as Store;
beforeEach(() => {
  vi.mocked(findSchema).mockResolvedValue({ properties: terms, classes });
  vi.mocked(readConnectionSubjects).mockResolvedValue(['https://test/table']);
  values = new Map(
    spec.properties.map(p => [
      terms[p.shortname],
      { [core.properties.datatype]: p.datatype },
    ]),
  );
  values.set('https://test/table', {
    [core.properties.classtype]: 'https://test/Row',
  });
  values.set('https://test/Row', {
    [core.properties.requires]: [core.properties.name],
    [core.properties.recommends]: Object.values(terms),
  });
});
it('finds an existing table by property identity despite a renamed display title', async () => {
  expect(await timeTrackerTables(store, 'drive')).toEqual([
    {
      tableSubject: 'https://test/table',
      classSubject: 'https://test/Row',
      name: 'Renamed timesheet',
      schema: { properties: terms, classes },
    },
  ]);
});
it('excludes lookalike columns and unmapped required fields', async () => {
  values.get('https://test/Row')![core.properties.recommends] = [
    'https://test/another-start',
  ];
  expect(await timeTrackerTables(store, 'drive')).toEqual([]);
  values.get('https://test/Row')![core.properties.recommends] =
    Object.values(terms);
  values.get('https://test/Row')![core.properties.requires] = [
    'https://test/unmapped-required',
  ];
  expect(await timeTrackerTables(store, 'drive')).toEqual([]);
});
it('rechecks datatype compatibility instead of mutating an incompatible schema', async () => {
  expect(await timeTrackerTables(store, 'drive')).toHaveLength(1);
  values.get(terms['work-project'])![core.properties.datatype] =
    'https://atomicdata.dev/datatypes/string';
  expect(await timeTrackerTables(store, 'drive')).toEqual([]);
});
it('does not disguise a failed authoritative query as no compatible tables', async () => {
  vi.mocked(readConnectionSubjects).mockRejectedValue(
    new Error('query failed'),
  );
  await expect(timeTrackerTables(store, 'drive')).rejects.toThrow(
    'query failed',
  );
});

it('excludes tables requiring a project because Clockify entries can be unassigned', async () => {
  values.get('https://test/Row')![core.properties.requires] = [
    terms['work-project'],
  ];
  expect(await timeTrackerTables(store, 'drive')).toEqual([]);
});
it('excludes changed related classes and incompatible relation constraints', async () => {
  values.set(classes['work-person'], {
    [core.properties.requires]: ['https://test/birthdate'],
  });
  expect(await timeTrackerTables(store, 'drive')).toEqual([]);
  values.delete(classes['work-person']);
  values.get(terms['work-project'])![core.properties.classtype] =
    classes['work-person'];
  expect(await timeTrackerTables(store, 'drive')).toEqual([]);
});
