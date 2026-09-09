import { describe, it, expect } from 'vitest';
import { core, dataBrowser, Datatype, Resource, Store } from '@tomic/react';
import {
  compatibleFieldTypes,
  classColumns,
  columnLabel,
  createMappedField,
} from './tableColumns';

function property(datatype: string, extra: Record<string, unknown> = {}) {
  const values: Record<string, unknown> = {
    [core.properties.datatype]: datatype,
    ...extra,
  };

  return {
    subject: 'https://example.com/column',
    get: (p: string) => values[p],
    hasClasses: (c: string) =>
      ((values[core.properties.isA] as string[]) ?? []).includes(c),
  } as Resource;
}

describe('table column presentations', () => {
  it('derives scalar types and limits switches to compatible storage shapes', () => {
    expect(compatibleFieldTypes(property(Datatype.STRING))).toEqual([
      'short-text',
      'long-text',
      'email',
      'phone',
      'url',
      'country',
    ]);
    expect(compatibleFieldTypes(property(Datatype.FLOAT))).toEqual([
      'number',
      'currency',
    ]);
    expect(compatibleFieldTypes(property(Datatype.INTEGER))).toEqual([
      'number',
      'likert',
      'rating',
    ]);
    expect(compatibleFieldTypes(property(Datatype.BOOLEAN))).toEqual([
      'checkbox',
    ]);
    expect(compatibleFieldTypes(property(Datatype.DATE))).toEqual(['date']);
    expect(compatibleFieldTypes(property(Datatype.TIMESTAMP))).toEqual([
      'datetime',
    ]);
  });
  it('uses select cardinality and recognizes relation columns', () => {
    const select = {
      [core.properties.isA]: [dataBrowser.classes.selectProperty],
      [core.properties.allowsOnly]: [],
    };
    expect(
      compatibleFieldTypes(
        property(Datatype.RESOURCEARRAY, {
          ...select,
          [dataBrowser.properties.max]: 1,
        }),
      ),
    ).toEqual(['dropdown', 'radio', 'picture-choice']);
    expect(
      compatibleFieldTypes(property(Datatype.RESOURCEARRAY, select)),
    ).toEqual(['dropdown-multi', 'multi-select']);
    expect(
      compatibleFieldTypes(
        property(Datatype.RESOURCEARRAY, {
          [core.properties.classtype]: 'https://example.com/Person',
        }),
      ),
    ).toEqual(['dropdown']);
    expect(compatibleFieldTypes(property(Datatype.RESOURCEARRAY))).toEqual([]);
  });
  it('never guesses composite or unknown types', () => {
    for (const type of [
      Datatype.JSON,
      'https://atomicdata.dev/datatypes/file',
      Datatype.LOCALIZEDTEXT,
      'unknown',
    ])
      expect(compatibleFieldTypes(property(type))).toEqual([]);
  });
  it('uses the column name before its shortname', () => {
    expect(
      columnLabel(
        property(Datatype.STRING, {
          [core.properties.name]: 'Full name',
          [core.properties.shortname]: 'name',
        }),
      ),
    ).toBe('Full name');
    expect(
      columnLabel(
        property(Datatype.STRING, { [core.properties.shortname]: 'name' }),
      ),
    ).toBe('name');
  });
  it('deduplicates required and recommended columns', () => {
    expect(
      classColumns({
        getSubjects: (p: string) =>
          p === core.properties.requires ? ['a'] : ['b', 'a'],
      } as Resource),
    ).toEqual(['a', 'b']);
  });
  it('rejects mapping a property outside the row class before creating anything', async () => {
    const dataClass = { getSubjects: () => [] } as unknown as Resource;
    await expect(
      createMappedField(
        {} as Store,
        {} as Resource,
        dataClass,
        property(Datatype.STRING),
      ),
    ).rejects.toThrow('Column is not part of this table');
  });
});

it('creates only a FormField when mapping a required existing column', async () => {
  const column = property(Datatype.INTEGER, { [core.properties.name]: 'Age' });
  const dataClass = {
    getSubjects: (p: string) =>
      p === core.properties.requires ? [column.subject] : [],
  } as unknown as Resource;
  let created: Parameters<Store['newResource']>[0] | undefined;
  const field = { save: async () => {} };
  const store = {
    newResource: async (opts: Parameters<Store['newResource']>[0]) => {
      created = opts;

      return field;
    },
  } as unknown as Store;
  await createMappedField(
    store,
    { subject: 'page' } as Resource,
    dataClass,
    column,
  );
  expect(created?.parent).toBe('page');
  expect(
    created?.propVals?.['https://atomicdata.dev/properties/form-maps-to'],
  ).toBe(column.subject);
  expect(
    created?.propVals?.['https://atomicdata.dev/properties/required'],
  ).toBe(true);
  expect(created?.propVals?.[core.properties.name]).toBe('Age');
});
