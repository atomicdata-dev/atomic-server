import { it, expect } from 'vitest';
import {
  projectPage,
  projectRow,
  pagePatch,
  rowPatch,
  projectView,
  viewPatch,
  uuid,
  P,
  type Config,
} from './model.js';
export const id = '11111111-1111-1111-1111-111111111111';
export const c: Config = {
  dataSource: id,
  table: 'did:ad:table',
  rowClass: 'did:ad:class',
  identity: 'did:ad:id',
  arrival: 'did:ad:arrival',
  fields: [
    { id: 'title', property: 'did:ad:title', type: 'title' },
    { id: 'n', property: 'did:ad:n', type: 'number' },
    { id: 'check', property: 'did:ad:check', type: 'checkbox' },
    {
      id: 's',
      property: 'did:ad:s',
      type: 'status',
      options: { todo: 'did:ad:todo', done: 'did:ad:done' },
    },
  ],
  views: [],
};
export const page = () => ({
  object: 'page',
  id,
  parent: { data_source_id: id },
  properties: {
    Name: {
      id: 'title',
      type: 'title',
      title: [{ type: 'text', text: { content: 'Task' } }],
    },
    Count: { id: 'n', type: 'number', number: null },
    Done: { id: 'check', type: 'checkbox', checkbox: false },
    Status: { id: 's', type: 'status', status: { id: 'todo', name: 'Todo' } },
    Untouched: { id: 'f', type: 'formula', formula: { number: 2 } },
  },
});
it('maps by property ID across renames and omits unmapped properties from writes', () => {
  const p: any = page();
  p.properties.Renamed = p.properties.Name;
  delete p.properties.Name;
  const before = projectPage(p, c);
  expect(before).toEqual({ title: 'Task', n: null, check: false, s: 'todo' });
  expect(pagePatch({ ...before, n: 0 }, before, c)).toEqual({
    n: { number: 0 },
  });
});
it('round-trips explicit clears, zero, false and option IDs', () => {
  const desired = { title: 'Task', n: null, check: false, s: null };
  const patch = rowPatch(desired, c);
  expect(patch.remove).toEqual(['did:ad:n']);
  expect(
    projectRow({ ...patch.set, [P.parent]: c.table, [P.isA]: [c.rowClass] }, c),
  ).toEqual(desired);
});
it('rejects rich text loss, changed types, foreign pages and unknown options', () => {
  const p: any = page();
  p.properties.Name.title[0].annotations = { bold: true };
  expect(() => projectPage(p, c)).toThrow('lossless');
  p.properties.Name.title[0].annotations = { bold: false, color: 'default' };
  p.properties.Count.type = 'formula';
  expect(() => projectPage(p, c)).toThrow('changed type');
  p.parent.data_source_id = '22222222-2222-2222-2222-222222222222';
  expect(() => projectPage(p, c)).toThrow('outside');
  expect(() =>
    pagePatch(
      { title: 'Task', n: 0, check: false, s: 'new-option' },
      undefined,
      c,
    ),
  ).toThrow('unmapped');
});
it('chunks long text without truncating or splitting surrogate pairs', () => {
  const text = 'x'.repeat(1999) + '😀' + 'y'.repeat(2010);
  const p: any = pagePatch(
    { title: text, n: 0, check: false, s: null },
    undefined,
    c,
  );
  expect(p.title.title.every((t: any) => t.text.content.length <= 2000)).toBe(
    true,
  );
  expect(p.title.title.map((t: any) => t.text.content).join('')).toBe(text);
});
it('preserves provider-only layout values while changing visible order', () => {
  const v = {
    name: 'Tasks',
    type: 'table',
    data_source_id: id,
    configuration: {
      type: 'table',
      wrap_cells: true,
      properties: [
        { property_id: 'title', visible: true, width: 300 },
        { property_id: 'n', visible: true, width: 90 },
        { property_id: 'f', visible: false, width: 80 },
      ],
    },
  };
  const before = projectView(v, c);
  const patch = viewPatch({ ...before, columns: ['n', 'title'] }, v, c);
  expect(patch.configuration.wrap_cells).toBe(true);
  expect(patch.configuration.properties).toEqual([
    { property_id: 'n', visible: true, width: 90 },
    { property_id: 'title', visible: true, width: 300 },
    { property_id: 'f', visible: false, width: 80 },
  ]);
});
it('does not pretend filtered views or grouped statuses have parity', () => {
  expect(() =>
    projectView({ type: 'table', data_source_id: id, filter: { or: [] } }, c),
  ).toThrow('filters');
  expect(() =>
    projectView(
      {
        type: 'board',
        data_source_id: id,
        configuration: {
          group_by: { type: 'status', property_id: 's', group_by: 'group' },
        },
      },
      c,
    ),
  ).toThrow('Status groups');
});
it('rejects path injection and normalizes compact UUIDs', () => {
  expect(uuid(id.replaceAll('-', ''))).toBe(id);
  expect(() => uuid('../pages')).toThrow('UUID');
});
it('reconciles the row title and Atomic display name against their shared baseline', () => {
  const row: any = {
    [P.parent]: c.table,
    [P.isA]: [c.rowClass],
    [P.name]: 'New title',
    'did:ad:title': 'Task',
    'did:ad:n': null,
    'did:ad:check': false,
    'did:ad:s': ['did:ad:todo'],
  };
  expect(projectRow(row, c, { title: 'Task' }).title).toBe('New title');
  row[P.name] = 'Task';
  row['did:ad:title'] = 'Column edit';
  expect(projectRow(row, c, { title: 'Task' }).title).toBe('Column edit');
  row[P.name] = 'Different edit';
  expect(() => projectRow(row, c, { title: 'Task' })).toThrow('local conflict');
});
