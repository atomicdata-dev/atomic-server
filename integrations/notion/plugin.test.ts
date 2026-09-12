import { it, expect } from 'vitest';
import { run } from './plugin.js';
import { P } from './model.js';
// Authored API fixtures, not live Notion conformance evidence.
const id = '11111111-1111-1111-1111-111111111111',
  pid = '22222222-2222-2222-2222-222222222222';
function fixture() {
  const config = {
    dataSource: id,
    table: 'did:ad:table',
    rowClass: 'did:ad:class',
    identity: 'did:ad:id',
    arrival: 'did:ad:arrival',
    fields: [
      { id: 'title', property: 'did:ad:title', type: 'title' },
      { id: 'n', property: 'did:ad:n', type: 'number' },
    ],
    views: [],
  };
  const records: any = {
    'did:ad:title': { [P.name]: 'Name' },
    'did:ad:n': { [P.name]: 'Count' },
  };
  const schema = {
    id,
    properties: {
      Name: { id: 'title', name: 'Name', type: 'title' },
      Count: { id: 'n', name: 'Count', type: 'number' },
    },
  };
  const page = {
    object: 'page',
    id: pid,
    parent: { data_source_id: id },
    properties: {
      Name: {
        id: 'title',
        type: 'title',
        title: [{ type: 'text', text: { content: 'Task' } }],
      },
      Count: { id: 'n', type: 'number', number: 2 },
    },
  };
  const responses: any = {
    schema,
    query: { results: [page], has_more: false, next_cursor: null },
    page,
  };
  const input: any = {
    phase: 'preview',
    config,
    connection: { revision: 0, records: {}, cursor: null },
    read: (s: string) => {
      if (!records[s]) throw Error('Not found');
      return records[s];
    },
    query: (p: string, v: string) =>
      Object.keys(records).filter(s => records[s][p] === v),
    http: (r: any) => ({
      status: 200,
      body: JSON.stringify(responses[r.operation]),
    }),
  };
  return { input, records, responses, page };
}
it('discovers rows and stable property identities without writes', () => {
  const f = fixture();
  const out: any = run(f.input);
  expect(out.kind).toBe('preview');
  expect(out.problems).toEqual([]);
  expect(out.proposal.changes.map((x: any) => x.kind)).toEqual([
    'schema',
    'schema',
    'page',
  ]);
});
it('fails closed for looping pagination, schema changes and duplicate bindings', () => {
  const f = fixture();
  f.responses.query = { results: [], has_more: true, next_cursor: 'same' };
  expect(() => run(f.input)).toThrow('pagination');
  f.responses.schema.properties.Count.type = 'formula';
  expect(() => run(f.input)).toThrow('changed type');
});
it('uses acknowledged baselines for independent field edits and conflicts', () => {
  const f = fixture();
  f.records.row = {
    [P.parent]: f.input.config.table,
    [P.isA]: [f.input.config.rowClass],
    [P.name]: 'Local title',
    'did:ad:title': 'Local title',
    'did:ad:n': 1,
    'did:ad:id': pid,
  };
  f.input.connection = {
    revision: 1,
    records: {
      [`page:${pid}`]: { local: 'row', baseline: { title: 'Task', n: 1 } },
    },
  };
  let out: any = run(f.input);
  expect(out.proposal.changes.at(-1).desired).toEqual({
    title: 'Local title',
    n: 2,
  });
  f.records.row['did:ad:n'] = 3;
  out = run(f.input);
  expect(out.problems[0].message).toContain('n');
});
it('rejects edits made after preview before proposing any writes', () => {
  const f = fixture();
  const out: any = run(f.input);
  f.input.phase = 'step';
  f.input.proposal = out.proposal;
  f.records['did:ad:title'][P.name] = 'Changed';
  expect(() => run(f.input)).toThrow('after preview');
});
it('stops on access and rate-limit errors instead of treating them as empty data', () => {
  for (const status of [403, 404, 429]) {
    const f = fixture();
    f.input.http = () => ({ status, body: '{}' });
    expect(() => run(f.input)).toThrow(`Notion returned ${status}`);
  }
});
