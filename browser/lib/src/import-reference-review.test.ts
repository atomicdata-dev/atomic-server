import { expect, it } from 'vitest';
import { reviewImportReferences } from './import-reference-review.js';
it('previews only typed application links and preserves array order and multiplicity', () => {
  const p = 'https://example.com/';
  const changes = reviewImportReferences(
    {
      'did:ad:row': {
        [p + 'project']: 'did:ad:copy?drive=x',
        [p + 'projects']: ['did:ad:copy', 'did:ad:primary'],
        [p + 'text']: 'did:ad:copy',
        [p + 'json']: { link: 'did:ad:copy' },
        'https://atomicdata.dev/properties/parent': 'did:ad:copy',
      },
      'did:ad:copy': { [p + 'project']: 'did:ad:copy' },
      'did:ad:commit:history': { [p + 'project']: 'did:ad:copy' },
    },
    {
      [p + 'project']: 'https://atomicdata.dev/datatypes/atomicURL',
      [p + 'projects']: 'https://atomicdata.dev/datatypes/resourceArray',
      [p + 'text']: 'string',
      [p + 'json']: 'json',
      'https://atomicdata.dev/properties/parent':
        'https://atomicdata.dev/datatypes/atomicURL',
    },
    ['did:ad:copy'],
    'did:ad:primary',
  );
  expect(changes).toEqual([
    {
      subject: 'did:ad:row',
      property: p + 'project',
      before: 'did:ad:copy?drive=x',
      after: 'did:ad:primary',
    },
    {
      subject: 'did:ad:row',
      property: p + 'projects',
      before: ['did:ad:copy', 'did:ad:primary'],
      after: ['did:ad:primary', 'did:ad:primary'],
    },
  ]);
});

import { applyImportReferences } from './import-reference-review.js';
it('recovers a lost receipt and reports stale records without overwriting them', async () => {
  const rows: Record<string, Record<string, unknown>> = {
    a: { link: 'old' },
    b: { link: 'edited' },
  };
  let writes = 0;
  const host = {
    read: async (s: string) => ({ ...rows[s] }),
    write: async (s: string, values: Record<string, unknown>) => {
      writes++;
      Object.assign(rows[s], values);
      throw new Error('Lost receipt');
    },
  };
  const plan = ['a', 'b'].map(subject => ({
    subject,
    property: 'link',
    before: 'old',
    after: 'new',
  }));
  expect((await applyImportReferences(host, plan)).map(o => o.status)).toEqual([
    'confirmed',
    'needs-review',
  ]);
  expect(rows.b.link).toBe('edited');
  expect(writes).toBe(1);
  await applyImportReferences(host, plan);
  expect(writes).toBe(1);
});
