import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { taskSchema } from './task-schema.js';
it('ships each shared property and option with consistent embedded definitions', () => {
  const records = JSON.parse(
    readFileSync(
      new URL('../../../lib/defaults/tasks.json', import.meta.url),
      'utf8',
    ),
  ) as Array<Record<string, unknown>>;
  const byId = new Map(records.map(r => [r['@id'], r]));
  for (const id of [
    ...Object.values(taskSchema.properties),
    ...Object.values(taskSchema.tags),
  ])
    expect(byId.has(id)).toBe(true);
  expect(
    byId.get(taskSchema.properties.status)?.[
      'https://atomicdata.dev/properties/allowsOnly'
    ],
  ).toEqual(Object.values(taskSchema.tags));
  expect(
    byId.get(taskSchema.properties.body)?.[
      'https://atomicdata.dev/properties/datatype'
    ],
  ).toBe('https://atomicdata.dev/datatypes/markdown');
});
