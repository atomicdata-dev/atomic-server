/** Real WASM engine, no AtomicServer or provider network required. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import init, {
  describeIntegration,
  fetchIntegration,
} from '../../wasm/pkg/atomic_wasm.js';
await init({
  module_or_path: await readFile(
    new URL('../../wasm/pkg/atomic_wasm_bg.wasm', import.meta.url),
  ),
});
const document = await readFile(
  new URL('./mock-document.json', import.meta.url),
  'utf8',
);
const description = JSON.parse(await describeIntegration(document));
assert.deepEqual(description.collections, ['pets']);
const urls = [];
const output = JSON.parse(
  await fetchIntegration(document, 'pets', '{}', undefined, async url => {
    urls.push(url);
    const second = url.includes('page=2');
    return JSON.stringify({
      status: 200,
      headers: second
        ? {}
        : { link: '<https://pets.example/pets?page=2>; rel="next"' },
      body: JSON.stringify([
        {
          id: second ? 2 : 1,
          name: 'Pet',
          age: 3,
          vaccinated: true,
          weight: 2.5,
          updated_at: '2026-09-09T00:00:00Z',
        },
      ]),
    });
  }),
);
assert.deepEqual(urls, [
  'https://pets.example/pets',
  'https://pets.example/pets?page=2',
]);
assert.equal(output.records.length, 2);
assert.equal(output.records[0].values.age, 3);
assert.equal(output.records[0].values.vaccinated, true);
assert.equal(output.records[0].values['updated-at'], 1788912000000);
assert.equal(
  output.ontology.terms.find(t => t.shortname === 'age').datatype,
  'https://atomicdata.dev/datatypes/integer',
);
await assert.rejects(
  fetchIntegration(document, 'pets', '{}', undefined, async () =>
    JSON.stringify({ status: 503, headers: {}, body: '{}' }),
  ),
  /Import incomplete/,
);
await assert.rejects(
  fetchIntegration(document, 'pets', '{}', undefined, async () =>
    JSON.stringify({
      status: 200,
      headers: { link: '<https://pets.example/pets?page=2>; rel="next"' },
      body: JSON.stringify([{ id: 1, name: 'Repeated' }]),
    }),
  ),
  /Import incomplete/,
);
console.log(
  'Real WASM pagination, typed ontology, timestamps and failure refusal passed',
);
