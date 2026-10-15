import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  contactSchema,
  moneySchema,
  pipelineSchema,
  sharedVocabularyOntologies,
  sharedVocabularyProperties,
  workSchema,
} from './shared-vocabularies.js';
import { isEmbeddedVocabulary } from './store.js';

const P = 'https://atomicdata.dev/properties/';
const records = JSON.parse(
  readFileSync(
    new URL('../../../lib/defaults/vocabularies.json', import.meta.url),
    'utf8',
  ),
) as Array<Record<string, unknown>>;
const byId = new Map(records.map(r => [r['@id'], r]));

it('defines each shared property once, under its own versioned vocabulary', () => {
  expect(sharedVocabularyProperties.length).toBe(
    Object.keys(workSchema.properties).length +
      Object.keys(contactSchema.properties).length +
      Object.keys(pipelineSchema.properties).length +
      Object.keys(moneySchema.properties).length,
  );

  for (const id of sharedVocabularyProperties) {
    const record = byId.get(id);
    expect(record, id).toBeDefined();
    const parent = record![`${P}parent`] as string;
    expect(sharedVocabularyOntologies).toContain(parent);
    expect(id.startsWith(`${parent}/`)).toBe(true);
    expect(byId.get(parent)?.[`${P}properties`]).toContain(id);
    expect(isEmbeddedVocabulary(id)).toBe(true);
  }

  for (const ontology of sharedVocabularyOntologies)
    expect(isEmbeddedVocabulary(ontology)).toBe(true);
});

it('keeps constraints off the shared properties', () => {
  // Options live on the class that uses a property, so the shared definition
  // stays identical for every table.
  for (const id of sharedVocabularyProperties) {
    const record = byId.get(id)!;
    expect(record[`${P}allowsOnly`]).toBeUndefined();
    expect(record[`${P}min`]).toBeUndefined();
    expect(record[`${P}max`]).toBeUndefined();
  }
});
