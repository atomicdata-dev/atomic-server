/**
 * Experimental shared vocabularies v1 for table templates. Embedded in
 * AtomicServer defaults (`lib/defaults/vocabularies.json`), like the task
 * vocabulary in `task-schema.ts`.
 *
 * A property's identity is a hash of its namespace, shortname and datatype, so
 * a template that creates its properties in each drive's own ontology gives
 * every drive different property IDs. These properties live in a fixed, shared
 * namespace instead: the same subject on every drive and every server. A table
 * template binds its columns to them (`propertySubject`), while the table's row
 * class stays in the drive's own ontology and points at them. Constraints such
 * as select options live on that class, so the shared definitions never change
 * per table.
 */
const work = 'https://atomicdata.dev/work/v1/';
const contact = 'https://atomicdata.dev/contact/v1/';
const pipeline = 'https://atomicdata.dev/pipeline/v1/';
const money = 'https://atomicdata.dev/money/v1/';

export const workSchema = {
  properties: {
    start: `${work}start`,
    end: `${work}end`,
    project: `${work}project`,
    person: `${work}person`,
    billable: `${work}billable`,
    sourceId: `${work}source-id`,
  },
} as const;

export const contactSchema = {
  properties: {
    email: `${contact}email`,
    company: `${contact}company`,
  },
} as const;

export const pipelineSchema = {
  properties: {
    stage: `${pipeline}stage`,
  },
} as const;

export const moneySchema = {
  properties: {
    amount: `${money}amount`,
  },
} as const;

/** Ontology subjects of the shared vocabularies. */
export const sharedVocabularyOntologies = [
  'https://atomicdata.dev/work/v1',
  'https://atomicdata.dev/contact/v1',
  'https://atomicdata.dev/pipeline/v1',
  'https://atomicdata.dev/money/v1',
] as const;

/** Every property of the shared vocabularies. */
export const sharedVocabularyProperties: readonly string[] = [
  ...Object.values(workSchema.properties),
  ...Object.values(contactSchema.properties),
  ...Object.values(pipelineSchema.properties),
  ...Object.values(moneySchema.properties),
];
