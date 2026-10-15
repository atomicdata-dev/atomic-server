import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import {
  type JSONValue,
  type Resource,
  type Store,
  core,
  isEmbeddedVocabulary,
  sharedVocabularyProperties,
} from '@tomic/react';

vi.mock('@components/Tag/tagColours', () => ({
  tagColours: ['blue', 'red', 'green'],
}));

const { createColumnOnClass, createRowClass } =
  await import('./createTableFromSpec');
const { TABLE_TEMPLATES } = await import('./tableTemplates');

// Module-wide, so subjects minted on two "drives" never collide by accident.
let counter = 0;

type Record_ = { classes: Set<string>; props: Map<string, JSONValue> };

/** The embedded vocabulary file, as the server hands it to every drive. */
const embedded = JSON.parse(
  readFileSync(
    new URL('../../../../../lib/defaults/vocabularies.json', import.meta.url),
    'utf8',
  ),
) as Array<Record<string, JSONValue>>;

/**
 * In-memory double of the store, seeded with the embedded shared vocabularies
 * and nothing else: a fresh drive. Each call is a separate "drive".
 */
function freshDrive() {
  const resources = new Map<string, Record_>();

  function add(
    subject: string,
    isA: string[],
    props: Record<string, JSONValue>,
  ) {
    resources.set(subject, {
      classes: new Set(isA),
      props: new Map(Object.entries(props)),
    });
  }

  for (const { '@id': id, ...props } of embedded) {
    add(String(id), (props[core.properties.isA] as string[]) ?? [], props);
  }

  // `name` is recommended by every row class and read when shortnames are taken.
  add(core.properties.name, [core.classes.property], {
    [core.properties.shortname]: 'name',
  });

  function make(subject: string): Resource {
    const record = resources.get(subject);

    if (!record) throw new Error(`no such resource ${subject}`);

    return {
      subject,
      get: (prop: string) => record.props.get(prop),
      getPropVals: () => Object.fromEntries(record.props),
      set: async (prop: string, value: JSONValue) => {
        record.props.set(prop, value);
      },
      push: (prop: string, values: JSONValue[], unique?: boolean) => {
        const existing = (record.props.get(prop) as JSONValue[]) ?? [];
        record.props.set(
          prop,
          unique
            ? [...new Set([...existing, ...values])]
            : [...existing, ...values],
        );
      },
      save: async () => 'persisted',
      hasClasses: (...classes: string[]) =>
        classes.some(c => record.classes.has(c)),
    } as unknown as Resource;
  }

  const store = {
    getServerUrl: () => 'https://localhost',
    getResource: async (subject: string) => make(subject),
    getResourceLoading: (subject: string) => make(subject),
    newResource: async (opts: {
      subject?: string;
      parent?: string;
      isA?: string | string[];
      propVals?: Record<string, JSONValue>;
    }) => {
      const subject = opts.subject ?? `drive:${++counter}`;
      const isA = opts.isA
        ? Array.isArray(opts.isA)
          ? opts.isA
          : [opts.isA]
        : [];
      add(subject, isA, {
        ...(opts.propVals ?? {}),
        ...(opts.parent ? { [core.properties.parent]: opts.parent } : {}),
      });

      return make(subject);
    },
    buildUniqueSubjectFromParts: async (parts: string[], parent: string) =>
      `${parent}/${parts.join('-')}`,
  } as unknown as Store;

  return { store, resources };
}

/** Builds every column of a template spec on a fresh drive with its own ontology. */
async function buildTemplate(id: string, ontologyName: string) {
  const { store } = freshDrive();
  const ontology = await store.newResource({
    subject: `drive:${ontologyName}`,
    isA: core.classes.ontology,
    propVals: { [core.properties.properties]: [] },
  });
  const template = TABLE_TEMPLATES.find(t => t.id === id)!;
  const rowClass = await createRowClass(store, {
    parent: ontology.subject,
    tableName: template.title,
    rowName: template.rowName,
  });
  const subjects: Record<string, string> = {};

  for (const column of template.spec!.columns) {
    const created = await createColumnOnClass(store, rowClass, column, true);
    subjects[column.name] = created.subject;
  }

  return { subjects, rowClass, ontology };
}

const SHARED_TEMPLATES = [
  'time-tracker',
  'expenses',
  'crm',
  'job-applications',
  'guest-list',
];

describe('shared template vocabularies', () => {
  it('ships every shared property in the embedded defaults', () => {
    const ids = new Set(embedded.map(r => r['@id']));

    for (const subject of sharedVocabularyProperties) {
      expect(ids.has(subject)).toBe(true);
      expect(isEmbeddedVocabulary(subject)).toBe(true);
    }
  });

  it.each(SHARED_TEMPLATES)(
    '%s binds its shared columns to the same property subjects on any drive',
    async id => {
      const a = await buildTemplate(id, 'ontology-a');
      const b = await buildTemplate(id, 'ontology-b');
      const shared = TABLE_TEMPLATES.find(t => t.id === id)!
        .spec!.columns.filter(c => c.propertySubject)
        .map(c => c.name);

      expect(shared.length).toBeGreaterThan(0);

      for (const name of shared) {
        expect(a.subjects[name]).toBe(b.subjects[name]);
        expect(sharedVocabularyProperties).toContain(a.subjects[name]);
        // Not minted in the drive: the property does not live in its ontology.
        expect(a.subjects[name].startsWith('drive:')).toBe(false);
      }
    },
  );

  it('keeps row classes in each drive, pointing at the shared properties', async () => {
    const a = await buildTemplate('crm', 'ontology-a');
    const b = await buildTemplate('crm', 'ontology-b');

    expect(a.rowClass.subject).not.toBe(b.rowClass.subject);
    expect(a.rowClass.get(core.properties.parent)).toBe(a.ontology.subject);
    expect(b.rowClass.get(core.properties.parent)).toBe(b.ontology.subject);
  });

  it('leaves template-specific columns in the drive', async () => {
    const a = await buildTemplate('crm', 'ontology-a');
    const b = await buildTemplate('crm', 'ontology-b');

    // CRM's "Last contact" is not a shared field.
    expect(a.subjects['Last contact']).not.toBe(b.subjects['Last contact']);
    expect(a.subjects['Last contact'].startsWith('drive:')).toBe(true);
  });
});
