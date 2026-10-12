import { describe, expect, it } from 'vitest';
import { isJsonSchema, ontologyFromSchemaFile } from './schema-file.js';

const SCHEMA = JSON.stringify({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'Notes',
  $defs: {
    note: {
      type: 'object',
      properties: { title: { type: 'string' } },
      required: ['title'],
    },
  },
});

const INPUT = JSON.stringify({
  shortname: 'notes',
  classes: [
    {
      shortname: 'note',
      requires: ['title'],
      properties: [
        {
          shortname: 'title',
          datatype: 'https://atomicdata.dev/datatypes/string',
        },
      ],
    },
  ],
});

describe('ontologyFromSchemaFile', () => {
  it('detects a JSON Schema and an ontology input', () => {
    expect(isJsonSchema({ $defs: {} })).toBe(true);
    expect(isJsonSchema({ type: 'object' })).toBe(true);
    expect(isJsonSchema({ shortname: 'x', classes: [] })).toBe(false);

    expect(ontologyFromSchemaFile(SCHEMA).classes[0].shortname).toBe('note');
    expect(ontologyFromSchemaFile(INPUT).classes[0].properties).toHaveLength(1);
  });

  it('overrides the shortname', () => {
    expect(ontologyFromSchemaFile(SCHEMA, { shortname: 'a' }).shortname).toBe(
      'a',
    );
    expect(ontologyFromSchemaFile(INPUT, { shortname: 'b' }).shortname).toBe(
      'b',
    );
  });

  it('rejects what is neither', () => {
    expect(() => ontologyFromSchemaFile('[]')).toThrow(/JSON object/);
    expect(() => ontologyFromSchemaFile('{"nonsense":1}')).toThrow(/Neither/);
    expect(() => ontologyFromSchemaFile('nope')).toThrow(/Not valid JSON/);
  });
});
