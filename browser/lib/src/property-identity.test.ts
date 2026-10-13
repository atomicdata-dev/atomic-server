import { describe, expect, it } from 'vitest';
import {
  isPropertyId,
  propertyId,
  verifyPropertyId,
} from './property-identity.js';

const STRING = 'https://atomicdata.dev/datatypes/string';
const SLUG = 'https://atomicdata.dev/datatypes/slug';

const vectors: [string, string, string][] = [
  [
    'atomic:ontologyGenesis',
    STRING,
    'atomic:prop:5a939a7ca63806573c204c88e8994252ef6e14f125f8bd258bce672344b2ba74',
  ],
  [
    'did:ad:ontologyGenesis',
    STRING,
    'atomic:prop:5a939a7ca63806573c204c88e8994252ef6e14f125f8bd258bce672344b2ba74',
  ],
  [
    'https://atomicdata.dev/ontology/core',
    STRING,
    'atomic:prop:2476b0c536e851a71bc0c1991bf3746c9370085c3e6e52a0dd8255e61be1a862',
  ],
  [
    'atomic:ontologyGenesis',
    SLUG,
    'atomic:prop:d744c0c58cf42bff6246a015b5e1429c93f1ca505c3355dd84c695c8da6e6626',
  ],
];

describe('propertyId', () => {
  it.each(vectors)('matches the spec vector for %s / %s', (o, d, id) => {
    expect(propertyId(o, 'name', d)).toBe(id);
  });

  it('rejects a bad slug', () => {
    expect(() => propertyId('atomic:o', 'Bad_Name', STRING)).toThrow();
    expect(() => propertyId('atomic:o', '-x', STRING)).toThrow();
  });

  it('rejects an unknown datatype', () => {
    expect(() =>
      propertyId('atomic:o', 'name', 'https://example.com/not-a-datatype'),
    ).toThrow();
  });
});

describe('verifyPropertyId', () => {
  const id = vectors[0][2];

  it('accepts both spellings', () => {
    expect(verifyPropertyId(id, 'atomic:ontologyGenesis', 'name', STRING)).toBe(
      true,
    );
    expect(
      verifyPropertyId(
        id.replace('atomic:', 'did:ad:'),
        'did:ad:ontologyGenesis',
        'name',
        STRING,
      ),
    ).toBe(true);
  });

  it('rejects a mismatch', () => {
    expect(verifyPropertyId(id, 'atomic:ontologyGenesis', 'name', SLUG)).toBe(
      false,
    );
    expect(verifyPropertyId(id, 'atomic:ontologyGenesis', 'Bad', STRING)).toBe(
      false,
    );
    expect(isPropertyId('atomic:agent:x')).toBe(false);
  });
});
