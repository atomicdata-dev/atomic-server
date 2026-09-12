import { describe, it } from 'vitest';
import { encodeB64 } from './base64.js';
import { commits } from './ontologies/commits.js';
import { JSONADParser } from './parse.js';
import { core } from './ontologies/core.js';
import { Resource } from './resource.js';

const EXAMPLE_SUBJECT = 'http://example.com/1';
const EXAMPLE_SUBJECT2 = 'http://example.com/2';
const EXAMPLE_SUBJECT3 = 'http://example.com/3';

const STRING_PROPERTY = 'http://example.com/some-string-property';
const NUMBER_PROPERTY = 'http://example.com/some-number-property';
const BOOLEAN_PROPERTY = 'http://example.com/some-boolean-property';
const NESTED_RESOURCE_PROPERTY =
  'http://example.com/some-nested-resource-property';
describe('parse.ts', () => {
  it('parses a JSON-AD object and returns it as a resource', ({ expect }) => {
    const jsonObject = {
      '@id': EXAMPLE_SUBJECT,
      [STRING_PROPERTY]: 'Hoi',
      [NUMBER_PROPERTY]: 10,
      [BOOLEAN_PROPERTY]: true,
    };

    const parser = new JSONADParser();
    const [resource] = parser.parse(jsonObject);

    expect(resource.get(STRING_PROPERTY)).toBe('Hoi');
    expect(resource.get(NUMBER_PROPERTY)).toBe(10);
    expect(resource.get(BOOLEAN_PROPERTY)).toBe(true);
  });

  it('parses an array of jsonObjects', ({ expect }) => {
    const array = [
      {
        '@id': EXAMPLE_SUBJECT,
        [STRING_PROPERTY]: 'First Resource',
      },
      {
        '@id': EXAMPLE_SUBJECT2,
        [STRING_PROPERTY]: 'Second Resource',
      },
      {
        '@id': EXAMPLE_SUBJECT3,
        [STRING_PROPERTY]: 'Third Resource',
        [NESTED_RESOURCE_PROPERTY]: {
          [STRING_PROPERTY]: 'Nested Resource',
        },
      },
    ];

    const parser = new JSONADParser();
    const resources = parser.parse(array);

    expect(resources).toHaveLength(3);
  });

  /**
   * Regression: legacy servers (and `include_nested` responses) inline
   * member resources as full objects. Leaving those objects in the propval
   * hands consumers an object where they expect a subject string —
   * `normalizeSubject` crashed rendering such a collection. The parser must
   * extract each nested resource and keep only its `@id` as the reference.
   */
  it('extracts nested resources with an @id, keeping only the reference', ({
    expect,
  }) => {
    const jsonObject = {
      '@id': EXAMPLE_SUBJECT,
      [NESTED_RESOURCE_PROPERTY]: [
        {
          '@id': EXAMPLE_SUBJECT2,
          [STRING_PROPERTY]: 'First member',
        },
        // Plain refs mixed in stay untouched.
        EXAMPLE_SUBJECT3,
      ],
    };

    const parser = new JSONADParser();
    const resources = parser.parse(jsonObject, EXAMPLE_SUBJECT);

    expect(resources).toHaveLength(2);

    // The requested resource stays last — `fetchResourceHTTP` falls back to
    // "last parsed resource" when no subject matches exactly.
    const main = resources.at(-1)!;
    expect(main.subject).toBe(EXAMPLE_SUBJECT);
    expect(main.get(NESTED_RESOURCE_PROPERTY)).toEqual([
      EXAMPLE_SUBJECT2,
      EXAMPLE_SUBJECT3,
    ]);

    const member = resources.find(r => r.subject === EXAMPLE_SUBJECT2);
    expect(member?.get(STRING_PROPERTY)).toBe('First member');
  });

  it('passes objects without an @id through as plain JSON values', ({
    expect,
  }) => {
    const columnWidths = { col1: 120, col2: 80 };
    const jsonObject = {
      '@id': EXAMPLE_SUBJECT,
      [NESTED_RESOURCE_PROPERTY]: columnWidths,
    };

    const parser = new JSONADParser();
    const resources = parser.parse(jsonObject, EXAMPLE_SUBJECT);

    // No extraction: the object is a value, not a resource. (The resource
    // layer stores object values JSON-stringified; equality after parsing is
    // what matters here.)
    expect(resources).toHaveLength(1);
    const value = resources[0].get(NESTED_RESOURCE_PROPERTY);
    const roundTripped = typeof value === 'string' ? JSON.parse(value) : value;
    expect(roundTripped).toEqual(columnWidths);
  });

  it('Handles resources without an ID', ({ expect }) => {
    const jsonObject = {
      [STRING_PROPERTY]: 'Hoi',
    };

    const parser = new JSONADParser();
    const [resource] = parser.parse(jsonObject, 'my-new-id');

    expect(resource.get(STRING_PROPERTY)).toBe('Hoi');
    expect(resource.subject).toBe('my-new-id');
  });

  it('heals missing parent and isA from hydrated JSON when the loro snapshot is stale', async ({
    expect,
  }) => {
    const legacy = new Resource(EXAMPLE_SUBJECT);
    await legacy.set(STRING_PROPERTY, 'Hoi', false);
    const snapshot = legacy.getLoroDoc()!.export({
      mode: 'snapshot',
    });

    const parser = new JSONADParser();
    const [resource] = parser.parse({
      '@id': EXAMPLE_SUBJECT,
      [STRING_PROPERTY]: 'Hoi',
      [core.properties.parent]: 'did:ad:test-drive',
      [core.properties.isA]: ['https://atomicdata.dev/classes/Document'],
      [core.properties.name]: 'Test doc',
      [commits.properties.loroUpdate]: {
        type: 'lorodoc',
        data: encodeB64(snapshot),
      },
    });

    expect(resource.get(core.properties.parent)).toBe('did:ad:test-drive');
    expect(resource.get(core.properties.isA)).toEqual([
      'https://atomicdata.dev/classes/Document',
    ]);
    expect(resource.hasUnsavedChanges()).toBe(false);

    const loroJson = resource.getLoroDoc()!.getMap('properties').toJSON();
    expect(loroJson[core.properties.parent]).toBe('did:ad:test-drive');
    // Arrays are stored as a native `LoroList` (per-element CRDT merge), not
    // as a JSON-stringified scalar — the original assertion predates that
    // change. `toJSON()` round-trips lists back to plain JS arrays.
    expect(loroJson[core.properties.isA]).toEqual([
      'https://atomicdata.dev/classes/Document',
    ]);
  });

  /**
   * Regression: a Commit resource (`did:ad:commit:<sig>`) carries a
   * `loroUpdate` property whose bytes are the snapshot of the *committed*
   * resource (the Document, Message, etc. that was edited). Parsing the
   * commit must NOT import those bytes into the commit's own Loro doc —
   * doing so overwrote the commit's propvals (`isA: [Commit]`,
   * `signature`, `signer`, …) with the committed resource's propvals
   * (`isA: [Message]`, `parent: ChatRoom`, …), so `/show?subject=did:ad:commit:…`
   * rendered the commit as if it WERE the message.
   *
   * The parse path is the one this fix lives on — fetched JSON-AD lands
   * here on every server response.
   */
  it('keeps a commit resource as a commit, not the committed resource it carries', async ({
    expect,
  }) => {
    // Build a snapshot of the committed resource — a hypothetical Message.
    const COMMITTED_SUBJECT = 'did:ad:abc123';
    const message = new Resource(COMMITTED_SUBJECT);
    await message.set(
      core.properties.isA,
      ['https://atomicdata.dev/classes/Message'],
      false,
    );
    await message.set(core.properties.description, ':)', false);
    const snapshot = message.getLoroDoc()!.export({
      mode: 'snapshot',
    });

    // The shape the server returns when you GET `did:ad:commit:<sig>`:
    // a Commit resource whose `loroUpdate` carries the COMMITTED
    // resource's snapshot, not its own.
    const COMMIT_SUBJECT = 'did:ad:commit:zzz999';
    const parser = new JSONADParser();
    const [commit] = parser.parse({
      '@id': COMMIT_SUBJECT,
      [core.properties.isA]: ['https://atomicdata.dev/classes/Commit'],
      [commits.properties.subject]: COMMITTED_SUBJECT,
      [commits.properties.signature]: 'zzz999',
      [commits.properties.loroUpdate]: {
        type: 'lorodoc',
        data: encodeB64(snapshot),
      },
    });

    // The commit's own propvals must survive — `isA` stays `[Commit]`,
    // and the committed Message's `description` does NOT leak in.
    expect(commit.get(core.properties.isA)).toEqual([
      'https://atomicdata.dev/classes/Commit',
    ]);
    expect(commit.get(core.properties.description)).toBeUndefined();
  });

  /**
   * Regression: `@tomic/cli` users copy `https://host/did:ad:…` from the
   * address bar. The server returns `@id: did:ad:…` (the resource's
   * identity). Treating that as a mismatch made `ad-generate ontologies`
   * fail after a successful fetch.
   */
  it('accepts a DID @id when the requested subject is the HTTP path alias', ({
    expect,
  }) => {
    const did = 'did:ad:ontology123';
    const httpAlias = `https://myserver.example/${did}`;
    const jsonObject = {
      '@id': did,
      [STRING_PROPERTY]: 'My ontology',
    };

    const parser = new JSONADParser();
    const [resource] = parser.parse(jsonObject, httpAlias);

    expect(resource.error).toBeUndefined();
    expect(resource.subject).toBe(did);
    expect(resource.get(STRING_PROPERTY)).toBe('My ontology');
  });

  it('still rejects a genuine @id mismatch', ({ expect }) => {
    const jsonObject = {
      '@id': 'https://example.com/other',
      [STRING_PROPERTY]: 'Hoi',
    };

    const parser = new JSONADParser();

    expect(() => parser.parse(jsonObject, EXAMPLE_SUBJECT)).toThrow(
      /wrong subject in @id/,
    );
  });
});
