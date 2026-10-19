import { describe, it, vi } from 'vitest';
import { Collection } from './collection.js';
import { collections, commits } from './index.js';
import { properties } from './urls.js';
import { Resource } from './resource.js';
import { Store } from './store.js';

/**
 * A page a person opens on someone's profile lists what they created. The
 * server answers the `createdBy` query, then the client loads each member and
 * tells the collection about it. The client's copy of a resource has no
 * `createdBy` property (the creator is in its genesis certificate), so it read
 * as a resource that no longer matches the query and was stripped from the
 * page the server had just answered. The list showed the member for a moment
 * and then ended up empty, on about one load in ten.
 */
const BOB = 'atomic:agent:bob';
const DOC = 'atomic:resource:doc';

function pageMembers(collection: Collection): string[] {
  const pages = (collection as unknown as { pages: Map<number, Resource> })
    .pages;

  return pages.get(0)?.getSubjects(collections.properties.members) ?? [];
}

describe('Collection filtered on createdBy', () => {
  it('keeps a member whose creator only its genesis certificate names', async ({
    expect,
  }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: properties.createdBy,
        value: BOB,
        sort_by: commits.properties.createdAt,
        sort_desc: true,
      },
      true,
    );

    // What the server answered: one member.
    const answered = new Resource<never>('https://example.com/answer');
    (
      collection as unknown as {
        writePageMembers(
          page: Resource,
          members: string[],
          total: number,
        ): void;
        setPage(page: number, resource: Resource): void;
      }
    ).writePageMembers(answered as unknown as Resource, [DOC], 1);
    (
      collection as unknown as { setPage(page: number, r: Resource): void }
    ).setPage(0, answered as unknown as Resource);
    (collection as unknown as { _totalMembers: number })._totalMembers = 1;
    expect(pageMembers(collection)).toEqual([DOC]);

    // The client's copy of the document: no `createdBy` property, creator in
    // the genesis certificate.
    const doc = new Resource(DOC);
    doc.loading = false;
    vi.spyOn(doc, 'getCreatedBy').mockReturnValue(BOB);
    expect(doc.get(properties.createdBy)).toBeUndefined();

    expect(collection.applyResourceChange(DOC, doc)).toBe('unchanged');
    expect(pageMembers(collection)).toEqual([DOC]);
    expect(collection.totalMembers).toBe(1);
  });

  it('still removes a member someone else created', async ({ expect }) => {
    const store = new Store({ serverUrl: 'https://example.com' });
    const collection = new Collection(
      store,
      'https://example.com',
      {
        page_size: '30',
        include_nested: false,
        property: properties.createdBy,
        value: BOB,
      },
      true,
    );
    const answered = new Resource<never>('https://example.com/answer');
    const internals = collection as unknown as {
      writePageMembers(page: Resource, members: string[], total: number): void;
      setPage(page: number, r: Resource): void;
      _totalMembers: number;
    };
    internals.writePageMembers(answered as unknown as Resource, [DOC], 1);
    internals.setPage(0, answered as unknown as Resource);
    internals._totalMembers = 1;

    const doc = new Resource(DOC);
    doc.loading = false;
    vi.spyOn(doc, 'getCreatedBy').mockReturnValue('atomic:agent:carol');

    expect(collection.applyResourceChange(DOC, doc)).toBe('member-removed');
    expect(pageMembers(collection)).toEqual([]);
  });
});
