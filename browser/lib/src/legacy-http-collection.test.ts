import { describe, expect, it, vi } from 'vitest';
import { CollectionBuilder } from './collectionBuilder.js';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import { collections } from './ontologies/collections.js';
import type { ClientDbWorker } from './client-db.js';

const HOME = 'https://app.example.com';
const LEGACY = 'https://legacy.example.com';
const DRIVE = `${LEGACY}/drive/old`;

function setup(localSubjects: string[] = []) {
  const store = new Store({ serverUrl: HOME, connect: false });
  const query = vi.fn(async () => ({
    subjects: localSubjects,
    count: localSubjects.length,
  }));
  store.setClientDb({
    isReady: true,
    waitForInit: async () => {},
    query,
  } as unknown as ClientDbWorker);
  const requests: URL[] = [];
  store.injectFetch(async input => {
    const url = new URL(String(input));
    requests.push(url);

    return new Response(
      JSON.stringify({
        '@id': url.href,
        [collections.properties.members]: [
          `${LEGACY}/document/one`,
          `${LEGACY}/document/two`,
        ],
        [collections.properties.totalMembers]: 2,
      }),
      { status: 200 },
    );
  });

  return { store, query, requests };
}

describe('legacy HTTP collections from another home server', () => {
  it('uses the HTTP parent drive even when another drive is still selected', async () => {
    const { store, requests } = setup();
    store.setDrive(`${LEGACY}/drive/previous`);
    store.hydrateResourceFromJsonAd(
      DRIVE,
      JSON.stringify({
        '@id': DRIVE,
        [core.properties.isA]: ['https://atomicdata.dev/classes/Drive'],
      }),
    );
    await new CollectionBuilder(store)
      .setProperty(core.properties.parent)
      .setValue(DRIVE)
      .buildAndFetch();
    expect(requests[0]!.searchParams.get('drive')).toBe(DRIVE);
  });

  it.each(['atomic:local', 'did:ad:local'])(
    'keeps %s parent queries away from the active HTTP server',
    async parent => {
      const { store, requests } = setup();
      store.setDrive(DRIVE);
      store.finishDriveSync(DRIVE, 0, Date.now());
      const collection = await new CollectionBuilder(store)
        .setProperty(core.properties.parent)
        .setValue(parent)
        .buildAndFetch();
      expect(collection['server']).toBe(HOME);
      expect(collection['params'].drive).toBeUndefined();
      expect(requests.every(url => url.origin === HOME)).toBe(true);
    },
  );

  it('honors an explicit query server', async () => {
    const { store, requests } = setup();
    store.setDrive(DRIVE);
    await new CollectionBuilder(store, 'https://replica.example.com')
      .setProperty(core.properties.parent)
      .setValue(DRIVE)
      .buildAndFetch();
    expect(requests[0]?.origin).toBe('https://replica.example.com');
  });

  it('does not route DID-drive class queries to the vocabulary host', async () => {
    const { store, query, requests } = setup();
    store.setDrive('did:ad:local');
    store.finishDriveSync('did:ad:local', 0, Date.now());
    await new CollectionBuilder(store)
      .setProperty(core.properties.isA)
      .setValue(core.classes.agent)
      .buildAndFetch();
    expect(query).toHaveBeenCalledOnce();
    expect(requests).toEqual([]);
  });

  it('does not remove the drive scope from a class query rejected by an old server', async () => {
    const { store, requests } = setup();
    store.setDrive(DRIVE);
    store.injectFetch(async input => {
      requests.push(new URL(String(input)));

      return new Response(
        JSON.stringify({
          '@id': 'unknown_subject',
          [core.properties.isA]: [core.classes.error],
          [core.properties.description]:
            'Error handling query Endpoint: Invalid query param: drive',
        }),
        { status: 400 },
      );
    });
    await expect(
      new CollectionBuilder(store)
        .setProperty(core.properties.isA)
        .setValue(core.classes.agent)
        .buildAndFetch(),
    ).rejects.toThrow('Invalid query param: drive');
    expect(requests).toHaveLength(2);
  });

  it('filters old-server matches by drive ancestry and AND filters before pagination', async () => {
    const { store, requests } = setup();
    store.setDrive(DRIVE);
    const message = `${LEGACY}/classes/Message`;
    const docs = {
      [`${LEGACY}/a`]: {
        [core.properties.parent]: `${LEGACY}/folder`,
        [core.properties.isA]: [message],
        [core.properties.name]: 'Z',
      },
      [`${LEGACY}/b`]: {
        [core.properties.parent]: DRIVE,
        [core.properties.isA]: [message],
        [core.properties.name]: 'A',
      },
      [`${LEGACY}/c`]: {
        [core.properties.parent]: `${LEGACY}/other`,
        [core.properties.isA]: [message],
      },
      [`${LEGACY}/d`]: {
        [core.properties.parent]: DRIVE,
        [core.properties.isA]: [core.classes.agent],
      },
      [`${LEGACY}/folder`]: { [core.properties.parent]: DRIVE },
      [`${LEGACY}/other`]: {},
    };
    store.injectFetch(async input => {
      const url = new URL(String(input));
      requests.push(url);
      if (url.searchParams.has('drive'))
        return new Response(
          JSON.stringify({
            '@id': 'unknown_subject',
            [core.properties.isA]: [core.classes.error],
            [core.properties.description]:
              'Error handling query Endpoint: Invalid query param: drive',
          }),
          { status: 500 },
        );

      if (url.pathname === '/query') {
        expect(url.searchParams.has('filters')).toBe(false);

        return new Response(
          JSON.stringify({
            '@id': url.href,
            [collections.properties.members]: Object.keys(docs).slice(0, 4),
            [collections.properties.totalMembers]: 4,
          }),
        );
      }

      return new Response(
        JSON.stringify({
          '@id': url.href,
          ...docs[url.href as keyof typeof docs],
        }),
      );
    });
    const collection = await new CollectionBuilder(store)
      .setProperty(core.properties.description)
      .setValue('related')
      .addFilter({ property: core.properties.isA, value: message })
      .setSortBy(core.properties.name)
      .setPageSize(1)
      .buildAndFetch();
    expect(await collection.getAllMembers()).toEqual([
      `${LEGACY}/b`,
      `${LEGACY}/a`,
    ]);
    expect(collection.totalMembers).toBe(2);
    expect(requests.filter(url => url.pathname === '/query')).toHaveLength(2);
  });

  it('retries a parent query without the drive parameter rejected by pre-DID servers', async () => {
    const { store, requests } = setup();
    store.setDrive(DRIVE);
    store.injectFetch(async input => {
      const url = new URL(String(input));
      requests.push(url);

      if (url.pathname === '/document/one')
        return new Response(
          JSON.stringify({
            '@id': url.href,
            [core.properties.parent]: DRIVE,
          }),
        );

      if (url.searchParams.has('drive')) {
        return new Response(
          JSON.stringify({
            '@id': 'unknown_subject',
            [core.properties.isA]: [core.classes.error],
            [core.properties.description]:
              'Error handling query Endpoint: Invalid query param: drive',
          }),
          { status: 400 },
        );
      }

      return new Response(
        JSON.stringify({
          '@id': url.href,
          [collections.properties.members]: url.searchParams.has('sort_by')
            ? []
            : [`${LEGACY}/document/one`],
          [collections.properties.totalMembers]: url.searchParams.has('sort_by')
            ? 0
            : 1,
        }),
      );
    });
    const collection = await new CollectionBuilder(store)
      .setProperty(core.properties.parent)
      .setValue(DRIVE)
      .setSortBy('https://atomicdata.dev/properties/createdAt')
      .setSortDesc(false)
      .buildAndFetch();
    expect(requests).toHaveLength(3);
    expect(requests[1]!.searchParams.has('drive')).toBe(false);
    expect(requests[1]!.searchParams.has('sort_by')).toBe(false);
    expect(requests[1]!.searchParams.get('value')).toBe(DRIVE);
    expect(await collection.getAllMembers()).toEqual([
      `${LEGACY}/document/one`,
    ]);
  });
  it.each([{ local: [] }, { local: [`${LEGACY}/document/one`] }])(
    'queries the HTTP authority with an incomplete local cache: $local',
    async ({ local }) => {
      const { store, query, requests } = setup(local);
      store.setDrive(DRIVE);
      const collection = await new CollectionBuilder(store)
        .setProperty(core.properties.parent)
        .setValue(DRIVE)
        .buildAndFetch();
      expect(requests).toHaveLength(1);
      expect(requests[0]!.origin).toBe(LEGACY);
      expect(requests[0]!.searchParams.get('value')).toBe(DRIVE);
      expect(requests[0]!.searchParams.get('drive')).toBe(DRIVE);
      expect(await collection.getAllMembers()).toEqual([
        `${LEGACY}/document/one`,
        `${LEGACY}/document/two`,
      ]);
      expect(query).not.toHaveBeenCalled();
      expect(store.getServerUrl()).toBe(HOME);
    },
  );

  it('loads a remote root parent without filtering by the unrelated local private drive', async () => {
    const { store, requests } = setup();
    store.setDrive('did:ad:private-drive');
    store.finishDriveSync('did:ad:private-drive', 1, Date.now());
    await new CollectionBuilder(store)
      .setProperty(core.properties.parent)
      .setValue(`${LEGACY}/`)
      .buildAndFetch();
    expect(requests).toHaveLength(1);
    expect(requests[0]!.origin).toBe(LEGACY);
    expect(requests[0]!.searchParams.has('drive')).toBe(false);
  });

  it('routes class queries by the HTTP drive, not the vocabulary origin', async () => {
    const { store, requests } = setup();
    store.setDrive(DRIVE);
    await new CollectionBuilder(store)
      .setProperty(core.properties.isA)
      .setValue(core.classes.agent)
      .buildAndFetch();
    expect(requests[0]?.origin).toBe(LEGACY);
  });
});
