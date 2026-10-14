import { CollectionBuilder } from './collectionBuilder.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { testStore } from './test-store.js';
import { Store } from './store.js';
import { Resource } from './resource.js';
import { core } from './ontologies/core.js';
import { collections } from './ontologies/collections.js';
import { server } from './ontologies/server.js';

const A = 'https://alpha.example.com';
const B = 'https://beta.example.com';
const DRIVE_A = 'atomic:drive-a';
const DRIVE_B = 'atomic:drive-b';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
  localStorage.setItem('ws-disconnected', '1');
});

async function ready(store: Store, subject: string, parent?: string) {
  const resource = new Resource(subject);
  resource.loading = false;
  if (parent) await resource.set(core.properties.parent, parent, false);
  store.addResource(resource);

  return resource;
}

describe('per-drive destinations', () => {
  it('does not send an edit from the previous drive to the newly selected server', async () => {
    const { store, postCommitSpy } = await testStore({ serverUrl: A });
    const drive = await store.newResource({ isA: server.classes.drive });
    await drive.save();
    store.setDrive(drive.subject);
    const child = await store.newResource({ parent: drive.subject });
    await child.save();
    postCommitSpy.mockClear();

    store.setServerUrl(B);
    store.setServerConnected(true);
    await child.set(
      core.properties.name,
      'Edited in the first workspace',
      false,
    );
    await child.save();

    expect(postCommitSpy).toHaveBeenCalled();
    expect(
      postCommitSpy.mock.calls.every(
        ([, endpoint]) => endpoint === `${A}/commit`,
      ),
    ).toBe(true);
  });

  it('resolves children and queries through their drive, including sibling subdomains', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setDriveServer(DRIVE_A, A);
    store.setDriveServer(DRIVE_B, B);
    await ready(store, 'atomic:folder-a', DRIVE_A);
    await ready(store, 'atomic:child-a', 'atomic:folder-a');
    store.setDrive(DRIVE_B);

    expect(store.getServerUrlForSubject('atomic:child-a')).toBe(A);
    expect(store.getServerUrlForSubject(DRIVE_B)).toBe(B);
    store.injectFetch(async () => {
      throw new Error('No network in this test');
    });
    const collection = new CollectionBuilder(store)
      .setProperty(core.properties.parent)
      .setValue('atomic:folder-a')
      .build();
    expect(
      new URL(
        (
          collection as unknown as { buildSubject(page: number): string }
        ).buildSubject(0),
      ).origin,
    ).toBe(A);
    await collection.waitForReady().catch(() => undefined);
  });

  it('does not deduplicate a new route with an old in-flight read or apply its late error', async () => {
    const store = new Store({ serverUrl: A });
    store.setDriveServer(DRIVE_A, A);
    let release!: (response: Response) => void;
    const pending = new Promise<Response>(resolve => {
      release = resolve;
    });
    const fetcher = vi.fn(async (url: string | URL | Request) => {
      if (String(url).startsWith(A)) return pending;

      return new Response(
        JSON.stringify({ '@id': DRIVE_A, [core.properties.name]: 'New host' }),
        {
          headers: { 'Content-Type': 'application/ad+json' },
        },
      );
    });
    store.injectFetch(fetcher);
    const old = store
      .fetchResourceFromServer(DRIVE_A, { noWebSocket: true })
      .catch(e => e);
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalled());
    store.setDriveServer(DRIVE_A, B);
    const current = await store.fetchResourceFromServer(DRIVE_A, {
      noWebSocket: true,
    });
    release(new Response('Old host no longer has it', { status: 404 }));
    await old;

    expect(current.get(core.properties.name)).toBe('New host');
    expect(store.resources.get(DRIVE_A)?.error).toBeUndefined();
    expect(fetcher.mock.calls.some(([url]) => String(url).startsWith(B))).toBe(
      true,
    );
  });

  it('keeps route ownership across reloads, scoped to the signed-in account', async () => {
    const { store } = await testStore({ serverUrl: A });
    const owner = store.getAgent()!;
    store.setDriveServer(DRIVE_A, `${A}:8443`);
    const other = (await testStore()).store.getAgent()!;
    store.setAgent(other);
    expect(store.getServerUrlForSubject(DRIVE_A)).toBe(A);

    const reload = new Store({ serverUrl: B, agent: owner });
    expect(reload.getServerUrlForSubject('did:ad:drive-a')).toBe(`${A}:8443`);
    reload.setAgent(other);
    expect(reload.getServerUrlForSubject(DRIVE_A)).toBe(B);
  });

  it('does not let an old placement receipt complete an A-to-B-to-A migration', () => {
    const store = new Store({ serverUrl: A });
    store.setDriveServer(DRIVE_A, A);
    store.setDriveServer(DRIVE_B, B);
    const receipt = store.captureRoute(DRIVE_A);
    store.setDrive(DRIVE_B);
    expect(receipt.current()).toBe(true);
    store.setDriveServer(DRIVE_A, B);
    store.setDriveServer(DRIVE_A, A);
    expect(receipt.current()).toBe(false);
  });

  it('keeps concurrent drive reconciliation progress separate', () => {
    const store = new Store({ serverUrl: A });
    store.startDriveSync(DRIVE_A);
    store.startDriveSyncPull(DRIVE_B);
    store.finishDriveSync(DRIVE_A, 1, Date.now());
    expect(store.getSyncStatus().syncInProgress).toBe(true);
    expect(store.isDriveSyncPulling()).toBe(true);
    expect(store.hasCompletedDriveSyncFor(DRIVE_B)).toBe(false);
    store.finishDriveSync(DRIVE_B, 2, Date.now());
    expect(store.getSyncStatus().syncInProgress).toBe(false);
  });

  it('does not consume a queued edit when its old server acknowledges after migration', async () => {
    const { store, postCommitSpy } = await testStore({ serverUrl: A });
    const drive = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
    });
    await drive.save();
    const child = await store.newResource({ parent: drive.subject });
    await child.save();
    let release!: () => void;
    const blocked = new Promise<void>(resolve => {
      release = resolve;
    });
    postCommitSpy.mockImplementationOnce(async commit => {
      await blocked;

      return { ...commit, id: 'atomic:commit:late' };
    });
    await child.set(core.properties.name, 'Migrating edit', false);
    const save = child.save().catch(error => error);
    await vi.waitFor(() =>
      expect(postCommitSpy.mock.calls.length).toBeGreaterThanOrEqual(3),
    );
    store.setDriveServer(drive.subject, B);
    release();
    expect(await save).toBeInstanceOf(Error);
    expect(store.outbox.hasPending(child.subject)).toBe(true);
    store.setServerConnected(false);
  });

  it('adopts a vanity root as an alias while keeping the canonical drive identity', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.injectFetch(
      async () =>
        new Response(
          JSON.stringify({
            '@id': DRIVE_A,
            [core.properties.isA]: [server.classes.drive],
            [core.properties.name]: 'Tenant Alpha',
          }),
          { headers: { 'Content-Type': 'application/ad+json' } },
        ),
    );
    const drive = await store.fetchResourceFromServer(`${A}/`, {
      noWebSocket: true,
    });
    expect(drive.error).toBeUndefined();
    expect(drive.subject).toBe(DRIVE_A);
    expect(store.getServerUrlForSubject(DRIVE_A)).toBe(A);
    store.setDrive(`${A}/`);
    expect(store.getDrive()).toBe(DRIVE_A);
    store.setServerUrl(B);
    expect(store.getServerUrlForSubject(DRIVE_A)).toBe(A);
  });
});

describe('routing evidence from server reads', () => {
  it('does not let an unselected origin claim an unknown drive by pushing a snapshot', async () => {
    const { store } = await testStore({ serverUrl: A });
    const resource = new Resource('atomic:unsolicited');
    await resource.set(core.properties.isA, [server.classes.drive], false);

    expect(
      store.acceptsServerResource(
        resource.subject,
        B,
        resource.getLoroDoc()!.export({ mode: 'snapshot' }),
      ),
    ).toBe(false);
  });

  it.each(['primary', 'nested'])(
    'rejects a foreign HTTP %s resource claiming a known drive',
    async kind => {
      const store = new Store({ serverUrl: A, connect: false });
      store.setDriveServer(DRIVE_A, A, { connect: false });
      const forged = {
        '@id': DRIVE_A,
        [core.properties.isA]: [server.classes.drive],
        [core.properties.name]: 'Forged',
      };
      store.injectFetch(
        async () =>
          new Response(
            JSON.stringify(
              kind === 'primary'
                ? forged
                : {
                    '@id': `${B}/resource`,
                    'https://atomicdata.dev/properties/description': forged,
                  },
            ),
            { headers: { 'Content-Type': 'application/ad+json' } },
          ),
      );

      await expect(
        store.fetchResourceFromServer(
          kind === 'primary' ? `${B}/` : `${B}/resource`,
          { noWebSocket: true },
        ),
      ).rejects.toThrow(/destination/i);
      expect(store.getServerUrlForSubject(DRIVE_A)).toBe(A);
      expect(store.resources.get(DRIVE_A)?.get(core.properties.name)).not.toBe(
        'Forged',
      );
    },
  );

  it('remembers a cold query member on its owning drive through a migration', async () => {
    const store = new Store({ serverUrl: B, connect: false });
    store.setDriveServer(DRIVE_A, A, { connect: false });
    store.reportServerConnection(A, true);
    store.injectFetch(
      async () =>
        new Response(
          JSON.stringify({
            [core.properties.isA]: [collections.classes.collection],
            [collections.properties.members]: ['atomic:cold-member'],
            [collections.properties.totalMembers]: 1,
          }),
          { headers: { 'Content-Type': 'application/ad+json' } },
        ),
    );
    const query = await new CollectionBuilder(store)
      .setDrive(DRIVE_A)
      .setProperty(core.properties.isA)
      .setValue('atomic:class')
      .buildAndFetch();
    expect(await query.getAllMembers()).toEqual(['atomic:cold-member']);
    expect(store.getServerUrlForSubject('atomic:cold-member')).toBe(A);
    store.setDriveServer(DRIVE_A, 'https://moved.example', { connect: false });
    expect(store.getServerUrlForSubject('atomic:cold-member')).toBe(
      'https://moved.example',
    );
  });
  it('rejects an authoritative snapshot if placement changes while reading', async () => {
    const store = new Store({ serverUrl: A, connect: false });
    store.setDriveServer(DRIVE_A, A, { connect: false });
    let release!: (r: Response) => void;
    store.injectFetch(
      () =>
        new Promise<Response>(resolve => {
          release = resolve;
        }),
    );
    const read = store.readServerSnapshot(DRIVE_A);
    await vi.waitFor(() => expect(release).toBeDefined());
    store.setDriveServer(DRIVE_A, B, { connect: false });
    release(
      new Response(
        JSON.stringify({
          '@id': DRIVE_A,
          [core.properties.name]: 'Old placement',
        }),
        { headers: { 'Content-Type': 'application/ad+json' } },
      ),
    );
    await expect(read).rejects.toThrow(/changed|cancelled/i);
  });
});
