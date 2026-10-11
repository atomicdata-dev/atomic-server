import { core, type Store } from '@tomic/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const load = () => import('./messageIndex');

const SOURCES = 'https://atomicdata.dev/properties/localSourceMessages';
const CONVERSATION = 'https://atomicdata.dev/properties/localConversation';

let saves = 0;

class FakeResource {
  destroyed = false;

  constructor(
    public subject: string,
    public props: Record<string, unknown>,
  ) {}

  get(prop: string) {
    return this.props[prop];
  }

  async set(prop: string, value: unknown) {
    this.props[prop] = value;
  }

  async save() {
    saves++;
  }

  async destroy() {
    this.destroyed = true;
  }
}

/** Just enough store: a registry, a substring search and exact filters. */
function fakeStore() {
  const resources = new Map<string, FakeResource>();
  const localOnly = new Set<string>();
  let counter = 0;

  const store = {
    getAgent: () => ({ subject: 'atomic:agent:me' }),
    isLocalOnlyDrive: (drive: string) => localOnly.has(drive),
    registerLocalOnlyDrive: (drive: string) => localOnly.add(drive),
    notifyError: vi.fn(),
    newResource: async (opts: {
      subject?: string;
      parent?: string;
      propVals: Record<string, unknown>;
    }) => {
      const resource = new FakeResource(
        opts.subject ?? `atomic:r${counter++}`,
        {
          ...opts.propVals,
          parent: opts.parent,
        },
      );
      resources.set(resource.subject, resource);

      return resource;
    },
    getResource: async (subject: string) => resources.get(subject),
    search: async (
      query: string,
      opts: { parents?: string; filters?: Record<string, string> },
    ) =>
      [...resources.values()]
        .filter(r => !r.destroyed && r.props.parent === opts.parents)
        .filter(r =>
          Object.entries(opts.filters ?? {}).every(
            ([k, v]) => r.props[k] === v,
          ),
        )
        .filter(r =>
          String(r.props[core.properties.name] ?? '')
            .toLowerCase()
            .includes(query.toLowerCase()),
        )
        .map(r => r.subject),
  };

  return { store: store as unknown as Store, resources, localOnly };
}

const chunks = (resources: Map<string, FakeResource>) =>
  [...resources.values()].filter(r => r.props[SOURCES] && !r.destroyed);

describe('messageIndex', () => {
  beforeEach(() => {
    saves = 0;
    const data = new Map<string, string>();

    vi.stubGlobal('localStorage', {
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => data.set(key, value),
    });
    // Each test starts a session: the module remembers what it asked for.
    vi.resetModules();
  });

  it('keeps decrypted text in a local-only drive', async () => {
    const index = await load();
    const { store, localOnly } = fakeStore();

    await index.indexMessage(
      store,
      'atomic:m1',
      'atomic:c1',
      'zeppelin at noon',
    );

    expect(localOnly.size).toBe(1);
    expect(await index.searchMessages(store, 'zeppelin')).toEqual([
      {
        conversation: 'atomic:c1',
        message: 'atomic:m1',
        text: 'zeppelin at noon',
      },
    ]);
  });

  it('copies a message once, also when asked again or in a new session', async () => {
    const index = await load();
    const { store, resources } = fakeStore();

    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', 'zeppelin');
    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', 'zeppelin');

    expect(chunks(resources)).toHaveLength(1);
    expect(chunks(resources)[0].props[SOURCES]).toEqual(['atomic:m1']);

    // A reload forgets the session but not the drive.
    vi.resetModules();
    const again = await load();
    await again.indexMessage(store, 'atomic:m1', 'atomic:c1', 'zeppelin');
    await again.indexMessage(store, 'atomic:m2', 'atomic:c1', 'zeppelin 2');

    expect(chunks(resources)).toHaveLength(1);
    expect(chunks(resources)[0].props[SOURCES]).toEqual([
      'atomic:m1',
      'atomic:m2',
    ]);
  });

  it('does not store empty text', async () => {
    const index = await load();
    const { store, resources } = fakeStore();

    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', '   ');

    expect(resources.size).toBe(0);
  });

  it('keeps line i for message i, also for multi-line text', async () => {
    const index = await load();
    const { store, resources } = fakeStore();

    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', 'first\nsecond');
    await index.indexMessage(store, 'atomic:m2', 'atomic:c1', 'zeppelin');

    const [chunk] = chunks(resources);

    expect(chunk.props[core.properties.name]).toBe('first second\nzeppelin');
    expect(await index.searchMessages(store, 'zeppelin')).toEqual([
      { conversation: 'atomic:c1', message: 'atomic:m2', text: 'zeppelin' },
    ]);
  });

  it('rolls over to a new chunk after CHUNK_SIZE messages', async () => {
    const index = await load();
    const { store, resources } = fakeStore();
    const total = index.CHUNK_SIZE * 2 + 5;

    await Promise.all(
      Array.from({ length: total }, (_, i) =>
        index.indexMessage(store, `atomic:m${i}`, 'atomic:c1', `line ${i}`),
      ),
    );

    const all = chunks(resources);

    expect(all.map(c => (c.props[SOURCES] as string[]).length)).toEqual([
      index.CHUNK_SIZE,
      index.CHUNK_SIZE,
      5,
    ]);
    expect(new Set(all.map(c => c.subject)).size).toBe(3);

    const hit = (await index.searchMessages(store, 'line 300'))[0];

    expect(hit.message).toBe('atomic:m300');
    expect(hit.text).toBe('line 300');
  });

  it('writes messages queued together with one save per chunk', async () => {
    const index = await load();
    const { store, resources } = fakeStore();

    await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        index.indexMessage(store, `atomic:m${i}`, 'atomic:c1', `line ${i}`),
      ),
    );

    // The drive's own save, and one for all fifty messages.
    expect(saves).toBe(2);
    expect(chunks(resources)).toHaveLength(1);
    expect(chunks(resources)[0].props[SOURCES]).toHaveLength(50);

    // A later pass is one more save, of the same chunk.
    saves = 0;
    await Promise.all([
      index.indexMessage(store, 'atomic:m50', 'atomic:c1', 'line 50'),
      index.indexMessage(store, 'atomic:m51', 'atomic:c1', 'line 51'),
    ]);
    expect(saves).toBe(1);

    // Crossing the chunk boundary: one save for the old chunk, one for the new.
    saves = 0;
    await Promise.all(
      Array.from({ length: index.CHUNK_SIZE }, (_, i) =>
        index.indexMessage(store, `atomic:n${i}`, 'atomic:c1', `more ${i}`),
      ),
    );
    expect(saves).toBe(2);
  });

  it('reports one match per conversation and nothing for an empty query', async () => {
    const index = await load();
    const { store } = fakeStore();

    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', 'zeppelin one');
    await index.indexMessage(store, 'atomic:m2', 'atomic:c1', 'zeppelin two');
    await index.indexMessage(store, 'atomic:m3', 'atomic:c2', 'zeppelin three');

    expect(await index.searchMessages(store, 'zeppelin')).toHaveLength(2);
    expect(await index.searchMessages(store, '  ')).toEqual([]);
  });

  it('forgets every chunk of the conversation that is left, and only those', async () => {
    const index = await load();
    const { store, resources } = fakeStore();

    for (let i = 0; i < index.CHUNK_SIZE + 1; i++) {
      await index.indexMessage(store, `atomic:m${i}`, 'atomic:c1', 'zeppelin');
    }

    await index.indexMessage(store, 'atomic:x1', 'atomic:c2', 'zeppelin two');
    expect(chunks(resources)).toHaveLength(3);

    await index.forgetConversation(store, 'atomic:c1');

    expect(chunks(resources).map(r => r.props[CONVERSATION])).toEqual([
      'atomic:c2',
    ]);
    // Opening the conversation again indexes it again.
    await index.indexMessage(store, 'atomic:m0', 'atomic:c1', 'zeppelin');
    expect(chunks(resources)).toHaveLength(2);
  });
});
