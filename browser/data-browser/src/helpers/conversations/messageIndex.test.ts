import { core, type Store } from '@tomic/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const load = () => import('./messageIndex');

const SOURCE = 'https://atomicdata.dev/properties/localSourceMessage';
const CONVERSATION = 'https://atomicdata.dev/properties/localConversation';

class FakeResource {
  destroyed = false;

  constructor(
    public subject: string,
    public props: Record<string, unknown>,
  ) {}

  get(prop: string) {
    return this.props[prop];
  }

  async save() {}

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
      parent?: string;
      propVals: Record<string, unknown>;
    }) => {
      const resource = new FakeResource(`atomic:r${counter++}`, {
        ...opts.propVals,
        parent: opts.parent,
      });
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

const copies = (resources: Map<string, FakeResource>) =>
  [...resources.values()].filter(r => r.props[SOURCE]);

describe('messageIndex', () => {
  beforeEach(() => {
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
      { conversation: 'atomic:c1', text: 'zeppelin at noon' },
    ]);
  });

  it('copies a message once, also when asked again', async () => {
    const index = await load();
    const { store, resources } = fakeStore();

    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', 'zeppelin');
    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', 'zeppelin');

    expect(copies(resources)).toHaveLength(1);
  });

  it('does not store empty text', async () => {
    const index = await load();
    const { store, resources } = fakeStore();

    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', '   ');

    expect(resources.size).toBe(0);
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

  it('forgets only the conversation that is left', async () => {
    const index = await load();
    const { store, resources } = fakeStore();

    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', 'zeppelin one');
    await index.indexMessage(store, 'atomic:m2', 'atomic:c2', 'zeppelin two');
    await index.forgetConversation(store, 'atomic:c1');

    const left = copies(resources).filter(r => !r.destroyed);

    expect(left.map(r => r.props[CONVERSATION])).toEqual(['atomic:c2']);
    // Opening the conversation again indexes it again.
    await index.indexMessage(store, 'atomic:m1', 'atomic:c1', 'zeppelin one');
    expect(copies(resources).filter(r => !r.destroyed)).toHaveLength(2);
  });
});
