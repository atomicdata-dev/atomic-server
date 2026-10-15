import { afterEach, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { ViewStore } from './store';
import { isViewRequest } from './viewProtocol';

afterEach(() => {
  vi.unstubAllGlobals();
});

function frame() {
  const listeners: Array<(event: MessageEvent) => void> = [];
  const parent = { postMessage: vi.fn() };
  const window = {
    parent,
    addEventListener: (type: string, listener: (typeof listeners)[number]) =>
      type === 'message' && listeners.push(listener),
    removeEventListener: vi.fn(),
  };
  const reply = (data: unknown) =>
    listeners.forEach(listener =>
      listener({ source: parent, data } as unknown as MessageEvent),
    );

  return { window, reply, parent };
}

function driveAppStore(f: ReturnType<typeof frame>) {
  const source = readFileSync(
    new URL(
      '../../../server/src/plugins/assets/view-client.js',
      import.meta.url,
    ),
    'utf8',
  );

  return new Function(
    'window',
    'setTimeout',
    'clearTimeout',
    source.replace('export const store', 'const store') + '\nreturn store;',
  )(
    f.window,
    () => 0,
    () => undefined,
  );
}

const methods = (object: object) =>
  [
    ...Object.keys(object),
    ...Object.getOwnPropertyNames(Object.getPrototypeOf(object)),
  ]
    .filter(
      name =>
        name !== 'constructor' &&
        typeof (object as Record<string, unknown>)[name] === 'function',
    )
    .sort();

const shared = [
  'apply',
  'undo',
  'getContext',
  'getResource',
  'newResource',
  'query',
  'search',
  'subscribe',
];

it('gives a drive app and a packaged view one store API', () => {
  const f = frame();
  vi.stubGlobal('window', f.window);
  const packaged = new ViewStore();
  const app = driveAppStore(f);

  for (const name of shared) {
    expect(typeof app[name], name).toBe('function');
    expect(typeof (packaged as never)[name], name).toBe('function');
  }

  expect(methods(app.ui)).toEqual(methods(packaged.ui));
});

it.each(['packaged', 'drive app'])(
  'shapes a resource like @tomic/lib does: %s',
  async kind => {
    const f = frame();
    vi.stubGlobal('window', f.window);
    const store = kind === 'packaged' ? new ViewStore() : driveAppStore(f);

    const pending = store.getResource('https://x.dev/row');
    const request = f.parent.postMessage.mock.calls[0][0];
    expect(isViewRequest(request)).toBe(true);
    f.reply({
      type: 'atomic.view.response',
      version: 1,
      id: request.id,
      result: {
        subject: 'https://x.dev/row',
        title: 'Row',
        props: { 'https://atomicdata.dev/properties/isA': ['https://x.dev/C'] },
      },
    });
    const resource = await pending;

    expect(resource.title).toBe('Row');
    expect(resource.getClasses()).toEqual(['https://x.dev/C']);
    expect(resource.hasClasses('https://x.dev/C')).toBe(true);

    // Stages, then sends only what changed, removals apart.
    resource.set('https://x.dev/a', 1).remove('https://x.dev/b');
    void resource.save();
    const save = f.parent.postMessage.mock.calls[1][0];
    expect(save).toMatchObject({
      op: 'save',
      args: {
        subject: 'https://x.dev/row',
        propVals: { 'https://x.dev/a': 1 },
        remove: ['https://x.dev/b'],
      },
    });
  },
);

it('sends a query with its sort, filters and page as they are', () => {
  const f = frame();
  vi.stubGlobal('window', f.window);
  const query = {
    property: 'https://atomicdata.dev/properties/parent',
    value: 'https://x.dev/table',
    filters: [{ property: 'https://x.dev/done', value: 'false' }],
    sortBy: 'https://x.dev/due',
    sortDesc: true,
    pageSize: 25,
    page: 2,
  };

  for (const store of [new ViewStore(), driveAppStore(f)]) {
    void store.query(query);
    expect(f.parent.postMessage.mock.calls.at(-1)![0]).toMatchObject({
      op: 'query',
      args: query,
    });
  }
});

it('reduces a picked resource to its subject, whichever host answered', async () => {
  const f = frame();
  vi.stubGlobal('window', f.window);
  const store = new ViewStore();

  for (const answer of ['https://x.dev/a', { subject: 'https://x.dev/a' }]) {
    const pending = store.ui.pickResource();
    const request = f.parent.postMessage.mock.calls.at(-1)![0];
    f.reply({
      type: 'atomic.view.response',
      version: 1,
      id: request.id,
      result: answer,
    });
    expect(await pending).toBe('https://x.dev/a');
  }
});

it('hands a subscriber the fresh resource when its subject changes', async () => {
  const f = frame();
  vi.stubGlobal('window', f.window);
  const store = new ViewStore();
  const seen: string[] = [];
  store.subscribe('https://x.dev/row', r => seen.push(r.title));

  f.reply({
    type: 'atomic.view.change',
    version: 1,
    subject: 'https://x.dev/row',
    resource: { subject: 'https://x.dev/row', title: 'Renamed', props: {} },
  });
  await Promise.resolve();
  await Promise.resolve();

  expect(seen).toEqual(['Renamed']);
});

it('still notifies a drive app when the changed resource cannot be read', async () => {
  const f = frame();
  vi.stubGlobal('window', f.window);
  const store = driveAppStore(f);
  const calls: unknown[] = [];
  store.subscribe('https://x.dev/row', (resource: unknown) =>
    calls.push(resource),
  );
  f.reply({
    type: 'atomic.view.change',
    version: 1,
    subject: 'https://x.dev/row',
  });
  const get = f.parent.postMessage.mock.calls.at(-1)![0];
  expect(get.op).toBe('get');
  f.reply({
    type: 'atomic.view.response',
    version: 1,
    id: get.id,
    error: 'gone',
  });
  await new Promise(r => setTimeout(r, 0));

  expect(calls).toEqual([undefined]);
});
