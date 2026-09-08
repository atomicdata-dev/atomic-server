import { expect, it, vi } from 'vitest';
import { core, server } from '@tomic/react';
import { LegacyViewAdapter } from './legacyViewAdapter';

function fixture() {
  let receive: (event: MessageEvent) => void = () => {};
  vi.stubGlobal('window', {
    addEventListener: (_: string, listener: unknown) => {
      receive = listener as typeof receive;
    },
    removeEventListener: vi.fn(),
  });
  const target = { postMessage: vi.fn() };
  const frame = {
    contentWindow: target,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  };
  let callback: (resource: unknown) => void = () => {};
  let granted = true;
  const stop = vi.fn();
  const page = 'did:ad:page';
  const record = (subject: string) => ({
    subject,
    title: subject,
    get: () => undefined,
    getEntries: () => [[core.properties.name, subject]],
    hasClasses: (klass: string) =>
      subject === 'plugin' && klass === server.classes.plugin,
    set: vi.fn(),
    save: vi.fn(),
  });
  const rows = new Map([page, 'outside', 'plugin'].map(id => [id, record(id)]));
  const store = {
    getResource: vi.fn(async (id: string) => rows.get(id)),
    getResourceAncestry: async () => [],
    subscribe: vi.fn((_: string, listener: typeof callback) => {
      callback = listener;

      return stop;
    }),
  };
  const permission = vi.fn(async () => false);
  const navigate = vi.fn();
  const adapter = new LegacyViewAdapter({
    context: {
      resource: { subject: page, title: page, loading: false, props: {} },
      agent: 'user',
    },
    store: store as never,
    iFrame: frame as never,
    pluginResource: { get: () => 'plugin-agent' } as never,
    navigate,
    pickFile: async () => undefined,
    pickResource: async () => undefined,
    requestReadPermission: async () => granted,
    hasReadPermission: () => granted,
    requestWritePermission: permission,
  });
  const send = (type: string, args: unknown, source: unknown = target) =>
    receive({
      source,
      data: { type, requestId: 'request', args },
    } as MessageEvent);

  return {
    adapter,
    send,
    target,
    store,
    rows,
    permission,
    navigate,
    stop,
    notify: () => callback(rows.get('outside')),
    revoke: () => {
      granted = false;
    },
  };
}

it('retains permitted edits, refuses outside writes and refuses editing plugin code', async () => {
  const f = fixture();
  f.send('commit', {
    commit: {
      subject: 'did:ad:page',
      set: { [core.properties.name]: 'Updated' },
    },
  });
  await vi.waitFor(() =>
    expect(f.rows.get('did:ad:page')!.save).toHaveBeenCalledTimes(1),
  );
  f.send('commit', {
    commit: { subject: 'outside', set: { [core.properties.name]: 'No' } },
  });
  await vi.waitFor(() => expect(f.permission).toHaveBeenCalled());
  expect(f.rows.get('outside')!.save).not.toHaveBeenCalled();
  f.send('commit', { commit: { subject: 'plugin', destroy: true } });
  await vi.waitFor(() =>
    expect(f.target.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'unauthorized',
        message: 'Plugin cannot edit plugin resources',
      }),
      '*',
    ),
  );
  f.adapter.stopServer();
});

it('stops notifications after a grant is revoked and routes navigation through the host', async () => {
  const f = fixture();
  f.send('subscribe', { subject: 'outside' });
  await vi.waitFor(() => expect(f.store.subscribe).toHaveBeenCalledTimes(1));
  f.notify();
  await vi.waitFor(() =>
    expect(f.target.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'resource-notification' }),
      '*',
    ),
  );
  f.target.postMessage.mockClear();
  f.revoke();
  f.notify();
  await vi.waitFor(() => expect(f.stop).toHaveBeenCalledTimes(1));
  expect(f.target.postMessage).not.toHaveBeenCalled();
  f.send('navigate', { subject: 'did:ad:page' });
  await vi.waitFor(() => expect(f.navigate).toHaveBeenCalled());
  f.adapter.stopServer();
});

it('does not resume a write when its permission dialog outlives the view', async () => {
  const f = fixture();
  let allow!: (granted: boolean) => void;
  f.permission.mockImplementation(
    () =>
      new Promise(resolve => {
        allow = resolve;
      }),
  );
  f.send('commit', {
    commit: { subject: 'outside', set: { [core.properties.name]: 'Late' } },
  });
  await vi.waitFor(() => expect(f.permission).toHaveBeenCalled());
  f.adapter.stopServer();
  allow(true);
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(f.rows.get('outside')!.save).not.toHaveBeenCalled();
  expect(f.target.postMessage).not.toHaveBeenCalled();
});
