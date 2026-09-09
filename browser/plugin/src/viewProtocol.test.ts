import { afterEach, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { RPCClient } from './rpc';
import { isViewRequest, viewRequest } from './viewProtocol';

afterEach(() => {
  vi.unstubAllGlobals();
});

function frame() {
  const listeners: Array<(event: MessageEvent) => void> = [];
  const parent = { postMessage: vi.fn() };
  const window = {
    parent,
    addEventListener: (_: string, listener: (typeof listeners)[number]) =>
      listeners.push(listener),
    removeEventListener: vi.fn(),
  };
  const reply = (data: unknown, source: unknown = parent) =>
    listeners.forEach(listener => listener({ source, data } as MessageEvent));

  return { window, reply, parent };
}

it('validates version, correlation id, operation and argument envelope', () => {
  const valid = viewRequest('one', 'get', { subject: 'row' });
  expect(isViewRequest(valid)).toBe(true);
  for (const change of [
    { version: 2 },
    { id: NaN },
    { id: '' },
    { op: 'sign-as-owner' },
    { args: [] },
    { args: null },
  ])
    expect(isViewRequest({ ...valid, ...change })).toBe(false);
});

it.each(['packaged', 'generated'])(
  'uses the same resource contract and trusts only the parent: %s',
  async kind => {
    const f = frame();
    vi.stubGlobal('window', f.window);
    let getResource: (
      subject: string,
    ) => Promise<{ subject: string; props: unknown }>;

    if (kind === 'packaged') {
      const client = new RPCClient();
      getResource = subject => client.getResource(subject);
    } else {
      const source = readFileSync(
        new URL(
          '../../../server/src/plugins/assets/view-client.js',
          import.meta.url,
        ),
        'utf8',
      );
      const store = new Function(
        'window',
        'setTimeout',
        source.replace('export const store', 'const store') + '\nreturn store;',
      )(f.window, () => 0);
      getResource = subject => store.getResource(subject);
    }

    const pending = getResource('row');
    const request = f.parent.postMessage.mock.calls[0][0];
    expect(isViewRequest(request)).toBe(true);
    expect(request).toMatchObject({ op: 'get', args: { subject: 'row' } });
    const result = {
      subject: 'row',
      props: { name: 'Shared shape' },
      title: 'Shared shape',
      loading: false,
    };
    const response = {
      type: 'atomic.view.response',
      version: 1,
      id: request.id,
      result,
    };
    let settled = false;
    void pending.then(() => {
      settled = true;
    });
    f.reply(response, {});
    await Promise.resolve();
    expect(settled).toBe(false);
    f.reply(response);
    expect(await pending).toMatchObject({
      subject: 'row',
      props: result.props,
    });
  },
);
