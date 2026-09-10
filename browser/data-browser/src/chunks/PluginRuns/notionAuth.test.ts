import { afterEach, expect, it, vi } from 'vitest';
import { waitForNotion, waitForManagedNotion } from './notionAuth';
vi.mock('@tomic/lib', () => ({ signRequest: vi.fn(async () => ({})) }));
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
it('accepts only the expected origin, popup and state, then removes the listener', async () => {
  const window = new EventTarget();
  vi.stubGlobal('window', window);
  const popup = { closed: false, close: vi.fn() } as unknown as Window;
  const abort = new AbortController();
  let settled = false;
  const waiting = waitForNotion(
    popup,
    'https://atomic.test',
    'expected',
    abort.signal,
  ).then(v => {
    settled = true;

    return v;
  });

  const send = (origin: string, source: unknown, state: string) => {
    const e = new Event('message');
    Object.assign(e, {
      origin,
      source,
      data: {
        type: 'atomic-notion-oauth',
        state,
        code: 'temporary-code',
        error: null,
      },
    });
    window.dispatchEvent(e);
  };

  send('https://evil.test', popup, 'expected');
  send('https://atomic.test', {}, 'expected');
  send('https://atomic.test', popup, 'wrong');
  await Promise.resolve();
  expect(settled).toBe(false);
  send('https://atomic.test', popup, 'expected');
  expect(await waiting).toEqual({ code: 'temporary-code', error: null });
  expect(popup.close).toHaveBeenCalledTimes(1);
  send('https://atomic.test', popup, 'expected');
  expect(popup.close).toHaveBeenCalledTimes(1);
});
it('closing a popup cancels the attempt and permits retry', async () => {
  vi.useFakeTimers();
  vi.stubGlobal('window', new EventTarget());
  const popup = { closed: false, close: vi.fn() };
  const waiting = waitForNotion(
    popup as unknown as Window,
    'https://atomic.test',
    'state',
    new AbortController().signal,
  );
  const rejected = expect(waiting).rejects.toThrow('cancelled');
  popup.closed = true;
  await vi.advanceTimersByTimeAsync(500);
  await rejected;
  expect(popup.close).toHaveBeenCalledOnce();
});
it('unmount aborts the popup listener', async () => {
  vi.stubGlobal('window', new EventTarget());
  const popup = { closed: false, close: vi.fn() } as unknown as Window;
  const controller = new AbortController();
  const waiting = waitForNotion(
    popup,
    'https://atomic.test',
    'state',
    controller.signal,
  );
  const rejected = expect(waiting).rejects.toThrow('cancelled');
  controller.abort();
  await rejected;
  expect(popup.close).toHaveBeenCalledOnce();
});

it('managed authorization polls only its host and returns no credential payload', async () => {
  vi.useFakeTimers();
  const fetchMock = vi
    .fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({ pending: true })))
    .mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          id: 'connection',
          name: 'Workspace',
          workspace: 'workspace',
        }),
      ),
    );
  vi.stubGlobal('fetch', fetchMock);
  const store = {
    getAgent: () => ({}),
    getServerUrl: () => 'http://localhost:9898',
  } as unknown as Parameters<typeof waitForManagedNotion>[0];
  const popup = { closed: false, close: vi.fn() } as unknown as Window;
  const result = waitForManagedNotion(
    store,
    'drive',
    'state',
    popup,
    new AbortController().signal,
  );
  await vi.advanceTimersByTimeAsync(1000);
  expect(await result).toMatchObject({ id: 'connection' });
  expect(fetchMock).toHaveBeenCalledTimes(2);

  for (const [url, request] of fetchMock.mock.calls) {
    expect(url).toBe('http://localhost:9898/integration-oauth/notion/finish');
    expect(JSON.parse(request.body)).toEqual({
      drive: 'drive',
      state: 'state',
    });
  }

  expect(popup.close).toHaveBeenCalledOnce();
});
it('managed authorization aborts without starting retrieval', async () => {
  const controller = new AbortController();
  controller.abort();
  const popup = { closed: false, close: vi.fn() } as unknown as Window;
  const store = {} as Parameters<typeof waitForManagedNotion>[0];
  await expect(
    waitForManagedNotion(store, 'drive', 'state', popup, controller.signal),
  ).rejects.toThrow('cancelled');
  expect(popup.close).toHaveBeenCalledOnce();
});
