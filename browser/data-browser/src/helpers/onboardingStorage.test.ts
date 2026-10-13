import { expect, it, vi } from 'vitest';
import { checkOnboardingStorage } from './onboardingStorage';

it('waits for the actual database before allowing onboarding', async () => {
  let ready!: (value: boolean) => void;
  const db = {
    waitForInit: () =>
      new Promise<boolean>(resolve => {
        ready = resolve;
      }),
  };
  const store = { waitForClientDb: async () => true, getClientDb: () => db };
  const done = vi.fn();
  const result = checkOnboardingStorage(store).then(done);
  await Promise.resolve();
  expect(done).not.toHaveBeenCalled();
  ready(true);
  await result;
  expect(done).toHaveBeenCalledWith(undefined);
});

it('reports initialization failure before account creation', async () => {
  const store = {
    waitForClientDb: async () => true,
    getClientDb: () => ({
      waitForInit: async () => false,
      initError: new Error('Storage denied'),
    }),
  };
  await expect(checkOnboardingStorage(store)).rejects.toThrow('Storage denied');
});

it('does not hang indefinitely if no database attaches', async () => {
  const store = {
    waitForClientDb: async () => false,
    getClientDb: () => undefined,
  };
  await expect(checkOnboardingStorage(store)).rejects.toThrow();
});

it('times out a stalled worker rather than leaving an endless loading screen', async () => {
  vi.useFakeTimers();

  try {
    const store = {
      waitForClientDb: async () => true,
      getClientDb: () => ({
        waitForInit: () => new Promise<boolean>(() => {}),
      }),
    };
    const assertion = expect(checkOnboardingStorage(store)).rejects.toThrow(
      'taking too long',
    );
    await vi.advanceTimersByTimeAsync(20_000);
    await assertion;
  } finally {
    vi.useRealTimers();
  }
});

it('accepts a ready native node without waiting for a browser database', async () => {
  const store = {
    waitForClientDb: vi.fn(),
    getClientDb: vi.fn(),
    waitForServerConnected: vi.fn().mockResolvedValue(true),
  };
  const fetchNode = vi.fn().mockResolvedValue(
    new Response(JSON.stringify({ '@id': 'internal:/server' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );

  await checkOnboardingStorage(store, 'http://localhost:9883', fetchNode);

  expect(store.waitForClientDb).not.toHaveBeenCalled();
  expect(store.waitForServerConnected).toHaveBeenCalledWith(20_000);
  expect(fetchNode).toHaveBeenCalledWith(
    'http://localhost:9883/server',
    expect.objectContaining({
      headers: { Accept: 'application/json' },
    }),
  );
});

it('does not allow native onboarding while the node socket is disconnected', async () => {
  const store = {
    waitForClientDb: vi.fn(),
    getClientDb: vi.fn(),
    waitForServerConnected: vi.fn().mockResolvedValue(false),
  };
  const fetchNode = vi.fn().mockResolvedValue(
    new Response(JSON.stringify({ '@id': 'internal:/server' }), {
      status: 200,
    }),
  );

  await expect(
    checkOnboardingStorage(store, 'http://localhost:9883', fetchNode),
  ).rejects.toThrow('not connected');
});

it('uses the server when local storage was deliberately disabled', async () => {
  const store = {
    waitForClientDb: vi.fn(),
    getClientDb: vi.fn(),
    waitForServerConnected: vi.fn().mockResolvedValue(true),
  };
  await checkOnboardingStorage(store, undefined, fetch, false);
  expect(store.waitForClientDb).not.toHaveBeenCalled();
  expect(store.waitForServerConnected).toHaveBeenCalledWith(20_000);
});
