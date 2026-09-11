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
