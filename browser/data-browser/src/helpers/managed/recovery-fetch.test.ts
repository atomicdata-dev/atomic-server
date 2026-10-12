// @wc-ignore-file
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { getRecoverySecret, getUnlockableRecoverySecret } from './recovery';
import { getManagedAccount } from './session';
import { managedFetch, getManagedApiBase } from './api';

vi.mock('./session', () => ({ getManagedAccount: vi.fn() }));
vi.mock('./api', () => ({ managedFetch: vi.fn(), getManagedApiBase: vi.fn() }));

beforeEach(() => {
  vi.mocked(getManagedAccount).mockResolvedValue({ email: 'one@example.com' });
  vi.mocked(getManagedApiBase).mockReturnValue('https://portal.example/api');
  vi.mocked(managedFetch).mockReset();
});

afterEach(() => vi.useRealTimers());

it.each([undefined, '120', 'invalid'])(
  'backs off repeated 429 reads (Retry-After: %s)',
  async retryAfter => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-22T12:00:00Z'));
    vi.mocked(getManagedApiBase).mockReturnValue(
      `https://rate-${retryAfter}.example/api`,
    );
    vi.mocked(managedFetch).mockResolvedValue(
      new Response(null, {
        status: 429,
        headers: retryAfter ? { 'Retry-After': retryAfter } : {},
      }),
    );
    await expect(getRecoverySecret()).rejects.toThrow();

    for (let i = 0; i < 10; i++) {
      await expect(getRecoverySecret()).rejects.toThrow();
    }

    expect(managedFetch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(retryAfter === '120' ? 120_000 : 60_000);
    vi.mocked(managedFetch).mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    expect(await getRecoverySecret()).toBeNull();
    expect(managedFetch).toHaveBeenCalledTimes(2);
  },
);

it('shares concurrent recovery reads without caching settled responses', async () => {
  let resolve!: (response: Response) => void;
  vi.mocked(managedFetch).mockImplementation(
    () =>
      new Promise(done => {
        resolve = done;
      }),
  );
  const first = getRecoverySecret();
  const second = getRecoverySecret();
  await vi.waitFor(() => expect(managedFetch).toHaveBeenCalledTimes(1));
  resolve(new Response(null, { status: 204 }));
  expect(await Promise.all([first, second])).toEqual([null, null]);
  vi.mocked(managedFetch).mockResolvedValue(
    new Response(null, { status: 204 }),
  );
  await getRecoverySecret();
  expect(managedFetch).toHaveBeenCalledTimes(2);
});

it('does not share reads between accounts or API origins', async () => {
  const resolve: ((response: Response) => void)[] = [];
  vi.mocked(managedFetch).mockImplementation(
    () =>
      new Promise(done => {
        resolve.push(done);
      }),
  );
  const first = getRecoverySecret();
  await vi.waitFor(() => expect(managedFetch).toHaveBeenCalledTimes(1));
  vi.mocked(getManagedAccount).mockResolvedValue({ email: 'two@example.com' });
  const second = getRecoverySecret();
  await vi.waitFor(() => expect(managedFetch).toHaveBeenCalledTimes(2));
  vi.mocked(getManagedApiBase).mockReturnValue('https://other.example/api');
  const third = getRecoverySecret();
  await vi.waitFor(() => expect(managedFetch).toHaveBeenCalledTimes(3));
  resolve.forEach(done => done(new Response(null, { status: 204 })));
  await Promise.all([first, second, third]);
});

it('retries a failed read and makes no request while signed out', async () => {
  vi.mocked(managedFetch).mockRejectedValueOnce(new Error('offline'));
  await expect(getRecoverySecret()).rejects.toThrow('offline');
  vi.mocked(managedFetch).mockResolvedValue(
    new Response(null, { status: 204 }),
  );
  expect(await getRecoverySecret()).toBeNull();
  vi.mocked(getManagedAccount).mockResolvedValue(null);
  expect(await getRecoverySecret()).toBeNull();
  expect(managedFetch).toHaveBeenCalledTimes(2);
});

it('matches a backup saved under the legacy did:ad: spelling of the agent', async () => {
  const backup = { agent_subject: 'did:ad:agent:abc', wrappers: [] };
  vi.mocked(managedFetch).mockResolvedValue(
    new Response(JSON.stringify(backup), { status: 200 }),
  );
  expect(await getUnlockableRecoverySecret('atomic:agent:abc')).toMatchObject(
    backup,
  );
});

it('keeps one cached backup per account when its agent changes', async () => {
  const items = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => items.get(key) ?? null,
    setItem: (key: string, value: string) => items.set(key, value),
    removeItem: (key: string) => items.delete(key),
  });
  const backup = (agent: string, owner: string) => ({
    owner_email: owner,
    agent_subject: agent,
    wrappers: [],
    created_at: 1,
    updated_at: 1,
  });
  items.set(
    'atomic.recovery.backups',
    JSON.stringify([
      backup('did:ad:agent:old', 'one@example.com'),
      backup('did:ad:agent:other', 'two@example.com'),
    ]),
  );
  vi.mocked(getManagedApiBase).mockReturnValue('https://cache.example/api');
  vi.mocked(managedFetch).mockResolvedValue(
    Response.json(backup('did:ad:agent:new', 'one@example.com')),
  );

  await getRecoverySecret();

  const cached = JSON.parse(items.get('atomic.recovery.backups')!) as {
    agent_subject: string;
  }[];
  expect(cached.map(entry => entry.agent_subject)).toEqual([
    'did:ad:agent:other',
    'did:ad:agent:new',
  ]);
  vi.unstubAllGlobals();
});
