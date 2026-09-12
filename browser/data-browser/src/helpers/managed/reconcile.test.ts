import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import {
  evaluateServerReconciliation,
  evaluateIdentityReconciliation,
  connectHostedDrive,
  localAgentIsDisposable,
} from './reconcile';
import type { ManagedEnrollmentSummary } from './enrollmentApi';

/**
 * `evaluateServerReconciliation` calls `getManagedAccount()` /
 * `getManagedEnrollments()` internally (both plain `fetch` wrappers against
 * the control plane) rather than taking them as params — mirrors
 * `evaluateIdentityReconciliation`. Mock `fetch` by URL suffix, same
 * approach as `cloudSync.test.ts`.
 */
function mockFetch(opts: {
  account?: { email: string } | null;
  enrollments?: ManagedEnrollmentSummary[];
}) {
  globalThis.fetch = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);

    if (url.endsWith('/me')) {
      if (!opts.account) {
        return Promise.resolve({ status: 401, ok: false } as Response);
      }

      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(opts.account),
      } as Response);
    }

    if (url.endsWith('/sync-enrollments')) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(opts.enrollments ?? []),
      } as Response);
    }

    throw new Error(`Unexpected fetch: ${url}`);
  }) as typeof fetch;
}

function enrollment(
  overrides: Partial<ManagedEnrollmentSummary>,
): ManagedEnrollmentSummary {
  return {
    drive_subject: 'did:ad:drive1',
    agent_subject: 'did:ad:agent:abc',
    status: 'Active',
    http_origin: 'https://node1.atomicserver.eu',
    ...overrides,
  };
}

describe('evaluateServerReconciliation', () => {
  beforeEach(() =>
    vi.stubEnv('VITE_MANAGED_API_BASE', 'https://portal.example/api'),
  );
  afterEach(() => vi.unstubAllEnvs());
  const realFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it('connects the restored drive before reading it and clears local-only routing', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({})],
    });
    const events: string[] = [];
    const store = {
      waitForServerConnected: vi.fn().mockResolvedValue(true),
      setServerUrl: (url: string) => events.push(url),
      unregisterLocalOnlyDrive: (drive: string) => events.push(drive),
    };
    const persist = vi.fn();
    expect(await connectHostedDrive(store, 'did:ad:drive1', persist)).toBe(
      true,
    );
    expect(events).toEqual(['did:ad:drive1', 'https://node1.atomicserver.eu']);
    expect(persist).toHaveBeenCalledWith('https://node1.atomicserver.eu');
  });

  it.each(['Pending', 'Disabled'])(
    'does not connect a %s placement',
    async status => {
      mockFetch({
        account: { email: 'a@example.com' },
        enrollments: [enrollment({ status })],
      });
      const store = {
        waitForServerConnected: vi.fn().mockResolvedValue(true),
        setServerUrl: vi.fn(),
        unregisterLocalOnlyDrive: vi.fn(),
      };
      expect(await connectHostedDrive(store, 'did:ad:drive1', vi.fn())).toBe(
        false,
      );
      expect(store.setServerUrl).not.toHaveBeenCalled();
    },
  );

  it('does not switch to another subscribed drive', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({})],
    });
    const store = {
      waitForServerConnected: vi.fn(),
      setServerUrl: vi.fn(),
      unregisterLocalOnlyDrive: vi.fn(),
    };
    expect(await connectHostedDrive(store, 'did:ad:other', vi.fn())).toBe(
      false,
    );
    expect(store.setServerUrl).not.toHaveBeenCalled();
  });

  it('does not switch servers when discovery completes after its deadline', async () => {
    let resolve!: (response: Response) => void;
    globalThis.fetch = vi.fn(
      () =>
        new Promise<Response>(done => {
          resolve = done;
        }),
    );
    const store = {
      waitForServerConnected: vi.fn(),
      setServerUrl: vi.fn(),
      unregisterLocalOnlyDrive: vi.fn(),
    };
    expect(await connectHostedDrive(store, 'did:ad:drive1', vi.fn(), 1)).toBe(
      false,
    );
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({})],
    });
    resolve(new Response(JSON.stringify({ email: 'a@example.com' })));
    await new Promise(done => setTimeout(done, 0));
    expect(store.setServerUrl).not.toHaveBeenCalled();
  });

  it('is ok with no managed session (self-hosted / local-only)', async () => {
    mockFetch({ account: null });

    const result = await evaluateServerReconciliation(
      'https://app.atomicserver.eu',
      'did:ad:drive1',
    );

    expect(result).toEqual({ ok: true });
  });

  it('is ok when there are no enrollments to match against', async () => {
    mockFetch({ account: { email: 'a@example.com' }, enrollments: [] });

    const result = await evaluateServerReconciliation(
      'https://app.atomicserver.eu',
      'did:ad:drive1',
    );

    expect(result).toEqual({ ok: true });
  });

  it('is ok when the current serverUrl already matches the enrollment origin', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({})],
    });

    const result = await evaluateServerReconciliation(
      'https://node1.atomicserver.eu',
      'did:ad:drive1',
    );

    expect(result).toEqual({ ok: true });
  });

  it('flags a mismatch and reports the expected origin', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({})],
    });

    const result = await evaluateServerReconciliation(
      'https://app.atomicserver.eu',
      'did:ad:drive1',
    );

    expect(result).toEqual({
      ok: false,
      expectedOrigin: 'https://node1.atomicserver.eu',
    });
  });

  it('ignores a disabled enrollment for the same drive', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({ status: 'Disabled' })],
    });

    const result = await evaluateServerReconciliation(
      'https://app.atomicserver.eu',
      'did:ad:drive1',
    );

    expect(result).toEqual({ ok: true });
  });

  it('resolves via the sole candidate when no drive is in view yet', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({})],
    });

    const result = await evaluateServerReconciliation(
      'https://app.atomicserver.eu',
      undefined,
    );

    expect(result).toEqual({
      ok: false,
      expectedOrigin: 'https://node1.atomicserver.eu',
    });
  });

  it('does not guess when no drive is in view and there are multiple candidates', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [
        enrollment({ drive_subject: 'did:ad:drive1' }),
        enrollment({
          drive_subject: 'did:ad:drive2',
          http_origin: 'https://node2.atomicserver.eu',
        }),
      ],
    });

    const result = await evaluateServerReconciliation(
      'https://app.atomicserver.eu',
      undefined,
    );

    expect(result).toEqual({ ok: true });
  });

  it('keeps the source server when placement exists but no data has arrived', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({ status: 'Pending', resource_count: 0 })],
    });
    expect(
      await evaluateServerReconciliation(
        'https://source.example',
        'did:ad:drive1',
      ),
    ).toEqual({ ok: true });
  });

  it('is ok when the matching enrollment has no http_origin yet', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({ http_origin: null })],
    });

    const result = await evaluateServerReconciliation(
      'https://app.atomicserver.eu',
      'did:ad:drive1',
    );

    expect(result).toEqual({ ok: true });
  });

  it('is ok (does not throw) when http_origin is malformed', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({ http_origin: 'not-a-url' })],
    });

    const result = await evaluateServerReconciliation(
      'https://app.atomicserver.eu',
      'did:ad:drive1',
    );

    expect(result).toEqual({ ok: true });
  });

  it('compares by origin, ignoring a trailing slash or path', async () => {
    mockFetch({
      account: { email: 'a@example.com' },
      enrollments: [enrollment({})],
    });

    const result = await evaluateServerReconciliation(
      'https://node1.atomicserver.eu/app/show?subject=x',
      'did:ad:drive1',
    );

    expect(result).toEqual({ ok: true });
  });
});

describe('localAgentIsDisposable', () => {
  const personalDrive = 'https://atomicdata.dev/properties/personalDrive';

  function reader(resource: {
    error?: unknown;
    props?: Record<string, unknown>;
  }) {
    return {
      getResource: () =>
        Promise.resolve({
          error: resource.error,
          get: (property: string) => resource.props?.[property],
        }),
    };
  }

  it('keeps an agent that has a workspace', async () => {
    const store = reader({ props: { [personalDrive]: 'did:ad:drive1' } });

    expect(await localAgentIsDisposable(store, 'did:ad:agent:a')).toBe(false);
  });

  it('treats a guest (no personal drive) as disposable', async () => {
    expect(
      await localAgentIsDisposable(reader({ props: {} }), 'did:ad:agent:a'),
    ).toBe(true);
  });

  it('treats an agent whose resource cannot load as disposable', async () => {
    expect(
      await localAgentIsDisposable(
        reader({ error: new Error('nope') }),
        'did:ad:agent:a',
      ),
    ).toBe(true);
  });

  it('treats a throwing store as disposable rather than blocking', async () => {
    const store = { getResource: () => Promise.reject(new Error('down')) };

    expect(await localAgentIsDisposable(store, 'did:ad:agent:a')).toBe(true);
  });
});

it('shares the account check within one identity reconciliation', async () => {
  vi.stubEnv('VITE_MANAGED_API_BASE', 'https://portal.example/api');
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async input => {
      const url = String(input);
      if (url.endsWith('/me'))
        return Response.json({ email: 'one@example.com' });
      if (url.endsWith('/recovery-secret'))
        return new Response(null, { status: 204 });
      if (url.endsWith('/sync-enrollments')) return Response.json([]);
      throw new Error(`Unexpected request ${url}`);
    });

  try {
    await expect(
      evaluateIdentityReconciliation(undefined),
    ).resolves.toMatchObject({ ok: true });
    expect(
      fetcher.mock.calls.filter(([url]) => String(url).endsWith('/me')),
    ).toHaveLength(1);
  } finally {
    fetcher.mockRestore();
    vi.unstubAllEnvs();
  }
});
