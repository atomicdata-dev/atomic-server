import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as Sentry from '@sentry/react';
import { StoreEvents } from '@tomic/react';
import {
  agentPseudonym,
  countRepeatedEvents,
  identifyAgentInSentry,
  initSentry,
  reportRepeatedCommitFailures,
  reportSyncProblem,
  reportUserFacingFailure,
} from './sentry';
vi.mock('@sentry/react', () => ({
  init: vi.fn(),
  browserSessionIntegration: vi.fn(() => ({ name: 'BrowserSession' })),
  isEnabled: vi.fn(() => true),
  captureMessage: vi.fn(),
  getClient: vi.fn(() => undefined),
  setUser: vi.fn(),
}));
describe('Sentry configuration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal('__APP_VERSION__', 'test');
    vi.stubGlobal('__GIT_COMMIT__', 'abc123');
    vi.stubEnv('VITE_SENTRY_DSN', 'https://public@example.com/123');
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });
  it('initializes packaged WebViews without injected server configuration', () => {
    vi.stubGlobal('window', {});
    vi.stubEnv('VITE_SENTRY_ENVIRONMENT', 'staging');
    initSentry();
    expect(Sentry.init).toHaveBeenCalledWith(
      expect.objectContaining({
        dsn: 'https://public@example.com/123',
        environment: 'staging',
        release: 'atomic-data-browser@test+abc123',
      }),
    );
  });
  it('allows a runtime empty DSN to disable a configured build', () => {
    vi.stubGlobal('window', { __ATOMIC_SENTRY__: { dsn: '' } });
    initSentry();
    expect(Sentry.init).not.toHaveBeenCalled();
  });
  it('attributes reports to the runtime environment and exact build', () => {
    vi.stubGlobal('window', {
      __ATOMIC_SENTRY__: {
        dsn: 'https://runtime@example.com/456',
        environment: 'staging',
      },
    });
    initSentry();
    expect(Sentry.init).toHaveBeenCalledWith(
      expect.objectContaining({
        dsn: 'https://runtime@example.com/456',
        environment: 'staging',
        release: 'atomic-data-browser@test+abc123',
        sendDefaultPii: false,
        tracesSampleRate: 0,
        integrations: [{ name: 'BrowserSession' }],
      }),
    );
    expect(Sentry.browserSessionIntegration).toHaveBeenCalledWith({
      lifecycle: 'page',
    });
  });
  it('relays through the tunnel the server injects', () => {
    vi.stubGlobal('window', {
      __ATOMIC_SENTRY__: {
        dsn: 'https://runtime@example.com/456',
        environment: 'production',
        tunnel: '/api/client-reports',
      },
    });
    initSentry();
    expect(Sentry.init).toHaveBeenCalledWith(
      expect.objectContaining({ tunnel: '/api/client-reports' }),
    );
  });
  it('stays silent on a dev server', () => {
    vi.stubGlobal('window', {});
    vi.stubEnv('VITE_SENTRY_ENVIRONMENT', '');
    vi.stubEnv('DEV', true);
    initSentry();
    expect(Sentry.init).not.toHaveBeenCalled();
  });
  it('still reports from a local build that asks for it', () => {
    vi.stubGlobal('window', {});
    vi.stubEnv('DEV', true);
    vi.stubEnv('VITE_SENTRY_ENVIRONMENT', 'staging');
    initSentry();
    expect(Sentry.init).toHaveBeenCalledWith(
      expect.objectContaining({ environment: 'staging' }),
    );
  });
  it('groups repeated commit failures by server and message, not by resource', () => {
    let handler: ((failure: unknown) => void) | undefined;
    const store = {
      on: vi.fn((event: string, cb: (failure: unknown) => void) => {
        if (event === StoreEvents.CommitRepeatedlyFailing) handler = cb;

        return () => {};
      }),
    };
    reportRepeatedCommitFailures(store as never);
    handler?.({
      subject: 'atomic:abc',
      error: new Error('Parent of atomic:abc (atomic:def) not found'),
      failures: 4,
      server: 'https://node1.example',
    });
    expect(Sentry.captureMessage).toHaveBeenCalledWith(
      'Commit keeps failing: Parent of <id> (<id>) not found',
      expect.objectContaining({
        fingerprint: [
          'commit-keeps-failing',
          'https://node1.example',
          'Parent of <id> (<id>) not found',
        ],
        tags: expect.objectContaining({
          error_kind: 'Parent of <id> (<id>) not found',
        }),
        extra: expect.objectContaining({
          error: 'Parent of atomic:abc (atomic:def) not found',
        }),
      }),
    );
  });

  it('truncates a long cause in the title and the tag', () => {
    let handler: ((failure: unknown) => void) | undefined;
    const store = {
      on: vi.fn((event: string, cb: (failure: unknown) => void) => {
        if (event === StoreEvents.CommitRepeatedlyFailing) handler = cb;

        return () => {};
      }),
    };
    reportRepeatedCommitFailures(store as never);
    const long = 'x'.repeat(500);
    handler?.({
      subject: 'atomic:abc',
      error: new Error(long),
      failures: 4,
      server: 'https://node1.example',
    });
    expect(Sentry.captureMessage).toHaveBeenCalledWith(
      `Commit keeps failing: ${'x'.repeat(160)}`,
      expect.objectContaining({
        fingerprint: ['commit-keeps-failing', 'https://node1.example', long],
        tags: expect.objectContaining({ error_kind: 'x'.repeat(200) }),
      }),
    );
  });

  it('hooks the repeat counter into the client when it initialises', () => {
    const on = vi.fn();
    vi.mocked(Sentry.getClient).mockReturnValueOnce({ on } as never);
    vi.stubGlobal('window', {});
    vi.stubEnv('VITE_SENTRY_ENVIRONMENT', 'staging');
    initSentry();
    expect(on).toHaveBeenCalledWith('preprocessEvent', expect.any(Function));
  });

  it('sends what the outbox knew when a commit keeps failing', () => {
    let handler: ((failure: unknown) => void) | undefined;
    const store = {
      on: vi.fn((event: string, cb: (failure: unknown) => void) => {
        if (event === StoreEvents.CommitRepeatedlyFailing) handler = cb;

        return () => {};
      }),
    };
    reportRepeatedCommitFailures(store as never);
    handler?.({
      subject: 'atomic:abc',
      error: new Error('boom'),
      failures: 4,
      server: 'https://node1.example',
      drive: 'atomic:drive',
      ageMs: 12_400,
      outboxSize: 3,
      connected: false,
      isGenesis: true,
      rearmedAfterResync: true,
    });
    expect(Sentry.captureMessage).toHaveBeenCalledWith(
      'Commit keeps failing: boom',
      expect.objectContaining({
        tags: {
          server: 'https://node1.example',
          error_kind: 'boom',
          connected: 'false',
          genesis: 'true',
        },
        extra: expect.objectContaining({
          drive: 'atomic:drive',
          ageSeconds: 12,
          outboxSize: 3,
          rearmedAfterResync: true,
        }),
      }),
    );
  });

  it('reports a failure only the toast showed, grouped by its phrase', () => {
    reportUserFacingFailure('Cloud Server setup failed after sign-in', {
      drive: 'atomic:drive',
    });
    expect(Sentry.captureMessage).toHaveBeenCalledWith(
      'Cloud Server setup failed after sign-in',
      expect.objectContaining({
        fingerprint: [
          'user-facing-failure',
          'Cloud Server setup failed after sign-in',
        ],
        extra: { drive: 'atomic:drive' },
      }),
    );
  });

  it('reports nothing when reporting is off', () => {
    vi.mocked(Sentry.isEnabled).mockReturnValueOnce(false);
    reportUserFacingFailure('anything');
    expect(Sentry.captureMessage).not.toHaveBeenCalled();
  });

  it('reports a sync problem once, however often the page asks', () => {
    const problem = { key: 'drive-sync', server: 'https://n.example' };
    reportSyncProblem(problem);
    reportSyncProblem(problem);
    expect(Sentry.captureMessage).toHaveBeenCalledTimes(1);
    expect(Sentry.captureMessage).toHaveBeenCalledWith(
      'Sync problem',
      expect.objectContaining({
        fingerprint: ['sync-problem', 'drive-sync', 'https://n.example', ''],
      }),
    );
  });
});

describe('Repeated event counter', () => {
  const error = (value: string): never =>
    ({ exception: { values: [{ type: 'Error', value }] } }) as never;

  it('reports once per power of ten, ignoring resource identifiers', () => {
    const report = vi.fn();
    const count = countRepeatedEvents(report);

    for (let i = 0; i < 100; i++) {
      count(error(`Parent of atomic:${i} not found`));
    }

    expect(report).toHaveBeenCalledTimes(2);
    expect(report).toHaveBeenNthCalledWith(
      1,
      'Error: Parent of <id> not found',
      10,
    );
    expect(report).toHaveBeenNthCalledWith(
      2,
      'Error: Parent of <id> not found',
      100,
    );
  });

  it('counts different errors separately', () => {
    const report = vi.fn();
    const count = countRepeatedEvents(report);

    for (let i = 0; i < 9; i++) {
      count(error('a'));
      count(error('b'));
    }

    expect(report).not.toHaveBeenCalled();
  });

  it('does not count its own summaries', () => {
    const report = vi.fn();
    const count = countRepeatedEvents(report);

    for (let i = 0; i < 20; i++) {
      count({ message: 'Event repeated', tags: { repeatSummary: 'true' } });
    }

    expect(report).not.toHaveBeenCalled();
  });

  it('stops tracking new errors past its bound', () => {
    const report = vi.fn();
    const count = countRepeatedEvents(report);

    for (let i = 0; i < 300; i++) count(error(`distinct-${i}-x`));

    // The 300th distinct error is untracked, so repeating it counts nothing.
    for (let i = 0; i < 20; i++) count(error('distinct-299-x'));

    expect(report).not.toHaveBeenCalled();
  });
});

describe('Sentry user', () => {
  beforeEach(() => vi.clearAllMocks());

  it('hashes the agent id into a short stable pseudonym', async () => {
    const first = await agentPseudonym('did:ad:agent:abc');

    expect(first).toMatch(/^[0-9a-f]{16}$/);
    expect(first).not.toContain('abc');
    expect(await agentPseudonym('did:ad:agent:abc')).toBe(first);
    expect(await agentPseudonym('did:ad:agent:abd')).not.toBe(first);
  });

  it('follows the store: set on sign-in, cleared on sign-out', async () => {
    let handler: ((agent: unknown) => void) | undefined;
    const store = {
      getAgent: () => ({ subject: 'did:ad:agent:abc' }),
      on: vi.fn((event: string, cb: (agent: unknown) => void) => {
        if (event === StoreEvents.AgentChanged) handler = cb;

        return () => {};
      }),
    };
    identifyAgentInSentry(store as never);
    await vi.waitFor(() => expect(Sentry.setUser).toHaveBeenCalledTimes(1));
    expect(Sentry.setUser).toHaveBeenLastCalledWith({
      id: await agentPseudonym('did:ad:agent:abc'),
    });

    handler?.(undefined);
    await vi.waitFor(() => expect(Sentry.setUser).toHaveBeenCalledTimes(2));
    expect(Sentry.setUser).toHaveBeenLastCalledWith(null);
  });

  it('keeps the newest identity when hashes finish out of order', async () => {
    let handler: ((agent: unknown) => void) | undefined;
    const store = {
      getAgent: () => undefined,
      on: vi.fn((event: string, cb: (agent: unknown) => void) => {
        if (event === StoreEvents.AgentChanged) handler = cb;

        return () => {};
      }),
    };
    identifyAgentInSentry(store as never);
    handler?.({ subject: 'did:ad:agent:one' });
    handler?.({ subject: 'did:ad:agent:two' });
    await vi.waitFor(() => expect(Sentry.setUser).toHaveBeenCalled());
    await new Promise(r => setTimeout(r, 20));

    const calls = vi.mocked(Sentry.setUser).mock.calls;
    expect(calls.at(-1)).toEqual([
      { id: await agentPseudonym('did:ad:agent:two') },
    ]);
  });
});
