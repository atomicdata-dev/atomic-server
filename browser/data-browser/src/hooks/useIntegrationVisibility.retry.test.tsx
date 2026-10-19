// @vitest-environment jsdom
// @wc-ignore-file
import { cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { findSchema } from '@tomic/react';
import { useIntegrationVisibility } from './useIntegrationVisibility';

const DRIVE = 'atomic:drive';
const ACTOR = 'atomic:agent';

const store = {
  getResource: vi.fn(async () => driveResource),
  fetchResourceFromServer: vi.fn(async () => driveResource),
  getAgent: () => ({ subject: ACTOR }),
};
const driveResource = {
  get: () => undefined,
  loading: false,
  error: undefined as Error | undefined,
};

vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  findSchema: vi.fn(),
  useStore: () => store,
  useResource: () => driveResource,
  useCurrentAgent: () => [{ subject: ACTOR }],
}));
vi.mock('./usePrivateDrive', () => ({
  usePrivateDrive: () => ({ privateDrive: DRIVE, loading: false }),
}));

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.resetAllMocks();
});

it('becomes ready after a read that failed, without a reload', async () => {
  // One timed-out read of the private drive used to settle this panel as not
  // ready for as long as the tab stayed open, with the checkboxes unusable.
  // The retry follows the failure by 150 ms. Holding its answer back keeps the
  // error on screen until this test has looked at it, however slowly a loaded
  // host gets around to polling.
  let release!: () => void;
  const retryMayAnswer = new Promise<void>(resolve => (release = resolve));
  vi.mocked(findSchema)
    .mockRejectedValueOnce(
      new Error(`Async Request for subject ${DRIVE} timed out after 10000ms`),
    )
    .mockImplementation(async () => {
      await retryMayAnswer;

      return {
        properties: {
          'show-api-plugins': 'atomic:api',
          'show-experimental-plugins': 'atomic:experimental',
        },
      };
    });

  const { result } = renderHook(() => useIntegrationVisibility());

  await waitFor(() => expect(result.current.error).toBeDefined(), {
    timeout: 5_000,
  });
  expect(result.current.ready).toBe(false);

  release();
  // A loaded CI host can take longer than waitFor's default one second.
  await waitFor(() => expect(result.current.ready).toBe(true), {
    timeout: 5_000,
  });
  expect(result.current.error).toBeUndefined();
  // The retry has to go back to the server: the store answers a read that
  // failed with the same error for as long as the tab is open.
  expect(store.fetchResourceFromServer).toHaveBeenCalledWith(DRIVE);
});
