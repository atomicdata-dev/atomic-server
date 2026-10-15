// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import {
  AtomicError,
  ErrorType,
  NOT_AVAILABLE_LOCALLY_MESSAGE,
  NOT_AVAILABLE_SERVER_UNREACHABLE_MESSAGE,
} from '@tomic/react';
import { buildTheme } from '../styling';
import { DriveUnavailable, RETRY_EVERY_MS } from './DriveUnavailable';

const store = vi.hoisted(() => ({
  isLocalOnlySubject: vi.fn(() => true),
  fetchResourceFromServer: vi.fn(),
  getAgent: vi.fn(() => ({ subject: 'did:ad:agent:x' })),
}));
const vaultState = vi.hoisted(() => ({
  current: {
    status: { state: 'unavailable' },
    busy: false,
    error: null,
    restoreProgress: null,
    restore: vi.fn(),
  } as Record<string, unknown>,
}));

vi.mock('../helpers/managed/useDriveVault', () => ({
  useDriveVault: () => vaultState.current,
}));

vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  useStore: () => store,
}));
const settings = vi.hoisted(() => ({ agent: undefined as unknown }));

vi.mock('../helpers/AppSettings', () => ({
  useSettings: () => ({ agent: settings.agent }),
}));
vi.mock('../helpers/browserPeerSync', () => ({
  resumePeerLinks: vi.fn(),
}));

afterEach(() => {
  cleanup();
  settings.agent = undefined;
  vaultState.current = {
    ...vaultState.current,
    status: { state: 'unavailable' },
  };
  vi.useRealTimers();
  store.fetchResourceFromServer.mockReset();
});

function show(props: { error?: Error; vault?: boolean } = {}) {
  render(
    <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
      <DriveUnavailable
        subject='atomic:local-only-drive'
        error={props.error ?? new Error('not available locally')}
        vault={props.vault}
      />
    </ThemeProvider>,
  );
}

/**
 * A local-only subject this device doesn't hold makes every fetch reject. The
 * screen exists to say exactly that, so neither the timer nor "Retry now" may
 * leak the rejection (as an unhandled rejection, it reached Sentry every 10 s).
 * Vitest fails the run on an unhandled rejection, so these tests guard that.
 */
describe('DriveUnavailable', () => {
  it('keeps retrying on a timer without leaking the failure', async () => {
    vi.useFakeTimers();
    store.fetchResourceFromServer.mockRejectedValue(
      new Error('Not found locally and local-only'),
    );
    show();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(RETRY_EVERY_MS * 2);
    });

    expect(store.fetchResourceFromServer).toHaveBeenCalledTimes(2);
  });

  it('"Retry now" settles back to idle when the fetch fails', async () => {
    store.fetchResourceFromServer.mockRejectedValue(
      new Error('Not found locally and local-only'),
    );
    show();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Retry now' }));
    });

    expect(store.fetchResourceFromServer).toHaveBeenCalledTimes(1);
    expect(
      screen
        .getByRole('button', { name: 'Retry now' })
        .hasAttribute('disabled'),
    ).toBe(false);
  });
});

describe('DriveUnavailable wording', () => {
  const noRequest = new AtomicError(
    NOT_AVAILABLE_LOCALLY_MESSAGE,
    ErrorType.Transport,
  );
  const failedRequest = new AtomicError(
    NOT_AVAILABLE_SERVER_UNREACHABLE_MESSAGE,
    ErrorType.Transport,
  );

  afterEach(() => {
    store.isLocalOnlySubject.mockImplementation(() => true);
  });

  it('only blames the server when a request to it failed', () => {
    store.isLocalOnlySubject.mockImplementation(() => false);
    show({ error: noRequest });
    expect(screen.queryByText(/isn't reachable/)).toBeNull();
    expect(screen.getByText('Not connected to the server yet.')).toBeTruthy();
    cleanup();

    show({ error: failedRequest });
    expect(screen.getByText("The server isn't reachable.")).toBeTruthy();
  });

  it('never says a private drive is not on this device', () => {
    store.isLocalOnlySubject.mockImplementation(() => false);
    show({ error: failedRequest, vault: true });

    expect(screen.queryByText(/isn't on this device/)).toBeNull();
    expect(
      screen.getByRole('heading', {
        name: "This item hasn't reached this device yet",
      }),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Retry now' })).toBeTruthy();
    expect(screen.getByText('Technical details')).toBeTruthy();
    expect(screen.queryByText('Your other devices')).toBeNull();
  });

  it('keeps the vault copy for a local-only private drive', () => {
    show({ error: noRequest, vault: true });

    expect(screen.queryByText(/isn't on this device/)).toBeNull();
    expect(screen.queryByText(/No device with this drive/)).toBeNull();
  });
});

describe('DriveUnavailable with a vault backup', () => {
  it('shows the restore, not the retry panel', () => {
    settings.agent = { subject: 'did:ad:agent:x' };
    vaultState.current = {
      status: { state: 'on', details: { confirmed_objects: 3 } },
      busy: true,
      error: null,
      restoreProgress: 0.4,
      restore: vi.fn(),
    };
    show({
      error: new AtomicError(
        NOT_AVAILABLE_LOCALLY_MESSAGE,
        ErrorType.Transport,
      ),
    });

    expect(screen.getByText('Restoring this drive… 40%')).toBeTruthy();
    expect(screen.queryByTestId('drive-unavailable')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Retry now' })).toBeNull();
  });
});
