// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../../styling';

const state = vi.hoisted(() => ({
  restore: vi.fn(),
  error: null as string | null,
}));

vi.mock('@tomic/react', async original => ({
  ...(await original<typeof import('@tomic/react')>()),
  useStore: () => ({}),
}));
vi.mock('../../helpers/AppSettings', () => ({
  useSettings: () => ({
    agent: { subject: 'did:ad:agent:test' },
    baseURL: 'https://node.example',
    setServer: vi.fn(),
  }),
}));
vi.mock('../../helpers/managed/useDriveVault', () => ({
  useDriveVault: () => ({
    status: { state: 'on', details: { confirmed_objects: 3 } },
    error: state.error,
    busy: false,
    restoreProgress: null,
    restore: state.restore,
    refresh: vi.fn(),
  }),
}));
vi.mock('../../helpers/managed/vault', () => ({
  listVaultDrives: async () => [],
}));
vi.mock('../../helpers/managed/session', () => ({
  getManagedAccount: async () => ({ email: 'a@b.c' }),
}));
vi.mock('../../helpers/managed/deviceLink', () => ({
  canHoldProviderCookie: () => true,
}));
vi.mock('../../helpers/managed/product', () => ({ PRODUCT_NAME: 'Atomic' }));
vi.mock('../../helpers/managedServer', () => ({
  fetchManagedInfo: async () => ({}),
}));
vi.mock('../../helpers/driveData', () => ({
  deviceHasDriveData: async () => false,
}));
vi.mock('../../helpers/privateDrive', () => ({
  fetchPrivateDriveSubject: async () => 'did:ad:home',
}));
vi.mock('../../helpers/tauri', () => ({ isRunningInTauri: () => false }));
vi.mock('../../hooks/useOwnNodeDid', () => ({ useOwnNodeDid: () => null }));
vi.mock('../../components/pairing/PairingFlowProvider', () => ({
  usePairingFlow: () => vi.fn(),
}));
vi.mock('../../components/PairingCode', () => ({ PairingCode: () => null }));
vi.mock('../../components/ConnectToDeviceForm', () => ({
  ConnectToDeviceForm: () => null,
}));
vi.mock('../../components/Vault/LinkProviderPanel', () => ({
  LinkProviderPanel: () => null,
}));

import { ConnectDeviceStep } from './ConnectDeviceStep';

const onConnected = vi.fn();

function mount() {
  return render(
    <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
      <ConnectDeviceStep
        drive='did:ad:home'
        portalUrl='https://portal.example'
        onSkip={vi.fn()}
        onConnected={onConnected}
      />
    </ThemeProvider>,
  );
}

beforeEach(() => {
  state.error = null;
  state.restore.mockReset();
  onConnected.mockReset();
});
afterEach(cleanup);

it('connects after a complete restore', async () => {
  state.restore.mockResolvedValue({ objectsUnreadable: 0 });
  mount();

  fireEvent.click(await screen.findByTestId('vault-restore-now'));

  await waitFor(() => expect(onConnected).toHaveBeenCalledWith('did:ad:home'));
});

it('does not count an incomplete restore as a connected device', async () => {
  state.restore.mockResolvedValue({
    incomplete: 'Restore incomplete: 2 backup objects could not be downloaded.',
  });
  mount();

  fireEvent.click(await screen.findByTestId('vault-restore-now'));

  expect(await screen.findByRole('alert')).toHaveProperty(
    'textContent',
    'Restore incomplete: 2 backup objects could not be downloaded.',
  );
  expect(onConnected).not.toHaveBeenCalled();

  // The recovered data can still be opened, on purpose.
  fireEvent.click(screen.getByTestId('vault-open-recovered'));
  expect(onConnected).toHaveBeenCalledWith('did:ad:home');
});
