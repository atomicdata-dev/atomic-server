// @vitest-environment jsdom
// @wc-ignore-file
import { act, cleanup, render, screen } from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { afterEach, expect, it, vi } from 'vitest';
import { buildTheme } from '../../styling';
vi.mock('./VaultContentsView', () => ({ VaultContentsView: () => null }));
import { VaultAccountStorage } from './VaultAccountStorage';
import {
  loadVaultStorageReport,
  type VaultStorageReport,
} from '../../helpers/managed/vaultStorageReport';
const session = vi.hoisted(() => ({ logout: () => {} }));
vi.mock('@tanstack/react-router', async original => ({
  ...(await original<typeof import('@tanstack/react-router')>()),
  Link: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
}));
vi.mock('../../helpers/managed/session', () => ({
  onManagedLogout: (callback: () => void) => {
    session.logout = callback;

    return () => {};
  },
  onManagedSessionChanged: () => () => {},
}));
vi.mock('../../helpers/managed/vaultStorageReport', async original => ({
  ...(await original<
    typeof import('../../helpers/managed/vaultStorageReport')
  >()),
  loadVaultStorageReport: vi.fn(),
}));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it('discards an in-flight report when the account signs out', async () => {
  let resolve!: (report: VaultStorageReport) => void;
  vi.mocked(loadVaultStorageReport).mockReturnValue(
    new Promise(done => {
      resolve = done;
    }),
  );
  render(
    <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
      <VaultAccountStorage />
    </ThemeProvider>,
  );
  const signal = vi.mocked(loadVaultStorageReport).mock.calls[0][0];
  act(() => session.logout());
  expect(signal.aborted).toBe(true);
  await act(async () =>
    resolve({
      account: 'old@example.com',
      accountId: 'old@example.com',
      generated_at: '',
      workspaces: [],
      total_bytes: 0,
    }),
  );
  expect(screen.queryByText('old@example.com')).toBeNull();
  expect(screen.getByRole('alert').textContent).toContain('Sign in');
});

it('does not display a zero allowance when the plan could not be read', async () => {
  vi.mocked(loadVaultStorageReport).mockResolvedValue({
    account: 'owner@example.com',
    accountId: 'owner@example.com',
    generated_at: '',
    total_bytes: 4096,
    workspaces: [
      {
        enrollment: {
          id: 'one',
          drive_subject: 'atomic:one',
          used_bytes: 4096,
          quota_bytes: 0,
          drive_name: 'Offline detail',
        } as never,
        usage: null,
        objects: null,
        error: 'Unavailable',
      },
    ],
  });
  render(
    <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
      <VaultAccountStorage />
    </ThemeProvider>,
  );
  expect(
    (await screen.findByText('4.0 KB used · allowance unavailable'))
      .textContent,
  ).toContain('allowance unavailable');
  expect(screen.queryByText(/of 0 B/)).toBeNull();
});
