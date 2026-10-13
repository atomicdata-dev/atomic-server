// @vitest-environment jsdom
// @wc-ignore-file
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { afterEach, expect, it, vi } from 'vitest';
import type { UseVaultBackup } from '../../helpers/managed/useVaultBackup';
import { VaultPanel } from './VaultPanel';
import { buildTheme } from '../../styling';

const theme = buildTheme(false, '#1b50d8');
const GB = 1024 ** 3;
const QUOTA = 50 * GB;

function vaultWith(usedBytes: number): UseVaultBackup {
  return {
    status: {
      state: 'on',
      enrollment: {
        status: 'active',
        used_bytes: usedBytes,
        quota_bytes: QUOTA,
        drive_pseudonym: 'p',
        last_backup_at: null,
      },
      details: { confirmed_objects: 10234 },
    },
    busy: false,
    error: null,
    enable: vi.fn(),
    disable: vi.fn(),
    backupNow: vi.fn(),
    restore: vi.fn(),
    downloadBackup: vi.fn(async () => 'saved'),
    restoreFromFile: vi.fn(async () => ({})),
    restoreProgress: null,
    refresh: vi.fn(),
  } as unknown as UseVaultBackup;
}

const show = (
  usedBytes: number,
  included: boolean,
  vault = vaultWith(usedBytes),
) =>
  render(
    <ThemeProvider theme={theme}>
      <VaultPanel vault={vault} included={included} />
    </ThemeProvider>,
  );

afterEach(cleanup);

it('shows no bar or quota when included in Cloud Server', () => {
  show(545 * 1024 ** 2, true);

  expect(screen.queryByRole('progressbar')).toBeNull();
  const text = screen.getByTestId('usage-meter-text').textContent ?? '';
  expect(text).toContain('10234 objects');
  expect(text).toContain('backed up');
  expect(text).not.toContain(' of ');
  expect(screen.getByTestId('vault-included-note')).toBeTruthy();
});

it('shows the bar and quota when the vault is the only service', () => {
  show(545 * 1024 ** 2, false);

  expect(screen.getByRole('progressbar')).toBeTruthy();
  expect(screen.getByTestId('usage-meter-text').textContent).toContain(' of ');
  expect(screen.queryByTestId('vault-included-note')).toBeNull();
});

it('brings the bar back when included but nearly full', () => {
  show(Math.round(QUOTA * 0.95), true);

  expect(screen.getByRole('progressbar').getAttribute('aria-valuenow')).toBe(
    '95',
  );
  expect(screen.getByTestId('usage-meter-text').textContent).toContain(' of ');
  expect(screen.queryByTestId('vault-included-note')).toBeNull();
});

it('downloads the backup and says so', async () => {
  const vault = vaultWith(1000);
  show(1000, false, vault);

  fireEvent.click(screen.getByTestId('vault-download'));

  await waitFor(() =>
    expect(screen.getByTestId('vault-notice').textContent).toContain('saved'),
  );
  expect(vault.downloadBackup).toHaveBeenCalled();
});

it('restores from a picked file and clears the input', async () => {
  const vault = vaultWith(1000);
  const onRestored = vi.fn();
  render(
    <ThemeProvider theme={theme}>
      <VaultPanel vault={vault} onRestored={onRestored} />
    </ThemeProvider>,
  );
  const input = screen.getByTestId('vault-file-input') as HTMLInputElement;
  const file = new File([new Uint8Array([1])], 'x.atomic-vault');

  fireEvent.change(input, { target: { files: [file] } });

  await waitFor(() => expect(onRestored).toHaveBeenCalled());
  expect(vault.restoreFromFile).toHaveBeenCalledWith(file);
});
