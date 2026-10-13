// @vitest-environment jsdom
// @wc-ignore-file
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { afterEach, expect, it, vi } from 'vitest';
import { DialogGlobalContextProvider } from '../Dialog/DialogGlobalContextProvider';
import { RootWelcomeLayoutProvider } from '../../context/RootWelcomeLayoutContext';
import { VaultStorage } from './VaultStorage';
import { buildTheme } from '../../styling';
import type { VaultUsage } from '../../helpers/managed/vault';

const theme = buildTheme(false, '#1b50d8');
const usageMock = vi.hoisted(() => vi.fn());

vi.mock('../../helpers/managed/vault', async importOriginal => ({
  ...(await importOriginal<typeof import('../../helpers/managed/vault')>()),
  getVaultUsage: usageMock,
}));

const usage = (over: Partial<VaultUsage> = {}): VaultUsage =>
  ({
    used_bytes: 5_000_000,
    quota_bytes: 50_000_000,
    by_kind: [{ kind: 'pack', bytes: 2_000_000 }],
    pending_bytes: 0,
    unaccounted_bytes: 0,
    reclaimable_bytes: 1_000_000,
    undo_window_bytes: 500_000,
    ...over,
  }) as VaultUsage;

const result = {
  freed: { bytes_reclaimed: 1_500_000 },
  checkpointBytes: 800_000,
};

function show(props: Partial<Parameters<typeof VaultStorage>[0]> = {}) {
  const onCompact = vi.fn(async () => result as never);
  render(
    <ThemeProvider theme={theme}>
      <RootWelcomeLayoutProvider>
        <DialogGlobalContextProvider>
          <VaultStorage
            drivePseudonym='p'
            onClose={() => {}}
            onCompact={onCompact}
            {...props}
          />
        </DialogGlobalContextProvider>
      </RootWelcomeLayoutProvider>
    </ThemeProvider>,
  );

  return onCompact;
}

// jsdom has no modal <dialog>; opening one is all these tests need from it.
HTMLDialogElement.prototype.showModal = function showModal() {
  this.setAttribute('open', '');
};

HTMLDialogElement.prototype.close = function close() {
  this.removeAttribute('open');
  this.dispatchEvent(new Event('close'));
};

afterEach(() => {
  cleanup();
  usageMock.mockReset();
});

it('compresses without touching the undo window', async () => {
  usageMock.mockResolvedValue(usage());
  const onCompact = show();

  fireEvent.click(await screen.findByTestId('vault-compress'));

  await screen.findByTestId('vault-storage-message');
  expect(onCompact).toHaveBeenCalledWith(false);
  expect(screen.getByTestId('vault-storage-message').textContent).toContain(
    'Freed',
  );
});

it('asks before discarding history and states the space gained', async () => {
  usageMock.mockResolvedValue(usage());
  const onCompact = show();

  fireEvent.click(await screen.findByTestId('vault-discard-history'));

  expect((await screen.findByTestId('vault-discard-warning')).textContent).toBe(
    'The backup will keep only its newest snapshot, and about 1.4 MB will be freed.',
  );
  expect(onCompact).not.toHaveBeenCalled();

  fireEvent.click(
    within(document.querySelector('dialog')!).getByText('Discard history'),
  );
  await screen.findByTestId('vault-storage-message');
  expect(onCompact).toHaveBeenCalledWith(true);
});

it('does not discard when the dialog is cancelled', async () => {
  usageMock.mockResolvedValue(usage());
  const onCompact = show();

  fireEvent.click(await screen.findByTestId('vault-discard-history'));
  fireEvent.click(await screen.findByText('Cancel'));

  expect(onCompact).not.toHaveBeenCalled();
});

it('disables both actions with a reason while a backup is busy', async () => {
  usageMock.mockResolvedValue(usage());
  show({ busy: true });

  const compress = await screen.findByTestId('vault-compress');
  expect((compress as HTMLButtonElement).disabled).toBe(true);
  expect(
    (screen.getByTestId('vault-discard-history') as HTMLButtonElement).disabled,
  ).toBe(true);
  expect(screen.getByTestId('vault-history-disabled').textContent).toContain(
    'current backup',
  );
});

it('hides the history actions when there is nothing to gain', async () => {
  usageMock.mockResolvedValue(
    usage({ by_kind: [], reclaimable_bytes: 0, undo_window_bytes: 0 }),
  );
  show();

  await screen.findByTestId('vault-storage-nothing');
  expect(screen.queryByTestId('vault-history')).toBeNull();
});
