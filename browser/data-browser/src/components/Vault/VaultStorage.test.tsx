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
    by_kind: [{ kind: 'pack', objects: 4, bytes: 2_000_000 }],
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

  const dialogs = document.querySelectorAll('dialog');

  fireEvent.click(
    within(dialogs[dialogs.length - 1] as HTMLElement).getByText(
      'Discard history',
    ),
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

const MB = 1024 * 1024;

const rich = (over: Partial<VaultUsage> = {}) =>
  usage({
    used_bytes: 117 * MB,
    quota_bytes: 10 * 1024 * MB,
    by_kind: [
      { kind: 'checkpoint', objects: 2, bytes: 15 * MB },
      { kind: 'checkpoint_image', objects: 6, bytes: 6 * MB },
      { kind: 'pack', objects: 148, bytes: 97 * MB },
      { kind: 'index', objects: 1, bytes: 1 * MB },
    ],
    ...over,
  });

const history = {
  lanes: 2,
  pack_objects: 148,
  pack_bytes: 97 * MB,
  tip_objects: 2,
  tip_bytes: 6 * MB,
  uncovered_objects: 100,
  uncovered_bytes: 80 * MB,
  in_undo_window_objects: 46,
  in_undo_window_bytes: 11 * MB,
  freeable_objects: 0,
  freeable_bytes: 0,
  checkpoint_objects: 2,
  anchor_covers_lanes: 1,
};

it('shows a bar and a legend with counts and sizes', async () => {
  usageMock.mockResolvedValue(rich());
  show();

  expect((await screen.findByTestId('vault-storage-total')).textContent).toBe(
    '117 MB of 10 GB used',
  );
  // Chunks of a snapshot's image add to its size, not to the count.
  expect(screen.getByTestId('vault-storage-snapshots').textContent).toContain(
    'Snapshots · 2 · 21 MB',
  );
  expect(screen.getByTestId('vault-storage-history').textContent).toContain(
    'Change history · 148 packs · 97 MB',
  );
  expect(screen.getByTestId('vault-storage-other').textContent).toContain(
    '1.0 MB',
  );
  expect(
    screen.getByTestId('vault-storage-bar').getAttribute('aria-label'),
  ).toContain('Snapshots: 21 MB');
  expect(screen.queryByTestId('vault-storage-files')).toBeNull();
});

it('explains what remains of the history when the server says', async () => {
  usageMock.mockResolvedValue(rich({ history }));
  show();

  const explain = await screen.findByTestId('vault-history-explain');

  expect(explain.textContent).toContain('Newest changes of each of 2 devices');
  expect(screen.getByTestId('vault-history-uncovered').textContent).toContain(
    '80 MB',
  );
  expect(screen.getByTestId('vault-history-undo').textContent).toContain(
    '11 MB',
  );
  // Nothing can be freed, so that row stays out.
  expect(screen.queryByTestId('vault-history-freeable')).toBeNull();
});

it('leaves the explanation out without the history field', async () => {
  usageMock.mockResolvedValue(rich());
  show();

  await screen.findByTestId('vault-storage-bar');
  expect(screen.queryByTestId('vault-history-explain')).toBeNull();
});

it('offers one compress action and a separate discard, not free-up buttons', async () => {
  usageMock.mockResolvedValue(rich());
  show();

  await screen.findByTestId('vault-compress');
  expect(screen.getByText('Compress history')).toBeTruthy();
  expect(screen.getByText('Discard history…')).toBeTruthy();
  expect(screen.queryByTestId('vault-free-up')).toBeNull();
  expect(screen.queryByTestId('vault-free-up-undo')).toBeNull();
});

it('falls back to free-up when the host cannot compress', async () => {
  usageMock.mockResolvedValue(rich());
  show({ onCompact: undefined });

  await screen.findByTestId('vault-free-up');
  expect(screen.queryByTestId('vault-compress')).toBeNull();
});

it('hides the history actions when there is nothing to gain', async () => {
  usageMock.mockResolvedValue(
    usage({ by_kind: [], reclaimable_bytes: 0, undo_window_bytes: 0 }),
  );
  show();

  await screen.findByTestId('vault-storage-nothing');
  expect(screen.queryByTestId('vault-history')).toBeNull();
});
