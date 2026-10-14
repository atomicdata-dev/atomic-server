// @vitest-environment jsdom
// @wc-ignore-file
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { afterEach, expect, it, vi } from 'vitest';
import { VaultContentsView } from './VaultContentsView';
import { buildTheme } from '../../styling';
import {
  inspectVaultContents,
  type VaultContents,
} from '../../helpers/managed/vaultContents';
vi.mock('@tomic/react', async original => {
  const agent = {};

  return {
    ...(await original<typeof import('@tomic/react')>()),
    useStore: () => ({ getAgent: () => agent }),
  };
});
vi.mock('../AtomicLink', () => ({ AtomicLink: () => null }));
vi.mock('../../helpers/managed/vaultContents', () => ({
  inspectVaultContents: vi.fn(),
}));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it('aborts on stop and unmount, and ignores a late result', async () => {
  let finish!: (value: VaultContents) => void;
  vi.mocked(inspectVaultContents).mockReturnValue(
    new Promise(resolve => {
      finish = resolve;
    }),
  );
  const view = render(
    <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
      <VaultContentsView
        accountId='owner'
        enrollment={{ id: 'drive' } as never}
      />
    </ThemeProvider>,
  );
  fireEvent.click(screen.getByText('Inspect contents'));
  const signal = vi.mocked(inspectVaultContents).mock.calls[0][3];
  fireEvent.click(screen.getByText('Stop inspection'));
  expect(signal.aborted).toBe(true);
  await act(async () =>
    finish({ items: [], storedBytes: 999, objects: 1, unreadable: 0 }),
  );
  expect(screen.queryByTestId('vault-contents-map')).toBeNull();
  fireEvent.click(screen.getByText('Inspect contents'));
  const second = vi.mocked(inspectVaultContents).mock.calls[1][3];
  view.unmount();
  expect(second.aborted).toBe(true);
});
