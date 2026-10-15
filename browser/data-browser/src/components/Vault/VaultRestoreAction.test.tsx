// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../../styling';
import { VaultRestoreAction } from './VaultRestoreAction';

const mocks = vi.hoisted(() => ({
  agent: { subject: 'did:ad:agent:x' } as unknown,
  vault: {} as Record<string, unknown>,
}));

vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  useStore: () => ({ getAgent: () => mocks.agent }),
}));
vi.mock('../../helpers/managed/useDriveVault', () => ({
  useDriveVault: () => mocks.vault,
}));

const restore = vi.fn();

function setVault(over: Record<string, unknown> = {}) {
  mocks.vault = {
    status: { state: 'on', details: { confirmed_objects: 2 } },
    busy: false,
    error: null,
    restoreProgress: null,
    restore,
    ...over,
  };
}

function show(subject = 'atomic:drive1') {
  return render(
    <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
      <VaultRestoreAction subject={subject} />
    </ThemeProvider>,
  );
}

afterEach(() => {
  cleanup();
  restore.mockReset();
  mocks.agent = { subject: 'did:ad:agent:x' };
});

describe('VaultRestoreAction', () => {
  it('restores by itself, once per subject', () => {
    setVault();
    const { rerender } = show();

    expect(restore).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/This drive has an encrypted backup/)).toBeTruthy();

    rerender(
      <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
        <VaultRestoreAction subject='atomic:drive1' />
      </ThemeProvider>,
    );
    expect(restore).toHaveBeenCalledTimes(1);
  });

  it('shows progress while restoring', () => {
    setVault({ busy: true, restoreProgress: 0.25 });
    show();

    expect(screen.getByText('Restoring this drive… 25%')).toBeTruthy();
  });

  it('does not start without a backup or a signed-in agent', () => {
    setVault({ status: { state: 'on', details: { confirmed_objects: 0 } } });
    show();
    expect(restore).not.toHaveBeenCalled();
    cleanup();

    setVault();
    mocks.agent = undefined;
    show();
    expect(restore).not.toHaveBeenCalled();
  });

  it('after a failure shows the error and waits for "Try again"', () => {
    setVault({ error: 'boom' });
    show();

    expect(restore).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toBe('boom');
    fireEvent.click(screen.getByRole('button', { name: /Try again/ }));
    expect(restore).toHaveBeenCalledTimes(1);
  });
});
