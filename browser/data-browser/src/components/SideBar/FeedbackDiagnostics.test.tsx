// @vitest-environment jsdom
// @wc-ignore-file
import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { buildTheme } from '../../styling';
import { FeedbackDiagnostics } from './FeedbackDiagnostics';

const listeners = new Set<() => void>();
const recorder = {
  active: true,
  session: 'session-1',
  subscribe: (cb: () => void) => {
    listeners.add(cb);

    return () => listeners.delete(cb);
  },
  snapshot: vi.fn(),
  start: vi.fn(),
  clear: vi.fn(),
  connection: vi.fn(),
  queue: vi.fn(),
};

vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  useStore: () => ({
    diagnostics: recorder,
    serverConnected: true,
    getSyncStatus: () => ({
      pendingDirtyCount: 0,
      blockedCount: 0,
      serverConnected: true,
    }),
  }),
}));
vi.mock('../../helpers/persistent-diagnostics', () => ({
  getPersistentDiagnostics: () => undefined,
}));
vi.mock('../../helpers/diagnostic-report', () => ({
  previewDiagnostics: () => ({ session: recorder.session, text: '{}' }),
  currentDiagnosticText: vi.fn(),
  downloadDiagnostics: vi.fn(),
}));

afterEach(() => {
  cleanup();
  listeners.clear();
});

function setup() {
  const onSelect = vi.fn();

  render(
    <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
      <FeedbackDiagnostics onSelect={onSelect} disabled={false} />
    </ThemeProvider>,
  );

  return { onSelect };
}

const checkbox = () =>
  screen.getByRole('checkbox', { name: 'Include diagnostic data' });

describe('FeedbackDiagnostics', () => {
  it('attaches the diagnostics by default', () => {
    const { onSelect } = setup();

    expect((checkbox() as HTMLInputElement).checked).toBe(true);
    expect(onSelect).toHaveBeenLastCalledWith({
      session: 'session-1',
      text: '{}',
    });
  });

  it('keeps an opt-out when the recorder updates', () => {
    const { onSelect } = setup();

    fireEvent.click(checkbox());
    expect((checkbox() as HTMLInputElement).checked).toBe(false);
    expect(onSelect).toHaveBeenLastCalledWith(undefined);

    act(() => listeners.forEach(cb => cb()));
    expect((checkbox() as HTMLInputElement).checked).toBe(false);
    expect(onSelect).toHaveBeenLastCalledWith(undefined);
  });
});
