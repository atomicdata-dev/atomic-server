// @vitest-environment jsdom
// @wc-ignore-file
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DarkModeOption, useDarkMode } from './useDarkMode';
import * as embedMode from './embedMode';
import { setActionsHost } from '../embed/hostActions';

let systemDark = false;
const listeners = new Set<() => void>();

beforeEach(() => {
  systemDark = false;
  listeners.clear();
  localStorage.clear();
  vi.stubGlobal('matchMedia', () => ({
    get matches() {
      return systemDark;
    },
    addEventListener: (_: string, l: () => void) => listeners.add(l),
    removeEventListener: (_: string, l: () => void) => listeners.delete(l),
  }));
});

afterEach(() => {
  cleanup();
  setActionsHost(undefined);
  embedMode.setHostColorScheme(undefined);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.documentElement.style.colorScheme = '';
});

const flipSystem = (dark: boolean) => {
  systemDark = dark;
  act(() => listeners.forEach(l => l()));
};

it('persists the choice under the web app key and restores it', () => {
  const first = renderHook(() => useDarkMode());

  act(() => first.result.current[1](true));
  expect(first.result.current[0]).toBe(true);
  expect(localStorage.getItem('darkMode')).toBe('"always"');
  first.unmount();

  const second = renderHook(() => useDarkMode());

  expect(second.result.current[0]).toBe(true);
  expect(second.result.current[2]).toBe(DarkModeOption.always);
});

it('auto follows the system, an explicit choice ignores it', () => {
  const { result } = renderHook(() => useDarkMode());

  flipSystem(true);
  expect(result.current[0]).toBe(true);

  act(() => result.current[1](false));
  flipSystem(false);
  flipSystem(true);
  // Chosen light: the system changing must not flip it (a stale listener did).
  expect(result.current[0]).toBe(false);

  act(() => result.current[1](undefined));
  expect(result.current[0]).toBe(true);
  flipSystem(false);
  expect(result.current[0]).toBe(false);
});

it('in the embed, auto follows the host app scheme and sets color-scheme', () => {
  vi.spyOn(embedMode, 'isEmbedded').mockReturnValue(true);
  const { result } = renderHook(() => useDarkMode());

  expect(document.documentElement.style.colorScheme).toBe('light');

  act(() => embedMode.setHostColorScheme('dark'));
  expect(result.current[0]).toBe(true);
  expect(document.documentElement.style.colorScheme).toBe('dark');

  act(() => result.current[1](false));
  expect(result.current[0]).toBe(false);
  expect(document.documentElement.style.colorScheme).toBe('light');
});

it('tells the app the saved choice and every new one', () => {
  localStorage.setItem('darkMode', '"never"');
  const call = vi.fn().mockResolvedValue(true);
  setActionsHost({ call });
  const hook = renderHook(() => useDarkMode());

  expect(call).toHaveBeenLastCalledWith('theme', ['light']);
  act(() => hook.result.current[1](true));
  expect(call).toHaveBeenLastCalledWith('theme', ['dark']);
  act(() => hook.result.current[1](undefined));
  expect(call).toHaveBeenLastCalledWith('theme', ['auto']);
});
