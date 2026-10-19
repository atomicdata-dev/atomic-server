import { Dispatch, useEffect, useRef, useState } from 'react';
import { useLocalStorage } from '../hooks/useLocalStorage';
import {
  getHostColorScheme,
  HOST_COLOR_SCHEME_EVENT,
  isEmbedded,
} from './embedMode';
import { reportTheme } from '../embed/hostActions';

export enum DarkModeOption {
  /** Always use dark mode */
  always = 'always',
  /** Never use dark mode, always light */
  never = 'never',
  /** Use OS / Browser setting */
  auto = 'auto',
}

/**
 * A hook for using dark mode. Sets using local storage. The second argument can
 * be called with true, false or undefined (which uses the OS default)
 */
export const useDarkMode = (): [
  boolean,
  Dispatch<boolean | undefined>,
  DarkModeOption,
] => {
  const [dark, setDark] = useState<boolean>(() => checkPrefersDark());
  const [darkLocal, setDarkLocal] = useLocalStorage<DarkModeOption>(
    'darkMode',
    DarkModeOption.auto,
  );

  /** True, false or auto (if undefined) */
  function setDarkBoth(a?: boolean) {
    if (a === undefined) {
      setDark(checkPrefersDark());
      setDarkLocal(DarkModeOption.auto);
    } else if (a === true) {
      setDark(a);
      setDarkLocal(DarkModeOption.always);
    } else if (a === false) {
      setDark(a);
      setDarkLocal(DarkModeOption.never);
    }
  }

  // The listener lives as long as the hook, so it reads the setting from a
  // ref: a closure over the first render's value ignored later changes.
  const darkLocalRef = useRef(darkLocal);
  useEffect(() => {
    darkLocalRef.current = darkLocal;
  }, [darkLocal]);

  useEffect(() => {
    const onChange = () => {
      if (darkLocalRef.current === DarkModeOption.auto) {
        setDark(checkPrefersDark());
      }
    };

    const list = window.matchMedia('(prefers-color-scheme: dark)');
    // Is called when user changes color scheme
    list.addEventListener('change', onChange);
    // The embed's host app reports its own scheme (see embedMode.ts).
    window.addEventListener(HOST_COLOR_SCHEME_EVENT, onChange);

    return () => {
      list.removeEventListener('change', onChange);
      window.removeEventListener(HOST_COLOR_SCHEME_EVENT, onChange);
    };
  }, []);

  // In the embed, native widgets (scrollbars, form controls) follow the chosen
  // scheme, not only the OS one: an explicit choice overrides it.
  useEffect(() => {
    if (isEmbedded()) {
      document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
    }
  }, [dark]);

  // In the app, its own screens follow the choice, also the one saved before
  // (nothing happens outside the app).
  useEffect(() => {
    reportTheme(
      darkLocal === DarkModeOption.always
        ? 'dark'
        : darkLocal === DarkModeOption.never
          ? 'light'
          : 'auto',
    );
  }, [darkLocal]);

  useEffect(() => {
    if (darkLocal === DarkModeOption.auto) {
      setDark(checkPrefersDark());
    } else if (darkLocal === DarkModeOption.always) {
      setDark(true);
    } else if (darkLocal === DarkModeOption.never) {
      setDark(false);
    }
  }, [darkLocal]);

  return [dark, setDarkBoth, darkLocal];
};

export function checkPrefersDark(): boolean {
  const host = getHostColorScheme();

  if (host) {
    return host === 'dark';
  }

  return (
    window.matchMedia &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  );
}
