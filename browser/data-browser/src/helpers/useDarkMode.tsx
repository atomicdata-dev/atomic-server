import { Dispatch, useEffect, useState } from 'react';
import { useLocalStorage } from '../hooks/useLocalStorage';

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

  useEffect(() => {
    const onChange = (e: MediaQueryListEvent) => {
      if (darkLocal === DarkModeOption.auto) {
        setDark(e.matches);
      }
    };

    const list = window.matchMedia('(prefers-color-scheme: dark)');
    // Is called when user changes color scheme
    list.addEventListener('change', onChange);

    return () => list.removeEventListener('change', onChange);
  }, []);

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

function checkPrefersDark() {
  return (
    window.matchMedia &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  );
}
