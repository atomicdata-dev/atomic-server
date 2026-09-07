import { useEffect, useState } from 'react';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';
import { useLocation, useSearch } from '@tanstack/react-router';
import { paths } from '../routes/paths';
import { ShowRoute } from '../routes/ShowRoute';
import { getLocalServerOrigin } from './tauri';
import { getHomeDrive } from './homeDrive';
import { useStore } from '@tomic/react';
import { isDev } from '../config';

type setFunc = (latestValue: string) => void;

/**
 * Returns and sets the current Location. Tries the `subject` query parameter,
 * otherwise uses the full current URL.
 */
export function useCurrentSubject(
  /** Replace URL instead of push it, so it does not get added to history */
  replace?: boolean,
): [string | undefined, setFunc] {
  const { subject: subjectQ } = useSearch({ strict: false });
  const store = useStore();

  const navigate = useNavigateWithTransition();
  const navigateShow = ShowRoute.useNavigate();
  const { pathname } = useLocation();

  function handleSetSubject(subject: string) {
    const url = new URL(subject);

    if (window.location.origin === url.origin) {
      // Navigate to the new subject.
      navigate({ to: url.pathname + url.search, replace });
    } else {
      // Add the new subject to the search params.
      navigateShow({ to: paths.show, search: { subject }, replace });
    }
  }

  if (subjectQ === undefined) {
    if (pathname === '/' && !getHomeDrive())
      return [undefined, handleSetSubject];

    if (pathname.startsWith('/app/')) {
      return [undefined, handleSetSubject];
    }

    // The pathname defaults to a trailing slash, which leads to issues
    const correctedPathName = pathname === '/' ? '' : pathname;
    // In Tauri the window origin (tauri://localhost) isn't a fetchable
    // subject; the embedded server's origin is.
    const subject =
      (isDev() ? store.getServerUrl() : getLocalServerOrigin()) +
      correctedPathName +
      window.location.search;

    return [subject, handleSetSubject];
  }

  return [subjectQ, handleSetSubject];
}

/** Hook for getting and setting a query param from the current Subject */
export function useSubjectParam(
  key: string,
): [string | undefined, (subject?: string) => void] {
  const [subject, setSubject] = useCurrentSubject();
  const [params, setParams] = useState<URLSearchParams | undefined>(undefined);

  useEffect(() => {
    if (subject) {
      setParams(new URL(subject).searchParams);
    } else {
      setParams(undefined);
    }
  }, [subject]);

  function setVal(newVal: string | undefined) {
    if (!params || !subject) {
      return;
    }

    if (newVal === undefined) {
      params.delete(key);
    } else {
      params.set(key, newVal);
    }

    const newUrl = new URL(subject);

    if (newVal) {
      newUrl.searchParams.set(key, newVal);
    }

    if (newVal === undefined || newVal === '' || newVal === null) {
      newUrl.searchParams.delete(key);
    }

    setSubject(newUrl.href);
  }

  let returnVal = params?.get(key);

  if (returnVal === null || returnVal === undefined) {
    returnVal = undefined;
  }

  return [returnVal, setVal];
}
