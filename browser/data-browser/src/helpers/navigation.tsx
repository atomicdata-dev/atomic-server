import { paths } from '../routes/paths';
import { unknownSubject } from '@tomic/react';

/** Constructs a URL string with a route, a query Parameter and a value */
function constructURL(
  /** The base path, e.g. '/new' */
  path: string,
  queryParams: Record<string, string> | string[][],
): string {
  const params = new URLSearchParams(queryParams);

  return `${path}?${params}`;
}

const isRemoteResource = (subject: URL) =>
  window.location.origin !== subject.origin;

/** Constructs a URL for opening / showing a Resource. */
export function constructOpenURL(
  subject: string,
  extraParams: Record<string, string> = {},
): string {
  if (subject === unknownSubject) {
    return '#';
  }

  let url: URL;

  try {
    url = new URL(subject);
  } catch {
    // Non-URL subjects (e.g. DIDs) are always treated as remote resources
    return constructURL(paths.show, { subject, ...extraParams });
  }

  if (isRemoteResource(url)) {
    return constructURL(paths.show, { subject, ...extraParams });
  }

  const path = url.pathname + url.search;

  return path;
}

/** Query parameters used by the `/new` route */
export const newURLParams = {
  classSubject: 'classSubject',
  parent: 'parent',
  newSubject: 'newSubject',
};

/** Constructs a URL for the New Resource form */
export function newURL(
  classUrl: string,
  parentURL?: string,
  subject?: string,
): string {
  const navTo = new URL(location.origin);
  navTo.pathname = paths.new;
  navTo.searchParams.append(newURLParams.classSubject, classUrl);

  if (parentURL) {
    navTo.searchParams.append(newURLParams.parent, parentURL);
  }

  if (subject) {
    navTo.searchParams.append(newURLParams.newSubject, subject);
  }

  return paths.new + navTo.search;
}

export function editURL(subject: string): string {
  return constructURL(paths.edit, { subject });
}

export function dataURL(subject: string): string {
  return constructURL(paths.data, { subject });
}

export function pathToURL(path: string): string {
  return window.location.origin + path;
}

export function importerURL(subject: string): string {
  return constructURL(paths.import, { subject });
}

export function historyURL(subject: string): string {
  return constructURL(paths.history, { subject });
}
