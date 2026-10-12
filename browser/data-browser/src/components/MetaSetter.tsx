import { core, useResource, useString, useTitle } from '@tomic/react';

import { useLocation } from '@tanstack/react-router';

import { useSettings } from '../helpers/AppSettings';
import { useCurrentSubject } from '../helpers/useCurrentSubject';
import { isHostedDistribution } from '../helpers/managedServer';
import { pathNames } from '../routes/paths';

import type { JSX } from 'react';

/** The name in the browser tab: the hosted product's, or a neutral one. */
export function appName(): string {
  return isHostedDistribution()
    ? /* @wc-ignore */ 'atomic.place'
    : /* @wc-ignore */ 'AtomicServer';
}

function useRouteTitle(): string | undefined {
  const { pathname } = useLocation();
  const route = pathname.replace(/^\/app/, '').replace(/\/$/, '');

  switch (route) {
    case pathNames.welcome:
      return 'Welcome';
    case pathNames.agentSettings:
      return 'Account';
    case pathNames.appSettings:
      return 'Settings';
    case pathNames.integrations:
      return 'Integrations';
    case pathNames.notifications:
      return 'Notifications';
    case pathNames.sync:
      return 'Sync';
    case pathNames.serverSettings:
      return 'Server settings';
    case pathNames.new:
      return 'New resource';
    case pathNames.newDrive:
      return 'New drive';
    case pathNames.shortcuts:
      return 'Keyboard shortcuts';
    case pathNames.search:
      return 'Search';
    case pathNames.share:
      return 'Share';
    case pathNames.token:
      return 'Token';
    case pathNames.data:
      return 'Data';
    case pathNames.edit:
      return 'Edit';
    case pathNames.about:
      return 'About';
    case pathNames.import:
      return 'Import';
    case pathNames.onboarding:
      return 'Get started';
    case pathNames.history:
      return 'History';
    case pathNames.invite:
      return 'Invitation';
    default:
      return undefined;
  }
}

/** Sets various HTML meta tags, depending on the currently opened resource */
export function MetaSetter(): JSX.Element {
  const { mainColor, darkMode } = useSettings();
  const [subject] = useCurrentSubject();
  const resource = useResource(subject);
  const [title] = useTitle(resource);
  const [name] = useString(resource, core.properties.name);
  const [description] = useString(resource, core.properties.description);

  // `resource.isReady()` is a method call on the mutable Resource proxy.
  // React Compiler memoizes its result on the proxy's reference identity,
  // and the proxy is reused across renders while its internal loading/error
  // state mutates — so the cached value locks in `false` from the first
  // render and the title stays on the product name forever. `name`, by contrast,
  // is reactive (`useString` → `useSyncExternalStore`), so use its
  // presence as the "have data" signal. See
  // `memory/react-compiler-resource-proxy-pitfall.md`.
  const routeTitle = useRouteTitle();
  const brand = appName();
  const hasName = name !== undefined && name !== '';
  // A resource shows its own name, a settings-style page its own title; the
  // product name closes either one, and stands alone while nothing is known.
  const pageTitle = routeTitle ?? (hasName ? title : undefined);
  const displayTitle = pageTitle ? `${pageTitle} · ${brand}` : brand;
  const displayDescription =
    !routeTitle && hasName && description
      ? description
      : isHostedDistribution()
        ? 'Your own place for documents, tables, meetings and chat. Local-first and open source, with optional cloud backup and sync.'
        : 'The easiest way to create, share and model Linked Atomic Data.';

  return (
    <>
      <title>{displayTitle}</title>
      <meta name='theme-color' content={darkMode ? 'black' : 'white'} />
      <meta
        name='apple-mobile-web-app-status-bar-style'
        content={darkMode ? 'black' : 'default'}
      />
      <meta name='msapplication-TileColor' content={mainColor} />
      <meta name='description' content={displayDescription} />
      <meta property='og:title' content={displayTitle} />
      <meta property='og:description' content={displayDescription} />
      <meta property='og:url' content={subject} />
    </>
  );
}
