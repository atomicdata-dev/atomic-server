import {
  createRootRoute,
  createRoute,
  Outlet,
  useLocation,
} from '@tanstack/react-router';
import { useStore } from '@tomic/react';
import { useEffect, useState } from 'react';
import { pathNames, paths } from './paths';
// import { TanStackRouterDevtools } from '@tanstack/router-devtools';
import { Providers } from '../Providers';
import { IdentityReconcileGate } from '../components/IdentityReconcileGate';
import { DeviceLockWatcher } from '../components/DeviceLockWatcher';
import { CloudVaultWatcher } from '../components/CloudVaultWatcher';
import { PairingLinkHandler } from '../components/PairingLinkHandler';
import { PairingFlowProvider } from '../components/pairing/PairingFlowProvider';
import ResourcePage from '../views/ResourcePage';
import { useSettings } from '../helpers/AppSettings';
import { isDev } from '../config';
import { getLocalServerOrigin, isRunningInTauri } from '../helpers/tauri';
import { fetchPrivateDriveSubject } from '../helpers/privateDrive';
import { constructOpenURL } from '../helpers/navigation';
import { getHomeDrive } from '../helpers/homeDrive';
import { useNavigateWithTransition } from '../hooks/useNavigateWithTransition';

export const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: pathNames.app,
  component: () => <Outlet />,
  notFoundComponent: () => <p>404 Not found</p>,
});

export const rootRoute = createRootRoute({
  component: () => (
    <Providers>
      {/* The one dialog every pairing entry point drives — the scanner, the
          paste field, and deep links. Wraps both, since the routes below start
          the flow and the link handler feeds it. */}
      <PairingFlowProvider>
        {/* Silently keep the device's Atomic agent aligned with the signed-in
            Managed Sync account (no-op when there's no managed session). */}
        <IdentityReconcileGate>
          <Outlet />
        </IdentityReconcileGate>
        {/* Consumes scanned/tapped atomic://pair deep links (QR pairing). */}
        <PairingLinkHandler />
        {/* Keeps the device-lock heartbeat alive and enforces idle policies
            while the app is open (no-op unless a policy is set). */}
        <DeviceLockWatcher />
        {/* Enrols the personal drive in Cloud Vault and backs it up after
            edits (no-op without an account session). */}
        <CloudVaultWatcher />
      </PairingFlowProvider>
      {/* Uncomment to get Tanstack Router Devtools */}
      {/* <TanStackRouterDevtools position='bottom-right' /> */}
    </Providers>
  ),
});

const TopRouteComponent: React.FC = () => {
  const { pathname } = useLocation();
  const { baseURL, agent, drive, setDrive } = useSettings();
  const store = useStore();
  const navigate = useNavigateWithTransition();

  // When the URL is the bare root, we shouldn't assume the server root IS a
  // drive — often it isn't, or the user isn't authorized to see it. Prefer:
  //   0. server declares a home drive → open it, for everyone
  //   1. signed-in agent with a personal drive → open that drive
  //   2. no agent → go to the welcome / sign-in flow
  //   3. otherwise → fall through to whatever lives at `/`
  //
  // Step 0 is deliberately first and deliberately ignores the Agent: the
  // operator has said "this Drive is my front page", and a front page is the
  // same for everyone. That is also what makes it instant — it comes from the
  // served HTML, so it needs neither a request nor the async IndexedDB read
  // that answering "is anyone signed in?" would require.
  const isRoot = pathname === '/' || pathname === '';
  const homeDrive = getHomeDrive();
  const [resolvingRoot, setResolvingRoot] = useState(isRoot);

  useEffect(() => {
    if (!isRoot) {
      setResolvingRoot(false);

      return;
    }

    if (homeDrive) {
      // Adopt the Drive the server actually named. `AppSettings` otherwise
      // defaults to `baseURL`, which is the origin *without* a trailing slash
      // and so is not the root Drive's subject (`http://host/`). Both spellings
      // answer over HTTP, so the split is invisible server-side — but on the
      // client they are two different cache keys, producing two separate
      // Collections. The sidebar reads the one keyed by `drive` and finds it
      // empty while the correctly-keyed one holds the children.
      if (drive !== homeDrive) {
        setDrive(homeDrive);
      }

      const target = constructOpenURL(homeDrive);

      // The home Drive is usually the server root itself, and
      // `constructOpenURL` maps a same-origin subject back to a bare path —
      // so `target` is `/`, the page we are already on. Navigating there is a
      // no-op, which would leave `resolvingRoot` set forever and render
      // `null`: no resource, no error, no loader, just an empty page with a
      // working sidebar around it. Nothing left to resolve — fall through and
      // render `/` as the resource it is.
      if (
        target === `${pathname}${window.location.search}` ||
        target === pathname
      ) {
        setResolvingRoot(false);

        return;
      }

      // `replace`, so Back leaves the site instead of returning to `/` and
      // being bounced straight back to the home Drive.
      navigate({ to: target, replace: true });

      return;
    }

    if (!agent) {
      navigate({ to: paths.welcome, replace: true });

      return;
    }

    // Fast path: user's last-used drive (persisted by AppSettings). Skip it
    // when it's still the initial default that equals the server root, since
    // that's the subject we're specifically trying to avoid landing on.
    if (drive && drive !== baseURL) {
      navigate(constructOpenURL(drive));

      return;
    }

    let cancelled = false;

    fetchPrivateDriveSubject(store, agent)
      .then(resolved => {
        if (cancelled) return;

        if (resolved && resolved !== baseURL) {
          navigate(constructOpenURL(resolved));
        } else {
          setResolvingRoot(false);
        }
      })
      .catch(() => {
        if (!cancelled) setResolvingRoot(false);
      });

    return () => {
      cancelled = true;
    };
  }, [
    isRoot,
    homeDrive,
    pathname,
    agent,
    drive,
    setDrive,
    baseURL,
    store,
    navigate,
  ]);

  // In dev, the UI is often on :6747 while JSON-AD is served from the Atomic
  // server (e.g. :9883). In Tauri, the UI is on a custom protocol while the
  // embedded server is on 9883. In both cases, resolve `/` against the
  // configured server (baseURL) or the embedded-server fallback — not
  // window.location.origin, which isn't fetchable.
  const origin =
    (isDev() || isRunningInTauri()) && baseURL
      ? new URL(baseURL).origin
      : isDev() || isRunningInTauri()
        ? getLocalServerOrigin()
        : window.location.origin;

  const subject = `${origin}${pathname}${window.location.search}`;

  // During a route transition this outgoing component can observe the new
  // location before it unmounts. App routes are screens, not data subjects.
  if (resolvingRoot || pathname.startsWith('/app/')) return null;

  return <ResourcePage subject={subject} key={subject} />;
};

export const topRoute = createRoute({
  path: '$',
  component: TopRouteComponent,
  getParentRoute: () => rootRoute,
});
