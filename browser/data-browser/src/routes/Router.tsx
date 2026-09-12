import { createRoute, createRouter, Link } from '@tanstack/react-router';
import { ShowRoute } from './ShowRoute';
import { SearchRoute } from './Search/SearchRoute';
import { NewRoute } from './NewResource/NewRoute';
import { AppSettingsRoute } from './AppSettings';
import { IntegrationStoreRoute } from './IntegrationStore';
import { EditRoute } from './EditRoute';
import { DataRoute } from './DataRoute';
import { ShortcutsRoute } from './ShortcutsRoute';
import { AboutRoute } from './AboutRoute';
import { AgentSettingsRoute } from './SettingsAgent';
import { SyncRoute } from './SyncRoute';
import { ServerSettingsRoute } from './SettingsServer';
import { pathNames } from './paths';
import { ShareRoute } from './Share/ShareRoute';
import { TokenRoute } from './TokenRoute';
import { devRoutesEnabled } from '../config';
import { rootRoute, topRoute, appRoute } from './RootRoutes';
import { unavailableLazyRoute } from './UnavailableLazyRoute';
import { ImportRoute } from './ImportRoute';
import { HistoryRoute } from './History/HistoryRoute';
import { InviteRoute } from './InviteRoute';
import { LinkOpenRouter } from './LinkOpenRouter';
import { OnboardingRoute } from './OnboardingRoute';
import { WelcomeRoute } from './WelcomeRoute';
import { NewDriveRoute } from './NewDriveRoute';

const DevDriveRoute = createRoute({
  getParentRoute: () => appRoute,
  path: pathNames.devDrive,
  // @ts-expect-error - Mismatch between unavailable route name and dev-drive route name
}).lazy(() => {
  if (devRoutesEnabled()) {
    return import('./DevDriveRoute').then(mod => mod.devDriveRouteLazy);
  } else {
    return Promise.resolve(unavailableLazyRoute);
  }
});

const DemoRoute = createRoute({
  getParentRoute: () => appRoute,
  path: pathNames.demo,
}).lazy(() => import('./DemoRoute').then(mod => mod.demoRouteLazy));

const DevonianDemoRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/devonian-demo',
}).lazy(() =>
  import('./DevonianDemoRoute').then(mod => mod.devonianDemoRouteLazy),
);

const PruneTestsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: pathNames.pruneTests,
  // @ts-expect-error - Mismatch between unavailable route name and prune route name, not sure how to fix this.
}).lazy(() => {
  if (devRoutesEnabled()) {
    return import('./PruneTestsRoute').then(mod => mod.pruneTestRouteLazy);
  } else {
    return Promise.resolve(unavailableLazyRoute);
  }
});

const SandboxRoute = createRoute({
  getParentRoute: () => appRoute,
  path: pathNames.sandbox,
  // @ts-expect-error - Mismatch between unavailable route name and sandbox route name, not sure how to fix this.
}).lazy(() => {
  if (devRoutesEnabled()) {
    return import('./Sandbox').then(mod => mod.sandboxRouteLazy);
  } else {
    return Promise.resolve(unavailableLazyRoute);
  }
});

const routeTree = rootRoute.addChildren({
  appRoute: appRoute.addChildren({
    WelcomeRoute,
    ShowRoute,
    SearchRoute,
    AppSettingsRoute,
    IntegrationStoreRoute,
    SyncRoute,
    ShortcutsRoute,
    AgentSettingsRoute,
    ServerSettingsRoute,
    DataRoute,
    EditRoute,
    ImportRoute,
    OnboardingRoute,
    ShareRoute,
    AboutRoute,
    TokenRoute,
    HistoryRoute,
    NewRoute,
    NewDriveRoute,
    PruneTestsRoute,
    SandboxRoute,
    DevDriveRoute,
    DemoRoute,
    DevonianDemoRoute,
    InviteRoute,
    LinkOpenRouter,
  }),
  topRoute,
});

export const router = createRouter({
  routeTree,
  defaultNotFoundComponent: () => {
    return (
      <div>
        <p>Not found!</p>
        <Link to='/'>Go home</Link>
      </div>
    );
  },
});

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
