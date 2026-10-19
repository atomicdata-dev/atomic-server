/**
 * Entry of the Flutter app's embedded renderer: one resource, no chrome.
 *
 * The host app (Rust `atomic_lib`) is the only store: this page keeps no
 * database and opens no connection. It reads through a `NativeClientDb` and
 * signs through a `NativeCryptoProvider`, both over the host's channel. Outside
 * the app (a desktop browser, for development) a mock host answers instead.
 *
 * Host API, on `window.atomicEmbed`:
 *   show(subject)     render this resource
 *   changed(subjects) these resources changed in the host's store
 */
import '../helpers/preloadLocale';
import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from '@tanstack/react-router';
import {
  Agent,
  enableLoro,
  NativeClientDb,
  NativeCryptoProvider,
  Store,
  StoreContext,
  type ClientDbWorker,
  type NativeChannel,
} from '@tomic/react';
import { enableEmbedMode } from '../helpers/embedMode';
import { Providers } from '../Providers';
import { ResourceContextMenu } from '../components/ResourceContextMenu';
import ResourcePage from '../views/ResourcePage';
import { paths } from '../routes/paths';
import { NewRoute } from '../routes/NewResource/NewRoute';
import { EditRoute } from '../routes/EditRoute';
import { DataRoute } from '../routes/DataRoute';
import { HistoryRoute } from '../routes/History/HistoryRoute';
import { ShareRoute } from '../routes/Share/ShareRoute';
import { ImportRoute } from '../routes/ImportRoute';
import { StorageRoute } from '../routes/StorageRoute';
import { NotificationsRoute } from '../routes/NotificationsRoute';
import { AppSettingsRoute } from '../routes/AppSettings';
import { createFlutterHost } from './flutterHost';
import { createMockHost } from './mockHost';

enableEmbedMode();

declare global {
  interface Window {
    /** Set by the Flutter host: how the page calls Rust. */
    atomicHost?: NativeChannel;
    /** Flutter's `JavaScriptChannel`, when the page runs inside the app. */
    AtomicFlutter?: { postMessage(message: string): void };
    atomicEmbed?: {
      show(subject: string): void;
      changed(subjects: string[]): void;
      openMenu(): void;
      back(): boolean;
    };
  }
}

const channel: NativeChannel =
  window.atomicHost ??
  (window.AtomicFlutter
    ? createFlutterHost(window.AtomicFlutter)
    : createMockHost());
const db = new NativeClientDb(channel);

const agentSubject = (await channel
  .call('agent', [])
  .catch(() => undefined)) as string | undefined;

const store = new Store({
  // Never used: nothing here connects. A valid origin is all the store wants.
  serverUrl: 'https://embed.invalid',
  connect: false,
  agent: agentSubject
    ? new Agent(new NativeCryptoProvider(channel), agentSubject)
    : undefined,
});

store.setClientDb(db as unknown as ClientDbWorker);
await db.waitForInit();

const rootRoute = createRootRoute({
  component: () => (
    <Providers>
      <Outlet />
    </Providers>
  ),
});

const showRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/app/show',
  validateSearch: (search): { subject: string } => ({
    subject: (search.subject as string) ?? '',
  }),
  component: function Show() {
    const { subject } = showRoute.useSearch();

    // The app's native "more" button opens the same menu as the web navbar's.
    const [menuId, setMenuId] = useState(0);

    useEffect(() => {
      const open = () => setMenuId(id => id + 1);

      window.addEventListener('atomic-embed-menu', open);

      return () => window.removeEventListener('atomic-embed-menu', open);
    }, []);

    if (!subject) {
      return null;
    }

    return (
      <>
        <ResourcePage key={subject} subject={subject} />
        {menuId > 0 && (
          <ResourceContextMenu
            key={menuId}
            subject={subject}
            isMainMenu
            anchorPoint={{ x: 16, y: window.innerHeight }}
          />
        )}
      </>
    );
  },
});

/** The pages the resource menu leads to: the web app's own route components,
 * mounted under this root (they are made for the app's root, which the embed
 * does not use). */
const actionRoutes = [
  [paths.new, NewRoute],
  [paths.edit, EditRoute],
  [paths.data, DataRoute],
  [paths.history, HistoryRoute],
  [paths.share, ShareRoute],
  [paths.import, ImportRoute],
  [paths.storage, StorageRoute],
  [paths.notifications, NotificationsRoute],
  [paths.appSettings, AppSettingsRoute],
].map(([path, source]) =>
  createRoute({
    getParentRoute: () => rootRoute,
    path: path as string,
    // @ts-expect-error - options are shared with the app's route of that page
    validateSearch: source.options.validateSearch,
    // @ts-expect-error - same component, other parent
    component: source.options.component,
  }),
);

const history = createMemoryHistory({
  initialEntries: [
    // The app opens a page of its own (notifications, settings) with `path`.
    new URLSearchParams(location.search).get('path') ??
      `/app/show?subject=${encodeURIComponent(
        new URLSearchParams(location.search).get('subject') ?? '',
      )}`,
  ],
});

const router = createRouter({
  routeTree: rootRoute.addChildren([showRoute, ...actionRoutes]),
  history,
});

window.atomicEmbed = {
  show(subject) {
    void router.navigate({ to: '/app/show', search: { subject } });
  },
  changed(subjects) {
    for (const subject of subjects) void store.getResource(subject);
  },
  /** One step back in the page's own history; false when there is none. */
  back() {
    if (!history.canGoBack()) {
      return false;
    }

    history.back();

    return true;
  },
  openMenu() {
    window.dispatchEvent(new Event('atomic-embed-menu'));
  },
};

// Documents, tables and canvases are Loro CRDTs; the module loads lazily.
enableLoro().catch(e => console.warn('Loro failed to load', e));

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <StoreContext.Provider value={store}>
      <RouterProvider router={router} />
    </StoreContext.Provider>
  </StrictMode>,
);
