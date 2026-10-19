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
import { StrictMode } from 'react';
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
  NativeClientDb,
  NativeCryptoProvider,
  Store,
  StoreContext,
  type ClientDbWorker,
  type NativeChannel,
} from '@tomic/react';
import { enableEmbedMode } from '../helpers/embedMode';
import { Providers } from '../Providers';
import ResourcePage from '../views/ResourcePage';
import { createMockHost } from './mockHost';

enableEmbedMode();

declare global {
  interface Window {
    /** Set by the Flutter host: how the page calls Rust. */
    atomicHost?: NativeChannel;
    atomicEmbed?: {
      show(subject: string): void;
      changed(subjects: string[]): void;
    };
  }
}

const channel: NativeChannel = window.atomicHost ?? createMockHost();
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

    return subject ? <ResourcePage key={subject} subject={subject} /> : null;
  },
});

const history = createMemoryHistory({
  initialEntries: [
    `/app/show?subject=${encodeURIComponent(
      new URLSearchParams(location.search).get('subject') ?? '',
    )}`,
  ],
});

const router = createRouter({
  routeTree: rootRoute.addChildren([showRoute]),
  history,
});

window.atomicEmbed = {
  show(subject) {
    void router.navigate({ to: '/app/show', search: { subject } });
  },
  changed(subjects) {
    for (const subject of subjects) void store.getResource(subject);
  },
};

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <StoreContext.Provider value={store}>
      <RouterProvider router={router} />
    </StoreContext.Provider>
  </StrictMode>,
);
