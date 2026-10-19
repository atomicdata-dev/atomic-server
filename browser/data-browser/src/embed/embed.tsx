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
 *   open(subject)     same, replacing the current page in the history (a
 *                     pre-loaded page: back then leaves the resource)
 *   changed(subjects) these resources changed in the host's store
 *   flush(leaving?)   hand every pending edit to the host; resolves when done
 *
 * Page to host, besides the store's calls: `openNative(kind, subject, title)`
 * (`hostActions.ts`) asks the app to show the chat of a meeting or chat room in
 * its own screen; the answer is whether it did.
 *
 * Saving: the store has no server, so its commits go to the host instead
 * (`commitTransport`): signed through the host, applied by `applyCommit`.
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
import {
  enableEmbedMode,
  setHostColorScheme,
  type HostColorScheme,
} from '../helpers/embedMode';
import { Providers } from '../Providers';
import { ResourceContextMenu } from '../components/ResourceContextMenu';
import ResourcePage from '../views/ResourcePage';
import { BreadCrumbs } from '../components/BreadCrumbs';
import { CalculatedPageHeight } from '../globalCssVars';
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
import { styled } from 'styled-components';
import { createFlutterHost } from './flutterHost';
import { createMockHost } from './mockHost';
import { createFlush } from './flush';
import { closeTopOverlay } from './overlayBack';
import { setActionsHost } from './hostActions';
import { useNativeChatRoom } from './useNativeChatRoom';

enableEmbedMode();

// The app already lays the page out inside the system bars, but the web view
// still reports their size as `env(safe-area-inset-*)`, so the page would leave
// that room empty a second time (the canvas toolbar floated 50px above the
// bottom bar). Nothing here is edge to edge: the insets are zero.
const withoutInsets = (css: string) =>
  css.replace(/env\(\s*safe-area-inset-[a-z]+\s*(?:,[^)]*)?\)/g, '0px');
const insertRule = CSSStyleSheet.prototype.insertRule;

CSSStyleSheet.prototype.insertRule = function (rule, index) {
  return insertRule.call(this, withoutInsets(rule), index);
};

new MutationObserver(records => {
  for (const record of records) {
    for (const node of record.addedNodes) {
      if (node instanceof HTMLStyleElement && node.textContent) {
        node.textContent = withoutInsets(node.textContent);
      }
    }
  }
}).observe(document.head, { childList: true });

declare global {
  interface Window {
    /** Set by the Flutter host: how the page calls Rust. */
    atomicHost?: NativeChannel;
    /** Flutter's `JavaScriptChannel`, when the page runs inside the app. */
    AtomicFlutter?: { postMessage(message: string): void };
    atomicEmbed?: {
      show(subject: string): void;
      open(subject: string): void;
      changed(subjects: string[]): void;
      /** `anchor`: the app's "more" button (right edge, top), in page px. */
      openMenu(anchor?: { x: number; y: number }): void;
      back(): boolean;
      flush(leaving?: boolean): Promise<void>;
      setColorScheme(scheme: HostColorScheme | undefined): void;
    };
  }
}

const channel: NativeChannel =
  window.atomicHost ??
  (window.AtomicFlutter
    ? createFlutterHost(window.AtomicFlutter)
    : createMockHost());
const db = new NativeClientDb(channel);

// Only the app can open its own screens; the mock host answers nothing to that.
setActionsHost(window.atomicHost || window.AtomicFlutter ? channel : undefined);

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
  // Edits go to the host, which keeps them and syncs them. Without this the
  // store, having no server, would only ever save them offline, into a page
  // database nobody keeps: the typing was gone once the page closed.
  commitTransport: db.commitTransport,
});

store.setClientDb(db as unknown as ClientDbWorker);
await db.waitForInit();

const flush = createFlush(store, db);

// The app going to the background, or the page being torn down: whatever is
// still in a debounce timer goes now. (Leaving a page, the app also asks for
// a flush itself and waits for it.)
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') void flush();
});
window.addEventListener('pagehide', () => void flush());

const rootRoute = createRootRoute({
  component: () => (
    <Providers>
      <Outlet />
    </Providers>
  ),
});

const HEADER_HEIGHT = '36px';
const OuterHeight = 'var(--embed-outer-height)';

/** The page area as the layout computed it, before the header took its part. */
const ShowFrame = styled.div`
  display: contents;
  --embed-outer-height: ${CalculatedPageHeight.var()};
`;

const EmbedHeader = styled.header`
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  align-items: center;
  height: ${HEADER_HEIGHT};
  box-sizing: border-box;
  background: ${p => p.theme.colors.bg};
  border-bottom: 1px solid ${p => p.theme.colors.bg2};

  & > nav {
    flex: 1;
  }
`;

/** Gives the page (whose `main` scrolls) the height left under the header. */
const BelowHeader = styled.div`
  display: contents;
  ${CalculatedPageHeight.define(`calc(${OuterHeight} - ${HEADER_HEIGHT})`)}
`;

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
    const [menuAnchor, setMenuAnchor] = useState({
      x: 16,
      y: window.innerHeight,
    });

    useEffect(() => {
      const open = (e: Event) => {
        const at = (e as CustomEvent<{ x: number; y: number } | undefined>)
          .detail;

        setMenuAnchor(at ?? { x: 16, y: window.innerHeight });
        setMenuId(id => id + 1);
      };

      window.addEventListener('atomic-embed-menu', open);

      return () => window.removeEventListener('atomic-embed-menu', open);
    }, []);

    // A chat room is the app's native chat screen when it has one.
    useNativeChatRoom(subject, () => {
      if (history.canGoBack()) history.back();
    });

    if (!subject) {
      return null;
    }

    return (
      <ShowFrame>
        <EmbedHeader>
          <BreadCrumbs
            subject={subject}
            onNavigate={target =>
              void router.navigate({
                to: '/app/show',
                search: { subject: target },
              })
            }
          />
        </EmbedHeader>
        <BelowHeader>
          <ResourcePage key={subject} subject={subject} />
        </BelowHeader>
        {menuId > 0 && (
          <ResourceContextMenu
            key={menuId}
            subject={subject}
            isMainMenu
            anchorPoint={menuAnchor}
          />
        )}
      </ShowFrame>
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
  open(subject) {
    void router.navigate({
      to: '/app/show',
      search: { subject },
      replace: true,
    });
  },
  changed(subjects) {
    for (const subject of subjects) void store.getResource(subject);
  },
  /** One step back in the page's own history; false when there is none. */
  back() {
    // An open overlay (the meeting chat) goes first.
    if (closeTopOverlay()) {
      return true;
    }

    if (!history.canGoBack()) {
      return false;
    }

    history.back();

    return true;
  },
  /** The app's own light/dark mode; "Auto" in the settings follows it. */
  setColorScheme(scheme) {
    setHostColorScheme(scheme);
  },
  openMenu(anchor) {
    window.dispatchEvent(
      new CustomEvent('atomic-embed-menu', { detail: anchor }),
    );
  },
  /** Every pending edit handed to the host. `leaving`: the page is about to
   * close, so an edit in progress (a focused field) ends first. */
  flush(leaving = false) {
    return flush({ leaving });
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

// Tells the host the page is up, so it can keep one loaded and hidden and show
// a resource in it with `open(subject)` instead of loading a page.
window.AtomicFlutter?.postMessage(JSON.stringify({ method: 'ready' }));
