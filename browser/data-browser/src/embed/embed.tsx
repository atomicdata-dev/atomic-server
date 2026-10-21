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
 * its own screen; the answer is whether it did. `opened(subject)` tells the app
 * the page settled on a resource, for its Recents.
 *
 * Saving: the store has no server, so its commits go to the host instead
 * (`commitTransport`): signed through the host, applied by `applyCommit`.
 * Reading: only from the host (`noServer`, `embedStore.ts`).
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
import { enableLoro, StoreContext, type NativeChannel } from '@tomic/react';
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
import { goToFirstEntry } from './resetHistory';
import { actionPages } from './actionPages';
import { styled } from 'styled-components';
import { createFlutterHost } from './flutterHost';
import { createMockHost } from './mockHost';
import { createFlush } from './flush';
import {
  adoptDriveOf,
  createEmbedStore,
  registerEmbedActions,
} from './embedStore';
import { installTouchGestures, setGestures } from './gestures';
import { closeTopOverlay } from './overlayBack';
import {
  reportShown,
  setActionsHost,
  SHOW_SIDEBAR_ICONS_KEY,
} from './hostActions';
import { setLocalStorageValue } from '../hooks/useLocalStorage';
import { useNativeChatRoom } from './useNativeChatRoom';
import { embedTouchCss } from './touchStyle';
import { aiCall } from './aiTools';
import { AiToolsHost } from './AiToolsHost';

enableEmbedMode();
registerEmbedActions();

// The app passes its light or dark mode in the URL (`?scheme=dark`), so the
// first frame is already in it: a page loaded ahead and shown later must not
// flash the other one before the app's `setColorScheme` arrives.
const startScheme = new URLSearchParams(location.search).get('scheme');

if (startScheme === 'dark' || startScheme === 'light') {
  setHostColorScheme(startScheme);
  document.documentElement.style.colorScheme = startScheme;
}

// "Show icons in the sidebar" is the app's setting (one value for the app's
// lists and this page): it passes it in the URL (`?sidebarIcons=0`) and updates
// it with `atomicEmbed.setSidebarIcons`. Written to the page's own storage so
// the settings page and the sidebar hook read it like the browser's setting.
function applyHostSidebarIcons(show: boolean): void {
  setLocalStorageValue(SHOW_SIDEBAR_ICONS_KEY, show);
}

const startSidebarIcons = new URLSearchParams(location.search).get(
  'sidebarIcons',
);

if (startSidebarIcons === '0' || startSidebarIcons === '1') {
  applyHostSidebarIcons(startSidebarIcons === '1');
}

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

// The web app styles `::-webkit-scrollbar` for desktop, which makes the
// Android web view draw a classic scrollbar: a grey bar along the whole
// right edge that takes 9px of the page, always visible. A phone scrolls by
// touch, so the page shows none (as the app's native lists).
const noScrollbars = document.createElement('style');
noScrollbars.textContent = '::-webkit-scrollbar { display: none; }';
document.head.append(noScrollbars);

const touchStyle = document.createElement('style');
touchStyle.textContent = embedTouchCss;
document.head.append(touchStyle);

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
      setSidebarIcons(show: boolean): void;
      /** Swipe-back needs of the page; the host hears changes. */
      setGestures(mode: 'default' | 'horizontal'): void;
      /** The app's AI chat (`?ai=1`): `aiCall(id, 'tools' | 'prompt' |
       * 'run', args)` answers with an `aiResult` message (`aiTools.ts`). */
      aiCall(
        id: number,
        method: 'tools' | 'prompt' | 'run',
        args?: unknown[],
      ): void;
    };
  }
}

const channel: NativeChannel =
  window.atomicHost ??
  (window.AtomicFlutter
    ? createFlutterHost(window.AtomicFlutter)
    : createMockHost());
// Only the app can open its own screens; the mock host answers nothing to that.
setActionsHost(window.atomicHost || window.AtomicFlutter ? channel : undefined);

const { store, db } = await createEmbedStore(channel);

const flush = createFlush(store, db);

// The app going to the background, or the page being torn down: whatever is
// still in a debounce timer goes now. (Leaving a page, the app also asks for
// a flush itself and waits for it.)
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') void flush();
});
window.addEventListener('pagehide', () => void flush());

// The app's AI chat loads this page without a screen to use the web chat's
// tools (`?ai=1&drive=<subject>`).
const aiParams = new URLSearchParams(location.search);
const aiMode = aiParams.get('ai') === '1';

const rootRoute = createRootRoute({
  component: () => (
    <Providers>
      {aiMode && <AiToolsHost drive={aiParams.get('drive') ?? undefined} />}
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

    // A resource reached inside the page (a folder's child, a link, one just
    // created) goes into the app's Recents like one opened from the app.
    useEffect(() => {
      reportShown(subject);

      return () => reportShown(undefined);
    }, [subject]);

    // The drive first: the rows of a table are asked of the host's per-drive
    // index, and a list built before the drive is known stays empty.
    const [driveOf, setDriveOf] = useState<string>();

    useEffect(() => {
      let live = true;

      void adoptDriveOf(store, subject).then(() => {
        if (live) setDriveOf(subject);
      });

      return () => {
        live = false;
      };
    }, [subject]);

    if (!subject || driveOf !== subject) {
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
const actionRoutes = actionPages.map(([path, source]) =>
  createRoute({
    getParentRoute: () => rootRoute,
    path: path as string,
    validateSearch: source.options.validateSearch,
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
    // The warm-up showed other resources here (`show`); none of them is a
    // place back goes to.
    goToFirstEntry(history);
    void router.navigate({
      to: '/app/show',
      search: { subject },
      replace: true,
    });
  },
  changed(subjects) {
    // `getResource` answers a resource the page already holds from memory,
    // so a change made outside the page (renamed in the app's own screen)
    // never showed: read it from the host again.
    for (const subject of subjects) {
      if (store.getResourceLoading(subject).hasPendingCommits) continue;
      void store.reloadResource(subject).catch(() => undefined);
    }
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
  setSidebarIcons(show) {
    applyHostSidebarIcons(!!show);
  },
  setGestures,
  aiCall(id, method, args) {
    void aiCall(m => window.AtomicFlutter?.postMessage(m), id, method, args);
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

installTouchGestures();

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
