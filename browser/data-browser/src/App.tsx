import { StoreContext, Store, enableLoro, Client } from '@tomic/react';

import { isDev } from './config';
import { registerHandlers } from './handlers';
import { getAgentFromIDB, saveAgentToIDB } from './helpers/agentStorage';
import { shouldLock } from './helpers/deviceLock';
import { registerCustomCreateActions } from './components/forms/NewForm/CustomCreateActions';
import { serverURLStorage } from './helpers/serverURLStorage';
import { driveStorage } from './helpers/driveStorage';
import { isRunningInTauri } from './helpers/tauri';
import {
  isOriginWithoutNode,
  originMayLackNode,
  probeOriginForNode,
} from './helpers/originNode';

import { useEffect, type JSX } from 'react';
import { RouterProvider } from '@tanstack/react-router';
import { router } from './routes/Router';

import { errorHandler } from './handlers/errorHandler';
import { PerformanceProfiler, attachStoreToProfiler } from './helpers/profiler';

/**
 * The atomic-server the Store talks to.
 *
 * Normally the SPA is *served by* atomic-server, so its own origin IS the
 * server. Two exceptions:
 * - Tauri: `window.location.origin` is a custom-protocol URL, not the server.
 * - Vite dev: vite serves the SPA on a separate port from the server, so set
 *   `VITE_ATOMIC_SERVER_URL` (see `.env.development`) to point at the real
 *   server (e.g. `http://localhost:9883`). This is the only "dev edge case" —
 *   no hardcoded vite port lives in the app anymore.
 */
const defaultServerUrl = isRunningInTauri()
  ? 'http://localhost:9883'
  : (import.meta.env.VITE_ATOMIC_SERVER_URL ?? window.location.origin);

// `?server=` on the entry URL (set by drive links once the app is served
// from a fixed shared origin instead of the hosting node's own domain — see
// planning/AUTOSCALING_AND_MIGRATION.md Part 2C in atomic-saas) takes
// precedence over the stored value: it's resolved fresh by the control
// plane at link-generation time, so it's more authoritative than whatever
// was last stored (which goes stale across a drive migration). Must be read
// here, synchronously, before `new Store(...)` below — `adoptDriveFromDeepLink`
// (further down this file) fetches against the Store's `serverUrl`
// immediately and runs before any async reconciliation
// (`IdentityReconcileGate`) would get a chance to fix it.
const searchServerUrl = (() => {
  const raw = new URLSearchParams(window.location.search).get('server');

  if (!raw) return undefined;

  try {
    const url = new URL(raw);

    return url.protocol === 'http:' || url.protocol === 'https:'
      ? url.origin
      : undefined;
  } catch {
    return undefined;
  }
})();

if (searchServerUrl) {
  // Following a `?server=` link is choosing that server.
  serverURLStorage.set(searchServerUrl, true);
}

const storedServerUrl = searchServerUrl ?? serverURLStorage.get();
// Reject obviously-invalid stored URLs (e.g. `tauri://localhost` left behind
// by an earlier buggy release). The Store requires http(s) URLs.
const storedIsValid =
  !!storedServerUrl &&
  (storedServerUrl.startsWith('http://') ||
    storedServerUrl.startsWith('https://'));
/**
 * A device running its own node uses it, unless the user said otherwise.
 *
 * A stored server used to win outright. But it was written by two very
 * different things: choosing a server, and merely opening a drive whose subject
 * happens to be an http(s) URL. A switcher with a couple of dozen
 * `https://atomicdata.dev/drive/…` entries meant one visit to any of them
 * pinned the public server — and the desktop app then booted against it every
 * launch, ignoring the node running in the same process, showing "Could not
 * reach the server" for drives sitting on disk.
 *
 * So on Tauri the bar is an explicit choice (see `wasExplicitlyChosen`).
 * Anything else loses to the embedded node, including a value stored before
 * this distinction existed — those get one reset, back to the node that was
 * always the right answer.
 */
const embeddedNodeWins =
  isRunningInTauri() && !serverURLStorage.wasExplicitlyChosen();

const serverUrl =
  storedIsValid && !embeddedNodeWins ? storedServerUrl! : defaultServerUrl;

// The hosted build may be served by something that is not a node (see
// `originNode.ts`). Find out before the Store exists: it opens its WebSocket
// in the constructor, and it is also the moment `createPrivateDrive` needs
// the answer for — a workspace made against a non-node is local-only from
// its first save. One same-origin request, hosted builds only.
if (originMayLackNode() && serverUrl === window.location.origin) {
  await probeOriginForNode(serverUrl);
}

// Fire-and-forget — first paint doesn't wait. Catch so a failed import
// (offline + no cached module) doesn't show up as an unhandledrejection
// in the console; LoroLoader.isLoaded() stays false and code paths
// that need Loro (editor, history scrub) gracefully no-op.
//
// We tried scheduling this via requestIdleCallback to keep the WASM
// download off the FCP-critical network bus, but that breaks the
// title-save round-trip in tests: useValue's setter calls
// `resource.set()` (which falls back to `_cache` when Loro isn't
// loaded) and then debounces a `save()`. Between those two, the input
// can unmount before signChanges runs, and the debounced save races
// the in-flight Loro import in ways we don't fully understand yet.
// Until the save flow is hardened (or the debounce moved into the
// resource itself), keep Loro eager.
enableLoro().catch(e =>
  console.warn('[Loro] init failed, edit/history features disabled:', e),
);

const storedAgent = await getAgentFromIDB();

// Device lock: withhold the stored agent when the gap since this app was
// last open exceeds the user's policy (see `deviceLock.ts`). Enforced on the
// way *in*, because nothing runs reliably when a browser is killed. The user
// then meets the normal sign-in screen, where their passkey (or secret) lets
// them back in.
const locked = shouldLock(storedAgent?.subject);

if (locked) {
  await saveAgentToIDB(undefined);
}

const initalAgent = locked ? undefined : storedAgent;

// Initialize the store
const store = new Store({
  agent: initalAgent,
  serverUrl,
  connect: !isOriginWithoutNode(serverUrl),
});

const initialDrive = driveStorage.get();

if (initialDrive) {
  // A stored *bare origin* used to be the pre-DID stand-in for a
  // drive and would still move `serverUrl`. Skip that restore — the
  // home server comes from `serverURLStorage`, not from `drive`.
  // An HTTP URL with a path is a real legacy drive and is safe to
  // restore: `setDrive` will not follow a foreign origin.
  if (Client.isBareHttpOrigin(initialDrive)) {
    console.warn(
      `[atomic] Ignoring stored drive '${initialDrive}': it is a server origin, not a workspace.`,
    );
  } else {
    store.setDrive(initialDrive);
  }
}

// On an origin with no node, a signed-in device with no drive of its own
// gets the account's key-derived one. The stored default is otherwise the
// origin itself — a server root that a node-less origin cannot serve, so the
// sidebar showed "/" with an offline error and nowhere to write. The derived
// drive is the one place this identity can write before anything has synced,
// and it lives only here until it does, hence local-only. A node-backed origin
// keeps the origin as its main drive (atomicdata.dev); this is not about
// which drive is open but about there being no server behind it. Only the
// drive is registered, not the agent: `fetchPrivateDriveSubject` treats a
// local-only agent as one whose drive is its secret's `initialDrive`.
if (
  initalAgent?.subject &&
  isOriginWithoutNode(serverUrl) &&
  (!initialDrive || Client.isBareHttpOrigin(initialDrive))
) {
  try {
    const home = await initalAgent.privateDriveSubject();
    store.registerLocalOnlyDrive(home);
    driveStorage.set(home);
    store.setDrive(home);
  } catch (e) {
    // A key that signs non-deterministically and no cached subject: the
    // sign-in flow recomputes it. Better no drive than a made-up one.
    console.warn('[atomic] Could not derive the personal drive:', e);
  }
}

// A deep link into a resource (share/show `?subject=` entry URL) starts the
// session in that resource's drive, overriding the stored/fallback drive.
// Fire-and-forget: resolves once the resource is fetched, and `setDrive`
// propagates into AppSettings via the DriveChanged event.
import { adoptDriveFromDeepLink } from './helpers/adoptDriveFromDeepLink';
adoptDriveFromDeepLink(store);

import { bootstrap } from './bootstrap';
bootstrap(store);

// Initialize the WASM ClientDb in a background worker.
// Non-blocking — the app works without it.
// Skipped under Tauri (embedded server makes OPFS redundant) or when the
// user explicitly opted out via the Sync page toggle.
import { initClientDb } from './helpers/initClientDb';
import { isClientDbEnabled } from './helpers/clientDbMode';
import { NgBridgeBadge } from '@tomic/ng-bridge-react';

if (isClientDbEnabled()) {
  initClientDb(store);
}

store.parseMetaTags();

declare global {
  interface Window {
    bugsnagApiKey: string;
  }
}

// Fetch all the Properties and Classes - this helps speed up the app.
// store.preloadPropsAndClasses();

registerCustomCreateActions();
// Register global event handlers.
registerHandlers(store);

// Make the Store available globally for debugging
window.store = store;

// Wire store events into the perf profiler so subscription / commit
// traffic shows up alongside React render counts. Cmd/Ctrl+Shift+P to
// dump a snapshot.
attachStoreToProfiler(store);

if (isDev()) {
  const { attachDevtools } = await import('./helpers/devtools');
  attachDevtools(store);
}

/** Entrypoint of the application. This is where providers go. */
function App(): JSX.Element {
  // Handle uncaught errors
  useEffect(() => {
    window.onerror = (message, _source, _lineno, _colno, error) => {
      // `return`, because without it the synthesized error was reported and
      // then `null` was reported straight after — and the second one threw
      // from inside the handler, burying the first.
      if (!error) {
        errorHandler(new Error(`message: ${message}`));

        return;
      }

      errorHandler(error);
    };

    window.onunhandledrejection = event => {
      errorHandler(event.reason);
    };
  }, []);

  return (
    <StoreContext.Provider value={store}>
      <PerformanceProfiler id='app'>
        <RouterProvider router={router}></RouterProvider>
        {/* Mirrors a local-only drive into NextGraph. Renders nothing, and
            loads nothing, unless enabled with `?ngbridge=1`. All NextGraph code
            lives in @tomic/ng-bridge-react and its siblings, never here. */}
        <NgBridgeBadge store={store} />
      </PerformanceProfiler>
    </StoreContext.Provider>
  );
}

export default App;

declare global {
  interface Window {
    store: Store;
  }
}
