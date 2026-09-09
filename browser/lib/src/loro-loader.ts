// Ambient subpath types must be included without adding a runtime import.
// oxlint-disable-next-line typescript/triple-slash-reference
/// <reference path="./loro-web.d.ts" />
import { pageRequestSignal } from './page-request-signal.js';
import type * as Loro from 'loro-crdt';

/**
 * To prevent bloat we don't always want to include Loro in the bundle.
 * Since loro-crdt is an optional dependency (WASM), we load it lazily.
 */
export class LoroLoader {
  private static _Loro: typeof Loro | undefined;
  private static _initInFlight: Promise<void> | undefined;
  private static _readyListeners: Set<() => void> = new Set();

  public static get Loro(): typeof Loro {
    if (!this._Loro) {
      throw new Error('Loro not initialized');
    }

    return this._Loro;
  }

  /**
   * Single-flight: concurrent callers MUST share one in-flight init.
   * `enableLoro()` is called fire-and-forget at app startup (App.tsx) AND
   * awaited on demand (`signChanges`, collections, canvas). The web build's
   * wasm-bindgen init has a TOCTOU hole — its `if (wasm !== undefined)`
   * guard is only satisfied AFTER the async fetch+instantiate completes —
   * so two overlapping `init()` calls instantiate TWO wasm modules and the
   * second silently replaces the module-global instance. Every doc created
   * against the first then dereferences (and writes!) stale pointers into
   * the second instance's heap: delayed dlmalloc heap-corruption panics,
   * "indirect call signature mismatch" on `doc.commit()`, and
   * finalizer crashes (`CLOSURE_DTORS` / `Loro*Finalization`), long after
   * the race itself. Sharing the promise closes the race window entirely.
   */
  public static initializeLoro(): Promise<void> {
    if (this._Loro) {
      return Promise.resolve();
    }

    if (!this._initInFlight) {
      this._initInFlight = this.doInitialize();
      // A failed load (network error fetching the .wasm) must not poison
      // the loader forever — clear the in-flight slot so a later call can
      // retry. `_Loro` stays unset, so retry goes through the full init.
      this._initInFlight.catch(() => {
        this._initInFlight = undefined;
      });
    }

    return this._initInFlight;
  }

  private static async doInitialize(): Promise<void> {
    const signal = pageRequestSignal();
    // In a browser, import loro-crdt's `web` build and run its
    // wasm-bindgen init. The default `loro-crdt` entry resolves (via
    // its `module` field) to the `bundler` build, whose WASM↔JS
    // circular import + top-level-await glue HANGS under
    // `vite-plugin-wasm` (loro-crdt ≥ 1.12) — `import()` never settles,
    // no error. The `web` build is purpose-built for direct browser
    // use: it fetches `loro_wasm_bg.wasm` and instantiates it via an
    // explicit `default()` init. In Node (tests) the `web` build's
    // `fetch(new URL(...))` can't read a file:// URL, so fall back to
    // the default entry (resolves to the Node build there).
    const isBrowser =
      typeof window !== 'undefined' && typeof window.document !== 'undefined';

    try {
      const mod = isBrowser
        ? // The browser entry includes its own type declarations.
          ((await import('loro-crdt/web')) as unknown as typeof Loro & {
            default?: unknown;
          })
        : await import('loro-crdt');

      // The `web` build (wasm-bindgen web target) exposes its async
      // init as the default export and instantiates nothing until it
      // runs. The `bundler` / Node builds have no default function and
      // auto-init, so this is a no-op for them.
      const init = (mod as { default?: unknown }).default;

      if (typeof init === 'function') {
        await (init as () => Promise<unknown>)();
      }

      this._Loro = mod;
    } catch (e) {
      // Navigation can discard the WASM response while compilation is pending.
      // The departing document no longer needs an editor; active-page failures
      // still reject and are reported below.
      if (signal?.aborted) return;
      console.error(
        '[LoroLoader] initializeLoro: loro-crdt import/init failed:',
        e,
      );
      throw e;
    }

    // Fire the ready callbacks. Hooks that called `getLoroDoc()` *before*
    // the WASM module finished loading would have observed it as
    // `undefined` and cached that result in `useSyncExternalStore`; they
    // need an external nudge to re-evaluate now that the WASM is ready.
    // Without this, opening a doc in a fresh tab leaves the editor
    // stuck on "Loading…" forever — the `store.subscribe(subject, …)`
    // signal that `useLoroDoc` listens to fires only on resource
    // updates, never on WASM-ready.
    const listeners = [...this._readyListeners];
    this._readyListeners.clear();

    for (const cb of listeners) {
      try {
        cb();
      } catch (e) {
        console.warn('[LoroLoader] ready listener threw:', e);
      }
    }
  }

  public static isLoaded(): boolean {
    return this._Loro !== undefined;
  }

  public static loadCheck(): void {
    if (!this.isLoaded()) {
      throw new Error('Loro not initialized. Call enableLoro() first.');
    }
  }

  /**
   * Register a callback that fires once when the Loro WASM module
   * finishes loading. If Loro is already loaded the callback runs
   * synchronously. Returns an unsubscribe function for callers that want
   * to clean up before the load completes (e.g. React unmount during
   * the lazy load). Callbacks fire exactly once.
   */
  public static onReady(cb: () => void): () => void {
    if (this.isLoaded()) {
      cb();

      return () => undefined;
    }

    this._readyListeners.add(cb);

    return () => this._readyListeners.delete(cb);
  }
}

/**
 * Enables the use of Loro CRDT features in the library.
 * Call this somewhere early on in your application and make sure the loro-crdt package is installed.
 */
export const enableLoro = async () => {
  await LoroLoader.initializeLoro();
};
