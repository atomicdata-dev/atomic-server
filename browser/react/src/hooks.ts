import {
  useState,
  useEffect,
  useCallback,
  useMemo,
  useContext,
  createContext,
  useRef,
  useSyncExternalStore,
} from 'react';
import {
  Property,
  Store,
  Resource,
  Datatype,
  datatypeFromUrl,
  truncateUrl,
  JSONValue,
  valToBoolean,
  valToNumber,
  valToDate,
  valToArray,
  valToString,
  FetchOpts,
  unknownSubject,
  JSONArray,
  OptionalClass,
  type Core,
  ResourceEvents,
  LoroLoader,
  core,
  server,
} from '@tomic/lib';
import type { LoroDoc } from 'loro-crdt';
import { useOnValueChange } from './helpers/useOnValueChange.js';

const asError = (error: unknown): Error =>
  error instanceof Error ? error : new Error(String(error));

export type UseResourceOptions = FetchOpts;

/**
 * Hook for getting a Resource in a React component. Wraps the
 * Store's per-subject snapshot via `useSyncExternalStore`: each
 * notify replaces the snapshot tuple, the Resource itself is
 * mutated in place, and reads like `resource.props.x` see the
 * latest values without us having to invalidate them.
 */
export function useResource<C extends OptionalClass = never>(
  subject: string = unknownSubject,
  opts: UseResourceOptions = {},
): Resource<C> {
  const store = useStore();
  const memoizedOpts = useMemoizedOpts(opts);

  const subscribe = useCallback(
    (cb: () => void) => store.subscribe(subject, () => cb()),
    [store, subject],
  );
  const getSnapshot = useCallback(
    () => store.getResourceSnapshot(subject, memoizedOpts),
    [store, subject, memoizedOpts],
  );

  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
    .resource as Resource<C>;
}

const stableEmptyArray: string[] = [];

/**
 * Converts an array of Atomic URL strings to an array of Resources.
 * !! Make sure the array is stable by memoizing it !!
 */
export function useResources(
  subjects: string[] | undefined = stableEmptyArray,
  opts: FetchOpts = {},
): Map<string, Resource> {
  const store = useStore();
  const memoizedOpts = useMemoizedOpts(opts);

  // One subscription per subject — cb() wakes useSyncExternalStore
  // which re-runs getSnapshot below. Same model as useResource.
  const subscribe = useCallback(
    (cb: () => void) => {
      const unsubs = subjects.map(s => store.subscribe(s, () => cb()));

      return () => unsubs.forEach(u => u());
    },
    [store, subjects],
  );

  // Cache the returned Map by "all snapshot identities". Build a
  // fresh Map only when at least one subject's snapshot changed,
  // so `useSyncExternalStore`'s `Object.is` reports stable when
  // nothing moved.
  const cacheRef = useRef<{
    map: Map<string, Resource>;
    snapshots: Array<{ resource: Resource }>;
  } | null>(null);

  const getSnapshot = useCallback((): Map<string, Resource> => {
    const snaps = subjects.map(s => store.getResourceSnapshot(s, memoizedOpts));
    const cached = cacheRef.current;

    if (
      cached &&
      cached.snapshots.length === snaps.length &&
      cached.snapshots.every((s, i) => s === snaps[i])
    ) {
      return cached.map;
    }

    const map = new Map<string, Resource>();
    subjects.forEach((s, i) => map.set(s, snaps[i].resource));
    cacheRef.current = { map, snapshots: snaps };

    return map;
  }, [store, subjects, memoizedOpts]);

  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

/**
 * Hook for using a Property. Will return `undefined` if the Property is not yet
 * loaded, and add Error strings to shortname and description if something goes wrong.
 *
 * Intentionally NOT `useMemo`'d: the underlying `Resource` mutates in
 * place when its fetch completes (loading → false, propvals populate),
 * which `useSyncExternalStore` reflects via a new snapshot tuple — but
 * the Resource *reference* stays the same across renders. A `useMemo`
 * keyed on `[resource, subject]` would therefore freeze on the initial
 * `loading` state and never reflect the populated shortname/datatype,
 * so any form rendered with `<ResourceField property=...>` would show
 * the "loading" label forever. Recomputing the small property object
 * each render is cheap; downstream `useMemo`s on individual fields
 * (`label`, `datatype`) stay valid because those fields are primitives.
 */
export function useProperty(subject: string): Property {
  const resource = useResource<Core.Property>(subject);

  if (resource.loading) {
    return {
      subject,
      datatype: Datatype.UNKNOWN,
      shortname: 'loading',
      description: `Loading property ${subject}`,
      loading: true,
    };
  }

  if (resource.error) {
    return {
      subject,
      datatype: Datatype.UNKNOWN,
      shortname: 'error',
      description: 'Error getting Property. ' + resource.error.message,
      error: resource.error,
    };
  }

  return {
    subject,
    datatype: datatypeFromUrl(resource.props.datatype),
    shortname: resource.props.shortname,
    description: resource.props.description,
    classType: resource.props.classtype,
    isDynamic: !!resource.props.isDynamic,
    allowsOnly: resource.props.allowsOnly,
  };
}

export type SetValue<T extends JSONValue = JSONValue> = (
  val: T | undefined,
) => Promise<void>;

/** Extra options for useValue hooks, mostly related to commits and validation */
type useValueOptions = {
  /**
   * Sends a Commit to the server when the value is changed. Disabled by
   * default. If this is false, you will need to manually call Resource.save()
   * to save changes
   */
  commit?: boolean;
  /**
   * Performs datatype validation. Enabled by default, but this could cause some
   * slowdown when the first validation is done as the Property needs to be
   * present in the store, and might have to be fetched
   */
  validate?: boolean;
  /** Amount of milliseconds to wait (debounce) before applying Commit. Defaults to 100. */
  commitDebounce?: number;
  /**
   * A callback function that will be called when the validation fails. For
   * example, pass a `setError` function. If you want to remove the Error, return `undefined`.
   */
  handleValidationError?: (e: Error | undefined) => unknown;
};

/**
 * Similar to React's `useState` hook. Returns a Value and a Setter as an array
 * of two items. Value will be `undefined` if the Resource isn't loaded yet. The
 * generated Setter function can be called to set the value. Be sure to look at
 * the various options for useValueOptions (debounce, commits, error handling).
 *
 * ```typescript
 * // Simple usage:
 * const resource = useResource('https://atomicdata.dev/classes/Agent');
 * const [shortname, setShortname] = useValue(
 *   resource,
 *   'https://atomicdata.dev/properties/shortname',
 * );
 * ```
 *
 * ```typescript
 * // With options:
 * const resource = useResource('https://atomicdata.dev/classes/Agent');
 * const [error, setError] = useState(null);
 * const [shortname, setShortname] = useValue(
 *   resource,
 *   'https://atomicdata.dev/properties/shortname',
 *   {
 *     commit: true,
 *     validate: true,
 *     commitDebounce: 500,
 *     handleValidationError: setError,
 *   },
 * );
 * ```
 */
export function useValue(
  resource: Resource,
  propertyURL: string,
  opts: useValueOptions = {},
): [JSONValue | undefined, SetValue] {
  const timeoutId = useRef<ReturnType<typeof setTimeout>>(undefined);
  const {
    commit = false,
    validate = true,
    commitDebounce = 100,
    handleValidationError,
  } = opts;

  const store = useStore();

  // Subscribe to per-property `LocalChange` (from `set()`) AND
  // store-level notify (from remote WS UPDATEs that don't fire
  // LocalChange). Either signal re-runs `resource.get(propertyURL)`.
  const stable = resource.stable;
  const subject = resource.subject;
  const subscribe = useCallback(
    (cb: () => void) => {
      const u1 = store.subscribe(subject, () => cb());
      const u2 = stable.on(ResourceEvents.LocalChange, p => {
        if (p === '' || p === propertyURL) cb();
      });

      return () => {
        u1();
        u2();
      };
    },
    [store, subject, stable, propertyURL],
  );
  const getSnapshot = () => resource.get(propertyURL);
  const val = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);

  const saveResource = useCallback(() => {
    if (!commit) {
      return;
    }

    // While the debounce timer is armed, the edit exists only in memory —
    // report it to the store so `getSyncStatus().pendingDirtyCount` stays
    // > 0 until the save settles (otherwise "synced" is a lie during the
    // debounce window and a reload drops the write).
    if (timeoutId.current !== undefined) {
      clearTimeout(timeoutId.current);
    } else {
      store.startScheduledSave();
    }

    timeoutId.current = setTimeout(async () => {
      timeoutId.current = undefined;

      try {
        await resource.__internalObject.save();
      } catch (e) {
        store.notifyError(asError(e));
      } finally {
        store.finishScheduledSave();
      }
    }, commitDebounce);
  }, [resource.__internalObject, store, commitDebounce, commit]);

  /**
   * Validates the value. If it fails, it calls the function in the second
   * Argument. Pass `undefined` to remove existing value.
   */
  const validateAndSet = useCallback(
    async (newVal: JSONValue): Promise<void> => {
      if (newVal === undefined) {
        resource.__internalObject.remove(propertyURL);
        saveResource();

        return;
      }

      try {
        await resource.__internalObject.set(propertyURL, newVal, validate);
        saveResource();
        handleValidationError?.(undefined);
      } catch (e) {
        if (handleValidationError) handleValidationError(asError(e));
        else store.notifyError(asError(e));
      }
    },

    [
      // Optimization: We don't need to track the whole resource here since the underlying reference is stable.
      resource.__internalObject,
      handleValidationError,
      store,
      validate,
      saveResource,
      propertyURL,
    ],
  );

  // `resource.get(prop)` is typed AtomicValue (JSONValue | Uint8Array).
  // useValue's contract is JSONValue-only (binary props live in auxValues
  // and are not surfaced through this hook), so narrow at the boundary.
  return [val as JSONValue | undefined, validateAndSet];
}

/**
 * Hook for getting and setting a stringified representation of an Atom in a
 * React component. See {@link useValue}
 */
export function useString(
  resource: Resource,
  propertyURL: string,
  opts?: useValueOptions,
): [string | undefined, SetValue<string>] {
  const [val, setVal] = useValue(resource, propertyURL, opts);

  if (typeof val === 'string') {
    return [val, setVal];
  }

  if (val === undefined) {
    return [undefined, setVal];
  }

  return [valToString(val), setVal];
}

export const noNestedSupport =
  'error:no_support_for_editing_nested_resources_yet';

/**
 * Hook for getting and setting a Subject. Converts Nested resources into paths.
 * See {@link useValue} for more info on using the `set` functionality.
 */
export function useSubject(
  resource: Resource,
  propertyURL: string,
  opts?: useValueOptions,
): [string | undefined, SetValue<string>] {
  const [val, setVal] = useValue(resource, propertyURL, opts);

  if (!val) {
    return [undefined, setVal];
  }

  if (typeof val === 'string') {
    return [val, setVal];
  } else {
    // It's a nested resource
    // TODO: Implement support for this. Get the subject from the Resource, or construct te Path.
    return [noNestedSupport, setVal];
  }
}

const titleHookOpts: useValueOptions = {
  commit: true,
};

const setTitleError = () => {
  throw new Error('Cannot set title of resource with error');
};

/**
 * Returns the most fitting title / name for a Resource. This is either the
 * Name, Shortname, Filename or truncated Subject URL of that resource.
 */
export function useTitle(
  resource: Resource,
  truncateLength = 40,
  opts: useValueOptions = titleHookOpts,
): [string, SetValue<string>] {
  const [name, setName] = useString(resource, core.properties.name, opts);
  const [shortname, setShortname] = useString(
    resource,
    core.properties.shortname,
    opts,
  );
  const [filename, setFileName] = useString(
    resource,
    server.properties.filename,
    opts,
  );

  if (resource.error) {
    return [truncateUrl(resource.subject, truncateLength), setTitleError];
  }

  if (resource.loading) {
    return ['...', setName];
  }

  if (name !== undefined) {
    return [name, setName];
  }

  if (shortname !== undefined) {
    return [shortname, setShortname];
  }

  if (filename !== undefined) {
    return [filename, setFileName];
  }

  const subject = resource?.subject;

  if (typeof subject === 'string' && subject.length > 0) {
    return [truncateUrl(subject, truncateLength), setName];
  }

  return [subject, setName];
}

/**
 * Hook for getting all URLs for some array. Returns the current Array (defaults
 * to empty array) and a callback for validation errors. See {@link useValue}
 */
export function useArray(
  resource: Resource,
  propertyURL: string,
  opts?: useValueOptions,
): [string[], SetValue<JSONArray>, (vals: string[]) => void] {
  const [value, set] = useValue(resource, propertyURL, opts);
  const [stableEmptyResourceArray] = useState<JSONArray>([]);

  const values = useMemo(() => {
    if (value === undefined) {
      return stableEmptyResourceArray;
    }

    try {
      // This cast isn't entirely correct - we should add a `useSubjects` hook.
      // https://github.com/atomicdata-dev/atomic-data-browser/issues/219
      return valToArray(value);
    } catch (e) {
      console.error(e, value, propertyURL, resource.subject);

      // If .toArray() errors, return an empty array. Useful in forms when datatypes haves changed!
      // https://github.com/atomicdata-dev/atomic-data-browser/issues/85
      return stableEmptyResourceArray;
    }
  }, [value, resource, propertyURL, stableEmptyResourceArray]);

  const push = useCallback(
    (val: string[]) => {
      resource.push(propertyURL, val);

      if (opts?.commit) {
        resource.save().catch(err => {
          console.error('Failed to save resource after push', err);
        });
      }
    },

    [resource, propertyURL, opts?.commit],
  );

  return [values as string[], set, push];
}

/** See {@link useValue} */
export function useNumber(
  resource: Resource,
  propertyURL: string,
  opts?: useValueOptions,
): [number | undefined, SetValue<number>] {
  const [value, set] = useValue(resource, propertyURL, opts);

  if (value === undefined) {
    return [undefined, set];
  }

  return [valToNumber(value), set];
}

/** Returns false if there is no value for this propertyURL. See {@link useValue} */
export function useBoolean(
  resource: Resource,
  propertyURL: string,
  opts?: useValueOptions,
): [boolean, SetValue<boolean>] {
  const [value, set] = useValue(resource, propertyURL, opts);

  useEffect(() => {
    if (value === undefined) {
      set(false);
    }
  }, [value, set]);

  if (value === undefined) {
    return [false, set];
  }

  return [valToBoolean(value), set];
}

/**
 * Hook for getting a stringified representation of an Atom in a React
 * component. See {@link useValue}
 */
export function useDate(
  resource: Resource,
  propertyURL: string,
  opts?: useValueOptions,
): Date | undefined {
  const store = useStore();
  const [value] = useValue(resource, propertyURL, opts);

  if (value === undefined) {
    return undefined;
  }

  try {
    return valToDate(value);
  } catch (e) {
    store.notifyError(asError(e));

    return;
  }
}

/**
 * Reactive creation timestamp (a `Date`) derived from the resource's genesis
 * certificate, with legacy fallbacks handled by {@link Resource.getCreatedAt}.
 * No commit fetch is required, and it survives a refresh.
 */
export function useCreatedAt(resource: Resource): Date | undefined {
  const stable = resource.stable;
  const subject = resource.subject;
  const store = useStore();
  // Subscribe to resource updates AND Loro WASM readiness — the oplog only
  // becomes readable once the lazy `loro-crdt` module lands (mirrors
  // `useLoroDoc`).
  const subscribe = useCallback(
    (cb: () => void) => {
      const unsubResource = store.subscribe(subject, () => cb());
      const unsubLoro = LoroLoader.onReady(cb);

      return () => {
        unsubResource();
        unsubLoro();
      };
    },
    [store, subject],
  );

  // getSnapshot returns a stable primitive (ms number) — the genesis change is
  // immutable, so successive calls are referentially equal and don't loop.
  const getSnapshot = () => stable.getCreatedAt();
  const ms = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);

  return useMemo(() => (ms === undefined ? undefined : new Date(ms)), [ms]);
}

/**
 * Reactive creator derived from the resource's genesis certificate, with
 * legacy fallbacks handled by {@link Resource.getCreatedBy}. No commit fetch.
 */
export function useCreatedBy(resource: Resource): string | undefined {
  const stable = resource.stable;
  const subject = resource.subject;
  const store = useStore();
  const subscribe = useCallback(
    (cb: () => void) => {
      const unsubResource = store.subscribe(subject, () => cb());
      const unsubLoro = LoroLoader.onReady(cb);

      return () => {
        unsubResource();
        unsubLoro();
      };
    },
    [store, subject],
  );

  const getSnapshot = () => stable.getCreatedBy();

  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

/**
 * Gets or creates a Loro document for the resource. Returns undefined
 * if the resource is still loading.
 */
export function useLoroDoc(resource: Resource): LoroDoc | undefined {
  const stable = resource.stable;
  const subject = resource.subject;
  const store = useStore();
  // Subscribe to BOTH resource updates AND Loro WASM readiness. The
  // resource may finish loading before the lazy `loro-crdt` import does;
  // when WASM finally lands, `getLoroDoc()` flips from `undefined` to a
  // real doc — but nothing in the resource update channel fires for that
  // transition. Without the `LoroLoader.onReady` subscription, the
  // `useSyncExternalStore` cache holds onto `undefined` and the editor
  // stays on "Loading…" forever (cold-tab repro: open a doc in a fresh
  // tab while WASM is still streaming in).
  const subscribe = useCallback(
    (cb: () => void) => {
      const unsubResource = store.subscribe(subject, () => cb());
      const unsubLoro = LoroLoader.onReady(cb);

      return () => {
        unsubResource();
        unsubLoro();
      };
    },
    [store, subject],
  );

  const getSnapshot = () => (stable.loading ? undefined : stable.getLoroDoc());

  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

/**
 * Reactively tracks whether the Loro CRDT WASM module has finished
 * loading. Re-renders when it becomes ready.
 *
 * Use this to distinguish "the editor engine is still streaming in"
 * (transient — keep showing a spinner) from "the engine failed to
 * load" (terminal — show an error). Without it, a tab where the
 * `loro-crdt` WASM import failed leaves every `useLoroDoc` consumer
 * stuck on `undefined` forever with no signal as to why.
 */
export function useLoroReady(): boolean {
  return useSyncExternalStore(
    cb => LoroLoader.onReady(cb),
    () => LoroLoader.isLoaded(),
    () => LoroLoader.isLoaded(),
  );
}

/** Preferred way of using the store in a Component or Hook */
export function useStore(): Store {
  const store = useContext(StoreContext);

  if (store === undefined) {
    throw new Error(
      'Store is not found in react context. Have you wrapped your application in `<StoreContext.Provider value={new Store}>`?',
    );
  }

  return store;
}

/**
 * Checks if the current agent has the appropriate rights to edit this resource.
 */
export function useCanWrite(resource: Resource): boolean {
  const store = useStore();
  const agent = store.getAgent();
  // Initialize optimistically for brand-new local resources — they have no
  // parent on the server yet, so `resource.canWrite()` would be skipped by
  // the effect below. Without this, the ResourceForm shows "Agent does not
  // have edit rights" on every new-resource page until the async permission
  // check runs (which never runs for `.new` resources).
  const [canWrite, setCanWrite] = useState<boolean>(
    () => !!agent?.subject && !!resource.new,
  );

  useOnValueChange(
    () => {
      if (agent?.subject === undefined) {
        setCanWrite(false);

        return;
      }

      if (resource.new) {
        setCanWrite(true);
      }
    },
    [resource, agent?.subject],
    true,
  );

  // Re-check write permissions when the subject or agent changes.
  // Using resource.subject instead of the full proxy to avoid re-running
  // on every property change.
  useEffect(() => {
    if (!agent || resource.new) return;
    // Cancellation guard: `canWrite` recurses across parents and can take
    // a few hundred ms; without it, a fast subject swap leaves an
    // in-flight check that writes a stale result after the effect re-ran
    // for the new subject.
    let cancelled = false;
    resource
      .canWrite(agent.subject)
      .then(([result]) => {
        if (cancelled) return;

        if (result) {
          setCanWrite(true);
        } else if (
          resource.subject?.startsWith('did:ad:') &&
          agent.subject?.startsWith('did:ad:')
        ) {
          // DID resources are self-sovereign — the owning agent always has write access.
          // The normal canWrite check fails because DID drives don't have explicit write rights.
          setCanWrite(true);
        } else {
          setCanWrite(false);
        }
      })
      .catch(() => {
        if (cancelled) return;

        // Offline fallback: assume write access for DID resources
        if (
          resource.subject?.startsWith('did:ad:') &&
          agent.subject?.startsWith('did:ad:')
        ) {
          setCanWrite(true);
        }
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resource.subject, agent?.subject]);

  return canWrite;
}

/**
 * The context must be provided by wrapping a high level React element in
 * `<StoreContext.Provider value={new Store}>My App</StoreContext.Provider>`
 */
export const StoreContext = createContext<Store>(new Store());

function useMemoizedOpts(
  opts: FetchOpts | undefined = {
    allowIncomplete: false,
    noWebSocket: false,
    newResource: false,
  },
): FetchOpts {
  return useMemo(
    () => ({
      allowIncomplete: opts.allowIncomplete,
      noWebSocket: opts.noWebSocket,
      newResource: opts.newResource,
    }),
    [opts.allowIncomplete, opts.noWebSocket, opts.newResource],
  );
}
