// @vitest-environment jsdom
// @wc-ignore-file
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import React from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { StoreContext } from '@tomic/react';
import { LoroLoader, Store, commits, core } from '@tomic/lib';
import { appsForClass, useDriveApps, type DriveApp } from './useDriveApps';

/**
 * #1846, as the atomic-plugins money e2e met it. The test gives an app a
 * table's class to render, reloads onto that table and opens "+ Add view".
 * The menu is open when the drive sync delivers the app's latest edit, as a
 * delta from the version the local database holds. The page's copy of the
 * app came from the local app query, which returns JSON-AD without the Loro
 * history, so the delta cannot apply ("incomplete Loro import") and the app
 * waited for a full snapshot from the server. That did not come within the
 * ten seconds the test waited for "New app" (#1905).
 */
const DRIVE = 'atomic:resource:drive';
const APP_CLASS = 'atomic:resource:class-app';
const RENDERS = 'atomic:resource:prop-renders';
const OWN = 'atomic:resource:class-own';
const TXN = 'atomic:resource:class-txn';
const APP = 'atomic:resource:app';

vi.mock('@chunks/PluginRuns/useDriveClass', () => ({
  useAppClass: () => APP_CLASS,
}));

vi.mock('@tomic/lib', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/lib')>()),
  findSchema: async () => ({ properties: { renders: RENDERS } }),
}));

beforeAll(async () => {
  // The app's vite config sends `loro-crdt` to its `web` build, which fetches
  // its WASM over HTTP. Hand it the file from disk instead.
  const wasm = await readFile(
    createRequire(import.meta.url).resolve('loro-crdt/web/loro_wasm_bg.wasm'),
  );
  const web = (await import('loro-crdt/web')) as unknown as {
    default: (opts: { module_or_path: Uint8Array }) => Promise<unknown>;
  };
  await web.default({ module_or_path: wasm });
  await LoroLoader.initializeLoro();
});

/** The app as the local database holds it, and the edit the server has
 *  beyond that: the table's class added to what it renders. */
function appHistory() {
  const { LoroDoc } = LoroLoader.Loro;
  const doc = new LoroDoc();
  doc.setPeerId(1n);
  const props = doc.getMap('properties');
  props.set(core.properties.isA, [APP_CLASS]);
  props.set(core.properties.parent, DRIVE);
  props.set(core.properties.name, 'New app');
  props.set(RENDERS, [OWN]);
  props.set(commits.properties.lastCommit, 'atomic:commit:one');
  doc.commit();
  const local = doc.export({ mode: 'snapshot' }) as Uint8Array;
  const synced = doc.version();

  props.set(RENDERS, [OWN, TXN]);
  props.set(commits.properties.lastCommit, 'atomic:commit:two');
  doc.commit();

  return {
    local,
    delta: doc.export({ mode: 'update', from: synced } as never) as Uint8Array,
    json: JSON.stringify({
      '@id': APP,
      [core.properties.isA]: [APP_CLASS],
      [core.properties.parent]: DRIVE,
      [core.properties.name]: 'New app',
      [RENDERS]: [OWN],
      [commits.properties.lastCommit]: 'atomic:commit:one',
    }),
  };
}

function reloadedStore(json: string, local: Uint8Array) {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.setDrive(DRIVE);
  store.finishDriveSync(DRIVE, 1, Date.now());
  store.setClientDb({
    isReady: true,
    waitForReady: async () => true,
    waitForInit: async () => true,
    // The app query: values only, no snapshots.
    query: async () => ({ subjects: [APP], resources: [json], count: 1 }),
    getResourceWithSnapshot: async () => ({ jsonAd: json, snapshot: local }),
    flush: async () => undefined,
    putResourceWithSnapshot: async () => undefined,
    removeResource: async () => undefined,
  } as unknown as Parameters<Store['setClientDb']>[0]);

  // The full snapshot the repair asks the server for does not arrive while
  // the menu is open.
  store.fetchResourceFromServer = (() =>
    new Promise(
      () => undefined,
    )) as unknown as Store['fetchResourceFromServer'];

  return store;
}

const wrapper = (store: Store) =>
  function Wrapper({ children }: { children: React.ReactNode }) {
    return React.createElement(
      StoreContext.Provider,
      { value: store },
      children,
    );
  };

/** The hook's apps, whether it returns them bare or next to `refresh`. */
const appsOf = (value: DriveApp[] | { apps: DriveApp[] }) =>
  Array.isArray(value) ? value : value.apps;

describe('an app whose latest edit arrives while "+ Add view" is open', () => {
  it('is offered once the edit lands, without reopening the menu', async () => {
    const { json, local, delta } = appHistory();
    const store = reloadedStore(json, local);

    // The table page is up and its menu open: the app is known, for its own
    // rows only.
    const { result } = renderHook(() => useDriveApps(DRIVE), {
      wrapper: wrapper(store),
    });
    await waitFor(() =>
      expect(appsOf(result.current).map(a => a.renders)).toEqual([[OWN]]),
    );

    // The drive sync delivers the edit that added the table's class.
    act(() => {
      store.applyIncoming({
        subject: APP,
        loroBytes: delta,
        source: 'ws-sync-push',
      });
    });

    await waitFor(
      () =>
        expect(
          appsForClass(appsOf(result.current), TXN).map(a => a.name),
        ).toEqual(['New app']),
      { timeout: 2_000 },
    );
  });
});
