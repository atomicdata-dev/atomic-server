import { beforeAll, describe, it, vi } from 'vitest';
import { LoroLoader } from './loro-loader.js';
import { Resource, ResourceEvents } from './resource.js';
import { core } from './index.js';

/**
 * Flaky "dev drive sometimes doesn't show" bug: a WS GET/SUB snapshot can arrive
 * BEFORE Loro WASM finishes loading. `importLoroUpdate` then buffers the bytes
 * (it can't apply them yet). The buffer must reliably materialize once Loro is
 * ready — `importLoroUpdate` registers a `LoroLoader.onReady` callback for that
 * so the resource doesn't stay stuck on its bare subject. This pins the
 * buffer-then-materialize path.
 */

const NAME = 'https://atomicdata.dev/properties/name';
const FOLDER = 'https://atomicdata.dev/classes/Folder';

let snapshotBytes: Uint8Array;

beforeAll(async () => {
  await LoroLoader.initializeLoro();
  const { LoroDoc } = LoroLoader.Loro;
  const doc = new LoroDoc();
  const props = doc.getMap('properties');
  props.set(core.properties.isA, [FOLDER]);
  props.set(NAME, 'RaceFolder');
  doc.commit();
  snapshotBytes = doc.export({ mode: 'snapshot' });
});

describe('importLoroUpdate — snapshot arriving before Loro is ready', () => {
  it('does not notify subscribers synchronously from lazy snapshot materialization', async ({
    expect,
  }) => {
    const unloaded = vi.spyOn(LoroLoader, 'isLoaded').mockReturnValue(false);
    const resource = new Resource('did:ad:lazy-read');
    resource.importLoroUpdate(snapshotBytes);
    unloaded.mockRestore();
    const changed = vi.fn();
    resource.on(ResourceEvents.LoadingChange, changed);
    resource.getLoroDoc();
    expect(changed).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(changed).toHaveBeenCalledWith(false);
  });

  it('buffers without applying, then materializes once Loro is ready', ({
    expect,
  }) => {
    const spy = vi.spyOn(LoroLoader, 'isLoaded').mockReturnValue(false);
    const r = new Resource('did:ad:loroRaceReproAAAAAAAAAAAAAAAAAAAAAAAA==');

    // Loro "not loaded" → the snapshot is buffered, not a failure.
    const { complete } = r.importLoroUpdate(snapshotBytes);
    expect(complete).toBe(true);
    expect(r.get(core.properties.isA)).toBeUndefined();

    // Loro becomes ready. In the app the `onReady` callback registered by
    // `importLoroUpdate` fires and calls `getLoroDoc()`, materializing the
    // buffer; here we trigger that doc access directly (the test env has Loro
    // pre-loaded, so the ready listeners can't re-fire).
    spy.mockRestore();
    r.getLoroDoc();

    expect(r.get(core.properties.isA)).toEqual([FOLDER]);
    expect(r.get(NAME)).toBe('RaceFolder');
    expect(r.loading).toBe(false);
  });
});
