// @vitest-environment jsdom
// @wc-ignore-file
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import React from 'react';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import {
  Datatype,
  LoroLoader,
  Resource,
  Store,
  core,
  setClassConstraint,
} from '@tomic/lib';
// From source, not `@tomic/react`'s dist: vitest compiles that package's source
// with the React Compiler, as the app does when it bundles the package.
import { StoreContext, useEffectiveConstraint } from '../../../react/src';

beforeAll(async () => {
  // The app's vite config sends `loro-crdt` to the `web` build, which fetches
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

const CLASS = 'https://example.com/classes/task';
const PROP = 'https://example.com/properties/title';

function Probe() {
  const constraint = useEffectiveConstraint([CLASS], PROP);

  return <output>{String(constraint.maxLength ?? 'none')}</output>;
}

async function setup() {
  const store = new Store({ connect: false });
  const property = new Resource(PROP);
  await property.set(core.properties.shortname, 'title', false);
  await property.set(core.properties.datatype, Datatype.STRING, false);
  property.loading = false;
  store.addResource(property);
  const klass = new Resource(CLASS);
  await klass.set(core.properties.shortname, 'task', false);
  klass.loading = false;
  store.addResource(klass);

  render(
    <StoreContext.Provider value={store}>
      <Probe />
    </StoreContext.Provider>,
  );

  return { store, klass: store.getResourceLoading(CLASS) };
}

afterEach(cleanup);

describe('useEffectiveConstraint', () => {
  it('re-renders on an unsaved class constraint edit', async () => {
    const { klass } = await setup();
    expect(screen.getByRole('status').textContent).toBe('none');

    await act(async () => {
      await setClassConstraint(klass, PROP, { maxLength: 120 });
    });

    expect(screen.getByRole('status').textContent).toBe('120');
  });

  it('re-renders after the class constraint is saved', async () => {
    const { klass } = await setup();

    await act(async () => {
      await setClassConstraint(klass, PROP, { maxLength: 120 });
      await klass.save().catch(() => undefined);
    });

    expect(screen.getByRole('status').textContent).toBe('120');

    await act(async () => {
      await setClassConstraint(klass, PROP, { maxLength: 80 });
      await klass.save().catch(() => undefined);
    });

    expect(screen.getByRole('status').textContent).toBe('80');
  });
});
