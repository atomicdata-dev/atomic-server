// @vitest-environment jsdom
// @wc-ignore-file
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import React from 'react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { Datatype, LoroLoader, Resource, Store, core } from '@tomic/lib';
import { StoreContext, useResource } from '@tomic/react';
import { buildTheme } from '../../../styling';
import { ClassConstraintEditor } from './ClassConstraintEditor';

vi.mock('../../../helpers/AppSettings', () => ({
  useSettings: () => ({ agent: { subject: 'atomic:agent:test' } }),
}));
vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  useCanWrite: () => true,
}));

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

const CLASS = 'did:ad:AAAAclasstask0000000000000000000000000000000';
const PROP = 'did:ad:BBBBproptitle0000000000000000000000000000000';

function Editor() {
  const classResource = useResource(CLASS);

  return (
    <ClassConstraintEditor
      classResource={classResource}
      propertySubject={PROP}
    />
  );
}

async function setup() {
  const store = new Store({
    serverUrl: 'http://localhost:9883',
    connect: false,
  });
  const property = new Resource(PROP);
  await property.set(core.properties.shortname, 'title', false);
  await property.set(core.properties.datatype, Datatype.STRING, false);
  property.loading = false;
  store.addResource(property);
  const klass = new Resource(CLASS);
  await klass.set(core.properties.shortname, 'task', false);
  klass.loading = false;
  store.addResource(klass);
  // Saving needs a server; the point is what the open editor shows.
  vi.spyOn(store.getResourceLoading(CLASS), 'save').mockResolvedValue(
    undefined as never,
  );

  render(
    <StoreContext.Provider value={store}>
      <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
        <Editor />
      </ThemeProvider>
    </StoreContext.Provider>,
  );
}

afterEach(cleanup);

describe('ClassConstraintEditor', () => {
  it('shows a committed max length in the open editor', async () => {
    await setup();
    fireEvent.click(screen.getByText('Constraints'));
    const input = await screen.findByLabelText('Max length');

    await act(async () => {
      fireEvent.change(input, { target: { value: '120' } });
      fireEvent.blur(input);
    });

    await waitFor(() =>
      expect(
        (screen.getByLabelText('Max length') as HTMLInputElement).value,
      ).toBe('120'),
    );
  });
});
