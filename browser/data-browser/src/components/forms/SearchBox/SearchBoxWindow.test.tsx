// @vitest-environment jsdom
// @wc-ignore-file
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import React, { createRef } from 'react';
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import { JSONADParser, Store, core } from '@tomic/lib';
import { StoreContext } from '@tomic/react';
import { buildTheme } from '../../../styling';
import { SearchBoxWindow } from './SearchBoxWindow';
import { searchLoadedExternal } from './loadedExternal';

/**
 * New Table's "Use existing class" picker searches the server, which only
 * knows the drive and atomicdata.dev. Shared classes published elsewhere, like
 * on atomic-plugins Pages, were only reachable by pasting their URL (#1839).
 */
const SERVER = 'https://server.example';
const DRIVE = 'did:ad:drive';
const PAGES = 'https://ontola.github.io/atomic-plugins/ontology';
const TIME_ENTRY = `${PAGES}/classes/time-entry`;
const INVOICE = `${PAGES}/classes/invoice`;
const LOCAL_CLASS = 'did:ad:local-class';

const fixture = vi.hoisted(() => ({ serverResults: [] as string[] }));

/**
 * No socket, and no reads. The picker resolves `atomicdata.dev/classes/Class`
 * and the row of a server result through the store, and a store without a
 * socket answers that with an HTTP request, a five-second wait for a socket and
 * a lookup in the local database, all of which can finish after the file does.
 * The answer then updates a component once jsdom is torn down: React reports
 * `window is not defined`, and vitest counts it as an unhandled error and fails
 * the run although every test passed. It only shows when the worker lingers
 * past the end of the file, so on a loaded CI machine and almost never here.
 */
const newStore = () => {
  const store = new Store({ serverUrl: SERVER, connect: false });
  vi.spyOn(
    store as unknown as { fetchResourceWithLocalFallback(): Promise<void> },
    'fetchResourceWithLocalFallback',
  ).mockResolvedValue();

  return store;
};

vi.mock('@tomic/react', async importOriginal => ({
  ...(await importOriginal<typeof import('@tomic/react')>()),
  useServerSearch: () => ({ results: fixture.serverResults }),
}));
vi.mock('../../../helpers/AppSettings', () => ({
  useSettings: () => ({ drive: DRIVE }),
}));
vi.mock('../hooks/useAvailableSpace', () => ({
  useAvailableSpace: () => ({ above: 1000, below: 1000 }),
}));

afterEach(() => {
  cleanup();
  fixture.serverResults = [];
});

function classJson(subject: string, shortname: string, description: string) {
  return {
    '@id': subject,
    [core.properties.isA]: [core.classes.class],
    [core.properties.shortname]: shortname,
    [core.properties.description]: description,
  };
}

function storeWithFetchedClasses(): Store {
  const store = newStore();
  const parser = new JSONADParser();

  for (const json of [
    classJson(TIME_ENTRY, 'time-entry', 'A span of tracked work.'),
    classJson(INVOICE, 'invoice', 'A bill for timed work.'),
    // Not a class: must not show up in a class search.
    {
      '@id': `${PAGES}/properties/duration`,
      [core.properties.isA]: [core.classes.property],
      [core.properties.shortname]: 'time-duration',
      [core.properties.description]: 'How long.',
    },
  ]) {
    for (const resource of parser.parse(json, json['@id'])) {
      store.addResource(resource);
    }
  }

  return store;
}

function show(store: Store, props: { searchValue: string }) {
  const onSelect = vi.fn();
  const onChange = vi.fn();
  const ui = (searchValue: string) => (
    <StoreContext.Provider value={store}>
      <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
        <SearchBoxWindow
          searchValue={searchValue}
          isA={core.classes.class}
          triggerRef={createRef()}
          onExit={vi.fn()}
          onChange={onChange}
          onSelect={onSelect}
        />
      </ThemeProvider>
    </StoreContext.Provider>
  );
  const { rerender } = render(ui(props.searchValue));

  return {
    onSelect,
    onChange,
    type: (searchValue: string) => rerender(ui(searchValue)),
  };
}

describe('searchLoadedExternal', () => {
  it('matches fetched external classes on shortname, name and description', () => {
    const store = storeWithFetchedClasses();
    const find = (q: string) =>
      searchLoadedExternal(store.resources, q, core.classes.class, SERVER);

    expect(find('time')).toEqual([TIME_ENTRY, INVOICE]);
    expect(find('BILL')).toEqual([INVOICE]);
    expect(find('')).toEqual([]);
    expect(find('nothing-like-it')).toEqual([]);
  });

  it('leaves out subjects the server search already covers', () => {
    const store = newStore();

    for (const subject of [
      `${SERVER}/classes/own`,
      'https://atomicdata.dev/classes/Timeline',
      LOCAL_CLASS,
    ]) {
      for (const resource of new JSONADParser().parse(
        classJson(subject, 'timeline', ''),
        subject,
      )) {
        store.addResource(resource);
      }
    }

    expect(
      searchLoadedExternal(store.resources, 'time', core.classes.class, SERVER),
    ).toEqual([]);
  });
});

describe('class picker', () => {
  // The first render in this file is where styled-components builds its
  // stylesheet, jsdom parses it and the picker's modules run for the first
  // time. Under CI load that one-time cost put whichever test ran first over
  // vitest's 5 s default, though the test itself takes a few milliseconds.
  // Paid here, under the hook's own timeout.
  beforeAll(() => {
    show(storeWithFetchedClasses(), { searchValue: '' });
    cleanup();
  });

  it('shows a fetched external class for a partial name, marked with its origin', () => {
    fixture.serverResults = [LOCAL_CLASS];
    const { onSelect } = show(storeWithFetchedClasses(), {
      searchValue: 'time-en',
    });

    const results = screen.getByTestId('searchbox-results');
    expect(within(results).getByText('time-entry')).toBeTruthy();
    expect(within(results).queryByText('invoice')).toBeNull();
    expect(
      within(results).getByTestId('searchbox-result-origin').textContent,
    ).toBe('ontola.github.io');

    fireEvent.click(within(results).getByText('time-entry'));
    expect(onSelect).toHaveBeenCalledWith(TIME_ENTRY);
  });

  it('keeps finding it while the query grows', () => {
    const { type } = show(storeWithFetchedClasses(), { searchValue: 't' });

    for (const query of ['ti', 'tim', 'time-e']) {
      type(query);
      expect(
        within(screen.getByTestId('searchbox-results')).getByText('time-entry'),
      ).toBeTruthy();
    }
  });

  it('does not list an external class twice when the server also returns it', () => {
    fixture.serverResults = [TIME_ENTRY];
    show(storeWithFetchedClasses(), { searchValue: 'time-entry' });

    expect(
      within(screen.getByTestId('searchbox-results')).getAllByText(
        'time-entry',
      ),
    ).toHaveLength(1);
  });

  it('still selects a pasted URL directly', () => {
    const { onSelect } = show(newStore(), {
      searchValue: '',
    });
    const url = `${PAGES}/classes/never-fetched`;

    fireEvent.paste(screen.getByRole('textbox'), {
      clipboardData: { getData: () => url },
    });

    expect(onSelect).toHaveBeenCalledWith(url);
  });

  it('takes a typed subject on Enter when nothing was found, after arrowing', () => {
    const { onSelect } = show(newStore(), { searchValue: 'atomic:abc123' });
    const input = screen.getByRole('textbox');

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(onSelect).toHaveBeenCalledWith('atomic:abc123');
  });

  it('ignores Enter on free text when nothing was found', () => {
    const { onSelect } = show(newStore(), { searchValue: 'foo bar' });
    const input = screen.getByRole('textbox');

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(onSelect).not.toHaveBeenCalled();
  });
});
