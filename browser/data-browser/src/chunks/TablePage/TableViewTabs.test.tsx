// @vitest-environment jsdom
// @wc-ignore-file
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { useRef, useState } from 'react';
import { afterEach, beforeAll, expect, it, vi } from 'vitest';
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import {
  core,
  dataBrowser,
  LoroLoader,
  Store,
  StoreContext,
} from '@tomic/react';
import { DropdownPortalContext } from '@components/Dropdown/dropdownContext';
import { buildTheme } from '../../styling';
import { TableViewTabs } from './TableViewTabs';
import { VIEW_KIND_LABELS, type ViewKind } from './tableViewKinds';

vi.mock('@chunks/AppPage/useDriveApps', () => ({
  useDriveApps: () => ({ apps: [], refresh: () => {} }),
  appsForClass: () => [],
}));

// jsdom has no layout; the menu scrolls its selected item into view.
Element.prototype.scrollIntoView = () => undefined;

beforeAll(async () => {
  // As in TableCell.test.tsx: hand loro its WASM from disk.
  const wasm = await readFile(
    createRequire(import.meta.url).resolve('loro-crdt/web/loro_wasm_bg.wasm'),
  );
  const web = (await import('loro-crdt/web')) as unknown as {
    default: (opts: { module_or_path: Uint8Array }) => Promise<unknown>;
  };
  await web.default({ module_or_path: wasm });
  await LoroLoader.initializeLoro();
});

afterEach(cleanup);

let n = 0;

async function newView(store: Store, name: string, kind: string) {
  const view = await store.newResource({
    subject: `_new:view-${++n}`,
    noParent: true,
  });
  await view.set(core.properties.name, name, false);
  await view.set(dataBrowser.properties.viewKind, kind, false);

  return view.subject;
}

/**
 * The tab bar with the hook's view list stood in for: `createView` adds a
 * view named after its kind and switches to it, as `useTableView` does.
 */
function Harness({
  store,
  initial,
  setViewKind,
}: {
  store: Store;
  initial: string[];
  setViewKind: (subject: string, kind: string) => void;
}) {
  const portal = useRef<HTMLDivElement>(null);
  const [views, setViews] = useState(initial);
  const [active, setActive] = useState(initial[0]);

  const createView = (kind: ViewKind | string = 'table', label?: string) => {
    void newView(store, label ?? VIEW_KIND_LABELS[kind as ViewKind], kind).then(
      subject => {
        setViews(v => [...v, subject]);
        setActive(subject);
      },
    );
  };

  return (
    <StoreContext value={store}>
      <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
        <DropdownPortalContext.Provider value={portal}>
          <TableViewTabs
            rowClass='https://example.com/classes/piece'
            views={views}
            activeView={active}
            setActiveView={setActive}
            reorderViews={setViews}
            createView={createView}
            setViewKind={setViewKind}
            duplicateView={() => undefined}
            deleteView={() => undefined}
            viewName=''
            renameView={() => undefined}
            allColumns={[]}
            columns={[]}
            derivedColumns={[]}
            showColumn={() => undefined}
            hideColumn={() => undefined}
            lockedColumns={new Set()}
            lockedReason=''
            canWrite
            quickAdd={undefined}
            setQuickAdd={() => undefined}
          />
          <div ref={portal} />
        </DropdownPortalContext.Provider>
      </ThemeProvider>
    </StoreContext>
  );
}

async function setup(views: Array<[string, string]>) {
  const store = new Store({ serverUrl: 'https://example.com' });
  const subjects: string[] = [];

  for (const [name, kind] of views) {
    subjects.push(await newView(store, name, kind));
  }

  const setViewKind = vi.fn();
  render(
    <Harness store={store} initial={subjects} setViewKind={setViewKind} />,
  );

  return { setViewKind };
}

/** Clicking the active tab opens its menu. */
async function openMenu(tabName: string) {
  fireEvent.click(await screen.findByRole('tab', { name: tabName }));

  return screen.findByRole('menu');
}

it('adds a Calendar view from the only Table tab and keeps the table (#1806)', async () => {
  const { setViewKind } = await setup([['All pieces', 'table']]);

  const menu = await openMenu('All pieces');
  fireEvent.click(within(menu).getByRole('menuitem', { name: 'Calendar' }));

  await waitFor(() =>
    expect(screen.getAllByRole('tab').map(t => t.textContent)).toEqual([
      'All pieces',
      'Calendar',
    ]),
  );
  expect(setViewKind).not.toHaveBeenCalled();
  expect(
    screen.getByRole('tab', { name: 'Calendar' }).getAttribute('aria-selected'),
  ).toBe('true');
});

it('offers no in-place change, and no delete, on the last table view', async () => {
  await setup([
    ['All pieces', 'table'],
    ['Calendar', 'calendar'],
  ]);

  const menu = await openMenu('All pieces');

  expect(within(menu).queryByText('Change this view to')).toBeNull();
  expect(
    within(menu)
      .getByRole('menuitem', { name: /Delete/ })
      .hasAttribute('disabled'),
  ).toBe(true);
});

it('offers an in-place change while another table view remains', async () => {
  const { setViewKind } = await setup([
    ['All pieces', 'table'],
    ['By author', 'table'],
  ]);

  const menu = await openMenu('All pieces');

  expect(within(menu).getByText('Change this view to')).toBeTruthy();
  // The change list sits after the add list; its Calendar is the second one.
  const calendars = within(menu).getAllByRole('menuitem', {
    name: 'Calendar',
  });
  expect(calendars).toHaveLength(2);
  fireEvent.click(calendars[1]);

  expect(setViewKind).toHaveBeenCalledWith(
    expect.stringMatching(/^_new:view-/),
    'calendar',
  );
});
