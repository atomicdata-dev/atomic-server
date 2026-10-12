// @vitest-environment jsdom
// @wc-ignore-file
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { StrictMode } from 'react';
import { beforeAll, afterEach, describe, expect, it, vi } from 'vitest';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ThemeProvider } from 'styled-components';
import {
  Datatype,
  type JSONValue,
  LoroLoader,
  Store,
  StoreContext,
  type Property,
  type Resource,
} from '@tomic/react';
import { FancyTable } from '@chunks/TableEditor';
import { buildTheme } from '../../styling';
import { TableCell } from './TableCell';

vi.mock('@chunks/TableEditor/DndWrapper', () => ({
  DndWrapper: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock('@chunks/TableEditor/TableHeader', () => ({
  TableHeader: () => <div role='row' />,
}));
// jsdom has no layout, so the grid's height probe would hand react-window a
// zero-height viewport and no row would render.
vi.mock('react-virtualized-auto-sizer', () => ({
  AutoSizer: ({
    renderProp,
  }: {
    renderProp: (props: { height: number }) => React.ReactNode;
  }) => renderProp({ height: 400 }),
}));
vi.mock('./helpers/useColumnLabel', () => ({ useColumnLabel: () => 'Day' }));

const DAY = 'https://example.com/properties/day';
const STORED = '2026-09-25';

const dayProperty: Property = {
  subject: DAY,
  datatype: Datatype.DATE,
  shortname: 'day',
  description: '',
};

beforeAll(async () => {
  // The app's vite config sends every `loro-crdt` import to the `web` build,
  // which fetches its WASM over HTTP. Hand it the file from disk instead;
  // the loader's own init then finds it initialized.
  const wasm = await readFile(
    createRequire(import.meta.url).resolve('loro-crdt/web/loro_wasm_bg.wasm'),
  );
  const web = (await import('loro-crdt/web')) as unknown as {
    default: (opts: { module_or_path: Uint8Array }) => Promise<unknown>;
  };
  await web.default({ module_or_path: wasm });
  await LoroLoader.initializeLoro();

  class ResizeObserverStub {
    public observe() {}
    public unobserve() {}
    public disconnect() {}
  }

  globalThis.ResizeObserver =
    ResizeObserverStub as unknown as typeof ResizeObserver;
});

afterEach(cleanup);

async function renderDateCell(): Promise<Resource> {
  return renderCell(dayProperty, STORED);
}

async function renderCell(
  property: Property,
  stored: JSONValue,
): Promise<Resource> {
  const store = new Store({ serverUrl: 'https://example.com', connect: false });
  // A `_new:` row stays local, so nothing here reaches for a server.
  const row = await store.newResource({
    subject: '_new:day-row',
    noParent: true,
  });
  await row.set(property.subject, stored, false);

  // StrictMode as the app runs it: an editor that stores on unmount must not
  // store when React only re-runs its effects.
  render(
    <StrictMode>
      <StoreContext value={store}>
        <ThemeProvider theme={buildTheme(false, '#1b50d8')}>
          <FancyTable
            columns={['title', 'day']}
            itemCount={1}
            columnToKey={String}
            labelledBy='table-title'
            HeadingComponent={() => <></>}
            NewColumnButtonComponent={() => null}
          >
            {() => (
              <TableCell
                rowIndex={0}
                columnIndex={1}
                subject={row.subject}
                property={property}
              />
            )}
          </FancyTable>
        </ThemeProvider>
      </StoreContext>
    </StrictMode>,
  );

  return row;
}

function editedCell(): HTMLElement {
  const cell = document.querySelector(
    '[aria-rowindex="2"] > [aria-colindex="2"]',
  );

  if (!cell) {
    throw new Error('No cell rendered');
  }

  return cell as HTMLElement;
}

/** Select the cell (not editing yet) and type one character on it. */
async function typeOnSelectedCell(key: string) {
  fireEvent.mouseDown(editedCell());
  fireEvent.click(editedCell());
  expect(screen.queryByRole('textbox')).toBeNull();

  await act(async () => {
    fireEvent.keyDown(editedCell(), { key });
  });
  await settle();
}

/** Lets the cell's async writes (`resource.set`, the debounced save) land. */
async function settle() {
  await act(() => new Promise(resolve => setTimeout(resolve, 300)));
}

describe('typing on a selected date cell (#1822)', () => {
  it('opens the editor with the character and keeps the stored date', async () => {
    const row = await renderDateCell();

    await typeOnSelectedCell('2');

    const input = screen.getByRole('textbox') as HTMLInputElement;
    expect(input.value).toBe('2');
    expect(row.get(DAY)).toBe(STORED);
  });

  it('keeps the stored date when the edit is abandoned with Escape', async () => {
    const row = await renderDateCell();

    await typeOnSelectedCell('2');
    await act(async () => {
      fireEvent.keyDown(screen.getByRole('textbox'), { key: 'Escape' });
    });
    await settle();

    expect(screen.queryByRole('textbox')).toBeNull();
    expect(row.get(DAY)).toBe(STORED);
    expect(editedCell().textContent).toMatch(/25.*2026|2026.*25/);
  });

  it('stores the date once the typed text is committed', async () => {
    const row = await renderDateCell();

    await typeOnSelectedCell('2');
    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: '2026-10-2' } });
    await act(async () => {
      fireEvent.keyDown(input, { key: 'Enter' });
    });

    await waitFor(() => expect(row.get(DAY)).toBe('2026-10-02'), {
      timeout: 5000,
    });
  });
});

const COUNT = 'https://example.com/properties/count';
const RATIO = 'https://example.com/properties/ratio';
const AT = 'https://example.com/properties/at';

const countProperty: Property = {
  subject: COUNT,
  datatype: Datatype.INTEGER,
  shortname: 'count',
  description: '',
};

const ratioProperty: Property = {
  subject: RATIO,
  datatype: Datatype.FLOAT,
  shortname: 'ratio',
  description: '',
};

const atProperty: Property = {
  subject: AT,
  datatype: Datatype.TIMESTAMP,
  shortname: 'at',
  description: '',
};

// Local time, so the editor's `datetime-local` text is predictable.
const STORED_AT = new Date(2026, 8, 25, 14, 30).getTime();

async function pressOnEditor(key: string, target: Element) {
  await act(async () => {
    fireEvent.keyDown(target, { key });
  });
  await settle();
}

function timestampInput(): HTMLInputElement {
  const input = editedCell().querySelector('input[type="datetime-local"]');

  if (!input) {
    throw new Error('No timestamp editor open');
  }

  return input as HTMLInputElement;
}

describe('typing on a selected timestamp cell (#1825)', () => {
  it('opens the editor on the stored time and stores no digit', async () => {
    const row = await renderCell(atProperty, STORED_AT);

    await typeOnSelectedCell('5');

    expect(row.get(AT)).toBe(STORED_AT);
    expect(timestampInput().value).toBe('2026-09-25T14:30');
  });

  it('keeps the stored time when the edit is abandoned with Escape', async () => {
    const row = await renderCell(atProperty, STORED_AT);

    await typeOnSelectedCell('5');
    await pressOnEditor('Escape', timestampInput());

    expect(editedCell().querySelector('input')).toBeNull();
    expect(row.get(AT)).toBe(STORED_AT);
  });
});

describe('typing on a selected number cell (#1825)', () => {
  it('ignores a letter on an integer cell and opens on the stored value', async () => {
    const row = await renderCell(countProperty, 42);

    await typeOnSelectedCell('a');

    expect(row.get(COUNT)).toBe(42);
    expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('42');

    await pressOnEditor('Escape', screen.getByRole('textbox'));
    expect(row.get(COUNT)).toBe(42);
  });

  it('seeds an integer cell with a digit, and Enter stores it', async () => {
    const row = await renderCell(countProperty, 42);

    await typeOnSelectedCell('7');

    const input = screen.getByRole('textbox') as HTMLInputElement;
    expect(input.value).toBe('7');
    expect(row.get(COUNT)).toBe(42);

    await pressOnEditor('Enter', input);
    await waitFor(() => expect(row.get(COUNT)).toBe(7), { timeout: 5000 });
  });

  it('keeps the stored integer when a seeded edit is abandoned with Escape', async () => {
    const row = await renderCell(countProperty, 42);

    await typeOnSelectedCell('7');
    await pressOnEditor('Escape', screen.getByRole('textbox'));

    expect(screen.queryByRole('textbox')).toBeNull();
    expect(row.get(COUNT)).toBe(42);
  });

  it('stores nothing for a partial number, only the finished one', async () => {
    const row = await renderCell(ratioProperty, 1.5);

    await typeOnSelectedCell('-');

    const input = screen.getByRole('textbox') as HTMLInputElement;
    expect(input.value).toBe('-');
    expect(row.get(RATIO)).toBe(1.5);

    fireEvent.change(input, { target: { value: '-2.' } });
    await settle();
    expect(row.get(RATIO)).toBe(1.5);

    fireEvent.change(input, { target: { value: '-2.25' } });
    await pressOnEditor('Tab', input);
    await waitFor(() => expect(row.get(RATIO)).toBe(-2.25), { timeout: 5000 });
  });

  it('ignores a letter on a float cell', async () => {
    const row = await renderCell(ratioProperty, 1.5);

    await typeOnSelectedCell('x');

    expect(row.get(RATIO)).toBe(1.5);
    expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('1.5');
  });
});
