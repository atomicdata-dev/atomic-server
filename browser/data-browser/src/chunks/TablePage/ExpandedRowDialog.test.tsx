// @vitest-environment jsdom
// @wc-ignore-file
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
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
  LoroLoader,
  Store,
  StoreContext,
  type JSONValue,
  type Property,
  type Resource,
} from '@tomic/react';
import { calendarRecurrenceShortname } from '@tomic/lib';
import {
  defaultRepeatRule,
  nativeCalendarPayload,
} from '@tomic/lib/calendar-recurrence.js';
import type { JSX, ReactNode } from 'react';
import { buildTheme } from '../../styling';
import { ExpandedRowDialog } from './ExpandedRowDialog';
import { RepeatSummaryCell } from './Calendar/RepeatSummaryCell';
import { allDayRowTime } from './Calendar/calendarRows';
import { useTableCalendarRow } from './Calendar/useTableCalendarRow';

// The dialog's frame, the property list and the JSON editor are not what is
// under test: render the dialog's content in place, and list which
// properties the dialog hands to its property list.
vi.mock(import('@components/Dialog'), async importOriginal => {
  const actual = await importOriginal();

  return {
    ...actual,
    // Keeps the slot statics (`Dialog.Actions`) other modules style.
    Dialog: Object.assign(
      ({ children }: { children?: ReactNode }) => <div>{children}</div>,
      actual.Dialog,
    ),
    DialogTitle: () => null,
    DialogContent: ({ children }: { children?: ReactNode }) => (
      <div>{children}</div>
    ),
    useDialog: (() => [{}, () => undefined]) as never,
  };
});
vi.mock('@components/AllProps', () => ({
  default: ({ except }: { except: string[] }) => (
    <div data-testid='all-props' data-except={except.join(' ')} />
  ),
}));
vi.mock('@components/forms/ValueForm', () => ({
  ValueForm: () => <pre data-testid='json-editor' />,
}));

const DAY = 'https://example.com/properties/day';
const RECURRENCE = 'https://example.com/properties/recurrence';
// Thursday 1 October 2026.
const ROW_DAY = '2026-10-01';

const dayProperty: Property = {
  subject: DAY,
  datatype: Datatype.DATE,
  shortname: 'atomic-calendar-day',
  description: '',
};

const recurrenceProperty: Property = {
  subject: RECURRENCE,
  datatype: Datatype.JSON,
  shortname: calendarRecurrenceShortname,
  description: '',
};

beforeAll(async () => {
  // See TableCell.test.tsx: hand loro its WASM from disk.
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

/** The table view's row dialog, with the calendar fields the table finds on
 * its class. */
function TableRowDialog({
  row,
  tableClass,
  columns,
}: {
  row: Resource;
  tableClass: Resource;
  columns: Property[];
}): JSX.Element {
  const calendar = useTableCalendarRow(tableClass, columns);

  return (
    <ExpandedRowDialog
      subject={row.subject}
      open
      bindOpen={() => undefined}
      calendar={calendar}
    />
  );
}

async function setup(values: Record<string, JSONValue>) {
  const store = new Store({ serverUrl: 'https://example.com', connect: false });
  vi.spyOn(store, 'getProperty').mockImplementation(async subject =>
    subject === DAY ? dayProperty : recurrenceProperty,
  );
  const tableClass = await store.newResource({
    subject: '_new:class',
    noParent: true,
  });
  // A `_new:` row stays local; its save is not what is under test.
  const row = await store.newResource({
    subject: '_new:row',
    noParent: true,
  });
  vi.spyOn(row, 'save').mockResolvedValue(undefined as never);

  for (const [prop, value] of Object.entries(values)) {
    await row.set(prop, value, false);
  }

  const renderWith = (ui: ReactNode) =>
    render(
      <StoreContext value={store}>
        <ThemeProvider theme={buildTheme(false, '#1b50d8')}>{ui}</ThemeProvider>
      </StoreContext>,
    );

  return { store, row, tableClass, renderWith };
}

describe('the table view row dialog (#1801)', () => {
  it('shows the Repeat field for the recurrence property, not its JSON', async () => {
    const { row, tableClass, renderWith } = await setup({ [DAY]: ROW_DAY });

    renderWith(
      <TableRowDialog
        row={row}
        tableClass={tableClass}
        columns={[dayProperty, recurrenceProperty]}
      />,
    );

    expect(screen.getByTestId('repeat-field')).toBeTruthy();
    // Start and End are the table's own columns: no time fields here.
    expect(screen.queryByLabelText('All day')).toBeNull();
    expect(screen.getByTestId('repeat-summary').textContent).toBe(
      'Does not repeat',
    );
    expect(
      screen.getByTestId('all-props').getAttribute('data-except'),
    ).toContain(RECURRENCE);
    // The JSON is behind Show JSON.
    expect(screen.queryByTestId('json-editor')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Show JSON' }));
    expect(screen.getByTestId('json-editor')).toBeTruthy();
  });

  it('writes the same payload as the calendar row dialog', async () => {
    const { row, tableClass, renderWith } = await setup({ [DAY]: ROW_DAY });

    renderWith(
      <TableRowDialog
        row={row}
        tableClass={tableClass}
        columns={[dayProperty, recurrenceProperty]}
      />,
    );

    await act(async () => {
      fireEvent.change(screen.getByLabelText('Repeat'), {
        target: { value: 'weekly' },
      });
    });

    // What the calendar's Repeat field stores for a Thursday row set to
    // Weekly: the native payload for the row's own day.
    const expected = nativeCalendarPayload(
      row.subject,
      {
        ...defaultRepeatRule('weekly', { date: ROW_DAY }),
        end: { type: 'never' },
      },
      allDayRowTime(ROW_DAY),
    );

    await waitFor(() => expect(row.get(RECURRENCE)).toEqual(expected));
    expect(row.save).toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByTestId('repeat-summary').textContent).toBe(
        'Every Thursday',
      ),
    );
  });

  it('keeps the JSON editor for a row without a day', async () => {
    const { row, tableClass, renderWith } = await setup({});

    renderWith(
      <TableRowDialog
        row={row}
        tableClass={tableClass}
        columns={[dayProperty, recurrenceProperty]}
      />,
    );

    expect(screen.queryByTestId('repeat-field')).toBeNull();
    expect(
      screen.getByTestId('all-props').getAttribute('data-except'),
    ).not.toContain(RECURRENCE);
  });

  it('has no Repeat field in a table without a recurrence property', async () => {
    const { row, tableClass, renderWith } = await setup({ [DAY]: ROW_DAY });

    renderWith(
      <TableRowDialog
        row={row}
        tableClass={tableClass}
        columns={[dayProperty]}
      />,
    );

    expect(screen.queryByTestId('repeat-field')).toBeNull();
  });
});

describe('the table view recurrence cell (#1801)', () => {
  it('shows the Repeat summary instead of the JSON', async () => {
    const payload = nativeCalendarPayload(
      '_new:row',
      {
        ...defaultRepeatRule('weekly', { date: ROW_DAY }),
        end: { type: 'count', count: 5 },
      },
      allDayRowTime(ROW_DAY),
    );
    const { row, renderWith } = await setup({
      [DAY]: ROW_DAY,
      [RECURRENCE]: payload as unknown as JSONValue,
    });

    renderWith(
      <RepeatSummaryCell
        resource={row}
        calendar={{
          dateProp: dayProperty,
          calendarDate: true,
          recurrenceProp: recurrenceProperty,
          ensureRecurrenceProp: async () => RECURRENCE,
          ensureTimeProps: async () => ({ start: '', end: '' }),
        }}
        fallback={<span data-testid='raw-json' />}
      />,
    );

    expect(screen.getByTestId('repeat-cell').textContent).toBe(
      'Every Thursday, 5 times',
    );
    expect(screen.queryByTestId('raw-json')).toBeNull();
  });
});
