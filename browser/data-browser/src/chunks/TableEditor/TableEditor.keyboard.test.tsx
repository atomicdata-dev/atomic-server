// @vitest-environment jsdom
// @wc-ignore-file
import { useMemo, useState, type JSX } from 'react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider, type DefaultTheme } from 'styled-components';
import { FancyTable } from './TableEditor';
import { Cell } from './Cell';
import { CursorMode, useTableEditorContext } from './TableEditorContext';
import { KeyboardInteraction } from './helpers/keyboardHandlers';
import { useCellOptions } from './hooks/useCellOptions';

vi.mock('./DndWrapper', () => ({
  DndWrapper: ({ children }: { children: React.ReactNode }) => children,
}));
vi.mock('./TableHeader', () => ({ TableHeader: () => <div role='row' /> }));
// jsdom has no layout, so the grid's height probe would hand react-window a
// zero-height viewport and no row would render.
vi.mock('react-virtualized-auto-sizer', () => ({
  AutoSizer: ({
    renderProp,
  }: {
    renderProp: (props: { height: number }) => React.ReactNode;
  }) => renderProp({ height: 400 }),
}));

const theme = {
  colors: { main: '#4C6FA5', bg: '#fff', bg1: '#eee', textLight: '#777' },
  animation: { duration: '0s' },
  size: () => '8px',
} as unknown as DefaultTheme;

const ROW_COUNT = 3;

/**
 * Mirrors how a real editor cell works (see TablePage/TableCell.tsx): the
 * display value is swapped for an editor while this cell is the active one
 * and the grid is in Edit mode.
 */
interface TestCellProps {
  rowIndex: number;
  /** Renders its own popover/dialog-like surface that owns the Escape key. */
  ownsEscape?: boolean;
  /** Drops focus when its surface closes, like a dialog restoring focus to a
   * trigger that has already unmounted. */
  dropsFocusOnClose?: boolean;
}

function TestCell({
  rowIndex,
  ownsEscape,
  dropsFocusOnClose,
}: TestCellProps): JSX.Element {
  const { cursorMode, selectedRow, selectedColumn } = useTableEditorContext();
  const isEditing =
    cursorMode === CursorMode.Edit &&
    selectedRow === rowIndex &&
    selectedColumn === 1;

  return (
    <Cell rowIndex={rowIndex} columnIndex={1}>
      {isEditing ? (
        ownsEscape ? (
          <SurfaceEditor
            rowIndex={rowIndex}
            dropsFocusOnClose={!!dropsFocusOnClose}
          />
        ) : (
          <input aria-label={`edit row ${rowIndex}`} autoFocus />
        )
      ) : (
        `row ${rowIndex}`
      )}
    </Cell>
  );
}

/**
 * Stand-in for the popover- and dialog-backed editors (AtomicURLCell,
 * MarkdownCell, JSONCell). While its surface is open it takes ownership of
 * Escape, and closing that surface is all it does with the key — it never
 * tells the grid to leave Edit mode. That is exactly the contract the real
 * editors have with the table, so the grid itself has to notice.
 */
function SurfaceEditor({
  rowIndex,
  dropsFocusOnClose,
}: {
  rowIndex: number;
  dropsFocusOnClose: boolean;
}): JSX.Element {
  const [open, setOpen] = useState(true);

  const options = useMemo(
    () =>
      open
        ? {
            disabledKeyboardInteractions: new Set([
              KeyboardInteraction.ExitEditMode,
            ]),
          }
        : {},
    [open],
  );

  useCellOptions(options);

  if (!open) {
    return <span>surface closed</span>;
  }

  return (
    <input
      aria-label={`surface row ${rowIndex}`}
      autoFocus
      onKeyDown={e => {
        if (e.key !== 'Escape') {
          return;
        }

        e.preventDefault();
        setOpen(false);

        if (dropsFocusOnClose) {
          (e.target as HTMLElement).blur();
        }
      }}
    />
  );
}

function renderGrid(cellProps: Omit<TestCellProps, 'rowIndex'> = {}) {
  const onSelectedCellChange = vi.fn();

  render(
    <ThemeProvider theme={theme}>
      <FancyTable
        columns={['name']}
        itemCount={ROW_COUNT}
        columnToKey={String}
        labelledBy='table-title'
        onSelectedCellChange={onSelectedCellChange}
        HeadingComponent={() => <></>}
        NewColumnButtonComponent={() => null}
      >
        {({ index }) => <TestCell rowIndex={index} {...cellProps} />}
      </FancyTable>
    </ThemeProvider>,
  );

  return { onSelectedCellChange };
}

function getCell(row: number): HTMLElement {
  const cell = document.querySelector(
    `[aria-rowindex="${row + 2}"] > [aria-colindex="2"]`,
  );

  if (!cell) {
    throw new Error(`No cell rendered for row ${row}`);
  }

  return cell as HTMLElement;
}

/** The row/column the grid reports as active, via `onSelectedCellChange`. */
function selectedCell(onSelectedCellChange: ReturnType<typeof vi.fn>) {
  const calls = onSelectedCellChange.mock.calls;

  return calls[calls.length - 1];
}

beforeAll(() => {
  class ResizeObserverStub {
    public observe() {}
    public unobserve() {}
    public disconnect() {}
  }

  globalThis.ResizeObserver =
    ResizeObserverStub as unknown as typeof ResizeObserver;

  // The first render in this file costs an order of magnitude more than the
  // ones after it, measured at rest: 251 ms against 17 to 20 ms. It is where
  // styled-components builds its stylesheet and jsdom parses it, and where the
  // grid's own modules run for the first time. That one-time cost used to land
  // on whichever test happened to run first, which under CI load put that test
  // over vitest's 5 s default. Paying it here, where the hook's own timeout
  // covers it, leaves each test measuring only its own work.
  renderGrid();
  cleanup();
});

afterEach(cleanup);

describe('keyboard navigation after leaving edit mode', () => {
  it('moves the cursor after Escape from a plain cell editor', () => {
    const { onSelectedCellChange } = renderGrid();

    fireEvent.mouseDown(getCell(0));
    fireEvent.click(getCell(0));
    expect(selectedCell(onSelectedCellChange)).toEqual([0, 1]);

    fireEvent.keyDown(getCell(0), { key: 'Enter' });
    const input = screen.getByLabelText('edit row 0');

    fireEvent.keyDown(input, { key: 'Escape' });
    expect(screen.queryByLabelText('edit row 0')).toBeNull();

    fireEvent.keyDown(document.activeElement!, { key: 'ArrowDown' });
    expect(selectedCell(onSelectedCellChange)).toEqual([1, 1]);
  });

  it('moves the cursor after a single Escape from an editor that owns the key', () => {
    const { onSelectedCellChange } = renderGrid({ ownsEscape: true });

    fireEvent.mouseDown(getCell(0));
    fireEvent.click(getCell(0));
    fireEvent.keyDown(getCell(0), { key: 'Enter' });

    const input = screen.getByLabelText('surface row 0');
    fireEvent.keyDown(input, { key: 'Escape' });

    // One Escape, and the grid is navigable again — no second one needed.
    fireEvent.keyDown(document.activeElement!, { key: 'ArrowDown' });
    expect(selectedCell(onSelectedCellChange)).toEqual([1, 1]);
  });

  it('hands focus back to the grid when the editor closes', () => {
    renderGrid({ ownsEscape: true, dropsFocusOnClose: true });

    fireEvent.mouseDown(getCell(0));
    fireEvent.click(getCell(0));
    fireEvent.keyDown(getCell(0), { key: 'Enter' });

    fireEvent.keyDown(screen.getByLabelText('surface row 0'), {
      key: 'Escape',
    });

    expect(screen.getByRole('grid').contains(document.activeElement)).toBe(
      true,
    );
  });

  it('keeps the grid in control after Escape: focus inside it, arrows move', () => {
    const { onSelectedCellChange } = renderGrid();

    fireEvent.mouseDown(getCell(1));
    fireEvent.click(getCell(1));
    fireEvent.keyDown(getCell(1), { key: 'Enter' });
    fireEvent.keyDown(screen.getByLabelText('edit row 1'), { key: 'Escape' });

    const grid = screen.getByRole('grid');
    expect(grid.contains(document.activeElement)).toBe(true);
    expect(document.activeElement).not.toBe(document.body);

    fireEvent.keyDown(document.activeElement!, { key: 'ArrowUp' });
    expect(selectedCell(onSelectedCellChange)).toEqual([0, 1]);
    expect(grid.contains(document.activeElement)).toBe(true);
  });

  it('leaves Edit mode on Enter, selecting the next row', () => {
    const { onSelectedCellChange } = renderGrid();

    fireEvent.mouseDown(getCell(0));
    fireEvent.click(getCell(0));
    fireEvent.keyDown(getCell(0), { key: 'Enter' });
    fireEvent.keyDown(screen.getByLabelText('edit row 0'), { key: 'Enter' });

    // Selection mode on the next row: no editor opened there.
    expect(selectedCell(onSelectedCellChange)).toEqual([1, 1]);
    expect(screen.queryByLabelText('edit row 1')).toBeNull();
    expect(screen.queryByLabelText('edit row 0')).toBeNull();
    expect(screen.getByRole('grid').contains(document.activeElement)).toBe(
      true,
    );

    // Arrows navigate right away, and Enter opens the editor again.
    fireEvent.keyDown(document.activeElement!, { key: 'ArrowDown' });
    expect(selectedCell(onSelectedCellChange)).toEqual([2, 1]);
    fireEvent.keyDown(document.activeElement!, { key: 'Enter' });
    expect(screen.getByLabelText('edit row 2')).toBeTruthy();
  });

  it('takes Escape back when an editor lost focus entirely', () => {
    const { onSelectedCellChange } = renderGrid();

    fireEvent.mouseDown(getCell(0));
    fireEvent.click(getCell(0));
    fireEvent.keyDown(getCell(0), { key: 'Enter' });

    // The editor is still mounted but nothing holds focus (a virtualized row
    // remounting under it, say), so the Escape never reaches the grid.
    (screen.getByLabelText('edit row 0') as HTMLElement).blur();
    expect(document.activeElement).toBe(document.body);

    fireEvent.keyDown(document.body, { key: 'Escape' });

    expect(screen.queryByLabelText('edit row 0')).toBeNull();
    expect(screen.getByRole('grid').contains(document.activeElement)).toBe(
      true,
    );

    fireEvent.keyDown(document.activeElement!, { key: 'ArrowDown' });
    expect(selectedCell(onSelectedCellChange)).toEqual([1, 1]);
  });

  it('keeps its rows mounted while the cursor moves', () => {
    renderGrid();

    const before = getCell(1);

    fireEvent.mouseDown(getCell(0));
    fireEvent.click(getCell(0));
    fireEvent.keyDown(getCell(0), { key: 'ArrowDown' });

    // react-window is handed a `Row` component; if its identity changes per
    // render every row unmounts and remounts, which resets the list's scroll
    // position and re-runs each cell's mount effects.
    expect(getCell(1)).toBe(before);
  });

  it('still routes arrow keys when focus was lost entirely', () => {
    const { onSelectedCellChange } = renderGrid();

    fireEvent.mouseDown(getCell(0));
    fireEvent.click(getCell(0));

    // Something outside the grid took focus and then went away — a dialog
    // restoring focus to a button that has since unmounted, say. The grid
    // still owns a selected cell, so it should still answer the arrow keys.
    (document.activeElement as HTMLElement | null)?.blur();
    expect(document.activeElement).toBe(document.body);

    fireEvent.keyDown(document.body, { key: 'ArrowDown' });

    expect(selectedCell(onSelectedCellChange)).toEqual([1, 1]);
    expect(screen.getByRole('grid').contains(document.activeElement)).toBe(
      true,
    );
  });
});
