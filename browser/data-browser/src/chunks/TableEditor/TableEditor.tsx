import {
  useCallback,
  useEffect,
  useEffectEvent,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
} from 'react';
import { styled } from 'styled-components';
import { List } from 'react-window';
import { AutoSizer } from 'react-virtualized-auto-sizer';
import { Cell, IndexCell } from './Cell';
import { TableRow } from './TableRow';
import { TableHeader, TableHeadingComponent } from './TableHeader';
import { useCellSizes } from './hooks/useCellSizes';
import {
  CursorMode,
  TableEditorContextProvider,
  useTableEditorContext,
} from './TableEditorContext';
import { useTableEditorKeyboardNavigation } from './hooks/useTableEditorKeyboardNavigation';
import { ActiveCellIndicator } from './ActiveCellIndicator';
import { ScrollArea, ScrollViewPort } from '@components/ScrollArea';
import { useCopyCommand } from './hooks/useCopyCommand';
import {
  CellIndex,
  CellPasteData,
  ColumnReorderHandler,
  CopyValue,
} from './types';
import { useClearCommands } from './hooks/useClearCommands';
import { usePasteCommand } from './hooks/usePasteCommand';
import { DndWrapper } from './DndWrapper';
import { VisuallyHidden } from '@components/VisuallyHidden';
import { Spinner } from '@components/Spinner';
import { useClickAwayListener } from '../../hooks/useClickAwayListener';
import { KeyboardInteraction } from './helpers/keyboardHandlers';
import { useAvailableHeight } from './hooks/useAvailableHeight';

const ARIA_TABLE_USAGE =
  'Use the arrow keys to navigate the table. Press enter to edit a cell. Press escape to exit edit mode.';

interface FancyTableProps<T> {
  readOnly?: boolean;
  columns: T[];
  itemCount: number;
  columnSizes?: number[];
  children: (props: { index: number }) => JSX.Element;
  rowHeight?: number;
  columnToKey: (column: T) => string;
  labelledBy: string;
  /**
   * The rows are still being fetched. Shows a spinner and `aria-busy` so
   * assistive tech, and tests, can tell a loading grid from a settled one:
   * the placeholder row is drawn before the collection answers, so "a row is
   * visible" no longer means "the data has arrived".
   */
  busy?: boolean;
  onUndoCommand?: () => void;
  onClearRow?: (index: number) => void;
  onClearCells?: (cells: CellIndex<T>[]) => void;
  onCopyCommand?: (cells: CellIndex<T>[]) => Promise<CopyValue[][]>;
  onPasteCommand?: (pasteData: CellPasteData<T>[]) => void;
  onCellResize?: (sizes: number[]) => void;
  onColumnReorder?: ColumnReorderHandler;
  onRowExpand?: (index: number) => void;
  /** See {@link TableCommands.insertRowBelow}. */
  onInsertRowBelow?: (index: number) => boolean;
  /** Fires when the active cell moves (both indexes `undefined` when the
   * selection clears or the table unmounts). Column index 0 is the row
   * header; data columns start at 1. Used for e.g. presence announcing. */
  onSelectedCellChange?: (
    row: number | undefined,
    column: number | undefined,
  ) => void;
  itemKey?: (index: number) => string;
  HeadingComponent: TableHeadingComponent<T>;
  NewColumnButtonComponent: React.ComponentType;
  /**
   * Rendered as a row under the last row, aligned to the columns. The list
   * scrolls inside its own box, so this stays in view while the rows move —
   * and scrolls sideways with them, keeping each cell under its column.
   *
   * It is handed the same columns the grid renders, so the two can't disagree
   * about how many cells a row has.
   */
  FooterComponent?: React.ComponentType<{ columns: T[] }>;
  ref?: React.RefObject<HTMLDivElement | null>;
}

interface RowProps {
  index: number;
  style: React.CSSProperties;
  ariaAttributes: React.AriaAttributes & { role: 'listitem' };
}

type OnScroll = Parameters<
  React.ComponentProps<typeof ActiveCellIndicator>['setOnScroll']
>[0];

export function FancyTable<T>({
  rowHeight = 40,
  readOnly = false,
  ...props
}: FancyTableProps<T>): JSX.Element {
  return (
    <TableEditorContextProvider readOnly={readOnly}>
      <FancyTableInner rowHeight={rowHeight} {...props} />
    </TableEditorContextProvider>
  );
}

function FancyTableInner<T>({
  children,
  columns,
  itemCount,
  rowHeight,
  columnSizes,
  columnToKey,
  labelledBy,
  busy = false,
  onCellResize = () => undefined,
  onClearCells,
  onClearRow,
  onCopyCommand,
  onUndoCommand,
  onPasteCommand,
  onColumnReorder,
  onRowExpand = () => undefined,
  onInsertRowBelow,
  onSelectedCellChange,
  HeadingComponent,
  NewColumnButtonComponent,
  FooterComponent,
}: FancyTableProps<T>): JSX.Element {
  const ariaUsageId = useId();
  const scrollerRef = useRef<HTMLDivElement>(null);
  const headerRef = useRef<HTMLDivElement>(null);
  const {
    listRef,
    tableRef,
    setCursorMode,
    cursorMode,
    disabledKeyboardInteractions,
    readOnly,
    selectedRow,
    selectedColumn,
  } = useTableEditorContext();
  const previousCursorMode = useRef(cursorMode);

  const [onScroll, setOnScroll] = useState<OnScroll>(() => undefined);

  const { templateColumns, contentRowWidth, resizeCell } = useCellSizes(
    columnSizes,
    columns,
    onCellResize,
  );

  const handleClickOutside = useCallback(() => {
    if (disabledKeyboardInteractions.has(KeyboardInteraction.ExitEditMode)) {
      return;
    }

    setCursorMode(CursorMode.Visual);
  }, [disabledKeyboardInteractions, setCursorMode]);

  useClickAwayListener([tableRef], handleClickOutside, true);

  useAvailableHeight(tableRef, headerRef);

  const triggerCopyCommand = useCopyCommand(columns, onCopyCommand);
  const triggerPasteCommand = usePasteCommand(columns, onPasteCommand);

  const tableCommands = useMemo(
    () => ({
      copy: triggerCopyCommand,
      undo: onUndoCommand,
      expand: onRowExpand,
      insertRowBelow: onInsertRowBelow,
    }),
    [triggerCopyCommand, onUndoCommand, onRowExpand, onInsertRowBelow],
  );

  const handleKeyDown = useTableEditorKeyboardNavigation(
    columns.length,
    itemCount,
    tableRef,
    headerRef,
    tableCommands,
  );

  // Escape leaves an editing cell, handled in the capture phase on the table
  // itself — the outermost ancestor of every cell editor and popover — so it
  // fires before any input can `stopPropagation` or a native `popover=auto`
  // can run its own Escape dismiss. `preventDefault` cancels that native
  // dismiss so focus handling stays ours. Switching to Visual unmounts the
  // editor; the `Edit -> Visual` layout effect above then focuses the table,
  // after the unmount, so there's no focus race to fight.
  const handleEscapeCapture = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (
        e.key === 'Escape' &&
        cursorMode === CursorMode.Edit &&
        // Editors that render their own surface (Markdown's Dialog, JSON's
        // inline editor) opt out via this flag and handle Escape themselves.
        !disabledKeyboardInteractions.has(KeyboardInteraction.ExitEditMode)
      ) {
        e.preventDefault();
        e.stopPropagation();
        setCursorMode(CursorMode.Visual);
      }
    },
    [cursorMode, disabledKeyboardInteractions, setCursorMode],
  );

  useLayoutEffect(() => {
    if (
      previousCursorMode.current === CursorMode.Edit &&
      cursorMode === CursorMode.Visual &&
      selectedRow !== undefined &&
      selectedColumn !== undefined
    ) {
      tableRef.current?.focus({ preventScroll: true });
    }

    previousCursorMode.current = cursorMode;
  }, [cursorMode, selectedColumn, selectedRow, tableRef]);

  useClearCommands(columns, onClearRow, onClearCells);

  const emitSelectedCellChange = useEffectEvent(
    (row: number | undefined, column: number | undefined) =>
      onSelectedCellChange?.(row, column),
  );

  useEffect(() => {
    emitSelectedCellChange(selectedRow, selectedColumn);
  }, [selectedRow, selectedColumn]);

  // Retract the selection announcement when the grid unmounts (e.g. a
  // switch to the kanban/calendar view) — there's no cell to sit on.
  useEffect(() => () => emitSelectedCellChange(undefined, undefined), []);

  const Row = useCallback(
    ({ index, style, ariaAttributes }: RowProps) => {
      // react-window v2 hands every virtual item `role="listitem"` plus
      // `aria-posinset` / `aria-setsize`. Those are wrong for a table — our
      // rows live inside `role="rowgroup"` and need `role="row"` with
      // `aria-rowindex`. Drop the listitem role so the TableRow's
      // `role='row'` is not overridden when the spread reaches it.
      const { role: _role, ...gridAria } = ariaAttributes;

      return (
        <TableRow
          {...gridAria}
          style={style}
          role='row'
          aria-rowindex={index + 2}
        >
          <IndexCell rowIndex={index} columnIndex={0} onExpand={onRowExpand}>
            {index + 1}
          </IndexCell>
          {children({ index })}
          <Cell rowIndex={Infinity} columnIndex={Infinity} disabled />
        </TableRow>
      );
    },
    [children, onRowExpand],
  );

  const rowProps = useMemo(() => ({}), []);

  // Render the StyledList (react-window) directly — NOT wrapped in a
  // `useCallback`'d component. A wrapper component's identity changes whenever
  // `itemCount`/`Row` change (every time a row is added), and `<Wrapper/>`
  // with a new function type makes React unmount + remount `StyledList`,
  // which resets react-window's scrollTop to 0. That's invisible while all
  // rows fit the viewport, but once the list has scrolled to follow the active
  // cell, the remount snaps it back to the top — throwing the active cell off
  // screen, where it's virtualized out and stops receiving keystrokes (so
  // rapid Enter-entry silently stops adding rows). Rendering the stable
  // `StyledList` type means only its props update; scroll position is kept.
  const renderList = useCallback(
    ({ height }: { height: number | undefined }) => (
      <StyledList
        style={{ height: height ?? 0, width: '100%' }}
        rowHeight={rowHeight!}
        rowCount={itemCount}
        rowProps={rowProps}
        defaultHeight={height ?? 0}
        overscanCount={4}
        onScroll={() => {
          onScroll({ scrollUpdateWasRequested: false });
        }}
        listRef={listRef}
        rowComponent={Row}
      />
    ),
    [rowHeight, itemCount, rowProps, listRef, Row, onScroll],
  );

  useEffect(() => {
    if (readOnly) {
      return;
    }

    document.addEventListener('paste', triggerPasteCommand);

    return () => {
      document.removeEventListener('paste', triggerPasteCommand);
    };
  }, [triggerPasteCommand, readOnly]);

  return (
    <DndWrapper>
      <VisuallyHidden id={ariaUsageId}>
        <p>{ARIA_TABLE_USAGE}</p>
      </VisuallyHidden>
      <Table
        aria-labelledby={labelledBy}
        aria-busy={busy}
        aria-rowcount={itemCount}
        aria-colcount={columns.length + 2}
        aria-describedby={ariaUsageId}
        role='grid'
        gridTemplateColumns={templateColumns}
        contentRowWidth={contentRowWidth}
        rowHeight={rowHeight!}
        tabIndex={0}
        onKeyDownCapture={handleEscapeCapture}
        onKeyDown={handleKeyDown}
        totalContentHeight={itemCount * rowHeight!}
        columnSizes={columnSizes ?? []}
        ref={tableRef}
      >
        <RelativeScrollArea ref={scrollerRef} type='hover'>
          <PercentageInsanityFix>
            <TableHeader
              headerRef={headerRef}
              columns={columns}
              columnToKey={columnToKey}
              onResize={resizeCell}
              onColumnReorder={onColumnReorder}
              HeadingComponent={HeadingComponent}
              NewColumnButtonComponent={NewColumnButtonComponent}
            />
            <AutoSizeTamer role='rowgroup'>
              <AutoSizer renderProp={renderList} />
            </AutoSizeTamer>
            {FooterComponent && (
              <FooterWrapper role='rowgroup'>
                <FooterComponent columns={columns} />
              </FooterWrapper>
            )}
            <ActiveCellIndicator
              sizeStr={templateColumns}
              scrollerRef={scrollerRef}
              setOnScroll={setOnScroll}
            />
          </PercentageInsanityFix>
        </RelativeScrollArea>
        {busy && (
          <div role='row'>
            <LoadingCell role='gridcell' aria-colspan={columns.length + 2}>
              <span role='status'>
                <Spinner size='20px' />
                Loading
              </span>
            </LoadingCell>
          </div>
        )}
      </Table>
    </DndWrapper>
  );
}

interface TableProps {
  gridTemplateColumns: string;
  columnSizes: number[];
  contentRowWidth: string;
  rowHeight: number;
  totalContentHeight: number;
}

const Table = styled.div.attrs<TableProps>(p => ({
  style: {
    '--table-template-columns': p.gridTemplateColumns,
    '--table-content-width': p.contentRowWidth,
    ...p.columnSizes.reduce(
      (acc, size, i) => ({
        ...acc,
        [`--cell-width-${i + 1}`]: `${size}px`,
      }),
      {},
    ),
  } as Record<string, string>,
}))`
  /* Replaced with the real space below the grid by useAvailableHeight, before
   * the first paint. Only a fallback for the measurement never running. */
  --table-height: 80vh;
  --table-row-height: ${p => p.rowHeight}px;
  --table-inner-padding: 0.5rem;
  --table-content-height: ${p => p.totalContentHeight}px;
  background: ${p => p.theme.colors.bg};
  border-radius: ${p => p.theme.radius};
  overflow: hidden;
  overflow-x: auto;
  border: 1px solid ${p => p.theme.colors.bg2};
  width: 100%;
  position: relative;
  contain: paint;
  overscroll-behavior: contain;

  &:focus-visible {
    outline: none;
    box-shadow: 0 0 0 2px ${p => p.theme.colors.main};
  }
`;

const LoadingCell = styled.div`
  padding: ${p => p.theme.size()};

  > span {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: ${p => p.theme.size()};
  }
`;

const PercentageInsanityFix = styled.div`
  width: fit-content;
  min-width: 100%;
`;

const StyledList = styled(List)`
  overflow-x: hidden !important;
  overflow-y: auto !important;
`;

/** Under the rows, above the horizontal scrollbar, always in view. */
const FooterWrapper = styled.div`
  position: relative;
  z-index: 9;
  background-color: ${p => p.theme.colors.bgBody};
  border-top: 1px solid ${p => p.theme.colors.bg2};
`;

const AutoSizeTamer = styled.div`
  height: min(var(--table-height), var(--table-content-height));
  width: 100%;
`;

const RelativeScrollArea = styled(ScrollArea)`
  & ${ScrollViewPort} {
    position: relative;
  }
`;
