import {
  memo,
  useCallback,
  useEffect,
  useEffectEvent,
  useRef,
  type JSX,
} from 'react';
import {
  Collection,
  dataBrowser,
  DataBrowser,
  Resource,
  unknownSubject,
  useMemberFromCollection,
  useResource,
} from '@tomic/react';
import { Cell } from '@chunks/TableEditor';
import { TableCell } from './TableCell';
import type { TableColumn } from './useTableColumns';
import { styled, keyframes } from 'styled-components';
import { useTableEditorContext } from '@chunks/TableEditor/TableEditorContext';
import { FaTriangleExclamation } from 'react-icons/fa6';
import { useIsUnsavedDraft } from './draftRow';
import { useMaterializeWhenDeselected } from './useMaterializeWhenDeselected';
import { withRowDefaults } from './rowDefaults';

interface TableRowProps {
  collection: Collection;
  index: number;
  columns: TableColumn[];
  /**
   * The row's subject when the caller already knows it (the quick filter's
   * matches), so the row draws at once instead of resolving its index first.
   */
  subject?: string;
}

const WarningIcon = styled(FaTriangleExclamation)`
  color: ${p => p.theme.colors.warning};
`;

const TableCellMemo = memo(TableCell);

function useMarkings(row: Resource, index: number) {
  const { setMarkings } = useTableEditorContext();

  const addMarkings = useEffectEvent(() => {
    setMarkings(markings => {
      const newMap = new Map(markings);
      newMap.set(
        index,
        <WarningIcon title='Row is incomplete or has invalid data' />,
      );

      return newMap;
    });
  });

  const removeMarkings = useEffectEvent(() => {
    setMarkings(markings => {
      const newMap = new Map(markings);
      newMap.delete(index);

      return newMap;
    });
  });

  useEffect(() => {
    if (row.commitError) {
      addMarkings();
    }

    return () => {
      removeMarkings();
    };

    // Markings don't need to be updated when the function address changes...
  }, [row.commitError, index]);
}

export function TableRow({
  collection,
  index,
  columns,
  subject,
}: TableRowProps): JSX.Element {
  const resource = useMemberFromCollection(collection, index);

  useMarkings(resource, index);

  // `useMemberFromCollection` resets to `unknownSubject` and re-resolves
  // asynchronously any time its underlying query re-runs (e.g. the
  // collection re-deriving after a save touches this row) — not just on
  // first load. Falling through to the Loader branch on every one of those
  // unmounts every cell in the row, including whatever's open inside one
  // (a cell's edit popover, an open file picker) — the "save → re-fetch →
  // remount churn" TableNewRow's comment below already calls out for the
  // virtual-row case; this is the same failure mode for already-materialized
  // rows. Keep rendering the last-known-good subject through a transient
  // re-resolution; only show the Loader while this row has never resolved
  // *at this index* — a genuine reorder (index actually changes) still
  // falls through to the Loader rather than flashing the previous row's data.
  const lastKnownRef = useRef<{ index: number; subject: string } | undefined>(
    undefined,
  );

  if (resource.subject !== unknownSubject) {
    lastKnownRef.current = { index, subject: resource.subject };
  }

  const displaySubject =
    subject ??
    (lastKnownRef.current?.index === index
      ? lastKnownRef.current.subject
      : undefined);

  if (!displaySubject) {
    return (
      <>
        {columns.map((column, i) => (
          <Loader key={column.key} delay={i * 100} title='loading' />
        ))}
      </>
    );
  }

  return (
    <>
      {columns.map((column, cIndex) =>
        column.property ? (
          <TableCellMemo
            key={column.key}
            rowIndex={index}
            columnIndex={cIndex + 1}
            subject={displaySubject}
            property={column.property}
            languageTag={column.languageTag}
          />
        ) : column.virtual ? (
          // A column the view computes for itself — a duration, a row action.
          <column.virtual.Cell
            key={column.key}
            subject={displaySubject}
            rowIndex={index}
            columnIndex={cIndex + 1}
          />
        ) : null,
      )}
    </>
  );
}

type TableNewRowProps = Omit<TableRowProps, 'collection'> & {
  parent: Resource<DataBrowser.Table>;
  /** The draft row's subject, minted by the parent with `store.newResource`
   * (also this row's react-window key). Passed in — NOT minted here — so a
   * remount reuses the same draft instead of orphaning typed data. */
  subject: string;
  /** True for the bottom-most new row — the only one that spawns a fresh
   * trailing placeholder when it first gains content. */
  isLast: boolean;
  addNewRow: () => void;
  /** Fractional sibling-order key minted with the subject. Seeded into the
   * draft so the row's on-screen position persists when it materializes
   * (rows are server-sorted by `sortOrder`, falling back to `createdAt`). */
  sortOrder?: number;
};

const resourceOpts = {
  newResource: true,
};

export function TableNewRow({
  index,
  columns,
  parent,
  subject,
  isLast,
  addNewRow,
  sortOrder,
}: TableNewRowProps): JSX.Element {
  // A draft row: the parent minted it ahead of time with
  // `store.newResource({ deferGenesis: true })`, so it has its final subject
  // and is editable on first paint. Its genesis is not signed yet, so it stays
  // purely local (the Loro dirty subscriber skips resources that are still
  // `new`) and is saved when the user moves off it
  // (`useMaterializeWhenDeselected`). Saving keeps the subject, so the cells
  // never remount.
  const resource = useResource(subject, resourceOpts);

  const isDraft = useIsUnsavedDraft(resource);

  useMarkings(resource, index);
  useMaterializeWhenDeselected(resource, index);

  // Spawn a fresh trailing placeholder the first time *this* (bottom-most) row
  // gains real content, so there is always exactly one empty row at the bottom
  // to type into — without persisting anything. This is the SOLE spawn trigger:
  // because it keeps a trailing empty row present once content exists, Enter and
  // Tab navigation just move into the row that's already there (no spawning on
  // navigation). The old code got this for free because the first keystroke
  // saved the row (→ collection invalidate → a new `TableNewRow` rendered
  // below). Guarded by a ref so it fires once per row, and gated on `isLast`
  // (read fresh via a ref so the callback stays stable) so only the bottom row
  // spawns. After it fires, this row is no longer last.
  const spawnedRef = useRef(false);
  const isLastRef = useRef(isLast);
  isLastRef.current = isLast;
  const seededOrderRef = useRef(false);
  const handleFirstContent = useCallback(() => {
    // Stamp the minted `sortOrder` the moment the row gains content — NOT at
    // mount: an empty draft must hold only what creating it wrote, because
    // anything more is what the materialize/rebase/advance heuristics treat
    // as user content (`hasUserContent`).
    if (!seededOrderRef.current) {
      seededOrderRef.current = true;

      if (sortOrder !== undefined) {
        void resource.set(dataBrowser.properties.sortOrder, sortOrder, false);
      }

      // The table's row defaults (a Status of Todo, say), for whatever the
      // user has not filled in themselves.
      for (const [property, value] of Object.entries(
        withRowDefaults(parent, {}),
      )) {
        if (resource.get(property) === undefined) {
          void resource.set(property, value, false);
        }
      }
    }

    if (spawnedRef.current || !isLastRef.current) {
      return;
    }

    spawnedRef.current = true;
    addNewRow();
  }, [addNewRow, resource, sortOrder, parent]);

  return (
    <>
      {columns.map((column, cIndex) =>
        column.property ? (
          <TableCellMemo
            key={column.key}
            rowIndex={index}
            columnIndex={cIndex + 1}
            subject={subject}
            property={column.property}
            languageTag={column.languageTag}
            onFirstContent={handleFirstContent}
          />
        ) : column.virtual && !isDraft ? (
          // Saved while it still renders here, so it has a row to read.
          <column.virtual.Cell
            key={column.key}
            subject={subject}
            rowIndex={index}
            columnIndex={cIndex + 1}
          />
        ) : (
          // Virtual columns read from a saved row; an unsaved draft has
          // nothing for them to show yet. It still needs a cell: Tab out of the
          // last stored column lands here, and with no cell to take focus the
          // keyboard goes to <body>, the grid never sees the Escape, and the
          // row stays "in use" for good, so it is never saved.
          <Cell key={column.key} rowIndex={index} columnIndex={cIndex + 1} />
        ),
      )}
    </>
  );
}

const pulse = keyframes`
  from {
    background-color: var(--from-color);
  }

  to {
    background-color: var(--to-color);
  }
`;

interface LoaderProps {
  delay: number;
}

const Loader = styled.div<LoaderProps>`
  width: 100%;
  --from-color: ${p => p.theme.colors.bg};
  --to-color: ${p => p.theme.colors.bg1};
  animation: 0.8s ${p => p.delay}ms ease-in-out infinite alternate ${pulse};
`;
