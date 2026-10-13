import {
  Collection,
  JSONValue,
  Property,
  Resource,
  core,
  dataBrowser,
  unknownSubject,
  useResource,
  useResources,
  useStore,
  useValue,
} from '@tomic/react';
import {
  DndContext,
  DragEndEvent,
  DragMoveEvent,
  DragOverlay,
  DragStartEvent,
  closestCenter,
} from '@dnd-kit/core';
import {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
} from 'react';
import { styled } from 'styled-components';
import { useDragSensors } from '@chunks/TableEditor/hooks/useDragSensors';
import { LoaderBlock } from '@components/Loader';
import { KanbanColumn, UNCATEGORIZED_COLUMN_ID } from './KanbanColumn';
import { KanbanCard } from './KanbanCard';
import { ExpandedRowDialog } from '../ExpandedRowDialog';
import { useKanbanGroupBy } from './useKanbanGroupBy';
import { DEFAULT_STATUS_TAGS } from './createSelectProperty';
import { TablePresenceContext } from '../TablePresence';
import { KanbanFlipContext, type CardFlipRecord } from './cardFlip';
import { computeSortOrder, readSortKey } from '@helpers/fractionalSortOrder';
import { setRowDefault } from '../rowDefaults';
import { useAllMembers } from '../helpers/useAllMembers';
import { useCreateRow } from '../helpers/useCreateRow';
import { optionSubjects, useColumnConstraint } from '../useColumnConstraint';

interface KanbanViewProps {
  /** The Table resource; new cards are created as its children. */
  tableSubject: string;
  tableClass: Resource;
  /** Every property of the class (used to find/adopt a group-by enum). */
  allColumns: Property[];
  /** The view's visible columns, in order (used for card field previews). */
  columns: Property[];
  collection: Collection;
  ready: boolean;
  viewGroupBy: string | undefined;
  setViewGroupBy: (property: string) => void;
  readOnly: boolean;
}

const MAX_CARD_FIELDS = 3;

export function KanbanView({
  tableSubject,
  tableClass,
  allColumns,
  columns,
  collection,
  ready,
  viewGroupBy,
  setViewGroupBy,
  readOnly,
}: KanbanViewProps): JSX.Element {
  const store = useStore();
  const sensors = useDragSensors();
  const table = useResource(tableSubject);

  // A Status column the board creates itself starts new rows in Todo, the same
  // as one a template sets up.
  const handleStatusCreated = useCallback(
    async (property: string, tagsByName: Record<string, string>) => {
      const todo = tagsByName[DEFAULT_STATUS_TAGS[0].name];

      if (todo) {
        await setRowDefault(table, property, [todo]);
      }
    },
    [table],
  );

  const { groupBy, status } = useKanbanGroupBy(
    tableClass,
    allColumns,
    viewGroupBy,
    setViewGroupBy,
    !readOnly,
    handleStatusCreated,
  );

  // The lane new rows start in, from whichever view they are added: the
  // table's default value for the group-by property. Read through `useValue`
  // so the star moves when the default changes; the Table resource object
  // itself stays the same.
  const [rowDefaults] = useValue(
    table,
    dataBrowser.properties.tableRowDefaults,
  );
  const defaultValue =
    groupBy && rowDefaults && typeof rowDefaults === 'object'
      ? (rowDefaults as Record<string, JSONValue>)[groupBy]
      : undefined;
  const defaultTag = Array.isArray(defaultValue)
    ? (defaultValue[0] as string | undefined)
    : undefined;

  const handleSetDefaultLane = useCallback(
    (tagSubject: string | undefined) => {
      if (!groupBy) {
        return;
      }

      void setRowDefault(
        table,
        groupBy,
        tagSubject ? [tagSubject] : undefined,
      ).catch(() => undefined);
    },
    [table, groupBy],
  );

  // All rows of the table, loaded up front so cards can be bucketed by their
  // group-by value (including the "no status" bucket, which the query index
  // can't express as an "is empty" filter).
  const memberSubjects = useAllMembers(collection);
  const rows = useResources(memberSubjects);

  const groupConstraint = useColumnConstraint(groupBy, tableClass.subject);
  // The constraint object is rebuilt every render, so key on its options.
  const optionsKey = JSON.stringify(optionSubjects(groupConstraint));
  const columnTags = useMemo(
    () => JSON.parse(optionsKey) as string[],
    [optionsKey],
  );

  // Bucket each row into its column by the first value of the group-by
  // property. Reactive: `useResources` re-snapshots when a card's status
  // changes (e.g. after a drag), so the buckets recompute.
  const buckets = useMemo(() => {
    const map = new Map<string, string[]>();
    map.set(UNCATEGORIZED_COLUMN_ID, []);

    for (const tag of columnTags) {
      map.set(tag, []);
    }

    if (!groupBy) {
      return map;
    }

    for (const subject of memberSubjects) {
      const resource = rows.get(subject);
      const value = resource?.get(groupBy) as string[] | undefined;
      const tag = value?.find(t => map.has(t));
      map.get(tag ?? UNCATEGORIZED_COLUMN_ID)?.push(subject);
    }

    // Order each column by the fractional `sortOrder` (createdAt fallback) so
    // a card dragged to a new vertical slot stays there — and reorders
    // reactively the moment `sortOrder` changes, without a re-fetch.
    for (const subjects of map.values()) {
      subjects.sort(
        (a, b) =>
          (readSortKey(rows.get(a)) ?? 0) - (readSortKey(rows.get(b)) ?? 0),
      );
    }

    return map;
  }, [columnTags, memberSubjects, rows, groupBy]);

  // Card preview fields: the view's columns minus the name (shown as the title)
  // and the group-by property (implied by the column), capped for density.
  const cardFields = useMemo(
    () =>
      columns
        .filter(
          c => c.subject !== core.properties.name && c.subject !== groupBy,
        )
        .slice(0, MAX_CARD_FIELDS),
    [columns, groupBy],
  );

  const [draggingSubject, setDraggingSubject] = useState<string>();
  // Live drag preview: the column→cards order with the dragged card moved to
  // where it would drop. Rendered instead of `buckets` while dragging, so the
  // cards visibly shift open a gap (animated by the FLIP hook). `null` when
  // not dragging.
  const [preview, setPreview] = useState<Map<string, string[]> | null>(null);

  // Presence: broadcast which card we're dragging so other sessions see
  // it pulse (hover is announced per card, in KanbanCard). Retract the
  // announcement when the board unmounts (e.g. a switch to grid view).
  const { setActiveCard } = useContext(TablePresenceContext);

  useEffect(() => () => setActiveCard(undefined), [setActiveCard]);

  // Last-commit card positions, for the FLIP move animation (see
  // `cardFlip.ts`). Board-wide so a card can animate across columns.
  const flipRegistry = useRef(new Map<string, CardFlipRecord>());

  // Open a card in the same modal the table's row-expand uses, rather than
  // navigating away to the full resource page.
  const [expandedSubject, setExpandedSubject] = useState<string>();
  const [showExpanded, setShowExpanded] = useState(false);

  const handleOpenCard = useCallback((subject: string) => {
    setExpandedSubject(subject);
    setShowExpanded(true);
  }, []);

  // Create a new card already assigned to a column: a row of the table's class
  // with its group-by property preset to that column's tag (empty for the
  // "No status" column, even when the table has a default lane). The table's
  // other row defaults apply (see `useCreateRow`).
  const createRow = useCreateRow(tableSubject, tableClass);
  const handleCreateCard = useCallback(
    async (tagSubject: string | undefined, name: string) => {
      const trimmed = name.trim();

      if (!trimmed) {
        return;
      }

      try {
        await createRow(
          trimmed,
          groupBy ? { [groupBy]: tagSubject ? [tagSubject] : null } : {},
        );
      } catch (error) {
        store.notifyError(error as Error);
      }
    },
    [createRow, store, groupBy],
  );

  const handleDragStart = useCallback(
    (event: DragStartEvent) => {
      setDraggingSubject(event.active.id as string);
      setActiveCard(event.active.id as string, true);
    },
    [setActiveCard],
  );

  // Rebuild the preview on EVERY pointer move (not just when the dnd-kit `over`
  // target changes — that stays fixed on the dragged card's own placeholder,
  // so `onDragOver` never fired for within-column nudges). The target column +
  // index come straight from the pointer and the live card rects, so it never
  // gets stuck and the very top/bottom are always reachable.
  const handleDragMove = useCallback(
    (event: DragMoveEvent) => {
      const activeId = event.active.id as string;
      const activator = event.activatorEvent as MouseEvent | TouchEvent;
      const start =
        'touches' in activator
          ? (activator.touches[0] ?? activator.changedTouches[0])
          : activator;

      if (!start) {
        return;
      }

      const x = start.clientX + event.delta.x;
      const y = start.clientY + event.delta.y;

      // The column under the pointer's X.
      const columnEls = Array.from(
        document.querySelectorAll<HTMLElement>('[data-kanban-column-id]'),
      );
      const columnEl = columnEls.find(el => {
        const r = el.getBoundingClientRect();

        return x >= r.left && x <= r.right;
      });

      if (!columnEl) {
        return;
      }

      const targetCol = columnEl.dataset.kanbanColumnId as string;

      // Insertion index: the first real card whose midline the pointer is above
      // (the dragged card's own placeholder is skipped), else the end.
      const cardEls = Array.from(
        columnEl.querySelectorAll<HTMLElement>('[data-kanban-card-subject]'),
      ).filter(el => el.dataset.kanbanCardSubject !== activeId);

      let index = cardEls.length;

      for (let i = 0; i < cardEls.length; i++) {
        const r = cardEls[i].getBoundingClientRect();

        if (y < r.top + r.height / 2) {
          index = i;
          break;
        }
      }

      setPreview(prev => {
        const next = new Map<string, string[]>();

        for (const [col, subs] of prev ?? buckets) {
          next.set(
            col,
            subs.filter(s => s !== activeId),
          );
        }

        const list = next.get(targetCol) ?? [];
        list.splice(index, 0, activeId);
        next.set(targetCol, list);

        // Skip the state update when the order is unchanged — most moves stay
        // within a slot, and churning the preview would re-render for nothing.
        if (prev) {
          let same = true;

          for (const [col, subs] of next) {
            const before = prev.get(col) ?? [];

            if (
              before.length !== subs.length ||
              !subs.every((s, i) => s === before[i])
            ) {
              same = false;
              break;
            }
          }

          if (same) {
            return prev;
          }
        }

        return next;
      });
    },
    [buckets],
  );

  const handleDragEnd = useCallback(
    (event: DragEndEvent) => {
      const activeId = event.active.id as string;
      const finalPreview = preview;
      setDraggingSubject(undefined);
      setActiveCard(undefined);

      if (!finalPreview || !groupBy) {
        setPreview(null);

        return;
      }

      // Persist from where the placeholder actually sits in the preview — at
      // drop time the pointer is usually over the placeholder itself, so
      // re-reading `event.over` would be ambiguous.
      let targetColumnId: string | undefined;
      let index = -1;

      for (const [col, subs] of finalPreview) {
        const i = subs.indexOf(activeId);

        if (i !== -1) {
          targetColumnId = col;
          index = i;
          break;
        }
      }

      if (targetColumnId === undefined) {
        setPreview(null);

        return;
      }

      let currentColumnId = UNCATEGORIZED_COLUMN_ID;

      for (const [col, subs] of buckets) {
        if (subs.includes(activeId)) {
          currentColumnId = col;
          break;
        }
      }

      const columnChanged = currentColumnId !== targetColumnId;
      const list = finalPreview.get(targetColumnId) ?? [];
      const prevSubject = list[index - 1];
      const nextSubject = list[index + 1];

      // No-op: same column, same neighbours as before the drag.
      if (!columnChanged) {
        const base = buckets.get(currentColumnId) ?? [];
        const baseIndex = base.indexOf(activeId);

        if (
          base[baseIndex - 1] === prevSubject &&
          base[baseIndex + 1] === nextSubject
        ) {
          setPreview(null);

          return;
        }
      }

      // Keep the preview rendered past the drop — clearing it now would flash
      // the card back to its old slot (and re-run the FLIP move animation)
      // until the async save re-sorts the buckets. The effect below drops the
      // preview once the persisted order has caught up, so the card just
      // stays put.

      const targetTag =
        targetColumnId === UNCATEGORIZED_COLUMN_ID ? undefined : targetColumnId;
      const newSortOrder = computeSortOrder(
        readSortKey(rows.get(prevSubject)),
        readSortKey(rows.get(nextSubject)),
      );
      const resource = store.getResourceLoading(activeId);

      void (async () => {
        await resource.set(
          dataBrowser.properties.sortOrder,
          newSortOrder,
          false,
        );

        if (columnChanged) {
          await resource.set(groupBy, targetTag ? [targetTag] : []);
        }

        await resource.save();
      })().catch(() => undefined);
    },
    [preview, groupBy, store, setActiveCard, buckets, rows],
  );

  const handleDragCancel = useCallback(() => {
    setDraggingSubject(undefined);
    setActiveCard(undefined);
    setPreview(null);
  }, [setActiveCard]);

  // After a drop, hold the preview until the real (sortOrder-derived) buckets
  // match it, then drop it — a seamless handoff with no flash-back and no
  // second FLIP animation. A short timeout guards against the order never
  // converging (e.g. a concurrent edit shifted the base while we dragged).
  useEffect(() => {
    if (!preview || draggingSubject) {
      return;
    }

    const matches = [...preview.entries()].every(([col, subs]) => {
      const base = buckets.get(col) ?? [];

      return subs.length === base.length && subs.every((s, i) => s === base[i]);
    });

    if (matches) {
      setPreview(null);

      return;
    }

    const timer = window.setTimeout(() => setPreview(null), 600);

    return () => window.clearTimeout(timer);
  }, [preview, draggingSubject, buckets]);

  if (status === 'creating' || (!ready && memberSubjects.length === 0)) {
    return (
      <Center>
        <LoaderBlock />
      </Center>
    );
  }

  if (status === 'resolving') {
    return <Center>Setting up the board…</Center>;
  }

  // Hide the "No status" column when it's empty — but keep it around for the
  // duration of any drag, so a card can still be dropped there to clear its
  // status. It reappears the moment a row loses its tag.
  const showUncategorized =
    (buckets.get(UNCATEGORIZED_COLUMN_ID)?.length ?? 0) > 0 ||
    !!draggingSubject;
  const columnIds = [
    ...columnTags,
    ...(showUncategorized ? [UNCATEGORIZED_COLUMN_ID] : []),
  ];
  // While dragging, render the preview order; the column holding the dragged
  // card is the drop target (highlighted).
  const displayBuckets = preview ?? buckets;
  const dropTargetColumn =
    preview && draggingSubject
      ? columnIds.find(id => preview.get(id)?.includes(draggingSubject))
      : undefined;

  return (
    <>
      <DndContext
        sensors={sensors}
        // The reorder is driven by `onDragMove` reading the pointer + live card
        // rects, so dnd-kit's own collision result is unused — `closestCenter`
        // is just a cheap default.
        collisionDetection={closestCenter}
        onDragStart={handleDragStart}
        onDragMove={handleDragMove}
        onDragEnd={handleDragEnd}
        onDragCancel={handleDragCancel}
      >
        <KanbanFlipContext value={flipRegistry}>
          <Board data-testid='kanban-board'>
            {columnIds.map(columnId => {
              const isUncategorized = columnId === UNCATEGORIZED_COLUMN_ID;

              return (
                <KanbanColumn
                  key={columnId}
                  columnId={columnId}
                  tagSubject={isUncategorized ? undefined : columnId}
                  cardSubjects={displayBuckets.get(columnId) ?? []}
                  fields={cardFields}
                  rowName={tableClass.title || 'Row'}
                  readOnly={readOnly}
                  isDropTarget={columnId === dropTargetColumn}
                  isDefault={!isUncategorized && columnId === defaultTag}
                  onSetDefault={
                    isUncategorized
                      ? undefined
                      : isDefault =>
                          handleSetDefaultLane(isDefault ? columnId : undefined)
                  }
                  onAddCard={name =>
                    handleCreateCard(
                      isUncategorized ? undefined : columnId,
                      name,
                    )
                  }
                  onOpenCard={handleOpenCard}
                />
              );
            })}
          </Board>
        </KanbanFlipContext>
        {/* No overlay drop animation — the CARD animates instead: on drop it
         * re-renders in its new column and the FLIP hook glides it over from
         * the source slot (see cardFlip.ts). Animating the overlay too would
         * double the motion. */}
        <DragOverlay dropAnimation={null}>
          {draggingSubject ? (
            <KanbanCard
              subject={draggingSubject}
              fields={cardFields}
              readOnly
            />
          ) : null}
        </DragOverlay>
      </DndContext>
      <ExpandedRowDialog
        subject={expandedSubject ?? unknownSubject}
        open={showExpanded}
        bindOpen={setShowExpanded}
      />
    </>
  );
}

const Board = styled.div`
  display: flex;
  gap: 1rem;
  /* Stretch columns to the board's full height so each column's own card list
   * is the scroll region — the column header stays pinned above it. */
  align-items: stretch;
  overflow-x: auto;
  /* Never scroll the board vertically; the per-column card lists do that. This
   * is what keeps the column headers visible while dragging a card downward. */
  overflow-y: hidden;
  /* Bleed past the page container's inline padding so the horizontal scroll
   * region spans the full width — cards reach the true edge instead of being
   * clipped inside the padding. The matching inline padding re-insets the
   * columns so they stay aligned with the page title above. */
  margin-inline: calc(-1 * ${p => p.theme.size()});
  padding: 1rem ${p => p.theme.size()};
  /* Fill the viewport below the title + view tabs, capped so a tall board still
   * leaves the page chrome visible. Mirrors FancyTable's bounded-height model. */
  height: min(80vh, calc(100dvh - 13rem));
  min-height: 18rem;
`;

const Center = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 2rem;
  color: ${p => p.theme.colors.textLight};
`;
