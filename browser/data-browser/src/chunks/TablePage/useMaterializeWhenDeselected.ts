import { Resource, useStore } from '@tomic/react';
import { useEffect, useMemo } from 'react';
import {
  CursorMode,
  useTableEditorContext,
} from '@chunks/TableEditor/TableEditorContext';

/** Delay before persisting a row the user has moved off of *while still
 * editing the table* (moved to another row, Edit mode still on). A short
 * debounce coalesces the burst of deselects during rapid Enter-Enter entry and
 * keeps each save out of the keystroke path. */
const MATERIALIZE_DEBOUNCE = 50;

/** Delay before persisting when the user has *left Edit mode* entirely (Escape
 * / click-away). This is the calm "I'm done" signal — there is no entry storm
 * to coalesce, and the last row (never deselected) must be saved promptly so a
 * follow-up "is everything synced?" check doesn't race ahead of it. A
 * microtask (delay 0) starts the save before the next poll/paint while still
 * running outside React's render cycle. */
const MATERIALIZE_FLUSH = 0;

/**
 * Materialize a virtual (`_new:`) row a short while after the user moves off
 * it.
 *
 * New rows are held purely locally while the user types ({@link TableNewRow}
 * renders a `_new:` resource and {@link TableCell} never persists it) — no
 * commit, no re-fetch, no remount reaches the cell mid-entry, which is what
 * makes rapid row entry stable. Once the active cell has been on a *different*
 * row for {@link MATERIALIZE_DEBOUNCE}ms, the row is saved: that signs its
 * genesis commit and renames `_new:` → `did:ad:` (the store keeps an alias so
 * the still-mounted `TableNewRow` resolves the same resource — it does not flip
 * to a collection member, see `TableResource`).
 *
 * The row is considered "in use" only while it is BOTH the selected row AND
 * the table is in Edit mode; otherwise the debounce timer runs. So a row
 * materializes when the user moves to another row (deselect) *or* leaves Edit
 * mode on it (the final Escape / click-away) — the latter is what persists the
 * last row, which is never deselected. A transient Edit→Visual→Edit blip (e.g.
 * the tag picker's Escape) is shorter than the debounce, so the timer is
 * cancelled before it fires and the active row is left undisturbed.
 *
 * Two properties make this safe under rapid entry:
 *  - The "in use" guard keeps the row the user is actively editing virtual.
 *  - The save is **deferred** (debounced via `setTimeout`), so it runs in its
 *    own macrotask well outside React's render/commit cycle. Calling `save()`
 *    synchronously from the effect lets its store mutations + notify cascade
 *    re-enter an in-progress render ("setState while rendering" → runaway
 *    recursion that crashes the tab). The timer also coalesces the burst of
 *    deselects during fast entry into far fewer signs.
 *
 * @param resource The row's virtual resource.
 * @param index    This row's grid index (matches the editor's `selectedRow`).
 */
export function useMaterializeWhenDeselected(
  resource: Resource,
  index: number,
): void {
  const { selectedRow, cursorMode } = useTableEditorContext();
  const store = useStore();
  const scheduler = useMemo(
    () =>
      store.createSaveScheduler(resource, {
        shouldSave: () =>
          resource.subject.startsWith('_new:') &&
          resource.getEntries().length > 2,
        onError: () => undefined,
      }),
    [store, resource],
  );

  // Flush before the following effect cancels its slot on unmount. Virtualized
  // rows can leave the screen while their last edit exists only in memory.
  useEffect(
    () => () => {
      void scheduler.flush();
    },
    [scheduler],
  );
  useEffect(() => {
    if (selectedRow === index && cursorMode === CursorMode.Edit) {
      scheduler.cancel();

      return;
    }

    scheduler.schedule(
      cursorMode === CursorMode.Edit ? MATERIALIZE_DEBOUNCE : MATERIALIZE_FLUSH,
    );

    return () => scheduler.cancel();
  }, [selectedRow, cursorMode, index, scheduler]);
}
