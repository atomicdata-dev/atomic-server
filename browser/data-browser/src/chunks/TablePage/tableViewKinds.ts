import type { IconType } from 'react-icons';
import {
  FaTable,
  FaTableColumns,
  FaCalendarDays,
  FaStopwatch,
} from 'react-icons/fa6';

/**
 * The `view-kind` string stored on a View resource decides which renderer
 * displays the table's rows. Stored as a plain string in the ontology so new
 * kinds can be added without a schema migration; this union is the frontend's
 * source of truth for the ones we actually render.
 */
export const VIEW_KINDS = ['table', 'kanban', 'calendar', 'timer'] as const;

export type ViewKind = (typeof VIEW_KINDS)[number];

export const DEFAULT_VIEW_KIND: ViewKind = 'table';

/** Narrows an arbitrary stored string to a known ViewKind, falling back to table. */
export function normalizeViewKind(kind: string | undefined): ViewKind {
  return (VIEW_KINDS as readonly string[]).includes(kind ?? '')
    ? (kind as ViewKind)
    : DEFAULT_VIEW_KIND;
}

/**
 * The app rendering this view, when the stored kind names one.
 *
 * A view kind is either one of the built-ins above or the subject of an app,
 * told apart by shape — the same tell `/plugin-ui` uses. Kept out of
 * `ViewKind` deliberately: the built-ins are a closed set with labels and
 * icons compiled in, and apps are open-ended data. Folding them together
 * would mean every exhaustive match over kinds had a case that cannot be
 * written.
 *
 * A table always keeps its own Table tab, and an app is never made the
 * default view. Adding an app is adding a way to look at the rows, never
 * taking one away.
 */
export function appViewOf(kind: string | undefined): string | undefined {
  return kind?.includes(':') ? kind : undefined;
}

export const VIEW_KIND_LABELS: Record<ViewKind, string> = {
  table: 'Table',
  kanban: 'Kanban',
  calendar: 'Calendar',
  timer: 'Timer',
};

export const VIEW_KIND_ICONS: Record<ViewKind, IconType> = {
  table: FaTable,
  kanban: FaTableColumns,
  calendar: FaCalendarDays,
  timer: FaStopwatch,
};
