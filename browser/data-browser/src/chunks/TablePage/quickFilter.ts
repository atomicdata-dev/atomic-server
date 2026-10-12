import {
  Datatype,
  localizeText,
  urls,
  type JSONValue,
  type LocalizedText,
} from '@tomic/react';
import { formatDate } from '@helpers/dates/formatDate';
import { calendarDateToLocalDate } from '@helpers/dates/calendarDate';
import { markdownToPlainText } from '@helpers/markdown';
import { formatNumber } from './helpers/formatNumber';

/**
 * The quick filter: one text field that keeps the rows where any visible
 * column *shows* that text. It matches what a person reads in the cell, not
 * what is stored — a date as it is formatted, a reference by its title — so it
 * answers "where is the row that says X", which the per-column filters (exact
 * stored values, one column at a time) do not.
 *
 * It narrows the rows the view already has (after its column filters, in its
 * sort order) on the client, and is not stored on the View: it resets when you
 * switch views or leave the table.
 */

/** What a column needs to be rendered as text, read once per column. */
export interface QuickFilterColumn {
  property: string;
  datatype: Datatype;
  /** The column heading. A ticked checkbox reads as this. */
  label: string;
  /** A split LocalizedText column shows exactly this language. */
  languageTag?: string;
  /** `constraints.dateFormat`; the numeric local format when unset. */
  dateFormat?: string;
  /** `constraints.numberFormatting` (percentage, currency). */
  numberFormatting?: string;
  decimalPlaces?: number;
  currency?: string;
}

export interface QuickFilterContext {
  /**
   * The title a reference shows (name, shortname, filename, else the subject),
   * or undefined while it has not loaded.
   */
  titleOf: (subject: string) => string | undefined;
  /** The app's content language, for an unsplit LocalizedText column. */
  contentLanguage: string;
}

/** The query as it is compared: trimmed and lower-cased. Empty = no filter. */
export function normalizeQuickFilter(query: string): string {
  return query.trim().toLocaleLowerCase();
}

const isNumber = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value);

/**
 * The texts one cell shows, per datatype. More than one when a cell has several
 * items (a multi-value reference) or reads two ways (a number as formatted and
 * as typed).
 */
export function cellTexts(
  value: JSONValue,
  column: QuickFilterColumn,
  context: QuickFilterContext,
): string[] {
  if (value === undefined || value === null || value === '') {
    return [];
  }

  switch (column.datatype) {
    case Datatype.MARKDOWN:
      // The cell shows the source; plain text also lets "a b" find "a **b**".
      return typeof value === 'string'
        ? [value, markdownToPlainText(value)]
        : [];

    case Datatype.INTEGER:

    case Datatype.FLOAT: {
      if (!isNumber(value)) {
        return [String(value)];
      }

      const shown = formatNumber(
        value,
        column.datatype === Datatype.INTEGER ? 0 : column.decimalPlaces,
        column.numberFormatting,
        column.currency,
      );

      // As shown ("1,234.5", "€ 12.00", "40%"), and as typed ("1234.5"), since
      // nobody types the grouping separator when looking for a number.
      return [shown, String(value)];
    }

    case Datatype.DATE: {
      const date = calendarDateToLocalDate(value);

      return date
        ? [formatDate(dateFormatOf(column), date, false)]
        : [String(value)];
    }

    case Datatype.TIMESTAMP:
      return isNumber(value)
        ? [formatDate(dateFormatOf(column), new Date(value), true)]
        : [];

    case Datatype.BOOLEAN:
      // The cell is a checkbox with no text of its own. A ticked one reads as
      // its column — "done" finds the done rows; an unticked one says nothing.
      return value === true ? [column.label] : [];

    case Datatype.ATOMIC_URL:
      return typeof value === 'string' ? titles([value], context) : [];

    case Datatype.RESOURCEARRAY:
      return Array.isArray(value)
        ? titles(
            value.filter((v): v is string => typeof v === 'string'),
            context,
          )
        : [];

    case Datatype.LOCALIZEDTEXT: {
      if (typeof value !== 'object' || Array.isArray(value)) {
        return [];
      }

      const localized = value as LocalizedText;
      const text =
        column.languageTag !== undefined
          ? localized[column.languageTag]
          : localizeText(localized, context.contentLanguage);

      return text ? [text] : [];
    }

    case Datatype.JSON:
      return [JSON.stringify(value)];

    default:
      // String, slug, URI and anything unknown: the text itself.
      return typeof value === 'object'
        ? [JSON.stringify(value)]
        : [String(value)];
  }
}

function dateFormatOf(column: QuickFilterColumn): string {
  return column.dateFormat ?? urls.instances.dateFormats.localNumeric;
}

function titles(subjects: string[], context: QuickFilterContext): string[] {
  return subjects.map(subject => context.titleOf(subject) ?? subject);
}

/** Anything that hands out a row's stored values, like a `Resource`. */
export interface QuickFilterRow {
  get(property: string): JSONValue;
}

/**
 * True when any of the columns shows `query` in this row. `query` must already
 * be normalized; an empty one matches every row.
 */
export function rowMatchesQuickFilter(
  row: QuickFilterRow,
  columns: QuickFilterColumn[],
  query: string,
  context: QuickFilterContext,
): boolean {
  if (query === '') {
    return true;
  }

  return columns.some(column =>
    cellTexts(row.get(column.property), column, context).some(text =>
      text.toLocaleLowerCase().includes(query),
    ),
  );
}

/** Joins a row's cells: a character nobody types, so no match spans two cells. */
const CELL_SEPARATOR = '\u0000';

/**
 * Everything a row shows in these columns, lower-cased, as one string to
 * search. Built once per row and reused for every keystroke: formatting dates
 * and numbers is the expensive part, a substring search is not.
 */
export function rowSearchText(
  row: QuickFilterRow,
  columns: QuickFilterColumn[],
  context: QuickFilterContext,
): string {
  return columns
    .flatMap(column => cellTexts(row.get(column.property), column, context))
    .join(CELL_SEPARATOR)
    .toLocaleLowerCase();
}

/**
 * The subjects whose search text contains the query, in the order given — the
 * view's own order, so sorting keeps working under the quick filter. A row with
 * no text (not loaded yet) is left out.
 */
export function filterSubjectsBySearchText(
  subjects: string[],
  textOf: (subject: string) => string | undefined,
  query: string,
): string[] {
  const normalized = normalizeQuickFilter(query);

  if (normalized === '') {
    return subjects;
  }

  return subjects.filter(subject => textOf(subject)?.includes(normalized));
}

/** {@link filterSubjectsBySearchText}, straight from the rows. */
export function filterSubjectsByQuickFilter(
  subjects: string[],
  rowOf: (subject: string) => QuickFilterRow | undefined,
  columns: QuickFilterColumn[],
  query: string,
  context: QuickFilterContext,
): string[] {
  return filterSubjectsBySearchText(
    subjects,
    subject => {
      const row = rowOf(subject);

      return row && rowSearchText(row, columns, context);
    },
    query,
  );
}

/** The references a row's columns show, whose titles have to be loaded. */
export function referencedSubjects(
  rows: Iterable<QuickFilterRow>,
  columns: QuickFilterColumn[],
): string[] {
  const referenceColumns = columns.filter(
    c =>
      c.datatype === Datatype.ATOMIC_URL ||
      c.datatype === Datatype.RESOURCEARRAY,
  );
  const found = new Set<string>();

  if (referenceColumns.length === 0) {
    return [];
  }

  for (const row of rows) {
    for (const column of referenceColumns) {
      const value = row.get(column.property);

      if (typeof value === 'string') {
        found.add(value);
      } else if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') {
            found.add(item);
          }
        }
      }
    }
  }

  return [...found];
}
