import { Datatype, JSONValue } from '@tomic/react';
import { CellAlign } from '@chunks/TableEditor/Cell';
import { AtomicURLCell } from './EditorCells/AtomicURLCell';
import { BooleanCell } from './EditorCells/BooleanCell';
import { DateCell } from './EditorCells/DateCell';
import { DateTimeCell } from './EditorCells/DateTimeCell';
import { FloatCell } from './EditorCells/FloatCell';
import { IntegerCell } from './EditorCells/IntegerCell';
import { ResourceArrayCell } from './EditorCells/ResourceArrayCell';
import { SlugCell } from './EditorCells/SlugCell';
import { StringCell } from './EditorCells/StringCell';
import { CellContainer } from './EditorCells/Type';
import { URICell } from './EditorCells/URICell';
import { parseFloatText, parseInteger } from './EditorCells/numberInput';
import { UNPARSED } from './EditorCells/useCommittedText';
import { MarkdownCell } from './EditorCells/MarkdownCell';
import { JSONCell } from './EditorCells/JSONCell';
import { LocalizedTextCell } from './EditorCells/LocalizedTextCell';

export const dataTypeCellMap = new Map<Datatype, CellContainer<JSONValue>>([
  [Datatype.STRING, StringCell],
  [Datatype.SLUG, SlugCell],
  [Datatype.MARKDOWN, MarkdownCell],
  [Datatype.URI, URICell],
  [Datatype.ATOMIC_URL, AtomicURLCell],
  [Datatype.RESOURCEARRAY, ResourceArrayCell],
  [Datatype.INTEGER, IntegerCell],
  [Datatype.FLOAT, FloatCell],
  [Datatype.BOOLEAN, BooleanCell],
  [Datatype.TIMESTAMP, DateTimeCell],
  [Datatype.DATE, DateCell],
  [Datatype.JSON, JSONCell],
  [Datatype.LOCALIZEDTEXT, LocalizedTextCell],
]);

export const dataTypeAlignmentMap = new Map<string, CellAlign>([
  [Datatype.INTEGER, CellAlign.End],
  [Datatype.FLOAT, CellAlign.End],
  [Datatype.DATE, CellAlign.End],
]);

const isURL = (value: string) => {
  try {
    new URL(value);

    return true;
  } catch {
    return false;
  }
};

export function appendStringToType<T extends JSONValue>(
  value: JSONValue,
  append: string,
  dataType: Datatype,
): T {
  const val = value ?? '';

  switch (dataType) {
    case Datatype.SLUG:
      // As the slug editor stores it: lower case, no whitespace.
      return `${val}${append}`.toLowerCase().replace(/\s/g, '-') as T;
    case Datatype.STRING:
    case Datatype.MARKDOWN:
    case Datatype.URI:
      return `${val}${append}` as T;

    // Text that is not a number keeps the value, never NaN (#1825).
    case Datatype.INTEGER: {
      const parsed = parseInteger(`${val}${append}`);

      return (parsed === UNPARSED ? value : parsed) as T;
    }

    case Datatype.FLOAT: {
      const parsed = parseFloatText(`${val}${append}`);

      return (parsed === UNPARSED ? value : parsed) as T;
    }

    case Datatype.ATOMIC_URL:
      if (isURL(append)) {
        return append as T;
      }

      return value as T;

    case Datatype.TIMESTAMP:
      if (!Number.isNaN(Number.parseInt(append, 10))) {
        const result = Number.parseInt(append, 10) as T;

        return result;
      }

      return value as T;

    case Datatype.DATE:
      if (/^\d{4}-\d{2}-\d{2}/.test(append)) {
        return append as T;
      }

      return value as T;

    case Datatype.RESOURCEARRAY: {
      const values = append.split(',');

      if (values.every(isURL)) {
        return values as T;
      }

      return value as T;
    }

    case Datatype.BOOLEAN:
      if (append === 'true' || append === 'false') {
        return (append === 'true') as T;
      }

      return undefined as T;

    default:
      return value as T;
  }
}

export type PasteValue =
  | { action: 'set'; value: JSONValue }
  | { action: 'clear' }
  | { action: 'skip' };

/**
 * What pasting `data` into a column of `datatype` should do. A value the type
 * can read is set. An empty clipboard cell clears the property. Text the type
 * cannot read is skipped, so a stray character never wipes a stored value.
 * `Resource.set` throws for `undefined`, so none of these is ever
 * `set(prop, undefined)`.
 */
export function resolvePasteValue(
  data: string,
  datatype: Datatype,
): PasteValue {
  const value = appendStringToType(undefined, data, datatype);

  if (value !== undefined) {
    return { action: 'set', value };
  }

  return data.trim() === '' ? { action: 'clear' } : { action: 'skip' };
}
