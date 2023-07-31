import { Datatype, JSONValue } from '@tomic/react';
import type { IconType } from 'react-icons';
import {
  FaCalendar,
  FaCheckSquare,
  FaClock,
  FaExternalLinkAlt,
  FaFont,
  FaHashtag,
  FaListUl,
  FaMarkdown,
} from 'react-icons/fa';
import { CellAlign } from '../../components/TableEditor/Cell';
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

export const dataTypeIconMap = new Map<string, IconType>([
  [Datatype.STRING, FaFont],
  [Datatype.SLUG, FaFont],
  [Datatype.MARKDOWN, FaMarkdown],
  [Datatype.ATOMIC_URL, FaExternalLinkAlt],
  [Datatype.INTEGER, FaHashtag],
  [Datatype.FLOAT, FaHashtag],
  [Datatype.RESOURCEARRAY, FaListUl],
  [Datatype.BOOLEAN, FaCheckSquare],
  [Datatype.DATE, FaCalendar],
  [Datatype.TIMESTAMP, FaClock],
]);

export const dataTypeCellMap = new Map<Datatype, CellContainer<JSONValue>>([
  [Datatype.STRING, StringCell],
  [Datatype.SLUG, SlugCell],
  [Datatype.ATOMIC_URL, AtomicURLCell],
  [Datatype.RESOURCEARRAY, ResourceArrayCell],
  [Datatype.INTEGER, IntegerCell],
  [Datatype.FLOAT, FloatCell],
  [Datatype.BOOLEAN, BooleanCell],
  [Datatype.TIMESTAMP, DateTimeCell],
  [Datatype.DATE, DateCell],
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
    case Datatype.STRING:
    case Datatype.SLUG:
    case Datatype.MARKDOWN:
      return `${val}${append}` as T;
    case Datatype.INTEGER:
      return Number.parseInt(
        `${val}${Number.isNaN(Number.parseInt(append)) ? '' : append}`,
      ) as T;
    case Datatype.FLOAT:
      return Number.parseFloat(
        `${val}${Number.isNaN(Number.parseFloat(append)) ? '' : append}`,
      ) as T;
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
