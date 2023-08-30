import { Client, JSONValue, urls } from './index.js';

/** Each possible Atomic Datatype. See https://atomicdata.dev/collections/datatype */
// TODO: use strings from `./urls`, requires TS fix: https://github.com/microsoft/TypeScript/issues/40793
export enum Datatype {
  /** A Resource - either a URL string or a Nested Resource */
  ATOMIC_URL = 'https://atomicdata.dev/datatypes/atomicURL',
  /** True / false */
  BOOLEAN = 'https://atomicdata.dev/datatypes/boolean',
  /** ISO date YYYY-MM-DD */
  DATE = 'https://atomicdata.dev/datatypes/date',
  /** Floating point number (number with comma) */
  FLOAT = 'https://atomicdata.dev/datatypes/float',
  INTEGER = 'https://atomicdata.dev/datatypes/integer',
  /** UTF-8 Markdown string */
  MARKDOWN = 'https://atomicdata.dev/datatypes/markdown',
  /** Array of Resources and */
  RESOURCEARRAY = 'https://atomicdata.dev/datatypes/resourceArray',
  /** String with only letters, numbers and dashes in between */
  SLUG = 'https://atomicdata.dev/datatypes/slug',
  STRING = 'https://atomicdata.dev/datatypes/string',
  /** Milliseconds since unix epoch */
  TIMESTAMP = 'https://atomicdata.dev/datatypes/timestamp',
  UNKNOWN = 'unknown-datatype',
}

/** Convert a URL to a Datatype */
export const datatypeFromUrl = (url: string): Datatype => {
  switch (url) {
    case urls.datatypes.atomicUrl: {
      return Datatype.ATOMIC_URL;
    }

    case urls.datatypes.boolean: {
      return Datatype.BOOLEAN;
    }

    case urls.datatypes.date: {
      return Datatype.DATE;
    }

    case urls.datatypes.float: {
      return Datatype.FLOAT;
    }

    case urls.datatypes.integer: {
      return Datatype.INTEGER;
    }

    case urls.datatypes.markdown: {
      return Datatype.MARKDOWN;
    }

    case urls.datatypes.resourceArray: {
      return Datatype.RESOURCEARRAY;
    }

    case urls.datatypes.slug: {
      return Datatype.SLUG;
    }

    case urls.datatypes.string: {
      return Datatype.STRING;
    }

    case urls.datatypes.timestamp: {
      return Datatype.TIMESTAMP;
    }

    default: {
      return Datatype.UNKNOWN;
    }
  }
};

const slug_regex = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
// https://stackoverflow.com/a/22061879/2502163
const dateStringRegex = /^\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])$/;

export interface ArrayError extends Error {
  index?: number;
}

/** Validates a JSON Value using a Datatype. Throws an error if things are wrong. */
export const validateDatatype = (
  value: JSONValue,
  datatype: Datatype,
): void => {
  let err: null | string = null;

  if (value === undefined) {
    throw new Error(`Value is undefined, expected ${datatype}`);
  }

  switch (datatype) {
    case Datatype.STRING: {
      if (!isString(value)) {
        err = 'Not a string';
        break;
      }

      break;
    }

    case Datatype.SLUG: {
      if (!isString(value)) {
        err = 'Not a slug, not even a string';
        break;
      }

      if (value.match(slug_regex) === null) {
        err =
          'Not a valid slug. Only lowercase letters and numbers with dashes `-` between them';
      }

      break;
    }

    case Datatype.ATOMIC_URL: {
      if (!isString(value)) {
        err = 'Not a string. Should be a URL';
        break;
      }

      Client.tryValidSubject(value);
      break;
    }

    case Datatype.RESOURCEARRAY: {
      if (!isArray(value)) {
        err = 'Not an array';
        break;
      }

      value.map((item, index) => {
        try {
          Client.tryValidSubject(item);
        } catch (e) {
          const arrError: ArrayError = new Error(`Invalid URL`);
          arrError.index = index;
          throw arrError;
        }
      });
      break;
    }

    case Datatype.INTEGER: {
      if (!isNumber(value)) {
        err = 'Not a number';
        break;
      }

      if (value % 1 !== 0) {
        err = 'Not an integer';
      }

      break;
    }

    case Datatype.DATE: {
      if (!isString(value)) {
        err = 'Not a string';
        break;
      }

      if (value.match(dateStringRegex) === null) {
        err = 'Not a date string: YYYY-MM-DD';
      }

      break;
    }
  }

  if (err !== null) {
    throw new Error(err);
  }
};

export function isArray(val: JSONValue): val is [] {
  return Object.prototype.toString.call(val) === '[object Array]';
}

export function isString(val: JSONValue): val is string {
  return typeof val === 'string';
}

export function isNumber(val: JSONValue): val is number {
  return typeof val === 'number';
}

export const reverseDatatypeMapping = {
  [Datatype.STRING]: 'String',
  [Datatype.SLUG]: 'Slug',
  [Datatype.MARKDOWN]: 'Markdown',
  [Datatype.INTEGER]: 'Integer',
  [Datatype.FLOAT]: 'Float',
  [Datatype.BOOLEAN]: 'Boolean',
  [Datatype.DATE]: 'Date',
  [Datatype.TIMESTAMP]: 'Timestamp',
  [Datatype.ATOMIC_URL]: 'Resource',
  [Datatype.RESOURCEARRAY]: 'ResourceArray',
  [Datatype.UNKNOWN]: 'Unknown',
};
