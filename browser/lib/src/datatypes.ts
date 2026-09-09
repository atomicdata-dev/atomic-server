/** Each possible Atomic Datatype. See https://atomicdata.dev/collections/datatype */

import { Client } from './client.js';
import type { AtomicValue } from './value.js';
import { isSafeHref } from './safeHref.js';

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
  /** JSON object */
  JSON = 'https://atomicdata.dev/datatypes/json',
  /** URI */
  URI = 'https://atomicdata.dev/datatypes/uri',
  LORODOC = 'https://atomicdata.dev/datatypes/lorodoc',
  /** Translated strings: a JSON object of BCP 47 language tag -> string */
  LOCALIZEDTEXT = 'https://atomicdata.dev/datatypes/localizedText',
  UNKNOWN = 'unknown-datatype',
}

/** A LocalizedText value: translated strings keyed by BCP 47 language tag */
export type LocalizedText = Record<string, string>;

/** Permissive BCP 47 shape check, mirroring Rust `LANG_TAG_REGEX` */
export const langTagRegex = /^[a-zA-Z]{2,8}(-[a-zA-Z0-9]{1,8})*$/;

const validDatatypes = Object.values(Datatype) as string[];

/** Convert a URL to a Datatype */
export const datatypeFromUrl = (url: string): Datatype => {
  if (validDatatypes.includes(url)) {
    return url as Datatype;
  }

  return Datatype.UNKNOWN;
};

/**
 * The sibling `datatypes` Loro-map tag for a property, mirroring the Rust
 * `datatype_tag` (`lib/src/loro.rs`). Lets the server materialize a value to
 * the exact `Value` variant instead of guessing from the primitive.
 *
 * Tagged: the load-bearing reference / array distinctions (which the server
 * cannot recover from the bare primitive) plus the cosmetic string-likes
 * (markdown/slug/date/uri) and timestamp — at least vector/search text
 * extraction branches on `Value::Markdown`, so we preserve the variant rather
 * than let the server guess. Plain string and scalars stay untagged (the
 * default). A nested resource (an object stored as a JSON string under an
 * `atomicURL` property) is left untagged for the server's heuristic — see
 * `planning/loro-source-of-truth.md`.
 *
 * `loroValue` is the value as stored in the Loro `properties` map.
 */
export const datatypeTag = (
  datatype: string,
  loroValue: unknown,
): string | undefined => {
  switch (datatype) {
    case Datatype.ATOMIC_URL:
      return typeof loroValue === 'string' && !loroValue.startsWith('{')
        ? 'atomicUrl'
        : undefined;
    case Datatype.RESOURCEARRAY:
      return 'resourceArray';
    case Datatype.JSON:
      return 'json';
    case Datatype.MARKDOWN:
      return 'markdown';
    case Datatype.SLUG:
      return 'slug';
    case Datatype.URI:
      return 'uri';
    case Datatype.DATE:
      return 'date';
    case Datatype.TIMESTAMP:
      return 'timestamp';
    case Datatype.LOCALIZEDTEXT:
      return 'localizedText';
    default:
      return undefined;
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
  value: AtomicValue,
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

    case Datatype.MARKDOWN: {
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
      if (!Array.isArray(value)) {
        err = 'Not an array';
        break;
      }

      value.map((item, index) => {
        try {
          Client.tryValidSubject(item as string);
        } catch (e) {
          const cause = e instanceof Error ? e.message : String(e);
          const arrError: ArrayError = new Error(
            `Invalid URL at [${index}] (${JSON.stringify(item)}): ${cause}`,
          );
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

    case Datatype.FLOAT: {
      if (!isNumber(value)) {
        err = 'Not a number';
        break;
      }

      break;
    }

    case Datatype.BOOLEAN: {
      if (typeof value !== 'boolean') {
        err = 'Not a boolean';
        break;
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

    case Datatype.TIMESTAMP: {
      if (!isNumber(value)) {
        err = 'Not a number';
        break;
      }

      break;
    }

    case Datatype.JSON: {
      try {
        JSON.stringify(value);
      } catch (e) {
        err = 'Not valid JSON';
      }

      break;
    }

    case Datatype.URI: {
      if (!isString(value) || value.length === 0) {
        err = 'Not a URI: expected a non-empty string';
        break;
      }

      // A URI is rendered as a link target. `javascript:`, `data:` and
      // `vbscript:` parse fine as URLs but run code when clicked.
      if (!isSafeHref(value)) {
        err =
          'Not a valid URI: javascript:, data: and vbscript: are not allowed';
        break;
      }

      try {
        new URL(value);
      } catch (e) {
        err = 'Not a valid URI';
      }

      break;
    }

    case Datatype.LORODOC: {
      if (!(value instanceof Uint8Array)) {
        err = 'Not a Loro document (expected Uint8Array)';
        break;
      }

      break;
    }

    case Datatype.LOCALIZEDTEXT: {
      if (
        typeof value !== 'object' ||
        value === null ||
        Array.isArray(value) ||
        value instanceof Uint8Array
      ) {
        err =
          'Not a LocalizedText: expected an object of language tag -> string';
        break;
      }

      for (const [tag, translation] of Object.entries(value)) {
        if (tag.match(langTagRegex) === null) {
          err = `Invalid language tag "${tag}". Use BCP 47 tags like "en" or "nl-BE"`;
          break;
        }

        if (typeof translation !== 'string') {
          err = `Translation for "${tag}" is not a string`;
          break;
        }
      }

      break;
    }

    default: {
      throw new Error(`Unsupported datatype: ${datatype}`);
    }
  }

  if (err !== null) {
    throw new Error(err);
  }
};

export function isString(val: AtomicValue): val is string {
  return typeof val === 'string';
}

export function isNumber(val: AtomicValue): val is number {
  return typeof val === 'number';
}

export const reverseDatatypeMapping = {
  [Datatype.STRING]: 'String',
  [Datatype.SLUG]: 'Slug',
  [Datatype.MARKDOWN]: 'Markdown',
  [Datatype.URI]: 'URI',
  [Datatype.JSON]: 'JSON',
  [Datatype.INTEGER]: 'Integer',
  [Datatype.FLOAT]: 'Float',
  [Datatype.BOOLEAN]: 'Boolean',
  [Datatype.DATE]: 'Date',
  [Datatype.TIMESTAMP]: 'Timestamp',
  [Datatype.ATOMIC_URL]: 'Resource',
  [Datatype.RESOURCEARRAY]: 'ResourceArray',
  [Datatype.LORODOC]: 'LoroDoc',
  [Datatype.LOCALIZEDTEXT]: 'LocalizedText',
  [Datatype.UNKNOWN]: 'Unknown',
};

/**
 * Picks the best translation from a LocalizedText value for a preferred
 * language: exact tag → primary subtag (`en-US` → `en`) → `defaultLanguage` →
 * `en` → the first tag. Mirrors Rust `Value::to_localized_string`.
 */
export const localizeText = (
  value: LocalizedText | undefined,
  preferred: string,
  defaultLanguage?: string,
): string | undefined => {
  if (!value) {
    return undefined;
  }

  if (value[preferred] !== undefined) {
    return value[preferred];
  }

  const primary = preferred.split('-')[0];

  return (
    value[primary] ??
    (defaultLanguage ? value[defaultLanguage] : undefined) ??
    value['en'] ??
    Object.values(value)[0]
  );
};
