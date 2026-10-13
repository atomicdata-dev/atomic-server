import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { Datatype } from './datatypes.js';
import type { JSONValue } from './value.js';
import { canonicalizeScheme, isLensSubject, lensSubject } from './subject.js';

/**
 * Lenses: content-addressed mappings between two properties.
 *
 * Properties are immutable, so renaming a shortname or changing a datatype
 * makes a new Property and strands the data stored under the old one. A Lens
 * says how a value under one Property maps to a value under another. It is
 * applied when a resource's Loro document is materialized into its property
 * cache; the document itself (signed data) is never changed by a lens.
 *
 * The Rust twin is `lib/src/lens.rs`; both read `lib/tests/fixtures/lenses.json`.
 * See `docs/src/schema/lenses.md`.
 */

/** Domain separation: a lens ID can never equal a property ID or a blob hash. */
export const LENS_IDENTITY_CONTEXT = 'atomic lens identity v1';

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

export type Transform =
  | { op: 'rename' }
  | { op: 'wrap' }
  | { op: 'head' }
  | { op: 'map'; values: Record<string, string> }
  | { op: 'convert'; to: string; from?: string };

const knownDatatypes = new Set<string>(
  Object.values(Datatype).filter(d => d !== Datatype.UNKNOWN),
);

/**
 * Parse and validate a `lensTransform`. Unknown ops and unknown fields throw,
 * so equal transforms hash equal.
 */
export function parseTransform(json: unknown): Transform {
  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    throw new Error('A lens transform must be a JSON object');
  }

  const obj = json as Record<string, unknown>;
  const op = obj.op;

  const allowed: Record<string, string[]> = {
    rename: ['op'],
    wrap: ['op'],
    head: ['op'],
    map: ['op', 'values'],
    convert: ['op', 'to', 'from'],
  };

  if (typeof op !== 'string' || !(op in allowed)) {
    throw new Error(`Unknown lens op: '${String(op)}'`);
  }

  for (const key of Object.keys(obj)) {
    if (!allowed[op].includes(key)) {
      throw new Error(`Unknown field '${key}' in lens op '${op}'`);
    }
  }

  switch (op) {
    case 'rename':
    case 'wrap':
    case 'head':
      return { op };

    case 'map': {
      const values = obj.values;

      if (
        typeof values !== 'object' ||
        values === null ||
        Array.isArray(values)
      ) {
        throw new Error("Lens op 'map' needs an object `values`");
      }

      for (const v of Object.values(values)) {
        if (typeof v !== 'string') {
          throw new Error("Lens op 'map' values must map strings to strings");
        }
      }

      return { op, values: { ...(values as Record<string, string>) } };
    }

    default: {
      const datatype = (key: 'to' | 'from'): string | undefined => {
        const v = obj[key];

        if (v === undefined) return undefined;

        if (typeof v !== 'string') {
          throw new Error(`Lens op 'convert' \`${key}\` must be a string`);
        }

        if (!knownDatatypes.has(v)) {
          throw new Error(`Unknown datatype: '${v}'`);
        }

        return v;
      };

      const to = datatype('to');

      if (to === undefined) {
        throw new Error("Lens op 'convert' needs a `to` datatype");
      }

      const from = datatype('from');

      return from === undefined
        ? { op: 'convert', to }
        : { op: 'convert', to, from };
    }
  }
}

const isScalar = (v: JSONValue): boolean =>
  typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';

function wrap(value: JSONValue): JSONValue {
  return isScalar(value) ? [value] : undefined;
}

function head(value: JSONValue): JSONValue {
  return Array.isArray(value) ? value[0] : undefined;
}

function mapValue(values: Record<string, string>, value: JSONValue): JSONValue {
  const one = (v: JSONValue): JSONValue =>
    typeof v === 'string' && Object.hasOwn(values, v) ? values[v] : v;

  if (typeof value === 'string') return one(value);

  if (Array.isArray(value)) return value.map(one);

  return undefined;
}

const INTEGER_TEXT = /^-?[0-9]+$/;
const FLOAT_TEXT = /^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;

const isTextType = (datatype: string): boolean =>
  datatype !== Datatype.INTEGER &&
  datatype !== Datatype.FLOAT &&
  datatype !== Datatype.BOOLEAN &&
  datatype !== Datatype.RESOURCEARRAY &&
  datatype !== Datatype.JSON &&
  datatype !== Datatype.TIMESTAMP &&
  datatype !== Datatype.LORODOC &&
  datatype !== Datatype.LOCALIZEDTEXT;

function convert(value: JSONValue, target: string): JSONValue {
  if (typeof value === 'string') {
    const text = value.trim();

    switch (target) {
      case Datatype.INTEGER: {
        if (!INTEGER_TEXT.test(text)) return undefined;

        const n = Number(text);

        return Math.abs(n) <= MAX_SAFE_INTEGER ? n : undefined;
      }

      case Datatype.FLOAT: {
        if (!FLOAT_TEXT.test(text)) return undefined;

        const n = Number(text);

        return Number.isFinite(n) ? n : undefined;
      }

      case Datatype.BOOLEAN: {
        const lower = text.toLowerCase();

        if (lower === 'true') return true;

        if (lower === 'false') return false;

        return undefined;
      }

      default:
        return isTextType(target) ? value : undefined;
    }
  }

  if (
    (typeof value === 'number' || typeof value === 'boolean') &&
    isTextType(target)
  ) {
    return typeof value === 'number' && !Number.isFinite(value)
      ? undefined
      : String(value);
  }

  return undefined;
}

/**
 * A `lensTransform` as read from a resource: a JSON value, or the JSON text of
 * one (how a `json` property is held until its datatype is known).
 */
export function readTransformValue(value: unknown): unknown {
  if (typeof value !== 'string') return value;

  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

/** True unless a `map` sends two values to one. */
export function hasBackward(transform: Transform): boolean {
  if (transform.op !== 'map') return true;

  const targets = Object.values(transform.values);

  return new Set(targets).size === targets.length;
}

/** `from` value to `to` value. `undefined` means there is no derived value. */
export function forward(transform: Transform, value: JSONValue): JSONValue {
  switch (transform.op) {
    case 'rename':
      return value;
    case 'wrap':
      return wrap(value);
    case 'head':
      return head(value);
    case 'map':
      return mapValue(transform.values, value);
    case 'convert':
      return convert(value, transform.to);
  }
}

/** `to` value back to a `from` value. `undefined` means there is no derived value. */
export function backward(transform: Transform, value: JSONValue): JSONValue {
  if (!hasBackward(transform)) return undefined;

  switch (transform.op) {
    case 'rename':
      return value;
    case 'wrap':
      // Only an array of exactly one item maps back without loss.
      return Array.isArray(value) && value.length === 1 ? value[0] : undefined;
    case 'head':
      return wrap(value);
    case 'map':
      return mapValue(
        Object.fromEntries(
          Object.entries(transform.values).map(([k, v]) => [v, k]),
        ),
        value,
      );
    case 'convert':
      return convert(value, transform.from ?? Datatype.STRING);
  }
}

/** JSON Canonicalization Scheme (RFC 8785) for the JSON a lens hashes. */
function jcs(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(jcs).join(',')}]`;
  }

  const obj = value as Record<string, unknown>;

  return `{${Object.keys(obj)
    .sort()
    .map(key => `${JSON.stringify(key)}:${jcs(obj[key])}`)
    .join(',')}}`;
}

/**
 * The content-addressed ID of a Lens: `atomic:lens:{blake3-hex}`, from `from`,
 * `to` and the transform. `from` and `to` are written in their `atomic:` form
 * first. Throws on bad input. See `docs/src/schema/lenses.md`.
 */
export function lensId(from: string, to: string, transform: unknown): string {
  if (!from || !to) {
    throw new Error('A lens needs a `from` and a `to` property');
  }

  const canonicalFrom = canonicalizeScheme(from);
  const canonicalTo = canonicalizeScheme(to);

  if (canonicalFrom === canonicalTo) {
    throw new Error('A lens cannot map a property onto itself');
  }

  const hash = blake3(
    utf8ToBytes(
      jcs({
        from: canonicalFrom,
        to: canonicalTo,
        transform: parseTransform(transform),
      }),
    ),
    { context: utf8ToBytes(LENS_IDENTITY_CONTEXT) },
  );

  return lensSubject(bytesToHex(hash));
}

/** True for `atomic:lens:{hex}` and `did:ad:lens:{hex}`. */
export function isLensId(subject: string): boolean {
  return isLensSubject(subject);
}

/** Does `subject` equal the ID derived from this `from`, `to` and transform? */
export function verifyLensId(
  subject: string,
  from: string,
  to: string,
  transform: unknown,
): boolean {
  if (!isLensId(subject)) return false;

  try {
    return canonicalizeScheme(subject) === lensId(from, to, transform);
  } catch {
    return false;
  }
}

/** One lens as the index holds it. */
export interface LensEntry {
  /** `atomic:lens:{hex}` */
  id: string;
  /** Canonical `lensFrom`. */
  from: string;
  /** Canonical `lensTo`. */
  to: string;
  transform: Transform;
  /** The ontology that owns `lensTo` (and this lens). */
  parent: string;
}

/** Lenses by the properties they touch. */
export class LensIndex {
  private byProp = new Map<string, LensEntry[]>();
  private ids = new Map<string, LensEntry>();

  public get size(): number {
    return this.ids.size;
  }

  public get(id: string): LensEntry | undefined {
    return this.ids.get(canonicalizeScheme(id));
  }

  /** Add a lens, replacing one with the same ID. */
  public insert(entry: LensEntry): void {
    this.remove(entry.id);
    this.ids.set(entry.id, entry);

    for (const prop of [entry.from, entry.to]) {
      const list = this.byProp.get(prop) ?? [];

      list.push(entry);
      this.byProp.set(prop, list);
    }
  }

  public remove(id: string): void {
    const canonical = canonicalizeScheme(id);

    if (!this.ids.delete(canonical)) return;

    for (const [prop, list] of this.byProp) {
      const rest = list.filter(e => e.id !== canonical);

      if (rest.length === 0) {
        this.byProp.delete(prop);
      } else {
        this.byProp.set(prop, rest);
      }
    }
  }

  /** Lenses that read or write this property. */
  public lensesFor(prop: string): readonly LensEntry[] {
    return this.byProp.get(canonicalizeScheme(prop)) ?? [];
  }

  public touches(prop: string): boolean {
    return this.lensesFor(prop).length > 0;
  }

  /** Every property some lens reads or writes. */
  public properties(): IterableIterator<string> {
    return this.byProp.keys();
  }

  /**
   * The values lenses derive from `own`, the properties a document really
   * holds. One pass, no chaining: a derived value never feeds another lens. A
   * real value always wins, and if two lenses derive the same property the one
   * with the smaller ID wins.
   */
  public derive(
    own: Readonly<Record<string, JSONValue>>,
  ): Map<string, JSONValue> {
    const derived = new Map<string, JSONValue>();

    if (this.ids.size === 0) return derived;

    const present = new Map<string, JSONValue>();

    for (const [key, value] of Object.entries(own)) {
      if (value !== undefined) present.set(canonicalizeScheme(key), value);
    }

    const candidates = new Map<string, LensEntry>();

    for (const key of present.keys()) {
      for (const lens of this.lensesFor(key)) candidates.set(lens.id, lens);
    }

    for (const id of [...candidates.keys()].sort()) {
      const lens = candidates.get(id)!;
      const fromValue = present.get(lens.from);
      const toValue = present.get(lens.to);
      let target: string;
      let value: JSONValue;

      if (fromValue !== undefined && toValue === undefined) {
        target = lens.to;
        value = forward(lens.transform, fromValue);
      } else if (fromValue === undefined && toValue !== undefined) {
        target = lens.from;
        value = backward(lens.transform, toValue);
      } else {
        continue;
      }

      if (value !== undefined && !derived.has(target)) {
        derived.set(target, value);
      }
    }

    return derived;
  }

  /**
   * Add derived values to a property cache, keeping real values. Returns the
   * properties that were derived.
   */
  public apply(cache: Record<string, JSONValue>): string[] {
    const applied: string[] = [];

    for (const [prop, value] of this.derive(cache)) {
      if (cache[prop] !== undefined) continue;

      cache[prop] = value;
      applied.push(prop);
    }

    return applied;
  }
}
