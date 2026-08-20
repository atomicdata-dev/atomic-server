import type { JSONValue } from './types.js';

/**
 * The contract for a plugin's `run` export.
 *
 * `run` never writes. It returns a {@link Verdict} describing what *should*
 * happen, and the host validates, previews, gets approval, and commits. A
 * validator returns problems and no intents, an importer returns intents and no
 * problems, an automation returns both, and a connector adds a cursor.
 *
 * Because `run` holds no authority, the same contract works whether it executes
 * in a Worker with a user watching or in a server-side sandbox at 3am.
 */

/**
 * Values referencing a resource created by the same verdict are written as
 * `local:<localId>`. The host mints real subjects during planning and rewrites
 * these references, so a verdict can describe a linked graph — an imported
 * contact pointing at an Organization that the same run creates.
 */
export const LOCAL_REF_PREFIX = 'local:';

export interface CreateIntent {
  op: 'create';
  /** Identifies this resource within the verdict. Referenced as `local:<localId>`. */
  localId: string;
  /** Subject of the parent, or a `local:` reference to one. */
  parent: string;
  isA: string[];
  set: Record<string, JSONValue>;
}

export interface SetIntent {
  op: 'set';
  subject: string;
  set: Record<string, JSONValue>;
}

export interface RemoveIntent {
  op: 'remove';
  subject: string;
  properties: string[];
}

export interface DestroyIntent {
  op: 'destroy';
  subject: string;
}

export type Intent = CreateIntent | SetIntent | RemoveIntent | DestroyIntent;

export type ProblemSeverity = 'error' | 'warning';

export interface Problem {
  /** `error` blocks the run from being applied. `warning` is shown and ignored. */
  severity: ProblemSeverity;
  message: string;
  subject?: string;
  property?: string;
}

export interface Verdict {
  intents: Intent[];
  problems: Problem[];
  /** Opaque resume token, persisted per plugin so the next run is incremental. */
  cursor?: string;
}

export interface ParseVerdictOptions {
  /**
   * Upper bound on intents the host will plan. Exceeding it is reported as an
   * error rather than quietly truncated — a half-applied import that looks
   * complete is worse than one that refuses.
   */
  maxIntents?: number;
}

const DEFAULT_MAX_INTENTS = 50_000;

/**
 * Normalizes whatever untrusted plugin code returned into a {@link Verdict}.
 *
 * Never throws and never trusts the input's shape. Anything malformed is
 * dropped and reported as a problem, so a broken plugin fails visibly in the
 * preview instead of silently proposing less than it meant to.
 */
export function parseVerdict(
  raw: unknown,
  options: ParseVerdictOptions = {},
): Verdict {
  const maxIntents = options.maxIntents ?? DEFAULT_MAX_INTENTS;
  const problems: Problem[] = [];

  if (!isPlainObject(raw)) {
    return {
      intents: [],
      problems: [
        {
          severity: 'error',
          message: `run() returned ${describe(raw)}, expected an object with { intents, problems }`,
        },
      ],
    };
  }

  problems.push(...parseProblems(raw.problems));

  const { intents, problems: intentProblems } = parseIntents(
    raw.intents,
    maxIntents,
  );
  problems.push(...intentProblems);

  const resolved = resolveLocalRefs(intents);
  problems.push(...resolved.problems);

  return {
    intents: resolved.intents,
    problems,
    ...parseCursor(raw.cursor, problems),
  };
}

/** True when the verdict must not be applied. */
export function hasBlockingProblems(verdict: Verdict): boolean {
  return verdict.problems.some(p => p.severity === 'error');
}

function parseCursor(raw: unknown, problems: Problem[]): { cursor?: string } {
  if (raw === undefined || raw === null) return {};

  if (typeof raw !== 'string') {
    problems.push({
      severity: 'error',
      message: `cursor must be a string, got ${describe(raw)}`,
    });

    return {};
  }

  return { cursor: raw };
}

function parseProblems(raw: unknown): Problem[] {
  if (raw === undefined || raw === null) return [];

  if (!Array.isArray(raw)) {
    return [
      {
        severity: 'error',
        message: `problems must be an array, got ${describe(raw)}`,
      },
    ];
  }

  return raw.flatMap((entry, index) => {
    if (!isPlainObject(entry) || typeof entry.message !== 'string') {
      return [
        {
          severity: 'error',
          message: `problems[${index}] is not a problem: ${describe(entry)}`,
        },
      ];
    }

    const problem: Problem = {
      // Anything a plugin reports blocks unless it opted into a warning: a
      // validator that meant to reject should not be downgraded by a typo.
      severity: entry.severity === 'warning' ? 'warning' : 'error',
      message: entry.message,
    };

    if (typeof entry.subject === 'string') problem.subject = entry.subject;

    if (typeof entry.property === 'string') problem.property = entry.property;

    return [problem];
  });
}

function parseIntents(
  raw: unknown,
  maxIntents: number,
): { intents: Intent[]; problems: Problem[] } {
  if (raw === undefined || raw === null) return { intents: [], problems: [] };

  if (!Array.isArray(raw)) {
    return {
      intents: [],
      problems: [
        {
          severity: 'error',
          message: `intents must be an array, got ${describe(raw)}`,
        },
      ],
    };
  }

  if (raw.length > maxIntents) {
    return {
      intents: [],
      problems: [
        {
          severity: 'error',
          message: `run() proposed ${raw.length} intents, over the limit of ${maxIntents}. Nothing was planned; narrow the run or raise the limit.`,
        },
      ],
    };
  }

  const intents: Intent[] = [];
  const problems: Problem[] = [];
  const localIds = new Set<string>();

  raw.forEach((entry, index) => {
    const parsed = parseIntent(entry, index, localIds);

    if (parsed.problem) problems.push(parsed.problem);

    if (parsed.intent) intents.push(parsed.intent);
  });

  return { intents, problems };
}

function parseIntent(
  entry: unknown,
  index: number,
  localIds: Set<string>,
): { intent?: Intent; problem?: Problem } {
  const at = `intents[${index}]`;

  if (!isPlainObject(entry)) {
    return { problem: err(`${at} is not an object: ${describe(entry)}`) };
  }

  switch (entry.op) {
    case 'create':
      return parseCreate(entry, at, localIds);
    case 'set':
      return parseSet(entry, at);
    case 'remove':
      return parseRemove(entry, at);
    case 'destroy':
      return typeof entry.subject === 'string' && entry.subject.length > 0
        ? { intent: { op: 'destroy', subject: entry.subject } }
        : { problem: err(`${at} destroy needs a subject`) };
    default:
      return {
        problem: err(`${at} has unknown op ${describe(entry.op)}`),
      };
  }
}

function parseCreate(
  entry: Record<string, unknown>,
  at: string,
  localIds: Set<string>,
): { intent?: Intent; problem?: Problem } {
  const { localId, parent } = entry;

  if (typeof localId !== 'string' || localId.length === 0) {
    return { problem: err(`${at} create needs a localId`) };
  }

  if (localIds.has(localId)) {
    return {
      problem: err(
        `${at} reuses localId "${localId}"; references to it would be ambiguous`,
      ),
    };
  }

  if (typeof parent !== 'string' || parent.length === 0) {
    return { problem: err(`${at} create needs a parent`) };
  }

  const isA = Array.isArray(entry.isA)
    ? entry.isA.filter((c): c is string => typeof c === 'string')
    : [];

  const set = parseSetMap(entry.set);

  if (!set) {
    return { problem: err(`${at} set must be an object of JSON values`) };
  }

  localIds.add(localId);

  return { intent: { op: 'create', localId, parent, isA, set } };
}

function parseSet(
  entry: Record<string, unknown>,
  at: string,
): { intent?: Intent; problem?: Problem } {
  const { subject } = entry;

  if (typeof subject !== 'string' || subject.length === 0) {
    return { problem: err(`${at} set needs a subject`) };
  }

  const set = parseSetMap(entry.set);

  if (!set) {
    return { problem: err(`${at} set must be an object of JSON values`) };
  }

  if (Object.keys(set).length === 0) {
    return {
      problem: {
        severity: 'warning',
        message: `${at} sets no properties and was skipped`,
        subject,
      },
    };
  }

  return { intent: { op: 'set', subject, set } };
}

function parseRemove(
  entry: Record<string, unknown>,
  at: string,
): { intent?: Intent; problem?: Problem } {
  const { subject } = entry;

  if (typeof subject !== 'string' || subject.length === 0) {
    return { problem: err(`${at} remove needs a subject`) };
  }

  const properties = Array.isArray(entry.properties)
    ? entry.properties.filter(
        (p): p is string => typeof p === 'string' && p.length > 0,
      )
    : [];

  if (properties.length === 0) {
    return { problem: err(`${at} remove needs at least one property`) };
  }

  return { intent: { op: 'remove', subject, properties } };
}

/**
 * Validates a property map. `undefined` values are dropped: optional fields are
 * the norm in a mapping, and `{ email: row.email }` on a row without an email
 * should mean "no email", not "malformed intent".
 */
function parseSetMap(raw: unknown): Record<string, JSONValue> | undefined {
  if (raw === undefined || raw === null) return {};

  if (!isPlainObject(raw)) return undefined;

  const out: Record<string, JSONValue> = {};

  for (const [key, value] of Object.entries(raw)) {
    if (value === undefined) continue;

    if (!isJsonValue(value)) return undefined;

    out[key] = value as JSONValue;
  }

  return out;
}

/**
 * Drops intents that reference a `local:` id the verdict never creates. Without
 * this the host would mint a subject for a dangling reference and write a link
 * to a resource that does not exist.
 */
function resolveLocalRefs(intents: Intent[]): {
  intents: Intent[];
  problems: Problem[];
} {
  const known = new Set(
    intents
      .filter((i): i is CreateIntent => i.op === 'create')
      .map(i => i.localId),
  );

  const problems: Problem[] = [];

  const kept = intents.filter(intent => {
    const dangling = localRefsOf(intent).filter(id => !known.has(id));

    if (dangling.length === 0) return true;

    problems.push(
      err(
        `intent references ${dangling
          .map(id => `"${LOCAL_REF_PREFIX}${id}"`)
          .join(', ')}, which no create intent defines`,
      ),
    );

    return false;
  });

  return { intents: kept, problems };
}

function localRefsOf(intent: Intent): string[] {
  const refs: string[] = [];

  const collect = (value: JSONValue) => {
    if (typeof value === 'string' && value.startsWith(LOCAL_REF_PREFIX)) {
      refs.push(value.slice(LOCAL_REF_PREFIX.length));
    } else if (Array.isArray(value)) {
      value.forEach(collect);
    } else if (value && typeof value === 'object') {
      Object.values(value).forEach(collect);
    }
  };

  if (intent.op === 'create') {
    collect(intent.parent);
    Object.values(intent.set).forEach(collect);
  } else if (intent.op === 'set') {
    Object.values(intent.set).forEach(collect);
  }

  return refs;
}

function err(message: string): Problem {
  return { severity: 'error', message };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isJsonValue(value: unknown): boolean {
  if (value === null) return true;

  const type = typeof value;

  if (type === 'string' || type === 'boolean') return true;

  if (type === 'number') return Number.isFinite(value as number);

  if (Array.isArray(value)) return value.every(isJsonValue);

  if (isPlainObject(value)) return Object.values(value).every(isJsonValue);

  return false;
}

function describe(value: unknown): string {
  if (value === null) return 'null';

  if (Array.isArray(value)) return 'an array';

  if (typeof value === 'object') return 'an unexpected object';

  return typeof value;
}
