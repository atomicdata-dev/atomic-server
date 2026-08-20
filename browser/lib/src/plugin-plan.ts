import { validateDatatype } from './datatypes.js';
import {
  LOCAL_REF_PREFIX,
  type Intent,
  type Problem,
  type Verdict,
} from './plugin-run.js';
import type { Property } from './store.js';
import type { JSONValue } from './value.js';

/**
 * Turns a {@link Verdict} into something a person can approve.
 *
 * Planning mints subjects for created resources, rewrites `local:` references
 * onto them, and checks every intent against the schema *before* anything is
 * offered for approval. Letting commits fail naturally would mean a user
 * approving 2,000 writes and finding out on write 1,700 that a column maps to a
 * property that does not exist — with 1,699 already applied.
 */

export interface PlannedProperty {
  property: string;
  shortname?: string;
  /** Current value. Absent when the property is not set today. */
  from?: JSONValue;
  /** Proposed value. Absent when the property is being removed. */
  to?: JSONValue;
}

export interface PlannedChange {
  op: Intent['op'];
  /** Real subject: minted for creates, as given otherwise. */
  subject: string;
  /** Present on creates, so the preview can tie a row back to its source. */
  localId?: string;
  parent?: string;
  isA?: string[];
  properties: PlannedProperty[];
  problems: Problem[];
}

export interface RunPlan {
  changes: PlannedChange[];
  /** Problems not tied to one change, including everything the verdict carried. */
  problems: Problem[];
  /** localId to the subject minted for it. */
  minted: Record<string, string>;
  /** True when the plan must not be applied. */
  blocked: boolean;
}

/**
 * What planning needs from a store. Narrow on purpose: the CLI and the
 * server-side runner need the same planner, and neither has a browser Store.
 */
export interface PlanHost {
  createSubject(parent?: string): string;
  getProperty(subject: string): Promise<Property>;
  /** Current property values, or undefined when the resource does not exist. */
  readResource(subject: string): Promise<Record<string, JSONValue> | undefined>;
}

/**
 * The slice of `Store` the planner needs. Structural on purpose: importing the
 * Store class here would pull the whole browser data layer into a module that
 * the CLI and the server-side runner also want.
 */
export interface PlanStore {
  createSubject(parent?: string): string;
  getProperty(subject: string): Promise<Property>;
  getResource(subject: string): Promise<{
    error?: Error;
    getPropVals(): Record<string, unknown>;
  }>;
}

/** Adapts a `Store` to a {@link PlanHost}. */
export function planHostFromStore(store: PlanStore): PlanHost {
  return {
    createSubject: parent => store.createSubject(parent),
    getProperty: subject => store.getProperty(subject),
    readResource: async subject => {
      const resource = await store.getResource(subject);

      // A subject that could not be fetched is indistinguishable from one that
      // was never created, and both mean the same thing for planning: there is
      // nothing here to change.
      if (resource.error) return undefined;

      return resource.getPropVals() as Record<string, JSONValue>;
    },
  };
}

export async function planVerdict(
  verdict: Verdict,
  host: PlanHost,
): Promise<RunPlan> {
  const problems: Problem[] = [...verdict.problems];

  const { minted, usable } = mintSubjects(verdict.intents, host, problems);
  const resolved = usable.map(intent => resolveRefs(intent, minted));

  const properties = memoize(async (url: string) => {
    try {
      return await host.getProperty(url);
    } catch {
      return undefined;
    }
  });

  const resources = memoize((subject: string) => host.readResource(subject));

  const changes: PlannedChange[] = [];

  for (const intent of resolved) {
    changes.push(await planIntent(intent, minted, properties, resources));
  }

  const blocked =
    problems.some(p => p.severity === 'error') ||
    changes.some(c => c.problems.some(p => p.severity === 'error'));

  return { changes, problems, minted, blocked };
}

/**
 * Mints a subject per create, parents first.
 *
 * A create whose parent is another create has to wait for that parent's subject
 * to exist, so this walks the dependency order. Creates in a parent cycle can
 * never be minted; they are reported and dropped rather than left to deadlock.
 */
function mintSubjects(
  intents: Intent[],
  host: PlanHost,
  problems: Problem[],
): { minted: Record<string, string>; usable: Intent[] } {
  const creates = intents.filter(i => i.op === 'create');
  const minted: Record<string, string> = {};
  const pending = new Map(creates.map(c => [c.localId, c]));

  let progressed = true;

  while (pending.size > 0 && progressed) {
    progressed = false;

    for (const [localId, create] of [...pending]) {
      const parentRef = localRef(create.parent);

      if (parentRef !== undefined && minted[parentRef] === undefined) continue;

      minted[localId] = host.createSubject(
        parentRef !== undefined ? minted[parentRef] : create.parent,
      );
      pending.delete(localId);
      progressed = true;
    }
  }

  if (pending.size > 0) {
    const stuck = [...pending.keys()].sort();
    problems.push({
      severity: 'error',
      message: `these resources are each other's parent, so none of them can be created: ${stuck.join(', ')}`,
    });
  }

  const dropped = new Set(pending.keys());

  return {
    minted,
    usable: intents.filter(i => i.op !== 'create' || !dropped.has(i.localId)),
  };
}

function resolveRefs(intent: Intent, minted: Record<string, string>): Intent {
  const rewrite = (value: JSONValue): JSONValue => {
    if (typeof value === 'string') {
      const ref = localRef(value);

      return ref !== undefined ? (minted[ref] ?? value) : value;
    }

    if (Array.isArray(value)) return value.map(rewrite);

    if (value && typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => [k, rewrite(v)]),
      );
    }

    return value;
  };

  if (intent.op === 'create') {
    return {
      ...intent,
      parent: rewrite(intent.parent) as string,
      set: rewrite(intent.set) as Record<string, JSONValue>,
    };
  }

  if (intent.op === 'set') {
    return { ...intent, set: rewrite(intent.set) as Record<string, JSONValue> };
  }

  return intent;
}

async function planIntent(
  intent: Intent,
  minted: Record<string, string>,
  properties: (url: string) => Promise<Property | undefined>,
  resources: (
    subject: string,
  ) => Promise<Record<string, JSONValue> | undefined>,
): Promise<PlannedChange> {
  if (intent.op === 'create') {
    const subject = minted[intent.localId];
    const change: PlannedChange = {
      op: 'create',
      subject,
      localId: intent.localId,
      parent: intent.parent,
      isA: intent.isA,
      properties: [],
      problems: [],
    };

    if (intent.isA.length === 0) {
      change.problems.push({
        severity: 'warning',
        message: 'created without a class, so nothing will validate it later',
        subject,
      });
    }

    await checkProperties(intent.set, undefined, change, properties);

    return change;
  }

  const current = await resources(intent.subject);
  const change: PlannedChange = {
    op: intent.op,
    subject: intent.subject,
    properties: [],
    problems: [],
  };

  if (current === undefined) {
    change.problems.push({
      severity: 'error',
      message: `${intent.subject} does not exist, so it cannot be changed`,
      subject: intent.subject,
    });

    return change;
  }

  if (intent.op === 'destroy') return change;

  if (intent.op === 'remove') {
    for (const property of intent.properties) {
      if (current[property] === undefined) {
        change.problems.push({
          severity: 'warning',
          message: 'is not set, so removing it does nothing',
          subject: intent.subject,
          property,
        });

        continue;
      }

      change.properties.push({ property, from: current[property] });
    }

    return change;
  }

  await checkProperties(intent.set, current, change, properties);

  return change;
}

async function checkProperties(
  set: Record<string, JSONValue>,
  current: Record<string, JSONValue> | undefined,
  change: PlannedChange,
  properties: (url: string) => Promise<Property | undefined>,
): Promise<void> {
  for (const [url, value] of Object.entries(set)) {
    const property = await properties(url);

    if (!property) {
      change.problems.push({
        severity: 'error',
        message: `no property ${url} exists, so this value has nowhere to go`,
        subject: change.subject,
        property: url,
      });

      continue;
    }

    try {
      validateDatatype(value, property.datatype);
    } catch (e) {
      change.problems.push({
        severity: 'error',
        message: `${property.shortname} expects ${property.datatype}: ${
          e instanceof Error ? e.message : String(e)
        }`,
        subject: change.subject,
        property: url,
      });

      continue;
    }

    const from = current?.[url];

    if (from !== undefined && sameValue(from, value)) {
      change.problems.push({
        severity: 'warning',
        message: `${property.shortname} already has this value`,
        subject: change.subject,
        property: url,
      });

      continue;
    }

    change.properties.push({
      property: url,
      shortname: property.shortname,
      from,
      to: value,
    });
  }
}

/** Cheap structural equality; property values are JSON by construction. */
function sameValue(a: JSONValue, b: JSONValue): boolean {
  if (a === b) return true;

  return JSON.stringify(a) === JSON.stringify(b);
}

function localRef(value: JSONValue): string | undefined {
  return typeof value === 'string' && value.startsWith(LOCAL_REF_PREFIX)
    ? value.slice(LOCAL_REF_PREFIX.length)
    : undefined;
}

function memoize<T>(
  fn: (key: string) => Promise<T>,
): (key: string) => Promise<T> {
  const cache = new Map<string, Promise<T>>();

  return key => {
    const hit = cache.get(key);

    if (hit) return hit;

    const value = fn(key);
    cache.set(key, value);

    return value;
  };
}
