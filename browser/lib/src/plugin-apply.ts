import type { PlannedChange, RunPlan } from './plugin-plan.js';
import type { JSONValue } from './value.js';

/**
 * Applies an approved {@link RunPlan}.
 *
 * The planner's minted subjects are placeholders: a store may mint the real one
 * itself (a DID derived from a genesis certificate cannot be guessed ahead of
 * time). So creates report back the subject they actually got, and later
 * changes have their references rewritten onto it.
 */

export interface CreateRequest {
  parent: string;
  isA: string[];
  propVals: Record<string, JSONValue>;
}

/** What applying needs from a store. Narrow, for the same reason `PlanHost` is. */
export interface ApplyHost {
  /** Creates the resource and returns the subject it actually got. */
  create(request: CreateRequest): Promise<string>;
  set(subject: string, propVals: Record<string, JSONValue>): Promise<void>;
  remove(subject: string, properties: string[]): Promise<void>;
  destroy(subject: string): Promise<void>;
}

/**
 * The slice of `Store` applying needs. Structural, matching `PlanStore`.
 */
export interface ApplyStore {
  newResource(opts: {
    parent: string;
    isA: string[];
    propVals: Record<string, JSONValue>;
  }): Promise<{ subject: string; save(): Promise<unknown> }>;
  getResource(subject: string): Promise<{
    set(prop: string, value: JSONValue): Promise<void>;
    remove(prop: string): void;
    save(): Promise<unknown>;
    destroy(): Promise<void>;
  }>;
}

/** Adapts a `Store` to an {@link ApplyHost}. */
export function applyHostFromStore(store: ApplyStore): ApplyHost {
  return {
    create: async request => {
      const resource = await store.newResource(request);
      await resource.save();

      // Read the subject after saving: for a DID agent the store mints it from
      // a genesis certificate during creation, so it is not knowable before.
      return resource.subject;
    },
    set: async (subject, propVals) => {
      const resource = await store.getResource(subject);

      for (const [property, value] of Object.entries(propVals)) {
        // Validation stays on: the planner already fetched every property, so
        // this reads the store cache rather than the network.
        await resource.set(property, value);
      }

      await resource.save();
    },
    remove: async (subject, properties) => {
      const resource = await store.getResource(subject);
      properties.forEach(property => resource.remove(property));
      await resource.save();
    },
    destroy: async subject => {
      const resource = await store.getResource(subject);
      await resource.destroy();
    },
  };
}

export type ChangeStatus = 'applied' | 'skipped' | 'failed' | 'not-attempted';

export interface ChangeOutcome {
  op: PlannedChange['op'];
  /** The subject as planned. */
  planned: string;
  /** The subject that exists now. Differs from `planned` for creates. */
  subject: string;
  localId?: string;
  status: ChangeStatus;
  error?: string;
}

export interface ApplyReport {
  outcomes: ChangeOutcome[];
  applied: number;
  skipped: number;
  failed: number;
  /** Planned subject to the real one, for creates. */
  subjects: Record<string, string>;
  /** True when a failure stopped the run before every change was attempted. */
  stoppedEarly: boolean;
}

export interface ApplyOptions {
  /**
   * Keep going after a change fails. Off by default: a failed create means
   * everything that links to it would point at nothing, and half a linked graph
   * is harder to reason about than a run that stopped.
   */
  continueOnError?: boolean;
  /**
   * How many writes may be in flight at once. Each write is a round trip, so
   * applying an import one at a time costs rows × latency — a minute for two
   * thousand rows on a 30ms link, spent almost entirely waiting.
   *
   * Only ever applied to changes that cannot affect each other: creates run
   * after everything they refer to, and two changes to one subject stay in
   * order.
   */
  concurrency?: number;
}

const DEFAULT_CONCURRENCY = 8;

/**
 * Applies a plan and reports what happened to every change.
 *
 * Refuses a blocked plan outright. Applying one would mean writing changes the
 * planner already knows are wrong, and a partially-applied bad import is the
 * expensive kind of mistake.
 */
export async function applyPlan(
  plan: RunPlan,
  host: ApplyHost,
  options: ApplyOptions = {},
): Promise<ApplyReport> {
  if (plan.blocked) {
    throw new Error(
      'refusing to apply a blocked plan: resolve its errors or drop the offending changes first',
    );
  }

  const subjects: Record<string, string> = {};
  const ordered = createsFirst(plan.changes);
  const plannedSubjects = new Set(
    plan.changes.filter(c => c.op === 'create').map(c => c.subject),
  );
  const positions = new Map(ordered.map((change, index) => [change, index]));
  const outcomes: Array<ChangeOutcome | undefined> = new Array(ordered.length);
  const limit = Math.max(1, options.concurrency ?? DEFAULT_CONCURRENCY);

  let stopped = false;

  const runOne = async (change: PlannedChange) => {
    const index = positions.get(change)!;

    if (stopped) {
      outcomes[index] = outcome(change, change.subject, 'not-attempted');

      return;
    }

    try {
      const result = await applyChange(change, host, subjects, plannedSubjects);

      if (result.subject !== change.subject) {
        subjects[change.subject] = result.subject;
      }

      outcomes[index] = outcome(change, result.subject, result.status);
    } catch (e) {
      outcomes[index] = outcome(
        change,
        change.subject,
        'failed',
        describeError(e),
      );

      if (!options.continueOnError) stopped = true;
    }
  };

  for (const wave of waves(ordered)) {
    await runBounded(
      wave.map(chain => async () => {
        // A chain is one subject's changes, kept in order; separate chains
        // cannot affect each other, so they run together.
        for (const change of chain) await runOne(change);
      }),
      limit,
    );
  }

  const settled = outcomes.filter((o): o is ChangeOutcome => o !== undefined);

  return {
    outcomes: settled,
    subjects,
    stoppedEarly: settled.some(o => o.status === 'not-attempted'),
    applied: settled.filter(o => o.status === 'applied').length,
    skipped: settled.filter(o => o.status === 'skipped').length,
    failed: settled.filter(o => o.status === 'failed').length,
  };
}

/**
 * Groups changes into waves of independent chains.
 *
 * A create may only run once everything it refers to exists, so creates form
 * one wave per dependency level. Everything else follows in a single wave,
 * chained per subject so two writes to one resource never race.
 */
function waves(ordered: PlannedChange[]): PlannedChange[][][] {
  const creates = ordered.filter(c => c.op === 'create');
  const rest = ordered.filter(c => c.op !== 'create');
  const bySubject = new Map(creates.map(c => [c.subject, c]));

  const levels = new Map<string, number>();

  // `ordered` is already topological, so a dependency's level is known by the
  // time its dependent is reached.
  for (const create of creates) {
    const depth = referencedCreates(create, bySubject).reduce(
      (deepest, dependency) =>
        Math.max(deepest, (levels.get(dependency.subject) ?? 0) + 1),
      0,
    );
    levels.set(create.subject, depth);
  }

  const createWaves: PlannedChange[][][] = [];

  for (const create of creates) {
    const level = levels.get(create.subject)!;
    createWaves[level] ??= [];
    createWaves[level].push([create]);
  }

  const chains = new Map<string, PlannedChange[]>();

  for (const change of rest) {
    const chain = chains.get(change.subject) ?? [];
    chain.push(change);
    chains.set(change.subject, chain);
  }

  return [
    ...createWaves.filter(Boolean),
    ...(chains.size > 0 ? [[...chains.values()]] : []),
  ];
}

/** Runs thunks with at most `limit` in flight. */
async function runBounded(
  tasks: Array<() => Promise<void>>,
  limit: number,
): Promise<void> {
  let next = 0;

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, () =>
    (async () => {
      while (next < tasks.length) {
        await tasks[next++]();
      }
    })(),
  );

  await Promise.all(workers);
}

async function applyChange(
  change: PlannedChange,
  host: ApplyHost,
  subjects: Record<string, string>,
  plannedSubjects: Set<string>,
): Promise<{ subject: string; status: ChangeStatus }> {
  const subject = subjects[change.subject] ?? change.subject;
  const values = writableValues(change);

  const dangling = unresolvedReferences(
    values,
    change.parent,
    plannedSubjects,
    subjects,
  );

  if (dangling.length > 0) {
    throw new Error(
      `refers to ${dangling.join(', ')}, which this run did not create — writing it would link to nothing`,
    );
  }

  switch (change.op) {
    case 'create': {
      const created = await host.create({
        parent: subjects[change.parent!] ?? change.parent!,
        isA: change.isA ?? [],
        propVals: rewrite(values, subjects),
      });

      return { subject: created, status: 'applied' };
    }

    case 'set': {
      if (change.properties.length === 0) {
        return { subject, status: 'skipped' };
      }

      await host.set(subject, rewrite(values, subjects));

      return { subject, status: 'applied' };
    }

    case 'remove': {
      if (change.properties.length === 0) {
        return { subject, status: 'skipped' };
      }

      await host.remove(
        subject,
        change.properties.map(p => p.property),
      );

      return { subject, status: 'applied' };
    }

    case 'destroy':
      await host.destroy(subject);

      return { subject, status: 'applied' };
  }
}

/**
 * Orders creates ahead of everything else, and each create after every create
 * it refers to.
 *
 * Following only `parent` was not enough: an imported contact whose employer
 * points at an Organization created by the same run is not that Organization's
 * child, so it could be written first — and then the link was written as the
 * planner's placeholder subject, which never exists. That is silent data
 * corruption, and it is exactly what a linked import produces.
 *
 * The plan keeps intent order so the preview reads the way the run was written;
 * only applying needs dependency order.
 */
function createsFirst(changes: PlannedChange[]): PlannedChange[] {
  const creates = changes.filter(c => c.op === 'create');
  const rest = changes.filter(c => c.op !== 'create');
  const bySubject = new Map(creates.map(c => [c.subject, c]));

  const ordered: PlannedChange[] = [];
  const placed = new Set<string>();

  const place = (change: PlannedChange, seen: Set<string>) => {
    if (placed.has(change.subject) || seen.has(change.subject)) return;

    seen.add(change.subject);

    for (const dependency of referencedCreates(change, bySubject)) {
      place(dependency, seen);
    }

    placed.add(change.subject);
    ordered.push(change);
  };

  for (const create of creates) place(create, new Set());

  return [...ordered, ...rest];
}

/** Creates this change refers to, by parent or by any property value. */
function referencedCreates(
  change: PlannedChange,
  bySubject: Map<string, PlannedChange>,
): PlannedChange[] {
  const found: PlannedChange[] = [];

  const visit = (value: JSONValue) => {
    if (typeof value === 'string') {
      const hit = bySubject.get(value);

      if (hit && hit.subject !== change.subject) found.push(hit);
    } else if (Array.isArray(value)) {
      value.forEach(visit);
    } else if (value && typeof value === 'object') {
      Object.values(value).forEach(visit);
    }
  };

  if (change.parent) visit(change.parent);

  change.properties.forEach(property => visit(property.to));

  return found;
}

/**
 * Planned subjects that no longer have a real one.
 *
 * Reachable when two creates refer to each other: no order can satisfy both, so
 * one of them would write a link to a resource that does not exist. Reported
 * rather than written — a dangling link that looks like data is worse than a
 * change that refused.
 */
function unresolvedReferences(
  values: Record<string, JSONValue>,
  parent: string | undefined,
  plannedSubjects: Set<string>,
  subjects: Record<string, string>,
): string[] {
  const dangling = new Set<string>();

  const visit = (value: JSONValue) => {
    if (typeof value === 'string') {
      if (plannedSubjects.has(value) && subjects[value] === undefined) {
        dangling.add(value);
      }
    } else if (Array.isArray(value)) {
      value.forEach(visit);
    } else if (value && typeof value === 'object') {
      Object.values(value).forEach(visit);
    }
  };

  if (parent !== undefined) visit(parent);

  Object.values(values).forEach(visit);

  return [...dangling];
}

function writableValues(change: PlannedChange): Record<string, JSONValue> {
  return Object.fromEntries(
    change.properties
      .filter(p => p.to !== undefined)
      .map(p => [p.property, p.to as JSONValue]),
  );
}

/** Points values at the subjects creates actually got. */
function rewrite(
  values: Record<string, JSONValue>,
  subjects: Record<string, string>,
): Record<string, JSONValue> {
  if (Object.keys(subjects).length === 0) return values;

  const swap = (value: JSONValue): JSONValue => {
    if (typeof value === 'string') return subjects[value] ?? value;

    if (Array.isArray(value)) return value.map(swap);

    if (value && typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => [k, swap(v)]),
      );
    }

    return value;
  };

  return Object.fromEntries(
    Object.entries(values).map(([k, v]) => [k, swap(v)]),
  );
}

function outcome(
  change: PlannedChange,
  subject: string,
  status: ChangeStatus,
  error?: string,
): ChangeOutcome {
  return {
    op: change.op,
    planned: change.subject,
    subject,
    localId: change.localId,
    status,
    ...(error ? { error } : {}),
  };
}

function describeError(e: unknown): string {
  if (e instanceof Error) return `${e.name}: ${e.message}`;

  return String(e);
}
