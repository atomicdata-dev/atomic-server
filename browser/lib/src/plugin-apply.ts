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
}

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
  const outcomes: ChangeOutcome[] = [];
  const ordered = createsFirst(plan.changes);

  let stoppedEarly = false;

  for (const [index, change] of ordered.entries()) {
    if (stoppedEarly) {
      outcomes.push(outcome(change, change.subject, 'not-attempted'));

      continue;
    }

    try {
      const result = await applyChange(change, host, subjects);

      if (result.subject !== change.subject) {
        subjects[change.subject] = result.subject;
      }

      outcomes.push(outcome(change, result.subject, result.status));
    } catch (e) {
      outcomes.push(
        outcome(change, change.subject, 'failed', describeError(e)),
      );

      if (!options.continueOnError) {
        stoppedEarly = index < ordered.length - 1;
      }
    }
  }

  return {
    outcomes,
    subjects,
    stoppedEarly,
    applied: outcomes.filter(o => o.status === 'applied').length,
    skipped: outcomes.filter(o => o.status === 'skipped').length,
    failed: outcomes.filter(o => o.status === 'failed').length,
  };
}

async function applyChange(
  change: PlannedChange,
  host: ApplyHost,
  subjects: Record<string, string>,
): Promise<{ subject: string; status: ChangeStatus }> {
  const subject = subjects[change.subject] ?? change.subject;

  switch (change.op) {
    case 'create': {
      const created = await host.create({
        parent: subjects[change.parent!] ?? change.parent!,
        isA: change.isA ?? [],
        propVals: rewrite(propVals(change), subjects),
      });

      return { subject: created, status: 'applied' };
    }

    case 'set': {
      if (change.properties.length === 0) {
        return { subject, status: 'skipped' };
      }

      await host.set(subject, rewrite(propVals(change), subjects));

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
 * Orders creates ahead of everything else, parents ahead of their children.
 *
 * The plan keeps intent order so the preview reads the way the run was written;
 * applying needs dependency order so a child is never created under a parent
 * that does not exist yet.
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

    const parent = change.parent ? bySubject.get(change.parent) : undefined;

    if (parent) place(parent, seen);

    placed.add(change.subject);
    ordered.push(change);
  };

  for (const create of creates) place(create, new Set());

  return [...ordered, ...rest];
}

function propVals(change: PlannedChange): Record<string, JSONValue> {
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
