import stringify from 'fast-json-stable-stringify';

export type SyncValue =
  | null
  | string
  | number
  | boolean
  | SyncValue[]
  | { [key: string]: SyncValue };

/** Canonical schema projection; null is an explicit deletion, undefined unseen. */
export type SyncRecord = Record<string, SyncValue> | null | undefined;
export interface SyncConflict {
  property: string;
  base: SyncValue | undefined;
  local: SyncValue | undefined;
  remote: SyncValue | undefined;
}
export interface SyncDecision {
  local: Record<string, SyncValue | undefined>;
  remote: Record<string, SyncValue | undefined>;
  createLocal: boolean;
  createRemote: boolean;
  deleteLocal: boolean;
  deleteRemote: boolean;
  conflicts: SyncConflict[];
  /** Only present when both observed sides agree, never on an unacknowledged write. */
  agreed?: Record<string, SyncValue> | null;
}
const equal = (a: unknown, b: unknown): boolean =>
  stringify(a) === stringify(b);

/** Three-way reconciliation over canonical properties. Provider adapters own
 * normalization; the shared engine owns conflict and checkpoint decisions. */
export function reconcileRecord(
  base: SyncRecord,
  local: SyncRecord,
  remote: SyncRecord,
): SyncDecision {
  const result: SyncDecision = {
    local: {},
    remote: {},
    createLocal: false,
    createRemote: false,
    deleteLocal: false,
    deleteRemote: false,
    conflicts: [],
  };

  if (equal(local, remote)) {
    if (local !== undefined) result.agreed = structuredClone(local);

    return result;
  }

  if (local === null || remote === null) {
    if (equal(local, base) && remote === null) result.deleteLocal = true;
    else if (equal(remote, base) && local === null) result.deleteRemote = true;
    else
      result.conflicts.push({
        property: '@record',
        base,
        local,
        remote,
      });

    return result;
  }

  // An unseen side can be created from a known side only when there is no
  // prior baseline. Absence from a partial API page is never a deletion.
  if (base !== undefined && (local === undefined || remote === undefined))
    return result;
  result.createLocal =
    base === undefined && local === undefined && remote !== undefined;
  result.createRemote =
    base === undefined && remote === undefined && local !== undefined;
  const properties = new Set([
    ...Object.keys(base ?? {}),
    ...Object.keys(local ?? {}),
    ...Object.keys(remote ?? {}),
  ]);

  for (const property of properties) {
    const before = base?.[property];
    const here = local?.[property];
    const there = remote?.[property];
    if (equal(here, there)) continue;
    if (equal(here, before)) result.local[property] = structuredClone(there);
    else if (equal(there, before))
      result.remote[property] = structuredClone(here);
    else
      result.conflicts.push({
        property,
        base: before,
        local: here,
        remote: there,
      });
  }

  return result;
}

/** A receipt is not an agreement until the actual canonical projections match. */
export function acknowledgedBaseline(
  local: Exclude<SyncRecord, undefined>,
  remote: Exclude<SyncRecord, undefined>,
): Exclude<SyncRecord, undefined> {
  if (!equal(local, remote))
    throw new Error('provider and Atomic projections still differ');

  return structuredClone(local);
}
