import {
  applyHostFromStore,
  applyPlan,
  ensureSchema,
  findSchema,
  planHostFromStore,
  planVerdict,
  pluginSchema,
  recordRun,
  runPlugin,
  type ApplyReport,
  type EnsuredSchema,
  type RunPlan,
  type RunTrigger,
  type Store,
} from '@tomic/react';
import pluginWorkerUrl from '@tomic/lib/plugin-run.worker.js?url';

/**
 * Running a plugin and applying what it proposed are separate calls on purpose.
 *
 * Everything in {@link prepareRun} is safe to do unasked — a run holds no
 * authority and cannot write. {@link applyRun} is the only part that needs
 * consent, which is what the dialog between them is for.
 */

/** Resolved once per drive: plugin classes are code-first, so drive-local. */
const schemaByDrive = new Map<string, Promise<EnsuredSchema>>();

/** What a read-only lookup found, for surfaces that must answer synchronously. */
const knownClasses = new Map<string, string | undefined>();
const lookedUp = new Set<string>();

/**
 * The plugin class of a drive, if it already has one, without creating it.
 *
 * `available()` on an action is synchronous, so the first call starts a lookup
 * and returns undefined; the menu shows the action from the next render on.
 * Deliberately read-only — opening a context menu must not bring a schema into
 * existence.
 */
export function pluginClassNow(
  store: Store,
  drive: string,
): string | undefined {
  if (!lookedUp.has(drive)) {
    lookedUp.add(drive);
    void findSchema(store, drive, pluginSchema())
      .then(schema =>
        knownClasses.set(drive, schema.classes?.['plugin-script']),
      )
      .catch(() => knownClasses.set(drive, undefined));
  }

  return knownClasses.get(drive);
}

export function pluginClassesFor(
  store: Store,
  drive: string,
): Promise<EnsuredSchema> {
  const cached = schemaByDrive.get(drive);

  if (cached) return cached;

  const resolving = ensureSchema(store, drive, pluginSchema());
  schemaByDrive.set(drive, resolving);

  return resolving;
}

export interface PreparedRun {
  plan: RunPlan;
  trigger: RunTrigger;
  timedOut: boolean;
}

/**
 * Runs the plugin and plans what it proposed. Writes nothing.
 *
 * The source is expected to already be an ES module exporting `run`; a builder
 * arrives with the plugin project format, and until then a plugin is written as
 * plain JS.
 */
export async function prepareRun(
  store: Store,
  source: string,
  trigger: RunTrigger,
): Promise<PreparedRun> {
  const { verdict, timedOut } = await runPlugin(
    source,
    { trigger },
    {
      createWorker: () =>
        new Worker(pluginWorkerUrl, { type: 'module' }) as never,
    },
  );

  const plan = await planVerdict(verdict, planHostFromStore(store));

  return { plan, trigger, timedOut };
}

export interface AppliedRun {
  report: ApplyReport;
  /** Subject of the record this run left behind. */
  logged: string;
}

/**
 * Applies an approved plan and records what happened.
 *
 * Logged whether or not every write succeeded: a partial import that left no
 * trace is the case this whole path exists to avoid.
 */
export async function applyRun(
  store: Store,
  prepared: PreparedRun,
  target: { plugin: string; drive: string },
): Promise<AppliedRun> {
  const report = await applyPlan(prepared.plan, applyHostFromStore(store));

  const logged = await recordRun(store, {
    parent: target.plugin,
    drive: target.drive,
    trigger: prepared.trigger,
    plan: prepared.plan,
    report,
  });

  return { report, logged };
}

/** Records a run that was refused, so the refusal is findable later. */
export async function recordBlockedRun(
  store: Store,
  prepared: PreparedRun,
  target: { plugin: string; drive: string },
): Promise<string> {
  return recordRun(store, {
    parent: target.plugin,
    drive: target.drive,
    trigger: prepared.trigger,
    plan: prepared.plan,
  });
}
