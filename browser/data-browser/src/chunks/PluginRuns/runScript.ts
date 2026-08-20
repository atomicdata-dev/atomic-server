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
  server,
  useStore,
  type Store,
} from '@tomic/react';
import pluginWorkerUrl from '@tomic/lib/plugin-run.worker.js?url';
import { useEffect, useState } from 'react';

/**
 * Running a plugin and applying what it proposed are separate calls on purpose.
 *
 * Everything in {@link prepareRun} is safe to do unasked — a run holds no
 * authority and cannot write. {@link applyRun} is the only part that needs
 * consent, which is what the dialog between them is for.
 */

/** Resolved once per drive: plugin classes are code-first, so drive-local. */
const schemaByDrive = new Map<string, Promise<EnsuredSchema>>();

/**
 * The drive's plugin schema, created if it is not there yet.
 *
 * Only called on the path that actually runs a plugin — creating classes is a
 * write, and no read path should trigger one.
 */
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

/**
 * The plugin class of a drive, if it already has one.
 *
 * Read-only: rendering a context menu must not bring a schema into existence.
 * Resolved into React state, because a module cache read during render never
 * re-renders when it later fills.
 *
 * Re-resolves when the drive's ontology changes, so a drive that gains plugin
 * classes — from a plugin created in this tab, or synced from elsewhere — shows
 * the action without a reload.
 */
export function usePluginClass(drive: string | undefined): string | undefined {
  const store = useStore();
  const [pluginClass, setPluginClass] = useState<string>();

  useEffect(() => {
    if (!drive) {
      setPluginClass(undefined);

      return;
    }

    let cancelled = false;
    let unsubscribe: (() => void) | undefined;

    const resolve = () =>
      findSchema(store, drive, pluginSchema())
        .then(schema => {
          if (!cancelled) setPluginClass(schema.classes?.['plugin-script']);
        })
        .catch(() => {
          if (!cancelled) setPluginClass(undefined);
        });

    (async () => {
      const driveResource = await store.getResource(drive);
      const ontology = driveResource.get(server.properties.defaultOntology) as
        | string
        | undefined;

      if (cancelled) return;

      await resolve();

      if (ontology && !cancelled) {
        unsubscribe = store.subscribe(ontology, () => {
          void resolve();
        });
      }
    })().catch(() => undefined);

    return () => {
      cancelled = true;
      unsubscribe?.();
    };
  }, [store, drive]);

  return pluginClass;
}

/**
 * The source a new plugin starts with.
 *
 * Doubles as the contract's documentation: the shape of `run`, what the input
 * carries, and the fact that returning intents is how a plugin writes. An LLM
 * asked to change a plugin reads this first, so it is written to be copied.
 */
const STARTER_SOURCE = `// A plugin proposes changes; the host reviews and writes them.
// Return intents — never write directly. You have no network and no clock:
// use input.trigger.at for the time.

export function run(input) {
  return {
    intents: [
      {
        op: 'create',
        localId: 'example',
        parent: input.trigger.subject,
        isA: [],
        set: {
          'https://atomicdata.dev/properties/name': 'Made by a plugin',
        },
      },
    ],
    problems: [],
  };
}
`;

/**
 * Creates a plugin, bringing the drive's plugin schema into existence if this
 * is the first one. Returns its subject.
 */
export async function createPlugin(
  store: Store,
  target: { parent: string; drive: string },
  name = 'New plugin',
): Promise<string> {
  const schema = await pluginClassesFor(store, target.drive);

  const plugin = await store.newResource({
    parent: target.parent,
    isA: [schema.classes['plugin-script']],
    propVals: {
      'https://atomicdata.dev/properties/name': name,
      [schema.properties['plugin-source']]: STARTER_SOURCE,
      [schema.properties.trigger]: 'manual',
    },
  });
  await plugin.save();

  return plugin.subject;
}

/**
 * Tells anything showing a plugin's runs that it just gained one.
 *
 * The run log is a collection query, and a query does not know a resource it
 * has never seen was created. Without this the log only caught up on reload —
 * which is exactly the moment someone wants to see what just happened.
 */
const runListeners = new Map<string, Set<() => void>>();

export function onRunsChanged(
  plugin: string,
  listener: () => void,
): () => void {
  const listeners = runListeners.get(plugin) ?? new Set();
  listeners.add(listener);
  runListeners.set(plugin, listeners);

  return () => {
    listeners.delete(listener);
  };
}

function notifyRunsChanged(plugin: string): void {
  runListeners.get(plugin)?.forEach(listener => listener());
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

  notifyRunsChanged(target.plugin);

  return { report, logged };
}

/** Records a run that was refused, so the refusal is findable later. */
export async function recordBlockedRun(
  store: Store,
  prepared: PreparedRun,
  target: { plugin: string; drive: string },
): Promise<string> {
  const logged = await recordRun(store, {
    parent: target.plugin,
    drive: target.drive,
    trigger: prepared.trigger,
    plan: prepared.plan,
  });

  notifyRunsChanged(target.plugin);

  return logged;
}
