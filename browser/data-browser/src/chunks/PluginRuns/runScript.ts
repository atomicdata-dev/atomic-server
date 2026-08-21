import {
  applyHostFromStore,
  applyPlan,
  ensureSchema,
  findSchema,
  planHostFromStore,
  planVerdict,
  parseVerdict,
  describePlugin,
  errorMessageFromResponse,
  pluginSchema,
  recordRun,
  runPlugin,
  type ApplyReport,
  type EnsuredSchema,
  type RunPlan,
  type RunTrigger,
  type Verdict,
  type PluginManifest,
  server,
  useStore,
  type Store,
} from '@tomic/react';
import pluginWorkerUrl from '@tomic/lib/plugin-run.worker.js?url';
import { useEffect, useState } from 'react';
import { signRequest } from '@tomic/react';

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
  source = STARTER_SOURCE,
): Promise<string> {
  const schema = await pluginClassesFor(store, target.drive);

  const plugin = await store.newResource({
    parent: target.parent,
    isA: [schema.classes['plugin-script']],
    propVals: {
      'https://atomicdata.dev/properties/name': name,
      [schema.properties['plugin-source']]: source,
      [schema.properties.trigger]: 'manual',
    },
  });
  await plugin.save();

  return plugin.subject;
}

/** Replaces a plugin's source, for an author iterating on it. */
export async function setPluginSource(
  store: Store,
  plugin: string,
  drive: string,
  source: string,
): Promise<void> {
  const schema = await pluginClassesFor(store, drive);
  const resource = await store.getResource(plugin);
  await resource.set(schema.properties['plugin-source'], source);
  await resource.save();
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

/**
 * A plugin's source, kept current as it is edited.
 *
 * The property is drive-local, so it is resolved through the schema rather than
 * a constant; `undefined` means still loading, `''` means genuinely empty.
 */
export function usePluginSource(
  store: Store,
  plugin: string,
  drive: string | undefined,
): string | undefined {
  const [source, setSource] = useState<string>();

  useEffect(() => {
    if (!drive) return;

    let cancelled = false;

    const read = async () => {
      const schema = await pluginClassesFor(store, drive);
      const resource = await store.getResource(plugin);
      const value = resource.get(schema.properties['plugin-source']);

      if (!cancelled) setSource(typeof value === 'string' ? value : '');
    };

    void read();

    // The assistant edits the source while this page is open, so follow it.
    const unsubscribe = store.subscribe(plugin, () => void read());

    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [store, plugin, drive]);

  return source;
}

/**
 * What a plugin declares it needs, read from its own source.
 *
 * Evaluated in the sandbox rather than parsed, so the declaration is whatever
 * the plugin actually exports — and a plugin that fails to load simply declares
 * nothing, with the reason surfacing when it is run.
 */
export function usePluginManifest(source: string | undefined): PluginManifest {
  const [manifest, setManifest] = useState<PluginManifest>({ secrets: [] });

  useEffect(() => {
    if (!source) {
      setManifest({ secrets: [] });

      return;
    }

    let cancelled = false;

    void describePlugin(source, {
      createWorker: () =>
        new Worker(pluginWorkerUrl, { type: 'module' }) as never,
      timeoutMs: 5000,
    }).then(found => {
      if (!cancelled) setManifest(found);
    });

    return () => {
      cancelled = true;
    };
  }, [source]);

  return manifest;
}

export interface PreparedRun {
  plan: RunPlan;
  trigger: RunTrigger;
  timedOut: boolean;
  /** True when the run happened on the server rather than in a Worker. */
  serverPlaced: boolean;
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
  target?: { plugin: string; drive: string },
): Promise<PreparedRun> {
  // A plugin that reaches the network or spends a credential cannot run in the
  // browser: the sandbox has no I/O, and a secret the page could read would not
  // be a secret. Placement follows from that rather than being configured.
  const serverPlaced = target ? await needsServer(store, target) : false;

  const { verdict, timedOut } = serverPlaced
    ? await runOnServer(store, source, trigger, target!)
    : await runPlugin(
        source,
        { trigger },
        {
          createWorker: () =>
            new Worker(pluginWorkerUrl, { type: 'module' }) as never,
        },
      );

  const plan = await planVerdict(verdict, planHostFromStore(store));

  return { plan, trigger, timedOut, serverPlaced };
}

/**
 * A plugin belongs on the server once it has a secret: that is the only way it
 * can reach anything, and the browser could never hold one.
 */
async function needsServer(
  store: Store,
  target: { plugin: string; drive: string },
): Promise<boolean> {
  const agent = store.getAgent();

  if (!agent) return false;

  const url = `${store.getServerUrl()}/plugin-secret?drive=${encodeURIComponent(
    target.drive,
  )}&plugin=${encodeURIComponent(target.plugin)}`;

  try {
    const response = await fetch(url, {
      headers: await signRequest(url, agent, {}),
    });

    if (!response.ok) return false;

    const view = (await response.json()) as { secrets?: unknown[] };

    return (view.secrets?.length ?? 0) > 0;
  } catch {
    // Unreachable server: fall back to the browser, where the plugin will fail
    // on its own terms rather than on a failed capability probe.
    return false;
  }
}

/** Runs in the embedded WASM runtime, which has the guards and the secrets. */
async function runOnServer(
  store: Store,
  source: string,
  trigger: RunTrigger,
  target: { plugin: string; drive: string },
): Promise<{ verdict: Verdict; timedOut: boolean }> {
  const agent = store.getAgent();

  if (!agent) throw new Error('Not signed in');

  const url = `${store.getServerUrl()}/plugin-run`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      ...(await signRequest(url, agent, {})),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      drive: target.drive,
      plugin: target.plugin,
      source,
      input: JSON.stringify({ trigger }),
    }),
  });

  if (!response.ok) {
    throw new Error(
      errorMessageFromResponse(await response.text(), response.status),
    );
  }

  // Absent fields arrive as `null`, not `undefined`: `error !== undefined` was
  // true for every successful run, so every one of them took the error branch
  // and reported "the run produced nothing".
  const body = (await response.json()) as {
    verdict?: string | null;
    error?: string | null;
  };

  if (body.error || !body.verdict) {
    return {
      verdict: {
        intents: [],
        problems: [
          {
            severity: 'error',
            message: body.error ?? 'the run produced nothing',
          },
        ],
      },
      timedOut: false,
    };
  }

  return { verdict: parseVerdict(JSON.parse(body.verdict)), timedOut: false };
}

/**
 * Plans a verdict that already exists, without running anything.
 *
 * A background run happened hours ago; reviewing it should not run the plugin
 * again. Doing so would hit the API a second time and could show a different
 * diff from the one being approved.
 */
export async function prepareFromVerdict(
  store: Store,
  verdictJson: string,
  trigger: RunTrigger,
): Promise<PreparedRun> {
  const verdict = parseVerdict(JSON.parse(verdictJson));
  const plan = await planVerdict(verdict, planHostFromStore(store));

  return { plan, trigger, timedOut: false, serverPlaced: true };
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
