import { Datatype } from './datatypes.js';
import { core } from './ontologies/core.js';
import {
  ensureSchema,
  type SchemaSpec,
  type SchemaStore,
} from './plugin-schema.js';
import type { ApplyReport } from './plugin-apply.js';
import type { RunPlan } from './plugin-plan.js';
import type { RunTrigger } from './plugin-sandbox.js';
import type { JSONValue } from './value.js';

/**
 * The record a run leaves behind.
 *
 * This is what makes an LLM-written plugin trustworthy to someone who did not
 * write it: not a description of what the code was supposed to do, but what it
 * actually did, every time it ran. It is also the only way to answer "why does
 * this resource say that" a week later.
 */

/**
 * Code-first, so it can move while triggers and preview are still being built.
 *
 * A function rather than a const on purpose: `index.ts` sits in an import cycle
 * with `parse.ts`, so a module-level `Datatype.STRING` is read before
 * `datatypes.js` has finished initializing and comes out undefined. Building
 * the spec on call sidesteps initialization order entirely.
 */
export function pluginSchema(): SchemaSpec {
  return {
    properties: [
      {
        shortname: 'plugin-source',
        name: 'Source',
        description:
          'The TypeScript the plugin runs. Compiled to a module before it reaches the sandbox.',
        datatype: Datatype.MARKDOWN,
      },
      {
        shortname: 'trigger',
        name: 'Trigger',
        description:
          'What started the run: manual, cron, a query edge, a webhook.',
        datatype: Datatype.STRING,
      },
      {
        shortname: 'started-at',
        name: 'Started at',
        description: 'When the host began the run.',
        datatype: Datatype.TIMESTAMP,
      },
      {
        shortname: 'run-status',
        name: 'Status',
        description: 'blocked, applied, partial or failed.',
        datatype: Datatype.STRING,
      },
      {
        shortname: 'run-problems',
        name: 'Problems',
        description: 'Everything the run and the planner reported.',
        datatype: Datatype.JSON,
      },
      {
        shortname: 'run-outcomes',
        name: 'Outcomes',
        description:
          'What happened to every planned change, including the ones never attempted.',
        datatype: Datatype.JSON,
      },
      {
        shortname: 'run-cursor',
        name: 'Cursor',
        description:
          'Resume token the run returned, so the next one is incremental.',
        datatype: Datatype.STRING,
      },
      {
        shortname: 'entrypoint',
        name: 'Entry point',
        description:
          'The plugin whose view() opens when someone opens this app.',
        datatype: Datatype.ATOMIC_URL,
      },
    ],
    classes: [
      {
        shortname: 'plugin-script',
        name: 'Plugin',
        description:
          'A plugin that proposes changes. Its run export returns intents the host reviews before writing anything.',
        requires: ['plugin-source'],
        recommends: ['trigger'],
      },
      {
        shortname: 'plugin-run',
        name: 'Plugin run',
        description:
          'One execution of a plugin: what triggered it, what it proposed, and what was written.',
        requires: ['trigger', 'started-at', 'run-status'],
        recommends: ['run-problems', 'run-outcomes', 'run-cursor'],
      },
      {
        shortname: 'app',
        name: 'App',
        description:
          'A parent whose children are its parts: its own ontology, the plugin that renders it, and any handlers that run on a schedule or a query edge. Sharing the app means sharing the subtree, which drive rights already do.',
        requires: ['entrypoint'],
      },
    ],
  };
}

export type RunStatus = 'blocked' | 'applied' | 'partial' | 'failed';

export interface RecordRunOptions {
  /** Where the run record lives. Usually the plugin resource. */
  parent: string;
  /** Drive whose ontology holds the plugin classes. */
  drive: string;
  trigger: RunTrigger;
  plan: RunPlan;
  /** Absent when the plan was blocked and never applied. */
  report?: ApplyReport;
  name?: string;
}

/**
 * Writes one run record and returns its subject.
 *
 * A blocked plan is recorded too. A run that refused to write is exactly the
 * kind of thing someone needs to find later, and leaving it unlogged would make
 * "it silently did nothing" indistinguishable from "it never ran".
 */
export async function recordRun(
  store: SchemaStore,
  options: RecordRunOptions,
): Promise<string> {
  const schema = await ensureSchema(store, options.drive, pluginSchema());
  const status = runStatus(options.plan, options.report);

  const propVals: Record<string, JSONValue> = {
    [core.properties.name]:
      options.name ?? defaultName(options.trigger, status),
    [schema.properties.trigger]: options.trigger.kind,
    [schema.properties['started-at']]: options.trigger.at,
    [schema.properties['run-status']]: status,
    [schema.properties['run-problems']]: problemsOf(options.plan),
    [schema.properties['run-outcomes']]: (options.report?.outcomes ??
      []) as unknown as JSONValue,
  };

  // Only after something was actually applied: persisting a cursor for a run
  // that wrote nothing would tell the next run to skip work never done.
  if (options.report && options.report.applied > 0 && options.plan.cursor) {
    propVals[schema.properties['run-cursor']] = options.plan.cursor;
  }

  const record = await store.newResource({
    parent: options.parent,
    isA: [schema.classes['plugin-run']],
    propVals,
  });
  await record.save();

  return record.subject;
}

export function runStatus(plan: RunPlan, report?: ApplyReport): RunStatus {
  if (plan.blocked || !report) return 'blocked';

  if (report.failed === 0) return 'applied';

  return report.applied > 0 ? 'partial' : 'failed';
}

/**
 * Problems worth keeping: everything the plan carried, plus everything attached
 * to a change, each tagged with the subject it concerns so the log reads
 * without the plan beside it.
 */
function problemsOf(plan: RunPlan): JSONValue {
  return [
    ...plan.problems,
    ...plan.changes.flatMap(change =>
      change.problems.map(problem => ({
        ...problem,
        subject: problem.subject ?? change.subject,
      })),
    ),
  ] as unknown as JSONValue;
}

function defaultName(trigger: RunTrigger, status: RunStatus): string {
  return `${trigger.kind} run — ${status}`;
}
