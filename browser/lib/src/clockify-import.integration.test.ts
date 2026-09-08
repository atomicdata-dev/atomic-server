import { expect, it, vi } from 'vitest';
import { importEntries } from '../../../integrations/clockify/plugin.js';
import { type Config } from '../../../integrations/clockify/model.js';
import { testStore } from './test-store.js';
import { timeTrackingSchema } from './time-tracking-schema.js';
import { parseVerdict } from './plugin-run.js';
import { planHostFromStore, planVerdict } from './plugin-plan.js';
import { applyHostFromStore, applyPlan } from './plugin-apply.js';
import { core } from './ontologies/core.js';
import { Resource } from './resource.js';
import { Datatype } from './datatypes.js';

/** Real Store, planner, Loro commits and DID reference rewriting; mocked transport. */
it('applies Clockify proposals with typed links and skips a repeated import', async () => {
  const { store, posted } = await testStore();
  // Datatype tags read the actual property cache at signing, not getProperty's mock.
  const baselineProperty = new Resource(core.properties.importBaseline);
  store.addResource(baselineProperty);
  await baselineProperty.set(core.properties.datatype, Datatype.JSON);
  const properties = timeTrackingSchema().properties;
  const terms = Object.fromEntries(
    properties.map(p => [p.shortname, `https://example.com/${p.shortname}`]),
  );
  vi.spyOn(store, 'getProperty').mockImplementation(async subject => {
    const p = properties.find(
      property => terms[property.shortname] === subject,
    );
    if (p)
      return {
        subject,
        shortname: p.shortname,
        datatype: p.datatype,
        description: p.description ?? '',
      };
    if (
      [
        core.properties.name,
        core.properties.localId,
        core.properties.importBaseline,
      ].some(property => property === subject)
    )
      return {
        subject,
        shortname: 'name',
        datatype:
          subject === core.properties.importBaseline
            ? Datatype.JSON
            : Datatype.STRING,
        description: '',
      };
    if (subject === core.properties.parent || subject === core.properties.isA)
      return {
        subject,
        shortname: 'builtin',
        datatype:
          subject === core.properties.parent
            ? Datatype.ATOMIC_URL
            : Datatype.RESOURCEARRAY,
        description: '',
      };
    throw new Error(`Unexpected property ${subject}`);
  });
  const c: Config = {
    workspace: 'a'.repeat(24),
    user: 'b'.repeat(24),
    userName: 'Person',
    drive: 'https://example.com',
    table: 'https://example.com/table',
    rowClass: 'https://example.com/TimeEntry',
    projectClass: 'https://example.com/Project',
    personClass: 'https://example.com/Person',
    lookbackDays: 7,
    properties: {
      start: terms['work-start'],
      end: terms['work-end'],
      project: terms['work-project'],
      person: terms['work-person'],
      billable: terms['work-billable'],
      identity: terms['work-source-id'],
    },
  };
  const bindings = new Map<string, string>();
  const saved = new Map<string, Record<string, unknown>>();
  const host = {
    query: (_p: string, identity: string) =>
      bindings.has(identity) ? [bindings.get(identity)!] : [],
    read: (subject: string) => saved.get(subject) ?? {},
    http: (r: { operation: string }) => ({
      status: 200,
      body: JSON.stringify(
        r.operation === 'projects'
          ? [{ id: 'c'.repeat(24), name: 'Project' }]
          : [
              {
                id: 'd'.repeat(24),
                userId: c.user,
                projectId: 'c'.repeat(24),
                description: 'Work',
                billable: true,
                timeInterval: {
                  start: '2026-09-02T08:00:00Z',
                  end: '2026-09-02T09:00:00Z',
                },
              },
            ],
      ),
    }),
  };
  const at = Date.parse('2026-09-08T00:00:00Z');
  const plan = await planVerdict(
    parseVerdict(importEntries(host, c, at)),
    planHostFromStore(store),
  );
  expect(plan.blocked, JSON.stringify(plan)).toBe(false);
  const base = applyHostFromStore(store);

  const remember = async (subject: string) => {
    const resource = await store.getResource(subject);
    saved.set(subject, resource.getPropVals());
    bindings.set(resource.get(c.properties.identity) as string, subject);
  };

  const interrupted = await applyPlan(
    plan,
    {
      ...base,
      create: async request => {
        const subject = await base.create(request);
        await remember(subject);
        throw new Error('Simulated lost receipt after durable creation');
      },
    },
    { concurrency: 1 },
  );
  expect(interrupted.failed).toBe(1);
  expect(saved.size).toBe(1);
  const retry = await planVerdict(
    parseVerdict(importEntries(host, c, at)),
    planHostFromStore(store),
  );
  expect(retry.blocked).toBe(false);
  const report = await applyPlan(retry, base);
  expect(report.failed).toBe(0);
  expect(report.applied).toBe(2);

  for (const outcome of report.outcomes) {
    const resource = await store.getResource(outcome.subject);
    saved.set(resource.subject, resource.getPropVals());
    bindings.set(
      resource.get(c.properties.identity) as string,
      resource.subject,
    );
  }

  const row = await store.getResource(
    bindings.get(`clockify:${c.workspace}:entry:${'d'.repeat(24)}`)!,
  );
  expect(row.get(c.properties.project)).toBe(
    bindings.get(`clockify:${c.workspace}:project:${'c'.repeat(24)}`),
  );
  expect(row.get(c.properties.person)).toBe(
    bindings.get(`clockify:${c.workspace}:person:${c.user}`),
  );
  expect(row.get(c.properties.start)).toBe(Date.parse('2026-09-02T08:00:00Z'));
  expect(row.get(c.properties.billable)).toBe(true);
  expect(
    posted.every(
      commit =>
        commit.loroUpdate instanceof Uint8Array && commit.loroUpdate.length > 0,
    ),
  ).toBe(true);
  expect(importEntries(host, c, at).intents).toEqual([]);
});
