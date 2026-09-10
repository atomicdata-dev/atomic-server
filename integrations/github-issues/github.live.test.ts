/** Explicit opt-in: mutates only the dedicated private Ontola sandbox repo. */
import { it, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import {
  Agent,
  Store,
  core,
  ensureSchema,
  pluginSchema,
  signRequest,
  planVerdict,
  planHostFromStore,
  applyPlan,
  applyHostFromStore,
  recordRun,
} from '../../browser/lib/src/index.js';
import { enableLoro } from '../../browser/lib/src/loro-loader.js';
import {
  previewPluginSync,
  applyPluginSync,
  getPluginSync,
  pluginSyncSchedule,
  readConnectionSubjects,
} from '../../browser/lib/src/plugin-connection.js';
import { install } from './atomic.js';

const repository = 'ontola/atomic-github-sync-sandbox';
it.skipIf(process.env.ATOMIC_LIVE_GITHUB_REPO !== repository)(
  'syncs real GitHub issues through WASM, kanban and an independent JS automation',
  async () => {
    const token = process.env.GITHUB_TOKEN;
    if (!token)
      throw new Error(
        'GITHUB_TOKEN is required for the explicitly enabled live test',
      );
    const serverUrl = process.env.ATOMIC_GITHUB_TEST_SERVER;
    if (!serverUrl || !/^http:\/\/(localhost|127\.0\.0\.1):/.test(serverUrl))
      throw new Error('Use an isolated loopback Atomic test server');
    const github = async (path: string, method = 'GET', body?: unknown) => {
      const response = await fetch(
        `https://api.github.com/repos/${repository}${path}`,
        {
          method,
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'Content-Type': 'application/json',
          },
          body: body === undefined ? undefined : JSON.stringify(body),
        },
      );
      if (!response.ok)
        throw new Error(`GitHub ${method} ${path}: ${response.status}`);
      return response.status === 204 ? undefined : response.json();
    };
    expect((await github('')).private).toBe(true);
    await enableLoro();
    const keys = await Agent.generateKeyPair();
    const agent = Agent.fromSecret(
      Agent.buildSecret(keys.privateKey, `did:ad:agent:${keys.publicKey}`),
      'js',
    );
    const store = new Store({ serverUrl, agent });
    store.setServerConnected(true);
    const drive = await store.createDrive('Live GitHub sandbox', {
      agentName: 'Live integration test',
      description: '[atomic-data:dev-drive]',
    });
    store.setDrive(drive.subject);
    const c = await install(
      store,
      drive.subject,
      repository,
      await readFile('integrations/github-issues/plugin.js', 'utf8'),
      token,
    );
    const target = { drive: c.drive, plugin: c.plugin };
    const marker = `Atomic live ${Date.now()}`;
    const issueNumbers = new Set<number>();
    let scheduled = false;
    let lastRun = '';
    const post = async (path: string, body: unknown) => {
      const url = serverUrl + path;
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          ...(await signRequest(url, agent, {})),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      if (!res.ok)
        throw new Error(`${path}: ${res.status} ${await res.text()}`);
      return res.json();
    };
    const sync = async () => {
      let run = await previewPluginSync(store, {
        ...target,
        release: c.release,
        config: c,
      });
      expect(run.problems.filter(p => p.severity === 'error')).toEqual([]);
      lastRun = run.run;

      for (let i = 0; i < 100; i++) {
        run = await applyPluginSync(store, { ...target, run: run.run });
        if (run.status !== 'running') break;
      }
      expect(run.error).toBeNull();
      expect(run.status).toBe('complete');
      return run;
    };
    const fresh = async (subject: string) => {
      const r = await store.fetchResourceFromServer(subject, {
        noWebSocket: true,
      });
      r.getLoroDoc();
      return r;
    };
    const rows = async () =>
      Promise.all(
        (
          await readConnectionSubjects(
            store,
            c.drive,
            core.properties.parent,
            c.table,
          )
        ).map(fresh),
      );
    const card = async (number: number) => {
      const all = await rows();

      const found = all.find(r => r.get(c.number) === number);
      expect(found, `Atomic card for issue ${number}`).toBeDefined();
      return found!;
    };
    try {
      const remote = await github('/issues', 'POST', {
        title: marker,
        body: 'Created on GitHub',
        labels: ['bug'],
      });
      issueNumbers.add(remote.number);
      // GitHub create is acknowledged before its list endpoint always includes it.
      // Wait for the backfill fixture to become list-visible before first sync.
      for (let i = 0; i < 30; i++) {
        const visible = await github(
          '/issues?state=all&per_page=100&sort=created&direction=asc',
        );
        if (visible.some((r: any) => r.number === remote.number)) break;
        await new Promise(r => setTimeout(r, 1000));
        if (i === 29)
          throw new Error('Created issue did not become list-visible');
      }
      await sync();
      let row = await card(remote.number);
      expect(row.get(c.body)).toBe('Created on GitHub');
      expect(row.get(c.arrival)).toBeUndefined();
      console.log('PASS GitHub backfill -> Atomic card; no discovery event');
      await row.set(core.properties.name, marker + ' edited in Atomic');
      await row.set(c.status, [c.tags.Doing]);
      await row.save();
      await sync();
      let external = await github(`/issues/${remote.number}`);
      expect(external.title).toBe(marker + ' edited in Atomic');
      expect(external.labels.map((l: any) => l.name)).toEqual(
        expect.arrayContaining(['bug', 'atomic:doing']),
      );
      row = await card(remote.number);
      await row.set(c.status, [c.tags.Done]);
      await row.save();
      await sync();
      expect((await github(`/issues/${remote.number}`)).state).toBe('closed');
      await github(`/issues/${remote.number}`, 'PATCH', {
        state: 'open',
        body: 'Updated remotely',
      });
      await sync();
      row = await card(remote.number);
      expect(row.get(c.body)).toBe('Updated remotely');
      expect(row.get(c.status)).toEqual([c.tags.Todo]);
      console.log(
        'PASS bidirectional edits, Doing labels, Done closes, remote reopen',
      );
      const local = await store.newResource({
        parent: c.table,
        isA: [c.rowClass],
        propVals: {
          [core.properties.name]: marker + ' local card',
          [c.body]: 'Created in Atomic',
          [c.status]: [c.tags.Todo],
        },
      });
      await local.save();
      await sync();
      const updated = await fresh(local.subject);
      const number = updated.get(c.number) as number;
      expect(number).toBeGreaterThan(0);
      issueNumbers.add(number);
      expect((await github(`/issues/${number}`)).body).toBe(
        'Created in Atomic',
      );
      expect(updated.get(c.arrival)).toBeUndefined();
      console.log('PASS local card -> real GitHub issue');

      const schema = await ensureSchema(store, c.drive, pluginSchema());
      const inbox = await store.newResource({
        parent: c.drive,
        propVals: { [core.properties.name]: 'Test notifications' },
      });
      await inbox.save();
      const source = `export const manifest = {schemaVersion:1,secrets:[],operations:[]};
        export function run(ctx) { const row=ctx.read(ctx.trigger.subject); return {problems:[],intents:[{
          op:'create',localId:'notification',parent:${JSON.stringify(inbox.subject)},isA:[],set:{
          ${JSON.stringify(core.properties.name)}:row[${JSON.stringify(core.properties.name)}],
          ${JSON.stringify(core.properties.description)}:'Issue discovered: '+ctx.trigger.subject}}]}; }`;
      const automation = await store.newResource({
        parent: c.drive,
        isA: [schema.classes['plugin-script']],
        propVals: {
          [core.properties.name]: 'Issue discovery notification',
          [schema.properties['plugin-source']]: source,
          [schema.properties['automation-integrations']]: [c.plugin],
          [schema.properties['automation-trigger']]: {
            integration: c.plugin,
            event: 'issue-discovered',
          },
        },
      });
      await automation.save();
      const trigger = {
        kind: 'manual' as const,
        at: Date.now(),
        subject: row.subject,
      };
      const sample = await post('/plugin-run', {
        drive: c.drive,
        plugin: automation.subject,
        source,
        input: JSON.stringify({ trigger }),
      });
      expect(sample.error).toBeNull();
      const plan = await planVerdict(
        JSON.parse(sample.verdict),
        planHostFromStore(store),
      );
      expect(plan.blocked, JSON.stringify(plan)).toBe(false);
      const report = await applyPlan(plan, applyHostFromStore(store));
      await recordRun(store, {
        parent: automation.subject,
        drive: c.drive,
        source,
        trigger,
        plan,
        report,
      });
      await post('/plugin-trigger', {
        drive: c.drive,
        plugin: automation.subject,
        onEnter: true,
        onLeave: false,
        autoApply: true,
        filters: [
          { property: core.properties.parent, value: c.table },
          { property: c.arrival, value: 'remote' },
        ],
      });
      const discovery = await github('/issues', 'POST', {
        title: marker + ' new discovery',
        body: 'Must trigger automation',
      });
      issueNumbers.add(discovery.number);
      await pluginSyncSchedule(store, {
        ...target,
        run: lastRun,
        interval_seconds: 60,
      });
      scheduled = true;
      const deadline = Date.now() + 100000;
      let notifications: string[] = [];
      while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 2000));
        try {
          notifications = await readConnectionSubjects(
            store,
            c.drive,
            core.properties.parent,
            inbox.subject,
          );
        } catch (error) {
          // A concurrent insertion can invalidate a paginated read. Retry only
          // incomplete/changing membership; never turn authorization into empty.
          if (
            error instanceof Error &&
            /^(Incomplete connection query response|Connection membership changed during pagination)/.test(
              error.message,
            )
          )
            continue;
          throw error;
        }
        if (notifications.length === 2) break;
      }
      expect(notifications).toHaveLength(2);
      const notificationRows = await Promise.all(notifications.map(fresh));
      expect(notificationRows.map(r => r.get(core.properties.name))).toContain(
        discovery.title,
      );
      expect((await card(discovery.number)).get(c.arrival)).toBe('remote');
      expect((await getPluginSync(store, target))?.run).not.toBe(lastRun);
      console.log(
        'PASS background real-GitHub discovery -> independent JS notification, without a browser',
      );
    } finally {
      if (scheduled)
        await pluginSyncSchedule(store, {
          ...target,
          run: lastRun,
          interval_seconds: 0,
        });
      for (const number of issueNumbers)
        await github(`/issues/${number}`, 'PATCH', { state: 'closed' });
      console.log(`Test issues closed in ${repository}`);
    }
  },
  360000,
);
