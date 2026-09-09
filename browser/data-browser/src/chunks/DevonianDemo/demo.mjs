// @wc-ignore-file
import { BrowserIntegrations } from '../../../../../integrations/localthought/browser';
import { endpoint } from '../../../../../integrations/github-issues/adapter';
import { get, set } from 'idb-keyval';
import { core, server, dataBrowser, Datatype, enableLoro } from '@tomic/lib';
import * as devonian from './devonian.js';
import { ensureAgentForDemo } from '../Demo/guestAgent';
import { buildTableFromSpec } from '../TablePage/createTableFromSpec';
import { Bridge } from '../../../../../integrations/github-issues/devonian/bridge.mjs';
import {
  AtomicPort,
  GitHubPort,
} from '../../../../../integrations/github-issues/devonian/ports.mjs';
import {
  fixtureTransport,
  proxyTransport,
} from '../../../../../integrations/github-issues/devonian/proxy.mjs';

export async function openDemo(store, options) {
  await enableLoro();
  await ensureAgentForDemo(store);
  await store.waitForClientDb(10000);
  const db = store.getClientDb();
  if (!db || !(await db.waitForReady()))
    throw new Error('Enable the browser database on the Sync page first.');
  const repository = options.sample ? 'demo/issues' : options.repository;
  endpoint(repository);
  const key = `devonian-demo:${JSON.stringify([store.getAgent().subject, repository, options.sample ? 'sample' : new URL(options.proxy).origin])}`;
  return navigator.locks.request(key, async () => {
    let state = await get(key);
    if (!state) {
      const actor = store.getAgent().subject;
      const drive = await store.newResource({
        noParent: true,
        isA: [server.classes.drive],
        propVals: {
          [core.properties.name]: options.sample
            ? 'Devonian sample tracker'
            : `GitHub: ${repository}`,
          [core.properties.read]: [actor],
          [core.properties.write]: [actor],
        },
      });
      store.registerLocalOnlyDrive(drive.subject);
      await drive.save();
      await store.createDefaultOntology(drive);
      const table = await buildTableFromSpec(
        store,
        {
          name: 'Issue Tracker',
          rowName: 'Issue',
          columns: [
            { name: 'Description', type: 'markdown' },
            {
              name: 'Status',
              type: 'select',
              options: ['Todo', 'Doing', 'Done'],
            },
            { name: 'GitHub issue number', type: 'number' },
          ],
          views: [
            {
              name: 'Board',
              kind: 'kanban',
              groupByColumn: 'Status',
              default: true,
            },
            { name: 'All issues', kind: 'table' },
          ],
        },
        {
          parent: drive.subject,
          driveSubject: drive.subject,
          addToOntology: async () => {},
        },
      );
      const provenance = await store.newResource({
        parent: drive.subject,
        isA: [core.classes.property],
        propVals: {
          [core.properties.name]: 'GitHub source',
          [core.properties.shortname]: 'github-source',
          [core.properties.description]:
            'Original author, identity and timestamps from GitHub.',
          [core.properties.datatype]: Datatype.JSON,
        },
      });
      await provenance.save();
      const folder = await store.newResource({
        parent: drive.subject,
        isA: [dataBrowser.classes.folder],
        propVals: { [core.properties.name]: 'Comments' },
      });
      await folder.save();
      await drive.set(dataBrowser.properties.commentsFolder, folder.subject);
      await drive.save();
      const config = {
        connection: {
          repository,
          drive: drive.subject,
          table: table.tableSubject,
          rowClass: table.classSubject,
          body: table.columns.Description,
          status: table.columns.Status,
          number: table.columns['GitHub issue number'],
          tags: table.tags.Status,
        },
        commentsFolder: folder.subject,
        provenance: provenance.subject,
      };
      state = {
        config,
        options: { sample: options.sample, proxy: options.proxy, repository },
        base: `https://atomicdata.dev/devonian-bridges/${crypto.randomUUID()}`,
        fixture: {},
        journal: {},
      };
      await db.flush();
      await set(key, state);
    }
    store.registerLocalOnlyDrive(state.config.connection.drive);
    store.setDrive(state.config.connection.drive);
    return { key, state };
  });
}

export async function syncDemo(store, demo) {
  return navigator.locks.request(demo.key, async () => {
    const state = await get(demo.key);
    const save = () => set(demo.key, state);
    const call = state.options.sample
      ? fixtureTransport(state.fixture, save)
      : proxyTransport({
          url: state.options.proxy,
          repository: state.options.repository,
          journal: state.journal,
          save,
          dispatch: (path, init) =>
            client(state.options.proxy).request(
              state.config.connection.drive,
              store.getAgent().subject,
              state.connection,
              'github-issues',
              path,
              init,
            ),
        });
    const bridge = new Bridge({
      devonian,
      local: new AtomicPort(store, state.config),
      remote: new GitHubPort(null, state.config.connection, call),
      base: state.base,
      snapshot: state.bridge,
      save: async snapshot => {
        await store.getClientDb().flush();
        state.bridge = snapshot;
        await save();
      },
    });
    await bridge.sync();
    demo.state = state;
    return Object.keys(bridge.records).length;
  });
}

export async function demoRows(store, demo) {
  const local = new AtomicPort(store, demo.state.config);
  const issues = await local.list('issue');
  for (const row of issues)
    row.comments = await local.list('comment:ui', { issueId: row.id });
  return issues;
}

export async function editAtomic(store, demo, command, id, text) {
  const port = new AtomicPort(store, demo.state.config);
  if (command === 'create')
    await port.create(
      'issue',
      { title: text, body: '', status: 'Todo' },
      crypto.randomUUID(),
    );
  else if (command === 'comment')
    await port.create(
      'comment:ui',
      { body: text },
      crypto.randomUUID(),
      undefined,
      { issueId: id },
    );
  else {
    const row = await port.get('issue', id);
    await port.update('issue', id, {
      ...row.value,
      status: row.value.status === 'Done' ? 'Todo' : 'Done',
    });
  }
  await store.getClientDb().flush();
}

export async function editFixture(demo, command, number, text) {
  return navigator.locks.request(demo.key, async () => {
    const state = await get(demo.key);
    const call = fixtureTransport(state.fixture, () => set(demo.key, state));
    if (command === 'create')
      await call(
        'create_issue',
        { title: text, body: '' },
        crypto.randomUUID(),
      );
    else if (command === 'comment')
      await call('create_comment', { number, body: text }, crypto.randomUUID());
    else {
      const issue = state.fixture.issues.find(r => r.number === number);
      await call(
        'update_issue',
        {
          number,
          title: issue.title,
          body: issue.body,
          state: issue.state === 'open' ? 'closed' : 'open',
        },
        crypto.randomUUID(),
      );
    }
    demo.state = state;
  });
}

const handoffKey = 'devonian-browser-handoff';
const resumeKey = 'devonian-browser-resume';
const client = origin =>
  new BrowserIntegrations(
    localStorage,
    async () => {
      throw new Error('Devonian uses its own resource lenses');
    },
    origin,
  );
export async function connectDemo(store, options, secret) {
  const demo = await openDemo(store, { ...options, sample: false });
  const result = await client(options.proxy).start(
    demo.state.config.connection.drive,
    store.getAgent().subject,
    'github-issues',
    `${location.origin}/app/devonian-demo`,
    secret,
  );
  sessionStorage.setItem(
    handoffKey,
    JSON.stringify({ key: demo.key, state: result.state }),
  );
  location.assign(result.url);
}
export async function resumeDemo(store) {
  const url = new URL(location.href);
  const callbackCode = url.searchParams.get('connection_code');
  const callbackState = url.searchParams.get('integration_state');
  const handoff = JSON.parse(sessionStorage.getItem(handoffKey) ?? 'null');
  // Save the validated handoff before removing credentials from the URL, so a
  // reload while OPFS opens cannot abandon the completed proxy consent.
  if (callbackCode || callbackState) {
    history.replaceState(null, '', url.pathname);
    if (!handoff || callbackState !== handoff.state || !callbackCode)
      throw new Error('Invalid connection callback state');
    handoff.code = callbackCode;
    sessionStorage.setItem(handoffKey, JSON.stringify(handoff));
  }
  const code = handoff?.code;
  const stateId = handoff?.state;
  const key = code ? handoff.key : sessionStorage.getItem(resumeKey);
  if (!key) {
    if (callbackCode || callbackState)
      throw new Error('Missing browser connection handoff');
    return;
  }
  const saved = await get(key);
  if (!saved) throw new Error('Missing local tracker');
  const demo = await openDemo(store, saved.options);
  if (demo.key !== key) throw new Error('Connection belongs to another agent');
  if (code) {
    if (!handoff.finished) {
      client(saved.options.proxy).finish(
        saved.config.connection.drive,
        store.getAgent().subject,
        stateId,
        code,
      );
      handoff.finished = true;
      sessionStorage.setItem(handoffKey, JSON.stringify(handoff));
    }
    demo.state.connection = stateId;
    await set(key, demo.state);
    sessionStorage.removeItem(handoffKey);
    sessionStorage.setItem(resumeKey, key);
  }
  return demo;
}
