import { chromium } from '@playwright/test';
import { readFile } from 'node:fs/promises';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1180, height: 850 } });
const errors = [];
page.on('pageerror', e => errors.push(e.message));
await page.setContent('<div id="root"></div>');
const source = await readFile(new URL('./view.js', import.meta.url), 'utf8');
await page.evaluate(async source => {
  const core = 'https://atomicdata.dev/properties/',
    rows = new Map();
  let next = 0;
  const row = (subject, props) => {
    const r = {
      subject,
      props,
      get(k) {
        return this.props[k];
      },
      set(k, v) {
        this.props[k] = v;
      },
      async save() {},
    };
    rows.set(subject, r);
    return r;
  };
  const p = Object.fromEntries(
    [
      'created',
      'heartbeat',
      'prompt',
      'state',
      'transcript',
      'error',
      'request',
      'answer',
      'cancel',
    ].map(k => [k, k]),
  );
  window.CONFIG = {
    app: 'app',
    data: 'data',
    rowClass: 'conversation',
    turnClass: 'turn',
    approvalClass: 'approval',
    properties: p,
  };
  row('app', { heartbeat: Date.now() });
  window.testRows = rows;
  const store = {
    async query({ property, value }) {
      return [...rows.values()]
        .filter(r => r.get(property) === value)
        .map(r => r.subject);
    },
    async getResource(s) {
      return rows.get(s);
    },
    async newResource({ parent, isA, propVals }) {
      return row('r' + ++next, {
        [core + 'parent']: parent,
        [core + 'isA']: isA,
        ...propVals,
      });
    },
  };
  const mod = await import(
    URL.createObjectURL(new Blob([source], { type: 'text/javascript' }))
  );
  await mod.view({ root: document.querySelector('#root'), store });
}, source);
await page
  .getByRole('textbox', { name: 'Message', exact: true })
  .fill('Help me build a local chat interface');
await page.getByRole('button', { name: 'Send', exact: true }).click();
await page.getByText('Queued · waiting for the local worker').waitFor();
await page.evaluate(() => {
  const turn = [...window.testRows.values()].find(r => r.get('prompt'));
  turn.set('state', 'completed');
  turn.set('transcript', [
    {
      id: 'answer',
      type: 'agentMessage',
      text: 'Yes. We can keep the conversations in Atomic and connect this view to your local Codex worker.\n\nThe first version supports saved conversations, streamed replies, and approval prompts.',
    },
  ]);
});
await page
  .getByText('Yes. We can keep the conversations', { exact: false })
  .waitFor();
await page.screenshot({
  path: new URL('./dist/chat-desktop.png', import.meta.url).pathname,
});
await page.evaluate(() => {
  const turn = [...window.testRows.values()].find(r => r.get('prompt'));
  turn.set('state', 'running');
  const props = {
    'https://atomicdata.dev/properties/parent': turn.subject,
    'https://atomicdata.dev/properties/name': 'Run command?',
    request: { choices: ['accept', 'decline'], params: { command: 'pwd' } },
  };
  window.testRows.set('approval', {
    subject: 'approval',
    props,
    get(k) {
      return this.props[k];
    },
    set(k, v) {
      this.props[k] = v;
    },
    async save() {},
  });
});
await page.getByRole('button', { name: 'Approve once', exact: true }).click();
if (
  (await page.evaluate(() => window.testRows.get('approval').get('answer'))) !==
  'accept'
)
  throw new Error('Approval was not saved');
await page.getByRole('button', { name: 'Stop', exact: true }).click();
if (
  !(await page.evaluate(() =>
    [...window.testRows.values()].some(r => r.get('cancel') === true),
  ))
)
  throw new Error('Stop was not saved');
await page
  .getByRole('button', { name: '+ New conversation', exact: true })
  .click();
await page
  .getByRole('textbox', { name: 'Message', exact: true })
  .fill('<img src=x onerror=alert(1)>');
await page.getByRole('button', { name: 'Send', exact: true }).click();
await page
  .getByText('<img src=x onerror=alert(1)>', { exact: true })
  .first()
  .waitFor();
if (await page.locator('img').count())
  throw new Error('Untrusted prompt became HTML');
await page.setViewportSize({ width: 390, height: 844 });
await page.screenshot({
  path: new URL('./dist/chat-mobile.png', import.meta.url).pathname,
});
if (errors.length) throw new Error(errors.join('\n'));
console.log(
  'VIEW_OK: create, send, queued state, saved reply, new conversation, approval, stop, escaped text, mobile',
);
await browser.close();
