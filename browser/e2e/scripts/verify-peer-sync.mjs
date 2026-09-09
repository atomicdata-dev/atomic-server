/* eslint-disable no-shadow -- Playwright callbacks run in a separate browser realm. */
// Real signaling + WebRTC + OPFS, with AtomicServer data requests disabled.
// Run the SaaS peer_signaling example and set ATOMIC_PEER_SIGNALING_URL.
// Requires built WASM, but deliberately starts no AtomicServer data process.
import { chromium } from '@playwright/test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const signalingUrl = process.env.ATOMIC_PEER_SIGNALING_URL;
if (!signalingUrl)
  throw new Error(
    'Set ATOMIC_PEER_SIGNALING_URL to the running SaaS signaling endpoint',
  );
const vite = await createServer({
  configFile: false,
  root,
  cacheDir: join(root, 'browser/node_modules/.vite/peer-acceptance'),
  optimizeDeps: { entries: ['browser/e2e/scripts/peer-sync-harness.ts'] },
  server: { host: 'localhost', port: 6772, strictPort: true },
});
vite.middlewares.use((req, res, next) => {
  if (req.url !== '/') return next();
  res.setHeader('Content-Type', 'text/html');
  res.end('<!doctype html><title>Peer sync acceptance</title>');
});
await vite.listen();
const browser = await chromium.launch();
const deadline = setTimeout(() => browser.close(), 90000);

try {
  const errors = [];
  const a = await browser.newPage();
  const b = await browser.newPage();

  for (const [label, page] of [
    ['a', a],
    ['b', b],
  ]) {
    page.on('pageerror', error => {
      if (!error.message.includes('ws://127.0.0.1:1'))
        errors.push(error.message);
    });
    page.on('console', msg => {
      if (msg.text().startsWith('PEER_STATUS')) {
        console.log(label, msg.text());
        if (
          !/^PEER_STATUS (Waiting for a peer|Connected|Disconnected|Peer disconnected|WebRTC (transport closed|channel is not open))/.test(
            msg.text(),
          )
        )
          errors.push(msg.text());
      }
    });
    await page.goto('http://localhost:6772/');
  }

  const init = async (page, secret) =>
    page.evaluate(async secret => {
      window.harness =
        await import('/browser/e2e/scripts/peer-sync-harness.ts');
      window.state = await window.harness.openPeer(secret);

      return window.state.secret;
    }, secret);
  await init(a);
  const otherSecret = await init(b);
  const drive = await a.evaluate(() =>
    window.harness.createDrive(window.state.store),
  );
  const identities = await Promise.all(
    [a, b].map(page => page.evaluate(() => window.state.agent.subject)),
  );
  await a.evaluate(
    async ({ drive, identities }) => {
      const resource = window.state.store.resources.get(drive);
      for (const prop of ['read', 'write'])
        await resource.set(
          `https://atomicdata.dev/properties/${prop}`,
          identities,
          false,
        );
      await resource.save();
    },
    { drive, identities },
  );
  const room = randomBytes(32).toString('hex');
  const connect = async page =>
    page.evaluate(
      ({ drive, room, expectedPeer, signalingUrl }) => {
        const { store } = window.state;
        store.registerLocalOnlyDrive(drive);
        store.setDrive(drive);
        window.link = new window.harness.BrowserPeerSync(store, {
          drive,
          room,
          signalingUrl,
          expectedPeer,
          iceServers: [],
          onStatus: status => {
            window.peerStatus = status;
            console.log('PEER_STATUS', status);
          },
        });
      },
      {
        drive,
        room,
        signalingUrl,
        expectedPeer: page === a ? identities[1] : identities[0],
      },
    );
  await connect(a);
  await connect(b);
  await b.waitForFunction(
    drive =>
      window.state.store.resources
        .get(drive)
        ?.get('https://atomicdata.dev/properties/name') === 'Peer workspace',
    drive,
    { timeout: 30000 },
  );
  console.log('PASS initial authenticated drive replication');
  const subject = await a.evaluate(async drive => {
    const resource = await window.state.store.newResource({
      isA: 'https://atomicdata.dev/classes/Folder',
      parent: drive,
      propVals: { 'https://atomicdata.dev/properties/name': 'Shared folder' },
    });
    await resource.save();

    return resource.subject;
  }, drive);
  await b.waitForFunction(
    subject =>
      window.state.store.resources
        .get(subject)
        ?.get('https://atomicdata.dev/properties/name') === 'Shared folder',
    subject,
    { timeout: 30000 },
  );
  const edit = (page, property, value) =>
    page.evaluate(
      async ({ subject, property, value }) => {
        const resource = await window.state.store.getResource(subject);
        await resource.set(property, value, false);
        await resource.save();
      },
      { subject, property, value },
    );
  const name = 'https://atomicdata.dev/properties/name';
  const description = 'https://atomicdata.dev/properties/description';
  await Promise.all([edit(a, name, 'From A'), edit(b, description, 'From B')]);
  for (const page of [a, b])
    await page.waitForFunction(
      ({ subject, name, description }) => {
        const r = window.state.store.resources.get(subject);

        return r?.get(name) === 'From A' && r?.get(description) === 'From B';
      },
      { subject, name, description },
      { timeout: 30000 },
    );
  console.log('PASS concurrent signed edits converge');
  for (const page of [a, b])
    await page.evaluate(drive => {
      const presence = window.state.store.getPresence(drive);
      window.stopPresence = presence.subscribe(() => {});
      presence.setLocal({ resource: drive });
    }, drive);
  for (const page of [a, b])
    await page.waitForFunction(
      drive => window.state.store.getPresence(drive).getSnapshot().length >= 2,
      drive,
      { timeout: 15000 },
    );
  console.log('PASS presence crosses the peer link');
  const file = await a.evaluate(
    async drive =>
      (
        await window.state.store.uploadFiles(
          [new File(['peer attachment'], 'note.txt', { type: 'text/plain' })],
          drive,
        )
      )[0],
    drive,
  );
  await b.waitForFunction(
    async subject => {
      const resource = window.state.store.resources.get(subject);
      const did = resource?.get('https://atomicdata.dev/properties/blob');
      if (!did) return false;
      const hex = did.split(':').pop();
      const hash = Uint8Array.from(
        hex.match(/../g).map(byte => parseInt(byte, 16)),
      );
      const bytes = await window.state.db.getBlob(hash);

      return bytes && new TextDecoder().decode(bytes) === 'peer attachment';
    },
    file,
    { timeout: 30000 },
  );
  console.log('PASS attachment blob reaches peer storage');
  await b.evaluate(() => window.link.close());
  await edit(a, name, 'Offline A');
  await edit(b, description, 'Offline B');
  await connect(b);
  for (const page of [a, b])
    await page.waitForFunction(
      ({ subject, name, description }) => {
        const r = window.state.store.resources.get(subject);

        return (
          r?.get(name) === 'Offline A' && r?.get(description) === 'Offline B'
        );
      },
      { subject, name, description },
      { timeout: 30000 },
    );
  console.log('PASS reconnect reconciles offline edits');
  await b.evaluate(() => {
    window.link.close();
    window.state.db.destroy();
  });
  await b.reload();
  await init(b, otherSecret);
  const restored = await b.evaluate(
    async subject =>
      (await window.state.store.getResource(subject)).get(
        'https://atomicdata.dev/properties/name',
      ),
    subject,
  );
  if (restored !== 'Offline A') throw new Error('OPFS reload lost peer edits');
  console.log('PASS reload restores peer edits from OPFS');
  await connect(b);
  await b.waitForFunction(
    () => window.peerStatus?.startsWith('Connected'),
    undefined,
    { timeout: 30000 },
  );
  await a.evaluate(
    async subject => (await window.state.store.getResource(subject)).destroy(),
    subject,
  );
  await b.waitForFunction(
    subject => !window.state.store.resources.has(subject),
    subject,
    { timeout: 30000 },
  );
  console.log('PASS signed deletion reaches peer');
  await new Promise(resolve => setTimeout(resolve, 2500));
  if (errors.length) throw new Error(errors.join('\n'));
} finally {
  clearTimeout(deadline);
  await browser.close();
  await vite.close();
}
