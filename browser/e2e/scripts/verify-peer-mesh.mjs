// Real signaling + WebRTC + OPFS, with AtomicServer data requests disabled.
// Prerequisites: cargo build -p atomic-server; wasm-pack build wasm --target web.
import { chromium } from '@playwright/test';
import { createServer } from 'vite';
import { fileURLToPath } from 'node:url';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const dir = await mkdtemp(join(tmpdir(), 'atomic-peer-'));
const backend = spawn(
  join(root, 'target/debug/atomic-server'),
  [
    '--port',
    '6791',
    '--data-dir',
    join(dir, 'data'),
    '--config-dir',
    join(dir, 'config'),
    '--cache-dir',
    join(dir, 'cache'),
  ],
  { cwd: root, stdio: 'ignore' },
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
const deadline = setTimeout(() => browser.close(), 180000);
try {
  for (let attempt = 0; ; attempt++) {
    try {
      await fetch('http://localhost:6791/');
      break;
    } catch {
      if (attempt > 100 || backend.exitCode !== null)
        throw new Error('Signaling server did not start');
      await new Promise(resolve => setTimeout(resolve, 200));
    }
  }
  const pages = [];
  const errors = [];
  for (let i = 0; i < 8; i++) {
    const page = await browser.newPage();
    page.on('pageerror', error => {
      if (!error.message.includes('ws://127.0.0.1:1'))
        errors.push(error.message);
    });
    page.on('console', message => {
      if (message.text().startsWith('PEER_STATUS')) {
        console.log(i, message.text());
        if (
          !/^PEER_STATUS (Waiting|Connected|Disconnected|Peer disconnected|WebRTC|Unexpected peer identity)/.test(
            message.text(),
          )
        )
          errors.push(message.text());
      }
    });
    await page.goto('http://localhost:6772/');
    await page.evaluate(async () => {
      window.harness =
        await import('/browser/e2e/scripts/peer-sync-harness.ts');
      window.state = await window.harness.openPeer();
    });
    pages.push(page);
  }
  const identities = await Promise.all(
    pages.map(page => page.evaluate(() => window.state.agent.subject)),
  );
  const drive = await pages[0].evaluate(() =>
    window.harness.createDrive(window.state.store),
  );
  await pages[0].evaluate(
    async ({ drive, identities }) => {
      const r = window.state.store.resources.get(drive);
      for (const prop of ['read', 'write'])
        await r.set(
          `https://atomicdata.dev/properties/${prop}`,
          identities,
          false,
        );
      await r.save();
    },
    { drive, identities },
  );
  const room = randomBytes(32).toString('hex');
  const connect = page =>
    page.evaluate(
      ({ drive, room, expectedPeer }) => {
        window.state.store.registerLocalOnlyDrive(drive);
        window.state.store.setDrive(drive);
        window.link = new window.harness.BrowserPeerSync(window.state.store, {
          drive,
          room,
          expectedPeer,
          signalingUrl: 'ws://localhost:6791/webrtc-signal',
          iceServers: [],
          onStatus: status => {
            window.peerStatus = status;
            console.log('PEER_STATUS', status);
          },
        });
      },
      { drive, room, expectedPeer: identities[0] },
    );
  for (const page of pages) {
    await connect(page);
    await page.waitForFunction(
      drive =>
        window.state.store.resources
          .get(drive)
          ?.get('https://atomicdata.dev/properties/name') === 'Peer workspace',
      drive,
      { timeout: 30000 },
    );
  }
  for (const page of pages)
    await page.waitForFunction(
      () => window.peerStatus === 'Connected to 7 browsers',
      undefined,
      { timeout: 45000 },
    );
  console.log('PASS eight distinct agents form a full authenticated mesh');
  const overflow = await pages[0].evaluate(
    ({ room }) =>
      new Promise(resolve => {
        const socket = new WebSocket('ws://localhost:6791/webrtc-signal');
        const timer = setTimeout(() => {
          socket.close();
          resolve(false);
        }, 5000);
        socket.onopen = () =>
          socket.send(
            JSON.stringify({ type: 'join', room, peer: 'f'.repeat(64) }),
          );
        socket.onclose = () => {
          clearTimeout(timer);
          resolve(true);
        };
      }),
    { room },
  );
  if (!overflow) throw new Error('Ninth browser was not refused');
  console.log('PASS ninth room member is refused');
  const subjects = await Promise.all(
    pages.map((page, i) =>
      page.evaluate(
        async ({ drive, i }) => {
          const r = await window.state.store.newResource({
            isA: 'https://atomicdata.dev/classes/Folder',
            parent: drive,
            propVals: { 'https://atomicdata.dev/properties/name': `From ${i}` },
          });
          await r.save();
          return r.subject;
        },
        { drive, i },
      ),
    ),
  );
  for (const page of pages)
    await page.waitForFunction(
      subjects =>
        subjects.every(subject =>
          window.state.store.resources.get(subject)?.isReady(),
        ),
      subjects,
      { timeout: 30000 },
    );
  console.log('PASS every browser receives all concurrent creations');
  for (const page of pages)
    await page.evaluate(drive => {
      const presence = window.state.store.getPresence(drive);
      window.off = presence.subscribe(() => {});
      presence.setLocal({ resource: drive });
    }, drive);
  for (const page of pages)
    await page.waitForFunction(
      drive => window.state.store.getPresence(drive).getSnapshot().length === 8,
      drive,
      { timeout: 15000 },
    );
  console.log('PASS all eight agents see group presence');
  const file = await pages[0].evaluate(
    async drive =>
      (
        await window.state.store.uploadFiles(
          [new File(['mesh attachment'], 'mesh.txt', { type: 'text/plain' })],
          drive,
        )
      )[0],
    drive,
  );
  for (const page of pages)
    await page.waitForFunction(
      async subject => {
        const did = window.state.store.resources
          .get(subject)
          ?.get('https://atomicdata.dev/properties/blob');
        if (!did) return false;
        const hash = Uint8Array.from(
          did
            .split(':')
            .pop()
            .match(/../g)
            .map(byte => parseInt(byte, 16)),
        );
        const bytes = await window.state.db.getBlob(hash);
        return bytes && new TextDecoder().decode(bytes) === 'mesh attachment';
      },
      file,
      { timeout: 30000 },
    );
  console.log('PASS attachment bytes reach all eight replicas');
  await pages[0].evaluate(() => window.link.close());
  const subject = subjects[1];
  await pages[1].evaluate(async subject => {
    const r = window.state.store.resources.get(subject);
    await r.set(
      'https://atomicdata.dev/properties/name',
      'Creator left',
      false,
    );
    await r.save();
  }, subject);
  for (const page of pages.slice(1))
    await page.waitForFunction(
      subject =>
        window.state.store.resources
          .get(subject)
          ?.get('https://atomicdata.dev/properties/name') === 'Creator left',
      subject,
      { timeout: 15000 },
    );
  console.log(
    'PASS remaining seven collaborate after invitation creator leaves',
  );
  await pages[0].evaluate(async subject => {
    const r = window.state.store.resources.get(subject);
    await r.set(
      'https://atomicdata.dev/properties/description',
      'Offline creator',
      false,
    );
    await r.save();
  }, subject);
  await connect(pages[0]);
  for (const page of pages)
    await page.waitForFunction(
      subject => {
        const r = window.state.store.resources.get(subject);
        return (
          r?.get('https://atomicdata.dev/properties/name') === 'Creator left' &&
          r?.get('https://atomicdata.dev/properties/description') ===
            'Offline creator'
        );
      },
      subject,
      { timeout: 30000 },
    );
  console.log(
    'PASS rejoining browser reconciles offline edits across the group',
  );
  await pages[1].evaluate(
    async subject => window.state.store.resources.get(subject).destroy(),
    subject,
  );
  for (const page of pages)
    await page.waitForFunction(
      subject => !window.state.store.resources.has(subject),
      subject,
      { timeout: 30000 },
    );
  await new Promise(resolve => setTimeout(resolve, 2500));
  for (const page of pages)
    await page.waitForFunction(
      () => window.peerStatus === 'Connected to 7 browsers',
      undefined,
      { timeout: 15000 },
    );
  if (errors.length) throw new Error(errors.join('\n'));
  console.log('PASS signed deletion converges across eight browsers');
} finally {
  clearTimeout(deadline);
  await browser.close();
  await vite.close();
  backend.kill('SIGTERM');
}
