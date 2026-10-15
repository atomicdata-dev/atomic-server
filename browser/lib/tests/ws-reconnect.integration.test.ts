import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import net from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { startServer, type ServerHandle } from './server-fixture.js';
import { Agent } from '../src/agent.js';
import { Store } from '../src/store.js';

/** A port nothing listens on yet: bind to 0, read the port, release it. */
async function freePort(): Promise<number> {
  const probe = net.createServer();
  await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as net.AddressInfo;
  await new Promise(resolve => probe.close(resolve));

  return port;
}

// Node's WebSocket fires only `error` on a refused connection, never `close`.
// The client used to schedule its retry on `close` alone, so a Store whose
// first attempt came before the server was up never connected at all
// (develop runs 5208 and 5211: upload-roundtrip logged "[WS] Connection
// failed" and then waited out its timeout).
describe('WebSocket reconnect', () => {
  let server: ServerHandle;

  beforeAll(async () => {
    server = await startServer();
  }, 120_000);

  afterAll(async () => {
    await server?.stop();
  });

  it('connects once the server comes up after a refused first attempt', async () => {
    const target = new URL(server.serverUrl);
    const port = await freePort();
    const agent = await Agent.fromSecret(server.agentSecret);
    const store = new Store({ serverUrl: `http://localhost:${port}`, agent });

    // Let the first attempt be refused, then put the server behind that port.
    await delay(1500);
    const proxy = net.createServer(socket => {
      const upstream = net.connect(Number(target.port), '127.0.0.1');
      socket.pipe(upstream);
      upstream.pipe(socket);
      socket.on('error', () => upstream.destroy());
      upstream.on('error', () => socket.destroy());
    });
    await new Promise<void>(resolve =>
      proxy.listen(port, '127.0.0.1', () => resolve()),
    );

    try {
      const start = Date.now();

      // The backoff after one failure is 2 s; allow a few more doublings.
      while (!store.serverConnected && Date.now() - start < 20_000) {
        await delay(100);
      }

      expect(store.serverConnected).toBe(true);
    } finally {
      store.disconnect();
      proxy.close();
    }
  }, 60_000);
});
