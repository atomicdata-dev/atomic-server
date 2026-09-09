/**
 * Full TS-side integration test for the unified upload path:
 *   Store.uploadFiles → local Tree::Blobs + Loro commit → WS sync to server →
 *   server fires BLOB_REQUEST → client answers BLOB_RESPONSE → server stores
 *   blob → HTTP GET /download/files/<hash> returns the bytes.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

import { startServer, type ServerHandle } from './server-fixture.js';
import { Agent } from '../src/agent.js';
import { Store } from '../src/store.js';
import { NodeClientDb } from '../src/client-db.node.js';
import type { ClientDbWorker } from '../src/client-db.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const wasmPath = path.resolve(here, '../../../wasm/pkg/atomic_wasm_bg.wasm');

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('upload roundtrip via unified sync path', () => {
  let server: ServerHandle;

  beforeAll(async () => {
    server = await startServer();
  }, 120_000);

  afterAll(async () => {
    await server?.stop();
  });

  it('uploads, syncs, and serves the blob via /download/files/<hash>', async () => {
    const agent = await Agent.fromSecret(server.agentSecret);

    const clientDb = new NodeClientDb({
      wasmPath,
      baseUrl: server.serverUrl,
    });
    await clientDb.init();

    const store = new Store({ serverUrl: server.serverUrl, agent });
    store.setClientDb(clientDb as unknown as ClientDbWorker);

    // Give the WS handshake a beat to authenticate.
    await delay(500);

    // A fresh server has no resource at its root URL: the agent's home is
    // the key-derived private drive, materialized by the client exactly as
    // the data-browser does at sign-in. Creating a File under a parent that
    // does not exist on the server is refused by the rights check.
    const drive = (await store.ensurePrivateDrive()).subject;

    const data = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
    const file = new File([data], 'hello.bin', {
      type: 'application/octet-stream',
    });

    const [subject] = await store.uploadFiles([file], drive);
    expect(subject).toBeTruthy();

    const hashBytes = await clientDb.blake3Hash(data);
    const hex = bytesToHex(hashBytes);
    const downloadUrl = `${server.serverUrl}/download/files/${hex}`;

    // Poll the server's CAS endpoint until the blob shows up. The sync push
    // is asynchronous (Loro update → server import_sync_push → BLOB_REQUEST →
    // our BLOB_RESPONSE → server inserts into Tree::Blobs).
    const deadline = Date.now() + 15_000;
    let lastStatus = 0;
    let lastBody = '';

    while (Date.now() < deadline) {
      const res = await fetch(downloadUrl);
      lastStatus = res.status;

      if (res.ok) {
        const buf = new Uint8Array(await res.arrayBuffer());
        expect(Array.from(buf)).toEqual(Array.from(data));
        // Close the WS so no more frames arrive. We deliberately DO NOT
        // call `clientDb.destroy()` — under `isolate: true` the worker
        // forks dies after the file finishes, and tearing down the WASM
        // module while pending WS callbacks still hold references panics
        // with "null pointer passed to rust" / "Rust value borrowed".
        store.disconnect();

        return;
      }

      lastBody = await res.text().catch(() => '');
      await delay(250);
    }

    store.disconnect();
    throw new Error(
      `download never returned bytes (last status: ${lastStatus}, body: ${lastBody.slice(0, 200)})`,
    );
  }, 60_000);
});
