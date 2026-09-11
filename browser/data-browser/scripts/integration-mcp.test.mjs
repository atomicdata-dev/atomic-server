import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { main } from './integration-mcp.mjs';

const { Agent } = createRequire(import.meta.url)('@tomic/lib');

test('real stdio handshake, discovery and signed calls; no approval tool', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'atomic-mcp-'));
  const keys = await Agent.generateKeyPair();
  const secret = Agent.buildSecret(
    keys.privateKey,
    `did:ad:agent:${keys.publicKey}`,
  );
  await writeFile(join(dir, 'agent'), secret, { mode: 0o600 });
  const seen = [];
  const endpoint = createServer(async (req, res) => {
    let text = '';
    for await (const chunk of req) text += chunk;
    assert.ok(req.headers['x-atomic-signature']);
    seen.push({ path: req.url, body: JSON.parse(text) });
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify(
        req.url === '/integration-actions'
          ? {
              tools: [
                {
                  name: 'create_issue',
                  description: 'Prepare',
                  inputSchema: {
                    type: 'object',
                    properties: { title: { type: 'string' } },
                    required: ['title'],
                    additionalProperties: false,
                  },
                },
              ],
            }
          : { status: 'needs_review', proposal: { id: 'stable' } },
      ),
    );
  });
  await new Promise(r => endpoint.listen(0, '127.0.0.1', r));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [new URL('./integration-mcp.mjs', import.meta.url).pathname],
    env: {
      ...process.env,
      ATOMIC_SERVER_URL: `http://127.0.0.1:${endpoint.address().port}`,
      ATOMIC_DRIVE: 'did:ad:fixture-drive',
      ATOMIC_CONNECTION: 'did:ad:fixture-connection',
      ATOMIC_AGENT_SECRET_FILE: join(dir, 'agent'),
    },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'atomic-test', version: '1' });

  try {
    await client.connect(transport);
    assert.deepEqual(
      (await client.listTools()).tools.map(t => t.name),
      ['create_issue'],
    );
    const result = await client.callTool({
      name: 'create_issue',
      arguments: { title: 'Synthetic' },
      _meta: { 'atomic/callId': 'stable' },
    });
    assert.equal(result.structuredContent.status, 'needs_review');
    assert.equal(seen[1].body.call.id, 'stable');
    assert.equal(
      seen.some(r => r.path.includes('approve')),
      false,
    );
  } finally {
    await client.close();
    await new Promise(r => endpoint.close(r));
    await rm(dir, { recursive: true, force: true });
  }
});
test('refuses remote plaintext endpoints and incomplete configuration', async () => {
  await assert.rejects(main({}), /Set ATOMIC_SERVER/);
  await assert.rejects(
    main({
      ATOMIC_SERVER_URL: 'http://remote.example',
      ATOMIC_DRIVE: 'd',
      ATOMIC_CONNECTION: 'c',
      ATOMIC_AGENT_SECRET_FILE: '/no-file',
    }),
    /HTTPS/,
  );
});
