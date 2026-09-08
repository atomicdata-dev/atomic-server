#!/usr/bin/env node
// Small stdio host: no listener, provider credentials, approval tool or new worker.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { Agent, integrationMcpAdapter } from '@tomic/lib';

export function createIntegrationMcpServer(store, target) {
  const adapter = integrationMcpAdapter(store, target);
  const server = new Server(
    { name: 'atomic-integration', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, () => adapter.listTools());
  server.setRequestHandler(CallToolRequestSchema, request =>
    adapter.callTool(request.params),
  );

  return server;
}
export async function main(env = process.env) {
  const {
    ATOMIC_SERVER_URL,
    ATOMIC_DRIVE,
    ATOMIC_CONNECTION,
    ATOMIC_AGENT_SECRET_FILE,
  } = env;
  if (
    !ATOMIC_SERVER_URL ||
    !ATOMIC_DRIVE ||
    !ATOMIC_CONNECTION ||
    !ATOMIC_AGENT_SECRET_FILE
  )
    throw new Error(
      'Set ATOMIC_SERVER_URL, ATOMIC_DRIVE, ATOMIC_CONNECTION and ATOMIC_AGENT_SECRET_FILE',
    );
  const url = new URL(ATOMIC_SERVER_URL);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== '/' ||
    !(
      url.protocol === 'https:' ||
      (url.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
    )
  )
    throw new Error(
      'Use an HTTPS AtomicServer origin, or loopback HTTP for development',
    );
  const agent = await Agent.fromSecret(
    readFileSync(ATOMIC_AGENT_SECRET_FILE, 'utf8').trim(),
  );
  const server = createIntegrationMcpServer(
    { getAgent: () => agent, getServerUrl: () => url.origin },
    { drive: ATOMIC_DRIVE, plugin: ATOMIC_CONNECTION },
  );
  await server.connect(new StdioServerTransport());

  return server;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch(() => {
    console.error(
      'Atomic integration MCP could not start. Check its configuration and agent secret file.',
    );
    process.exitCode = 1;
  });
}
