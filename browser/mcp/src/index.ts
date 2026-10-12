#!/usr/bin/env node
/**
 * `atomic-mcp`: lets an MCP client that runs a local process (Claude Code,
 * Claude Desktop, Cursor) use your Atomic Data. It is a bridge to the node's
 * own `/mcp` endpoint, the one implementation of the tools, with the token
 * that `atomic-mcp connect` got after you approved it in the app.
 * See ../README.md for client setup.
 */
import { hostname } from 'node:os';
import { Bridge, runBridge } from './bridge.js';
import { connect, loadConnection, normalizeServer } from './oauth.js';

const log = (message: string) =>
  process.stderr.write(`[atomic-mcp] ${message}\n`);

const serverEnv = process.env.ATOMIC_SERVER_URL;

if (!serverEnv) {
  log(
    'Set ATOMIC_SERVER_URL to the server your drives live on, e.g. https://atomicdata.dev',
  );
  process.exit(1);
}

const server = normalizeServer(serverEnv);
const command = process.argv[2];

if (command === 'connect') {
  const clientName =
    process.env.ATOMIC_CLIENT_NAME ?? `AI assistant on ${hostname()}`;

  try {
    const connection = await connect({
      server,
      clientName,
      write: process.env.ATOMIC_READ_ONLY !== 'true',
      desktop: process.argv.includes('--desktop'),
    });

    process.stderr.write(
      `\nConnected to ${server} (${connection.scope}). You can see and revoke it in the app under your account settings, Connected apps.\n`,
    );
  } catch (error) {
    log((error as Error).message);
    process.exit(1);
  }

  process.exit(0);
}

if (command !== undefined) {
  log(`Unknown command "${command}". Use "connect", or no command to serve.`);
  process.exit(1);
}

log(
  (await loadConnection(server))
    ? `Bridging to ${server}/mcp`
    : `Not connected yet: run \`atomic-mcp connect\`. The tools will say so until then.`,
);

await runBridge(new Bridge(server), process.stdin, process.stdout);
