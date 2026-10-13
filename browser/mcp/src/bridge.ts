/**
 * The stdio side of `atomic-mcp`: a thin bridge from an MCP client that runs a
 * local process to the node's own `/mcp` endpoint. It adds nothing of its own
 * to the tools; the node is the one implementation, and this only carries
 * JSON-RPC messages over HTTP with the token from `atomic-mcp connect`.
 */
import { loadConnection, refresh, type StoredConnection } from './oauth.js';

type Json = Record<string, unknown>;

const NOT_CONNECTED = (server: string) =>
  `This machine is not connected to ${server} yet. Ask the person to run \`npx -y @tomic/mcp connect\` (with ATOMIC_SERVER_URL=${server}) in a terminal, choose what to share in the browser and click Allow, then try again.`;

const rpcError = (id: unknown, code: number, message: string): Json => ({
  jsonrpc: '2.0',
  id,
  error: { code, message },
});

/**
 * Answers for a machine that is not connected: enough of MCP that the client
 * starts, and a single tool that tells the assistant what to ask the person.
 */
function notConnected(server: string, message: Json): Json | undefined {
  const { id, method } = message;

  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion:
            (message.params as Json | undefined)?.protocolVersion ??
            '2025-06-18',
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'atomic', version: 'not-connected' },
          instructions: NOT_CONNECTED(server),
        },
      };
    case 'ping':
      return { jsonrpc: '2.0', id, result: {} };
    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            {
              name: 'connect_atomic',
              title: 'Connect to Atomic',
              description: `Not connected yet. Call this to learn how the person connects this machine to ${server}.`,
              inputSchema: { type: 'object', properties: {} },
            },
          ],
        },
      };
    case 'tools/call':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: NOT_CONNECTED(server) }],
          isError: true,
        },
      };
    default:
      return rpcError(id, -32601, 'Method not found');
  }
}

export class Bridge {
  private connection: StoredConnection | undefined;
  private loaded = false;
  private readonly doFetch: typeof fetch;

  constructor(
    private readonly server: string,
    doFetch: typeof fetch = fetch,
  ) {
    this.doFetch = doFetch;
  }

  private async current(): Promise<StoredConnection | undefined> {
    if (!this.loaded) {
      this.connection = await loadConnection(this.server);
      this.loaded = true;
    }

    if (this.connection && this.connection.expiresAt < Date.now() / 1000 + 60) {
      await this.renew();
    }

    return this.connection;
  }

  private async renew() {
    if (!this.connection) return;

    try {
      this.connection = await refresh(this.connection, this.doFetch);
    } catch {
      // Revoked or expired for good: the next call reports it.
      this.connection = undefined;
    }
  }

  private post(connection: StoredConnection, body: string) {
    return this.doFetch(`${this.server}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${connection.accessToken}`,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body,
    });
  }

  /** Forwards one message. Returns the answer, or nothing for a notification. */
  async handle(message: Json): Promise<Json | undefined> {
    const isNotification = message.id === undefined || message.id === null;
    let connection = await this.current();

    if (!connection) {
      return isNotification ? undefined : notConnected(this.server, message);
    }

    const body = JSON.stringify(message);
    let response: Response;

    try {
      response = await this.post(connection, body);

      if (response.status === 401) {
        await this.renew();
        connection = this.connection;

        if (!connection) {
          return isNotification
            ? undefined
            : notConnected(this.server, message);
        }

        response = await this.post(connection, body);
      }
    } catch (error) {
      return isNotification
        ? undefined
        : rpcError(
            message.id,
            -32000,
            `Could not reach ${this.server}: ${(error as Error).message}`,
          );
    }

    if (isNotification) return undefined;

    const text = await response.text();

    if (!response.ok) {
      return rpcError(
        message.id,
        -32000,
        response.status === 401
          ? NOT_CONNECTED(this.server)
          : `${this.server} answered ${response.status}: ${text.slice(0, 300)}`,
      );
    }

    try {
      return JSON.parse(text) as Json;
    } catch {
      return rpcError(
        message.id,
        -32603,
        'The node sent something that is not JSON.',
      );
    }
  }
}

/** Reads newline-delimited JSON-RPC from `input` and writes answers to `output`. */
export async function runBridge(
  bridge: Bridge,
  input: NodeJS.ReadableStream,
  output: { write(chunk: string): unknown },
): Promise<void> {
  const pending = new Set<Promise<void>>();
  let buffer = '';

  const dispatch = (line: string) => {
    if (!line.trim()) return;

    let message: Json;

    try {
      message = JSON.parse(line) as Json;
    } catch {
      output.write(
        `${JSON.stringify(rpcError(null, -32700, 'Parse error'))}\n`,
      );

      return;
    }

    const job = bridge
      .handle(message)
      .then(answer => {
        if (answer) output.write(`${JSON.stringify(answer)}\n`);
      })
      .catch(error => {
        if (message.id !== undefined) {
          output.write(
            `${JSON.stringify(rpcError(message.id, -32603, String(error)))}\n`,
          );
        }
      })
      .finally(() => pending.delete(job));
    pending.add(job);
  };

  input.setEncoding?.('utf8');

  for await (const chunk of input) {
    buffer += chunk;
    let newline = buffer.indexOf('\n');

    while (newline >= 0) {
      dispatch(buffer.slice(0, newline));
      buffer = buffer.slice(newline + 1);
      newline = buffer.indexOf('\n');
    }
  }

  dispatch(buffer);
  await Promise.all(pending);
}
