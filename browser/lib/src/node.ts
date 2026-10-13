import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { Agent } from './agent.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { agentSubject } from './subject.js';

/**
 * `@tomic/lib/node`: helpers that need Node's file system, kept out of the
 * main entry so browsers never bundle them.
 *
 * A tool's own Agent on this machine, for one server: a keypair made here,
 * kept in the user's config directory, never shown to anyone. The person
 * grants it rights from the app (`connectAgentUrl`), so their own secret never
 * leaves the app and every edit is signed as this tool. Used by `@tomic/mcp`
 * and `@tomic/cli`.
 */
export interface LocalAgent {
  agent: Agent;
  publicKey: string;
  /** Where the key lives on disk. */
  path: string;
}

interface StoredKey {
  privateKey: string;
  publicKey: string;
}

const configDir = (tool: string) =>
  join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), tool);

/**
 * One key per tool and server, so a grant to one tool or on one server says
 * nothing about another.
 */
export const keyPath = (tool: string, serverUrl: string) =>
  join(
    configDir(tool),
    `${new URL(serverUrl).host.replace(/[^\w.-]/g, '_')}.json`,
  );

/**
 * @param tool Names the config directory, e.g. `atomic-mcp`.
 * @param create When false, resolves `undefined` instead of making a key.
 */
export async function loadOrCreateLocalAgent(
  tool: string,
  serverUrl: string,
  { create = true }: { create?: boolean } = {},
): Promise<LocalAgent | undefined> {
  const path = keyPath(tool, serverUrl);
  let stored: StoredKey | undefined;

  try {
    stored = JSON.parse(await readFile(path, 'utf8')) as StoredKey;
  } catch {
    stored = undefined;
  }

  if (!stored?.privateKey || !stored.publicKey) {
    if (!create) {
      return undefined;
    }

    stored = await Agent.generateKeyPair();
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await writeFile(path, JSON.stringify(stored, null, 2), { mode: 0o600 });
  }

  const agent = new Agent(
    new JSCryptoProvider(stored.privateKey),
    agentSubject(stored.publicKey),
  );

  return { agent, publicKey: stored.publicKey, path };
}
