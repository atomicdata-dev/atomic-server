import { core } from './ontologies/core.js';
import type { Store } from './store.js';

/**
 * Rights a person gives an Agent that holds its own key (an app that made a
 * keypair and asked to be allowed, like the Atomic MCP server).
 *
 * Only an agent may edit its own Agent resource, so nothing about the grant
 * can be written there. The ACLs on the shared resources are the record:
 * both sides find the grants by searching for resources whose `read` or
 * `write` lists the agent. Search only returns what the searcher may read,
 * so the app sees what it was given and the person sees what they gave.
 */

export interface AgentGrant {
  subject: string;
  /** Granted by the person. Without it, the key holds `write` only because
   * it created the resource (the server adds a creator to `write`). */
  read: boolean;
  write: boolean;
}

/** Add `agent` to `read` (and `write`) on each target. */
export async function grantAgent(
  store: Store,
  agent: string,
  targets: string[],
  write: boolean,
): Promise<void> {
  for (const target of targets) {
    const resource = await store.getResource(target);

    if (resource.error) {
      throw resource.error;
    }

    resource.push(core.properties.read, [agent], true);

    if (write) {
      resource.push(core.properties.write, [agent], true);
    }

    await resource.save();
  }
}

/** The resources whose ACL names `agent`, as far as the store's agent can see. */
export async function grantsTo(
  store: Store,
  agent: string,
): Promise<AgentGrant[]> {
  const [readable, writable] = await Promise.all(
    [core.properties.read, core.properties.write].map(property =>
      store.search('', { filters: { [property]: agent }, limit: 500 }),
    ),
  );

  return [...new Set([...readable, ...writable])].map(subject => ({
    subject,
    read: readable.includes(subject),
    write: writable.includes(subject),
  }));
}

/**
 * Take `agent` off every resource that grants it, including what it created
 * itself. Reports what failed, so a caller never says "revoked" while access
 * remains.
 */
export async function revokeAgent(
  store: Store,
  agent: string,
): Promise<{
  revoked: string[];
  failed: { subject: string; reason: string }[];
}> {
  const revoked: string[] = [];
  const failed: { subject: string; reason: string }[] = [];

  for (const { subject } of await grantsTo(store, agent)) {
    try {
      const resource = await store.getResource(subject);

      for (const property of [core.properties.read, core.properties.write]) {
        const current = (resource.get(property) as string[] | undefined) ?? [];

        if (current.includes(agent)) {
          await resource.set(
            property,
            current.filter(s => s !== agent),
          );
        }
      }

      await resource.save();
      revoked.push(subject);
    } catch (e) {
      failed.push({
        subject,
        reason: e instanceof Error ? e.message : String(e),
      });
    }
  }

  return { revoked, failed };
}

/**
 * Asking for access from an app that holds its own key: a CLI, an MCP server,
 * a script, another app. The app makes a keypair, sends the person to
 * {@link connectAgentUrl}, and waits with {@link waitForGrant}. The person's
 * secret never leaves their app, and what they allow is revocable from
 * account settings (Connected apps).
 */
export const CONNECT_AGENT_PATH = '/app/connect-agent';

export interface ConnectAgentRequest {
  /** The app's public key (base64), or its agent subject. */
  publicKey: string;
  /** What the person sees, e.g. "Claude Code on MacBook". */
  name: string;
  /** Preselect "Read and edit". The person still decides. */
  write?: boolean;
  /** Preselect these resources. The person still decides. */
  targets?: string[];
}

/** The page in the app where the person allows a key. */
export function connectAgentUrl(
  appUrl: string,
  request: ConnectAgentRequest,
): string {
  const url = new URL(CONNECT_AGENT_PATH, appUrl);
  url.searchParams.set('key', request.publicKey);
  url.searchParams.set('name', request.name);

  if (request.write) {
    url.searchParams.set('write', '1');
  }

  for (const target of request.targets ?? []) {
    url.searchParams.append('target', target);
  }

  return url.toString();
}

/**
 * What the person shared with `agent`: resources whose `read` names it. A
 * resource where it only holds `write` is one it created itself.
 */
export async function sharedWith(
  store: Store,
  agent: string,
): Promise<string[]> {
  return (await grantsTo(store, agent))
    .filter(grant => grant.read)
    .map(grant => grant.subject);
}

/**
 * Poll until the person allows `agent` (the store must sign as it), and
 * return what they shared. Rejects after `timeoutMs` or when `signal` aborts.
 */
export async function waitForGrant(
  store: Store,
  agent: string,
  opts: { timeoutMs?: number; intervalMs?: number; signal?: AbortSignal } = {},
): Promise<string[]> {
  const deadline = Date.now() + (opts.timeoutMs ?? 15 * 60 * 1000);

  for (;;) {
    const shared = await sharedWith(store, agent);

    if (shared.length > 0) {
      return shared;
    }

    opts.signal?.throwIfAborted();

    if (Date.now() > deadline) {
      throw new Error('Nobody allowed this key in time.');
    }

    await new Promise(resolve => setTimeout(resolve, opts.intervalMs ?? 2000));
  }
}

/**
 * Put a readable name on the store's own Agent resource, so the person sees
 * it in Connected apps rather than a key. Only an agent may edit its own
 * Agent resource, so the app has to do this itself.
 */
export async function publishAgentName(
  store: Store,
  name: string,
): Promise<void> {
  const subject = store.getAgent()?.subject;

  if (!subject) {
    throw new Error('publishAgentName needs a store that signs as the app');
  }

  const profile = await store.getResource(subject);

  if (profile.get(core.properties.name) === name) {
    return;
  }

  await profile.set(core.properties.name, name, false);
  await profile.save();
}
