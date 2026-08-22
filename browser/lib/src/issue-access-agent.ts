import { Agent } from './agent.js';
import { core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import type { Store } from './store.js';
import { instances } from './urls.js';

/**
 * Grant-target cache on an issued agent. The live ACL on each target is still
 * what authorization consults; this list is so revoke and the Settings row
 * can find a folder- or page-level grant, not only a workspace.
 *
 * Reuses the data-browser `resources` property (a resourceArray). Target DIDs
 * are unguessable; titles stay behind those resources' own read rights.
 */
const GRANT_TARGETS = dataBrowser.properties.resources;

export const REVOKED_NAME_SUFFIX = ' (revoked)';

export interface IssueAccessAgentOpts {
  /** Shown in the App keys list and on the public Agent resource. */
  name: string;
  description?: string;
  /** When true, the new agent is added to `write` as well as `read`. */
  write: boolean;
  /**
   * Resources that receive this key on `read` (and `write` if asked).
   * Any ACL-bearing resource — a workspace, a folder, a page. Rights
   * inherit to children.
   */
  targets: string[];
  /** App keys folder — or any private parent that should own the registry row. */
  parent?: string;
}

export interface IssuedAccessAgent {
  subject: string;
  secret: string;
}

/**
 * Mint a new Agent, publish its public resource, and grant it rights on the
 * given targets — without switching the store's current agent.
 *
 * The new secret is returned once and is not stored. The caller shows it;
 * lost secrets are rotated by minting again and revoking this one.
 */
export async function issueAccessAgent(
  store: Store,
  opts: IssueAccessAgentOpts,
): Promise<IssuedAccessAgent> {
  const current = store.getAgent();

  if (!current?.subject) {
    throw new Error('Cannot issue an app key while signed out');
  }

  const name = opts.name.trim();

  if (!name) {
    throw new Error('App keys need a name');
  }

  if (opts.targets.length === 0) {
    throw new Error('Choose at least one resource');
  }

  const keys = await Agent.generateKeyPair();
  const subject = `did:ad:agent:${keys.publicKey}`;

  await publishIssuedAgentProfile(store, {
    subject,
    publicKey: keys.publicKey,
    name,
    parent: opts.parent,
    description: opts.description,
  });
  await grantAccessAgent(store, subject, opts.targets, opts.write);

  return {
    subject,
    secret: Agent.buildSecret(keys.privateKey, subject),
  };
}

/**
 * Grant an agent the app already holds. OAuth's preferred shape: the client
 * minted the keypair, sent only the public key / DID, and never needs a
 * secret copied out of this session.
 */
export async function bindAccessAgent(
  store: Store,
  opts: IssueAccessAgentOpts & { publicKey: string },
): Promise<{ subject: string }> {
  const current = store.getAgent();

  if (!current?.subject) {
    throw new Error('Cannot grant an app key while signed out');
  }

  const name = opts.name.trim();

  if (!name) {
    throw new Error('App keys need a name');
  }

  if (opts.targets.length === 0) {
    throw new Error('Choose at least one resource');
  }

  const { subject, publicKey } = agentSubjectFromPublicKey(opts.publicKey);

  await publishIssuedAgentProfile(store, {
    subject,
    publicKey,
    name,
    parent: opts.parent,
    description: opts.description,
  });
  await grantAccessAgent(store, subject, opts.targets, opts.write);

  return { subject };
}

export function agentSubjectFromPublicKey(value: string): {
  subject: string;
  publicKey: string;
} {
  const trimmed = value.trim();

  if (trimmed.startsWith('did:ad:agent:')) {
    return {
      subject: trimmed,
      publicKey: trimmed.slice('did:ad:agent:'.length),
    };
  }

  return {
    subject: `did:ad:agent:${trimmed}`,
    publicKey: trimmed,
  };
}

async function publishIssuedAgentProfile(
  store: Store,
  opts: {
    subject: string;
    publicKey: string;
    name: string;
    parent?: string;
    description?: string;
  },
): Promise<void> {
  const cached = store.resources.get(opts.subject);
  const alreadyPublished =
    cached &&
    !cached.error &&
    !cached.new &&
    Boolean(cached.get(core.properties.publicKey));

  if (alreadyPublished) {
    return;
  }

  const resource = await store.newResource({
    subject: opts.subject,
    parent: opts.parent,
    noParent: !opts.parent,
    isA: core.classes.agent,
    propVals: {
      [core.properties.publicKey]: opts.publicKey,
      [core.properties.name]: opts.name,
      [core.properties.read]: [instances.publicAgent],
      ...(opts.description
        ? { [core.properties.description]: opts.description }
        : {}),
    },
  });
  await resource.save();
  // Agents skip `signChanges` on create (identity is the public key, not a
  // genesis signature). `save()` must have cleared `new`; do it here too so
  // `useChildren` / `applyResourceChange` will admit this row. A `new`
  // resource is treated as a table-row placeholder and never listed.
  resource.new = false;
  await store.notifyResourceManuallyCreated(resource);
}

/**
 * Add an existing issued agent to more resources. Does not mint a secret.
 * Each target can be a workspace, folder, or any other ACL-bearing resource;
 * children inherit the grant.
 */
export async function grantAccessAgent(
  store: Store,
  agentSubject: string,
  targets: string[],
  write: boolean,
): Promise<void> {
  for (const target of targets) {
    const resource = await store.getResource(target);
    resource.push(core.properties.read, [agentSubject], true);

    if (write) {
      resource.push(core.properties.write, [agentSubject], true);
    }

    await resource.save();
  }

  await appendRecordedTargets(store, agentSubject, targets);
}

/** Subjects this key was granted on, as last recorded on the agent. */
export async function grantedTargetsOf(
  store: Store,
  agentSubject: string,
): Promise<string[]> {
  const agent = await store.getResource(agentSubject);

  return recordedTargetsOn(agent);
}

/** What a revocation actually managed to do. */
export interface RevokeReport {
  /** Targets this key was removed from, confirmed by re-reading the ACL. */
  revoked: string[];
  /** Targets checked that did not grant this key in the first place. */
  untouched: string[];
  /** Targets still granting this key, and why. ACCESS PERSISTS on these. */
  failed: { target: string; reason: string }[];
}

/**
 * Remove an issued agent from the given targets' ACLs and mark its profile
 * revoked. The Agent resource is kept — old commits still need the public key.
 *
 * Returns what it managed to do rather than succeeding silently. A revoke that
 * quietly leaves access behind is worse than one that fails loudly: the user
 * reads "Key revoked", stops worrying, and the secret still opens their
 * workspaces. So every target is verified by re-reading its ACL after the
 * save, an unreachable target is reported instead of aborting the rest, and
 * the profile is only marked revoked when nothing was left behind.
 *
 * `targets` is merged with the list recorded on the key, so a folder-level
 * grant is not missed just because the caller only passed workspaces. A
 * grant on a resource in neither list still survives — say what you checked.
 */
export async function revokeAccessAgent(
  store: Store,
  agentSubject: string,
  targets: string[],
): Promise<RevokeReport> {
  const report: RevokeReport = { revoked: [], untouched: [], failed: [] };
  const recorded = await grantedTargetsOf(store, agentSubject);
  const allTargets = [...new Set([...targets, ...recorded])];

  for (const target of allTargets) {
    try {
      const resource = await store.getResource(target);

      if (resource.error) {
        throw resource.error;
      }

      if (!grantsAgent(resource, agentSubject)) {
        report.untouched.push(target);
        continue;
      }

      await removeFromRights(resource, core.properties.read, agentSubject);
      await removeFromRights(resource, core.properties.write, agentSubject);
      await resource.save();

      // Confirm rather than assume: a save can be rejected by rights or fail
      // to reach the server, and the in-memory resource would still look
      // edited.
      const after = await store.getResource(target);

      if (after.error || grantsAgent(after, agentSubject)) {
        throw new Error('the resource still grants this key after saving');
      }

      report.revoked.push(target);
    } catch (e) {
      report.failed.push({
        target,
        reason: e instanceof Error ? e.message : String(e),
      });
    }
  }

  // Only claim the key is dead when it is. A "(revoked)" label on a key that
  // still opens a resource is exactly the lie this function exists to avoid.
  if (report.failed.length === 0) {
    const agentResource = await store.getResource(agentSubject);
    const name = (
      agentResource.get(core.properties.name) as string | undefined
    )?.trim();

    if (name && !isRevokedAccessAgentName(name)) {
      await agentResource.set(
        core.properties.name,
        `${name}${REVOKED_NAME_SUFFIX}`,
      );
    }

    await agentResource.set(GRANT_TARGETS, []);
    await agentResource.save();
  }

  return report;
}

/** Whether `resource` currently lists `agentSubject` in read or write. */
function grantsAgent(
  resource: Awaited<ReturnType<Store['getResource']>>,
  agentSubject: string,
): boolean {
  return [core.properties.read, core.properties.write].some(property =>
    ((resource.get(property) as string[] | undefined) ?? []).includes(
      agentSubject,
    ),
  );
}

export function isRevokedAccessAgentName(name: string): boolean {
  return name.endsWith(REVOKED_NAME_SUFFIX);
}

function recordedTargetsOn(
  agent: Awaited<ReturnType<Store['getResource']>>,
): string[] {
  return ((agent.get(GRANT_TARGETS) as string[] | undefined) ?? []).filter(
    Boolean,
  );
}

async function appendRecordedTargets(
  store: Store,
  agentSubject: string,
  targets: string[],
): Promise<void> {
  if (targets.length === 0) {
    return;
  }

  const agent = await store.getResource(agentSubject);
  const next = [...new Set([...recordedTargetsOn(agent), ...targets])];
  await agent.set(GRANT_TARGETS, next);
  await agent.save();
}

async function removeFromRights(
  resource: Awaited<ReturnType<Store['getResource']>>,
  property: string,
  agentSubject: string,
): Promise<void> {
  const current = (resource.get(property) as string[] | undefined) ?? [];

  if (!current.includes(agentSubject)) {
    return;
  }

  await resource.set(
    property,
    current.filter(subject => subject !== agentSubject),
  );
}
