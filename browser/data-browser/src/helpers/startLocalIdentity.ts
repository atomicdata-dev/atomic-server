import {
  Agent,
  JSCryptoProvider,
  agentPublicKey,
  agentSubject,
  core,
  type Resource,
  type Store,
} from '@tomic/react';
import { saveAgentToIDB } from './agentStorage';

/**
 * Write the Agent resource every identity has: its public key and class, and
 * its display name when it has one. The personal drive is linked to this
 * resource afterwards, which is what makes the identity count as having a
 * workspace (`localAgentWorkspace`).
 */
export async function saveAgentResource(
  store: Store,
  agent: string,
  name?: string,
): Promise<Resource> {
  const resource = store.getResourceLoading(agent, { newResource: true });

  await resource.set(core.properties.publicKey, agentPublicKey(agent) ?? '');
  await resource.set(core.properties.isA, [core.classes.agent]);

  if (name) await resource.set(core.properties.name, name);

  await resource.save();

  return resource;
}

/**
 * Start without an account: mint a real agent on this device, keep it local,
 * and give it its personal drive straight away.
 *
 * Nothing here is disposable. The key is stored like any account's (not as the
 * demo's throwaway guest, `adoptOnDevice: false`) and the personal drive exists
 * before this resolves, so the reconcile gate never mistakes the identity for
 * an empty one. The agent and its drive are registered local-only, which is
 * what lets a later sign-in to an existing account bring this workspace along
 * (`canBringAlong`) rather than only keep its key.
 *
 * Returns the agent to hand to `setAgent` and the drive to open.
 */
export async function startLocalIdentity(
  store: Store,
): Promise<{ agent: Agent; drive: string }> {
  const keys = await Agent.generateKeyPair();
  const did = agentSubject(
    await new JSCryptoProvider(keys.privateKey).getPublicKey(),
  );
  const agent = new Agent(new JSCryptoProvider(keys.privateKey), did);

  try {
    store.setAgent(agent);
    // Registered before anything async so no consumer fetches the agent from a
    // server that has never heard of it.
    store.registerLocalOnlyDrive(did);
    await saveAgentResource(store, did);

    const drive = await store.ensurePrivateDrive(undefined, {
      localOnly: true,
    });
    const secret = Agent.buildSecret(keys.privateKey, did, drive.subject);

    await saveAgentToIDB(secret);

    const stored = await Agent.fromSecret(secret);

    store.setAgent(stored);

    return { agent: stored, drive: drive.subject };
  } catch (error) {
    // Leave no half-made identity behind for a retry to trip over.
    store.setAgent(undefined);

    throw error;
  }
}
