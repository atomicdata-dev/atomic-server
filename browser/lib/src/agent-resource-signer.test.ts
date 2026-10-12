import { describe, expect, it } from 'vitest';
import { Agent } from './agent.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { core } from './ontologies/core.js';
import { agentPublicKey } from './subject.js';
import { testStore } from './test-store.js';

async function otherAgent(): Promise<Agent> {
  const keys = await Agent.generateKeyPair();

  return new Agent(
    new JSCryptoProvider(keys.privateKey),
    `did:ad:agent:${keys.publicKey}`,
  );
}

const keyOf = (subject: unknown) => agentPublicKey(String(subject));

type TestStoreT = Awaited<ReturnType<typeof testStore>>['store'];

/** A published, parentless Agent resource for `subject`, as sign-in makes it. */
async function profileOf(store: TestStoreT, subject: string) {
  const resource = await store.newResource({
    subject,
    noParent: true,
    isA: core.classes.agent,
    propVals: { [core.properties.name]: 'Before' },
  });
  await resource.save();
  await store.syncDirtyResources();

  return resource;
}

/**
 * A commit for an Agent resource may only be signed by that agent. Signing is
 * done at drain time with the store's current agent, so an identity swap
 * between the edit and the drain used to send agent A's profile signed by B,
 * which the server rejects ("Only A itself may create its Agent resource").
 */
describe('Agent resource signer', () => {
  it('never signs a parentless Agent resource as another agent', async () => {
    const { store, agentDID: agentA, posted } = await testStore();
    const resource = await profileOf(store, agentA);
    await resource.set(core.properties.name, 'Alice', false);

    // Identity swap (sign-in as another identity) before the save drains.
    store.setAgent(await otherAgent());
    await resource.save().catch(() => undefined);
    await store.syncDirtyResources();

    const forA = posted.filter(c => keyOf(c.subject) === keyOf(agentA));
    expect(forA.filter(c => keyOf(c.signer) !== keyOf(agentA))).toEqual([]);
    expect(store.getSyncStatus().blockedCount).toBe(0);
  });

  it('keeps the edit and sends it once agent A is current again', async () => {
    const { store, agentDID: agentA, posted } = await testStore();
    const agent = store.getAgent()!;
    const resource = await profileOf(store, agentA);
    await resource.set(core.properties.name, 'Alice', false);

    store.setAgent(await otherAgent());
    await resource.save().catch(() => undefined);
    await store.syncDirtyResources();
    const before = posted.length;

    store.setAgent(agent);
    await store.syncDirtyResources();

    const sent = posted
      .slice(before)
      .filter(c => keyOf(c.subject) === keyOf(agentA));
    expect(sent.length).toBeGreaterThan(0);
    expect(sent.every(c => keyOf(c.signer) === keyOf(agentA))).toBe(true);
  });
});
