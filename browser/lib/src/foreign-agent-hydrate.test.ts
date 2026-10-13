import { describe, expect, it } from 'vitest';
import { Agent } from './agent.js';
import { core } from './ontologies/core.js';
import { Resource } from './resource.js';
import { testStore } from './test-store.js';

/**
 * A member's Agent resource arrives as plain JSON-AD (no Loro snapshot). Its
 * lazily seeded Loro doc leaves the seeded ops in an open transaction; the
 * next server refresh (`applyHydratedValues` -> `sealPendingEdits`) used to
 * commit them as a LOCAL edit, which the outbox then signed as the owner.
 */
describe('foreign Agent resource hydration', () => {
  it('never turns a viewed member Agent resource into a local write', async () => {
    const { store, posted } = await testStore();
    const keys = await Agent.generateKeyPair();
    const member = `did:ad:agent:${keys.publicKey}`;
    const resource = new Resource(member);
    resource.setStore(store);
    resource.applyHydratedValues([
      [core.properties.isA, [core.classes.agent]],
      [core.properties.name, 'Polle Pas 1'],
    ]);
    store.addResource(resource);

    resource.getLoroDoc(); // e.g. a render reading the doc
    // `_revalidatedAgents` refetch: a second server response lands.
    resource.applyHydratedValues([[core.properties.name, 'Polle Pas 1']]);

    await new Promise(r => setTimeout(r, 50));
    await store.syncDirtyResources();

    const held = (store as unknown as { heldForOwner: Map<string, unknown> })
      .heldForOwner;
    expect(held.size).toBe(0);
    expect(store.outbox.hasPending(resource.subject)).toBe(false);
    expect(posted).toEqual([]);
  });
});
