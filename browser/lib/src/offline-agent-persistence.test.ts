import { beforeAll, describe, it, expect } from 'vitest';
import { Store, Agent, JSCryptoProvider, core, commits } from './index.js';
import { LoroLoader } from './loro-loader.js';

beforeAll(async () => {
  await LoroLoader.initializeLoro();
});

describe('Offline Agent Persistence', () => {
  it('saves and resolves agent offline successfully', async () => {
    // 1. Create a store and an agent
    const store = new Store({ serverUrl: 'https://example.com' });

    // Disable network requests
    store.injectFetch(async () => {
      throw new Error('offline: network disabled');
    });

    const keys = await Agent.generateKeyPair();
    const provider = new JSCryptoProvider(keys.privateKey);
    const agentSubject = `did:ad:agent:${keys.publicKey}`;
    const initialAgent = new Agent(provider, agentSubject);
    store.setAgent(initialAgent);

    // Mock clientDb to intercept put and get calls
    const storageMap = new Map<
      string,
      { jsonAd: string; snapshot: Uint8Array | null }
    >();
    const mockClientDb = {
      isReady: true,
      isInitialized: true,
      initError: undefined,
      waitForReady: async () => true,
      waitForInit: async () => undefined,
      flush: async () => undefined,
      putResourceWithSnapshot: async (
        subject: string,
        jsonAd: string,
        snapshot: Uint8Array | null,
      ) => {
        storageMap.set(subject, { jsonAd, snapshot });
      },
      getResourceWithSnapshot: async (subject: string) => {
        const hit = storageMap.get(subject);

        return hit
          ? { jsonAd: hit.jsonAd, snapshot: hit.snapshot }
          : { jsonAd: null, snapshot: null };
      },
    };
    store.setClientDb(
      mockClientDb as unknown as Parameters<typeof store.setClientDb>[0],
    );

    // 2. Create the Agent resource offline (like signup does)
    const agentResource = store.getResourceLoading(agentSubject, {
      newResource: true,
    });
    await agentResource.set(core.properties.publicKey, keys.publicKey);
    await agentResource.set(core.properties.isA, [core.classes.agent]);
    await agentResource.set(core.properties.name, 'Offline Tester');

    // Save offline
    const saveResult = await agentResource.save();
    expect(saveResult).toBe('offline');

    // Verify it was persisted to mockClientDb
    expect(storageMap.has(agentSubject)).toBe(true);
    const savedData = storageMap.get(agentSubject)!;
    expect(JSON.parse(savedData.jsonAd)).toEqual({
      '@id': agentSubject,
      [commits.properties.createdAt]: expect.any(Number),
      [core.properties.publicKey]: keys.publicKey,
      [core.properties.isA]: [core.classes.agent],
      [core.properties.name]: 'Offline Tester',
    });
    expect(savedData.snapshot).toBeDefined();
    expect(savedData.snapshot!.length).toBeGreaterThan(0);

    // 3. Clear store resources to simulate reload
    store.resources.clear();

    // 4. Try to resolve the agent resource from local storage fallback
    const resolvedResource = store.getResourceLoading(agentSubject);
    expect(resolvedResource.loading).toBe(true);

    // Wait for the fallback fetch to run: it awaits `waitForInit`, then reads
    // back through `getResourceWithSnapshot` — an async microtask hop.
    await new Promise(resolve => setTimeout(resolve, 50));

    // It must resolve from local storage rather than falling back to
    // `fetchResourceFromServer` (which throws here because the network is off).
    expect(resolvedResource.error).toBeUndefined();
    expect(resolvedResource.loading).toBe(false);
    expect(resolvedResource.get(core.properties.name)).toBe('Offline Tester');
  });
});
