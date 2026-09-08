import { describe, it, beforeEach, vi } from 'vitest';
import {
  Agent,
  Store,
  core,
  JSCryptoProvider,
  isTransportError,
} from './index.js';
import { bootstrapCoreVocab } from './test-vocab.js';

/**
 * What a client may conclude from a request that never got an answer.
 *
 * A fetch that throws (server down, DNS, CORS) says nothing about the
 * resource — only about the connection. The failure used to be written into
 * the store like any other response, which is how an agent could render its
 * own avatar and title next to "Error loading resource", and stay that way
 * until a page reload.
 */
async function freshStore(): Promise<Store> {
  const store = new Store({ serverUrl: 'https://example.com' });
  await bootstrapCoreVocab(store);

  return store;
}

/** Puts a renderable copy of an agent in the store, as an OPFS hydration would. */
function hydrateAgentLocally(store: Store, subject: string, name: string) {
  store.hydrateResourceFromJsonAd(
    subject,
    JSON.stringify({
      '@id': subject,
      [core.properties.isA]: [core.classes.agent],
      [core.properties.name]: name,
    }),
  );
}

describe('A delayed missing-resource response', () => {
  it('does not overwrite a resource created while the lookup was pending', async ({
    expect,
  }) => {
    const store = await freshStore();
    store.setServerConnected(true);
    const subject = 'did:ad:created-during-fetch';
    let rejectFetch!: (error: Error) => void;
    const pending = new Promise<never>((_, reject) => {
      rejectFetch = reject;
    });
    const fetch = vi
      .spyOn(store, 'fetchResourceFromServer')
      .mockReturnValue(pending);
    store.getResourceLoading(subject);
    await vi.waitFor(() => expect(fetch).toHaveBeenCalled());
    hydrateAgentLocally(store, subject, 'Created locally');
    rejectFetch(new Error('Resource not found locally'));
    // Let the pending lookup's rejection handler finish.
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(store.resources.get(subject)?.error).toBeUndefined();
    expect(store.resources.get(subject)?.get(core.properties.name)).toBe(
      'Created locally',
    );
  });
});

describe('Unreachable server', () => {
  let agentSubject: string;

  beforeEach(async () => {
    const keys = await Agent.generateKeyPair();
    const provider = new JSCryptoProvider(keys.privateKey);
    const agent = new Agent(provider, `did:ad:agent:${keys.publicKey}`);
    agentSubject = agent.subject!;
  });

  it('keeps a locally known resource instead of failing it', async ({
    expect,
  }) => {
    const store = await freshStore();
    hydrateAgentLocally(store, agentSubject, 'joepie!');

    store.injectFetch(async () => {
      throw new TypeError('NetworkError when attempting to fetch resource.');
    });

    const resource = await store.fetchResourceFromServer(agentSubject);

    expect(resource.error).toBeUndefined();
    expect(resource.loading).toBe(false);
    expect(resource.get(core.properties.name)).toBe('joepie!');
  });

  it('surfaces the failure when there is nothing to show', async ({
    expect,
  }) => {
    const store = await freshStore();

    store.injectFetch(async () => {
      throw new TypeError('NetworkError when attempting to fetch resource.');
    });

    const resource = await store.fetchResourceFromServer(agentSubject);

    expect(isTransportError(resource.error)).toBe(true);
  });

  it('retries a transport failure on reconnect', async ({ expect }) => {
    const store = await freshStore();
    let attempts = 0;

    store.injectFetch(async () => {
      attempts++;
      throw new TypeError('NetworkError when attempting to fetch resource.');
    });

    await store.fetchResourceFromServer(agentSubject);
    expect(attempts).toBe(1);

    // Reconnecting used to retry only resources whose error message started
    // with the `Offline:` marker this file writes — never the raw fetch
    // failure, which is the common way to get here.
    store.refetchOfflineErroredResources();
    await new Promise(resolve => setTimeout(resolve, 0));

    expect(attempts).toBe(2);
  });
});
