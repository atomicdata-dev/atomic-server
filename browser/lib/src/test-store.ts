import { vi } from 'vitest';
import { Store } from './store.js';
import { Agent } from './agent.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import type { Commit } from './commit.js';

export interface TestStore {
  store: Store;
  agentDID: string;
  /** Every commit handed to `client.postCommit`, in order. The signed
   *  envelope the server would receive — assert `isGenesis`,
   *  `loroUpdate`, `subject`, count, etc. against these. */
  posted: Commit[];
  /** `client.postCommit` spy (echoes the commit back with an `id`). */
  postCommitSpy: ReturnType<typeof vi.fn>;
}

/**
 * A Store wired for unit tests against the PUBLIC API
 * (`newResource` → `set` → `save`). No `_new:` subjects,
 * `markNextCommitAsGenesis`, `CommitBuilder`, or
 * `syncDirtyResources` plumbing in the tests themselves.
 *
 * - Connected, with a freshly-generated DID agent.
 * - The low-level `client.postCommit` is mocked (so `Store.postCommit`'s
 *   real materialization still runs) to echo each commit with a fake
 *   `id`; captured in `posted`.
 * - `getProperty` is stubbed to reject, so validated `set()` calls skip
 *   the datatype fetch instead of hitting the network. `set()` already
 *   degrades gracefully when a property can't be loaded.
 */
export async function testStore(): Promise<TestStore> {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.setServerConnected(true);

  const keys = await Agent.generateKeyPair();
  const agentDID = `did:ad:agent:${keys.publicKey}`;
  store.setAgent(new Agent(new JSCryptoProvider(keys.privateKey), agentDID));

  const posted: Commit[] = [];
  const postCommitSpy = vi.fn(async (commit: Commit) => {
    const created = {
      ...commit,
      id: `https://example.com/commits/${commit.signature}`,
    } as Commit;
    posted.push(created);

    return created;
  });
  (
    store as unknown as { client: { postCommit: typeof postCommitSpy } }
  ).client.postCommit = postCommitSpy;

  // Skip datatype-validation fetches: `set()` catches a getProperty
  // rejection and proceeds without validating (the same path used when
  // a server is unreachable). Keeps tests off the network.
  vi.spyOn(store, 'getProperty').mockRejectedValue(
    new Error('test-store: property validation skipped'),
  );

  // Keep unit tests off the network. A failed GET still returns an error
  // resource (see `Client.fetchResourceHTTP`); callers must not then wait
  // on `getResource` for that stub to become ready.
  store.injectFetch(async () => {
    throw new Error('test-store: network disabled');
  });

  return { store, agentDID, posted, postCommitSpy };
}
