import { describe, expect, it, vi } from 'vitest';
import { Collection } from './collection.js';
import { Resource } from './resource.js';
import { Store } from './store.js';
import { core } from './ontologies/core.js';
import { collections } from './ontologies/collections.js';

describe('server collection member hydration', () => {
  it('keeps a queried child while its resource is still loading', async () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    store.setServerConnected(true);
    const parent = 'did:ad:parent';
    const child = 'did:ad:child';
    const page = new Resource('https://example.com/query');
    page.applyHydratedValues([
      [collections.properties.members, [child]],
      [collections.properties.totalMembers, 1],
    ]);
    vi.spyOn(store, 'fetchResourceFromServer').mockResolvedValue(page);
    const collection = new Collection(store, store.getServerUrl(), {
      property: core.properties.parent,
      value: parent,
      page_size: '30',
      include_nested: false,
    });
    await collection.waitForReady();

    // A server-only query gives us IDs before getResource has loaded each
    // member. Its loading notification does not mean the parent was removed.
    const loading = new Resource(child);
    loading.loading = true;
    expect(collection.applyResourceChange(child, loading)).toBe('unchanged');
    expect(collection.totalMembers).toBe(1);
    expect(await collection.getMemberWithIndex(0)).toBe(child);

    // An actual re-parent still removes the member once the read is complete.
    loading.applyHydratedValues([[core.properties.parent, 'did:ad:elsewhere']]);
    loading.loading = false;
    expect(collection.applyResourceChange(child, loading)).toBe(
      'member-removed',
    );
    expect(collection.totalMembers).toBe(0);
  });
});
