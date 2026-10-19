import { describe, expect, it } from 'vitest';
import { Collection } from './collection.js';
import { Store } from './store.js';
import { core } from './ontologies/core.js';

const HOME = 'https://app.example.com';

function failingStore() {
  const store = new Store({ serverUrl: HOME, connect: false });
  store.injectFetch(async () => {
    throw new Error('network down');
  });

  return store;
}

function build(store: Store) {
  return new Collection(store, HOME, {
    page_size: '30',
    include_nested: false,
    property: core.properties.parent,
    value: 'did:ad:parent',
  });
}

describe('a failed page fetch', () => {
  it('rejects reads when the store is server-connected', async () => {
    const store = failingStore();
    store.setServerConnected(true);

    await expect(build(store).getMembersOnPage(0)).rejects.toThrow();
    await expect(build(store).getAllMembers()).rejects.toThrow();
  });

  it('still reads as empty when the store is offline', async () => {
    const store = failingStore();

    expect(await build(store).getMembersOnPage(0)).toEqual([]);
  });
});
