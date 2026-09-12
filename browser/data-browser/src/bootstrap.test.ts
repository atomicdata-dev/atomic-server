import { describe, it, expect } from 'vitest';
import { core, Store } from '@tomic/lib';
import { bootstrap } from './bootstrap';

const PUBLIC_AGENT = 'https://atomicdata.dev/agents/publicAgent';
const PROPERTIES_CONTAINER = 'https://atomicdata.dev/properties';

/**
 * Which bundled entries are allowed to be marked `incomplete`. The marker
 * makes the store refetch the subject on first read, so anything carrying
 * content of its own must stay out of it: a client with no route to
 * atomicdata.dev would otherwise hold a resource that never becomes ready,
 * and every control gated on `isReady()` stays disabled.
 */
describe('bootstrap', () => {
  it('marks a bare container as incomplete so it does not shadow the real one', () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    bootstrap(store);

    const container = store.resources.get(PROPERTIES_CONTAINER);

    expect(container).toBeDefined();
    expect(container?.get(core.properties.incomplete)).toBe(true);
  });

  it('makes website language properties available before network access', () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    bootstrap(store);

    for (const name of [
      'language',
      'translationOf',
      'defaultLanguage',
      'languages',
    ]) {
      const property = store.resources.get(
        `https://atomicdata.dev/properties/${name}`,
      );
      expect(property, name).toBeDefined();
      expect(property?.isReady(), name).toBe(true);
      expect(property?.get(core.properties.datatype), name).toBeDefined();
    }
  });

  it('leaves the public agent usable without a fetch', () => {
    const store = new Store({ serverUrl: 'https://example.com' });
    bootstrap(store);

    const publicAgent = store.resources.get(PUBLIC_AGENT);

    expect(publicAgent).toBeDefined();
    // Bundled with a description and shortname, so it is not a bare anchor —
    // the share page's "Public (anyone)" toggle reads this resource and stays
    // disabled until it is ready.
    expect(publicAgent?.get(core.properties.incomplete)).toBeUndefined();
    expect(publicAgent?.loading).toBe(false);
  });
});
