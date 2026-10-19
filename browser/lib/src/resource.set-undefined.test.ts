import { describe, expect, it, vi } from 'vitest';
import { Datatype } from './datatypes.js';
import { core } from './ontologies/core.js';
import { Resource, ResourceEvents } from './resource.js';
import { Store } from './store.js';

const property = 'https://example.com/properties/optional';

describe('Resource.set(undefined)', () => {
  it.each([
    [Datatype.STRING, 'A note'],
    [Datatype.DATE, '2026-10-20'],
  ])(
    'removes a %s property with default validation',
    async (datatype, value) => {
      const store = new Store();
      store.injectFetch(async () => {
        throw new Error('Unexpected network access');
      });
      const definition = new Resource(property);
      definition.setUnsafe(core.properties.isA, [core.classes.property]);
      definition.setUnsafe(core.properties.shortname, 'optional');
      definition.setUnsafe(
        core.properties.description,
        'Optional test property',
      );
      definition.setUnsafe(core.properties.datatype, datatype);
      store.addResources(definition, { skipCommitCompare: true });
      const resource = new Resource('https://example.com/record');
      resource.setStore(store);
      await resource.set(property, value);
      const getProperty = vi.spyOn(store, 'getProperty');
      const changed = vi.fn();
      resource.on(ResourceEvents.LocalChange, changed);

      await resource.set(property, undefined);

      expect(resource.get(property)).toBeUndefined();
      expect(getProperty).not.toHaveBeenCalled();
      expect(changed).toHaveBeenCalledTimes(1);
      expect(changed).toHaveBeenCalledWith(property, undefined);
      await expect(resource.set(property, 42)).rejects.toThrow();
    },
  );
});
