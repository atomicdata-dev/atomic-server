import { describe, expect, it, vi } from 'vitest';
import { Datatype } from './datatypes.js';
import { core } from './ontologies/core.js';
import { Resource, ResourceEvents } from './resource.js';
import { Store } from './store.js';

const property = 'https://example.com/properties/optional';

function setup(datatype: Datatype) {
  const store = new Store({ serverUrl: 'https://example.com' });
  store.injectFetch(async () => {
    throw new Error('Unexpected network access');
  });
  const definition = new Resource(property);
  definition.applyHydratedValues([
    [core.properties.isA, [core.classes.property]],
    [core.properties.shortname, 'optional'],
    [core.properties.description, 'Optional test property'],
    [core.properties.datatype, datatype],
  ]);
  store.addResource(definition);

  const resource = new Resource('https://example.com/record');
  resource.setStore(store);

  return { store, resource };
}

describe('Resource.set(undefined)', () => {
  it.each([
    [Datatype.STRING, 'A note'],
    [Datatype.DATE, '2026-10-20'],
  ])(
    'removes a %s property with default validation',
    async (datatype, value) => {
      const { store, resource } = setup(datatype as Datatype);
      await resource.set(property, value);
      const getProperty = vi.spyOn(store, 'getProperty');
      const changed = vi.fn();
      resource.on(ResourceEvents.LocalChange, changed);

      await resource.set(property, undefined);

      expect(resource.get(property)).toBeUndefined();
      expect(getProperty).not.toHaveBeenCalled();
      expect(changed).toHaveBeenCalledExactlyOnceWith(property, undefined);

      const reopened = new Resource(resource.subject);
      reopened.importLoroUpdate(
        resource.getLoroDoc()!.export({ mode: 'snapshot' }),
      );
      expect(reopened.get(property)).toBeUndefined();
    },
  );

  it.each([Datatype.STRING, Datatype.DATE])(
    'removes a property with known datatype %s',
    async datatype => {
      const { store, resource } = setup(datatype);
      await resource.set(property, 'Original value', false);
      const getProperty = vi.spyOn(store, 'getProperty');
      const changed = vi.fn();
      resource.on(ResourceEvents.LocalChange, changed);

      await resource.set(property, undefined, true, datatype);

      expect(resource.get(property)).toBeUndefined();
      expect(getProperty).not.toHaveBeenCalled();
      expect(changed).toHaveBeenCalledExactlyOnceWith(property, undefined);
    },
  );

  it('still rejects invalid non-undefined values in both validation paths', async () => {
    const { resource } = setup(Datatype.DATE);
    await resource.set(property, '2026-10-20');

    await expect(resource.set(property, 'not a date')).rejects.toThrow();
    await expect(
      resource.set(property, 'not a date', true, Datatype.DATE),
    ).rejects.toThrow();
    expect(resource.get(property)).toBe('2026-10-20');
  });
});
