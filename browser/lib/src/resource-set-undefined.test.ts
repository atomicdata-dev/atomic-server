import { describe, it, vi } from 'vitest';
import { Datatype } from './datatypes.js';
import { Resource, ResourceEvents } from './resource.js';
import { Store, type Property } from './store.js';

const due = 'https://example.org/due';

/** A store that knows `due` as an optional date Property, without network. */
function storeWithDateProperty(): Store {
  const store = new Store();
  vi.spyOn(store, 'getProperty').mockResolvedValue({
    subject: due,
    datatype: Datatype.DATE,
    shortname: 'due',
    description: 'Optional due date',
  } as Property);

  return store;
}

describe('Resource.set(prop, undefined) (#2315)', () => {
  it('removes a validated property instead of throwing', async ({ expect }) => {
    const row = new Resource('https://example.org/row');
    row.setStore(storeWithDateProperty());
    await row.set(due, '2026-10-20');

    const changes: unknown[] = [];
    row.on(ResourceEvents.LocalChange, (prop, value) => {
      if (prop === due) changes.push(value);
    });

    await row.set(due, undefined);

    expect(row.get(due)).toBeUndefined();
    expect(row.hasUnsavedChanges()).toBe(true);
    expect(changes).toEqual([undefined]);
  });

  it('removes via the known-datatype path too', async ({ expect }) => {
    const row = new Resource('https://example.org/row');
    row.setStore(storeWithDateProperty());
    await row.set(due, '2026-10-20', true, Datatype.DATE);

    await row.set(due, undefined, true, Datatype.DATE);

    expect(row.get(due)).toBeUndefined();
  });

  it('still rejects an invalid value', async ({ expect }) => {
    const row = new Resource('https://example.org/row');
    row.setStore(storeWithDateProperty());

    await expect(row.set(due, 'not a date')).rejects.toThrow(/due/);
    expect(row.get(due)).toBeUndefined();
  });
});
