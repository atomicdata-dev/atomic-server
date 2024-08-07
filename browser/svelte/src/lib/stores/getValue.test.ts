import { Store } from '@tomic/lib';
import { get } from 'svelte/store';
import { describe, it, expect, beforeEach, vi } from 'vitest';

import { getResource, getValue, initStore, store } from '../index.js';

const resourceSubject = 'https://resource1';
const property = 'https://property';

describe('getValue', () => {
  beforeEach(() => {
    const newStore = new Store();

    initStore(newStore);
  });

  it('should return a value store with the correct value', () => {
    const expectedValue = "Psyduck is the best pokemon don't @ me";

    const _store = get(store);

    const initialResource = _store.getResourceLoading(resourceSubject, {
      newResource: true,
    });

    initialResource.setUnsafe(property, expectedValue);

    const resourceStore = getResource(resourceSubject);
    const valueStore = getValue(resourceStore, property);

    const value = get(valueStore);
    expect(value).toBe(expectedValue);
  });

  it('should notify the atomic store when updated', () => {
    const fn = vi.fn();
    const _store = get(store);

    _store.getResourceLoading(resourceSubject, { newResource: true });
    _store.subscribe(resourceSubject, fn);

    const resourceStore = getResource(resourceSubject);
    const valueStore = getValue(resourceStore, property);

    expect(fn).toHaveBeenCalledTimes(0);

    valueStore.set('Updated Value');

    expect(fn).toHaveBeenCalledTimes(1);
  });
});
