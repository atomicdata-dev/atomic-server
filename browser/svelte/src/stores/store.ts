import { writable, readable } from 'svelte/store';
import type { Store } from '@tomic/lib';

export const __store_internal = writable<Store>(undefined);

export const store = readable<Store>(undefined, set => {
  __store_internal.subscribe(value => {
    set(value);
  });
});
