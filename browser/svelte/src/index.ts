import type { Store } from '@tomic/lib';
import { __store_internal } from './stores/store';

export const initStore = (store: Store) => {
  __store_internal.set(store);
};

export { store } from './stores/store';
export { getResource } from './stores/getResource';
export { getValue } from './stores/getValue';
export * from './loadResourceTree';
