// Reexport your entry components here

import type { Store } from '@tomic/lib';
import { __store_internal } from './stores/store.js';

export const initStore = (store: Store) => {
  __store_internal.set(store);
};

export * from './components/Image/index.js';
export { store } from './stores/store.js';
export { getResource } from './stores/getResource.js';
export { getValue } from './stores/getValue.js';
export * from './loadResourceTree.js';
