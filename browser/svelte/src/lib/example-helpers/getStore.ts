import { initStore } from '$lib/index.js';
import { store as atomicStore } from '$lib/stores/store.js';
import { Store } from '@tomic/lib';
import { get } from 'svelte/store';

const init = () => {
	const atomicStore = new Store({
		// Drive with example data
		serverUrl: 'https://atomicdata.dev/drive/WnY9YDmm'
	});
	initStore(atomicStore);
};

export const getStore = () => {
	let store = get(atomicStore);

	if (store === undefined) {
		init();
		store = get(atomicStore);
	}

	return store;
};
