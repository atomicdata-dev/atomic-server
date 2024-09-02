import { get } from 'svelte/store';
import { initStore, store as atomicStore } from '@tomic/svelte';
import { Store } from '@tomic/lib';
import { PUBLIC_ATOMIC_SERVER_URL } from '$env/static/public';
import { initOntologies } from '$lib/ontologies';

const init = () => {
	const atomicStore = new Store({
		serverUrl: PUBLIC_ATOMIC_SERVER_URL
	});
	initStore(atomicStore);
	initOntologies();
};

export const getStore = () => {
	let store = get(atomicStore);

	if (store === undefined) {
		init();
		store = get(atomicStore);
	}

	return store;
};
