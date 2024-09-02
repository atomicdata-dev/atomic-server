import { derived, type Writable } from 'svelte/store';

export function generateId(): string {
	return (Math.random().toString(36) + '00000000000000000').slice(2, 10);
}

export function debounced<T>(store: Writable<T>, delay = 100) {
	let initialised = false;
	return derived(store, ($value, set: (value: T) => void) => {
		if (!initialised) {
			set($value);
			initialised = true;
			return;
		}
		const timeout = setTimeout(() => {
			set($value);
		}, delay);

		return () => {
			clearTimeout(timeout);
		};
	});
}
