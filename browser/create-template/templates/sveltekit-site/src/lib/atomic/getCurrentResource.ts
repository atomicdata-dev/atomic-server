import { CollectionBuilder, type Resource } from '@tomic/lib';
import { getStore } from './getStore';
import { website } from '$lib/ontologies/website';

type Fetch = typeof fetch;

/**
 * Queries the server for a resource with a href property that matches the given url pathname.
 * @param fetchOverride A fetch function given by Sveltekit.
 * @param url The current URL in the browser.
 * @returns Promise that resolves to the subject of the resource, or undefined if no resource was found.
 */
export async function getCurrentResource(
	fetchOverride: Fetch,
	url: URL
): Promise<Resource | undefined> {
	const store = getStore();
	// Svelte uses a special fetch function that inlines responses during server-side rendering. To make sure the store can make use of this we need to inject the fetch function into the store.
	store.injectFetch(fetchOverride);

	const path = url.pathname;

	// Find the resource with the current path as href.
	const collection = await new CollectionBuilder(store)
		.setProperty(website.properties.href)
		.setValue(path)
		.buildAndFetch();

	if (collection.totalMembers === 0) {
		return undefined;
	}

	const currentResourceSubject = await collection.getMemberWithIndex(0);

	return await store.getResource(currentResourceSubject);
}
