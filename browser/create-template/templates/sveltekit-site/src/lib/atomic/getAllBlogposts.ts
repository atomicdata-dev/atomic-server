import { website } from '$lib/ontologies/website';
import { CollectionBuilder, core } from '@tomic/lib';
import { store as storeStore } from '@tomic/svelte';
import { get } from 'svelte/store';
export async function getAllBlogposts(): Promise<string[]> {
	const store = get(storeStore);

	const collection = new CollectionBuilder(store)
		.setProperty(core.properties.isA)
		.setValue(website.classes.blogpost)
		.setSortBy(website.properties.publishedAt)
		.setSortDesc(true)
		.build();

	return await collection.getAllMembers();
}
