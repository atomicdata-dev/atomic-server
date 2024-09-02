import type { PageLoad } from './$types';
import { getCurrentResource } from '$lib/atomic/getCurrentResource';
import { error } from '@sveltejs/kit';
import { preloadResources } from '$lib/atomic/preloadResources';

export const load = (async ({ fetch, url }) => {
	const resource = await getCurrentResource(fetch, url);

	if (resource === undefined) {
		error(404, {
			message: 'Page not found'
		});
	}

	await preloadResources(resource);

	return {
		subject: resource.subject
	};
}) satisfies PageLoad;
