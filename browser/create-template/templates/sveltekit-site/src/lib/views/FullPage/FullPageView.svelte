<script lang="ts">
	import { website } from '$lib/ontologies/website';
	import { getResource } from '@tomic/svelte';
	import PageFullPage from './PageFullPage.svelte';
	import DefaultFullPage from './DefaultFullPage.svelte';
	import BlogIndexPage from './BlogIndexPage.svelte';
	import BlogpostPage from './BlogpostPage.svelte';

	/*
		Renders a full page view. The actual view component is determined by the resource's class.
	*/

	export let subject: string;

	$: resource = getResource(subject);

	$: component = $resource.matchClass(
		{
			[website.classes.page]: PageFullPage,
			[website.classes.blogIndexPage]: BlogIndexPage,
			[website.classes.blogpost]: BlogpostPage
		},
		DefaultFullPage
	);
</script>

<svelte:component this={component} {resource} />
