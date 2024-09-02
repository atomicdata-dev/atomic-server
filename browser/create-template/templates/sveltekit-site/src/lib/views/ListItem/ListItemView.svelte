<script lang="ts">
	import { website } from '$lib/ontologies/website';
	import { getResource } from '@tomic/svelte';
	import DefaultView from '../DefaultView.svelte';
	import BlogListItem from './BlogListItem.svelte';

	export let subject: string;
	let listItem = getResource(subject);

	$: component = $listItem.matchClass(
		{
			[website.classes.blogpost]: BlogListItem
		},
		DefaultView
	);
</script>

<svelte:component this={component} resource={$listItem} />
