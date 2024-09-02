<script lang="ts">
	import { website } from '$lib/ontologies/website';
	import { getResource } from '@tomic/svelte';
	import DefaultView from '../DefaultView.svelte';
	import TextBlock from './TextBlock.svelte';
	import ImageGalleryBlock from './ImageGalleryBlock.svelte';

	export let subject: string;
	let block = getResource(subject);

	$: component = $block.matchClass(
		{
			[website.classes.textBlock]: TextBlock,
			[website.classes.imageGalleryBlock]: ImageGalleryBlock
		},
		DefaultView
	);
</script>

<svelte:component this={component} resource={$block} />
