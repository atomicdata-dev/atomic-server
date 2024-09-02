<script lang="ts">
	import { core, type Resource } from '@tomic/lib';
	import { Image } from '@tomic/svelte';
	import type { ImageGalleryBlock } from '$lib/ontologies/website';

	export let resource: Resource<ImageGalleryBlock>;
</script>

{#if resource.get(core.properties.name)}
	<h2>{resource.title}</h2>
{/if}
<div class="wrapper">
	{#each resource.props.images as image}
		<Image subject={image} alt="" />
	{/each}
</div>

<style>
	.wrapper {
		width: 100%;
		display: grid;
		grid-template-columns: repeat(
			auto-fill,
			minmax(calc(var(--theme-size-container-width) / 3 - 4rem), 1fr)
		);
		gap: 1rem;
		& img {
			aspect-ratio: 1 / 1;
			object-fit: cover;
		}
	}
</style>
