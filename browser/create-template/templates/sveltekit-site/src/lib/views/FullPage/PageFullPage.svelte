<script lang="ts">
	import Container from '$lib/components/Layout/Container.svelte';
	import type { Page } from '$lib/ontologies/website';
	import { core, type Resource } from '@tomic/lib';
	import BlockView from '../Block/BlockView.svelte';
	import type { Readable } from 'svelte/store';
	import { getValue } from '@tomic/svelte';

	export let resource: Readable<Resource<Page>>;

	$: title = getValue(resource, core.properties.name);
</script>

<Container>
	<div class="wrapper">
		<h1>{$title}</h1>

		{#each $resource.props.blocks ?? [] as block (block)}
			<BlockView subject={block} />
		{/each}
	</div>
</Container>

<style>
	.wrapper {
		padding: 1rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;

		& h1 {
			margin: 0;
		}
	}
</style>
