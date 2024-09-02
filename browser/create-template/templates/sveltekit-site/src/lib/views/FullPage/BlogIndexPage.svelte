<script lang="ts">
	import Container from '$lib/components/Layout/Container.svelte';
	import { website } from '$lib/ontologies/website';
	import { CollectionBuilder, core, type Resource } from '@tomic/lib';
	import { store } from '@tomic/svelte';
	import { writable, type Readable } from 'svelte/store';
	import ListItemView from '../ListItem/ListItemView.svelte';
	import VStack from '$lib/components/Layout/VStack.svelte';
	import HStack from '$lib/components/Layout/HStack.svelte';
	import Searchbar from '$lib/components/Searchbar.svelte';
	import { debounced } from '$lib/utils';
	import Loader from '$lib/components/Loader.svelte';
	import { getAllBlogposts } from '$lib/atomic/getAllBlogposts';

	export let resource: Readable<Resource>;

	let searchValue = writable('');
	// debouncedSearchValue gets updated at most once every 100ms to prevent too many requests being sent when the user is typing.
	// Low end devices can't handle that many requests at once so we should limit it.
	let debouncedSearchValue = debounced(searchValue, 200);

	let allItems: string[] = [];
	let results: string[] = [];

	// We create a collection that collects all resources with the blogpost class. Sorted by publishedAt in descending order.
	getAllBlogposts().then((members) => {
		allItems = members;
		results = members;
	});

	// Everytime debouncedSearchValue changes we perform a search and filter the results to only include blogposts.
	$: {
		if ($debouncedSearchValue) {
			$store
				.search($debouncedSearchValue, {
					filters: {
						[core.properties.isA]: website.classes.blogpost
					}
				})
				.then((r) => (results = r));
		} else {
			// If the query is empty we show all blogposts.
			results = allItems;
		}
	}
</script>

<Loader resource={$resource}>
	<Container>
		<div class="wrapper">
			<VStack>
				<HStack wrap fullWidth align="center" justify="space-between">
					<h1>{$resource.title}</h1>
					<Searchbar bind:value={$searchValue} placeholder="Search blogposts..." />
				</HStack>
				{#if results.length === 0}
					<p>No results found</p>
				{/if}
				<ul>
					{#each results as item (item)}
						<li>
							<ListItemView subject={item} />
						</li>
					{/each}
				</ul>
			</VStack>
		</div>
	</Container>
</Loader>

<style>
	.wrapper {
		padding: 1rem;
	}

	ul {
		display: grid;
		grid-template-columns: repeat(
			auto-fill,
			minmax(calc(var(--theme-size-container-width) / 3 - 4rem), 1fr)
		);
		gap: 1rem;
		list-style-type: none;
		padding: 0;
	}
</style>
