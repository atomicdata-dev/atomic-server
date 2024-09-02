<script lang="ts">
	import type { Resource } from '@tomic/lib';
	import { store } from '@tomic/svelte';
	import { onMount } from 'svelte';

	export let resource: Resource;
	let loading = resource.loading;

	onMount(() => {
		return $store.subscribe(resource.subject, (r) => (loading = r.loading));
	});
</script>

{#if loading}
	<div class="loader">Loading...</div>
{:else}
	<slot />
{/if}
