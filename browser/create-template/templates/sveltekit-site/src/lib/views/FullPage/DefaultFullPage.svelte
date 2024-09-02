<script lang="ts">
	import Container from '$lib/components/Layout/Container.svelte';
	import type { Resource } from '@tomic/lib';
	import type { Readable } from 'svelte/store';

	export let resource: Readable<Resource>;
</script>

<Container>
	<h1>{$resource.title}</h1>

	<p>No valid page view for this resource.</p>
</Container>
