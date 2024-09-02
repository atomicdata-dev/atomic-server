<script lang="ts">
	import type { TextBlock } from '$lib/ontologies/website';
	import type { Resource } from '@tomic/lib';
	import SvelteMarkdown from 'svelte-markdown';

	export let resource: Resource<TextBlock>;
</script>

<div class="wrapper">
	<SvelteMarkdown source={resource.props.description} />
</div>

<style>
	.wrapper {
		max-width: 70ch;
	}
</style>
