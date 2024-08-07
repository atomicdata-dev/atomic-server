<script lang="ts">
	import { getStore } from '$lib/example-helpers/getStore.js';

	// Initialize a store if it isn't already
	getStore();
</script>

<main>
	<slot />
</main>

<style>
	:global(body) {
		font-family: system-ui;
	}

	main {
		width: min(100%, 1000px);
		margin: auto;
		padding-inline: 1rem;
	}
</style>
