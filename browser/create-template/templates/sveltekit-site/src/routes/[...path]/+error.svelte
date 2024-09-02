<script lang="ts">
	import Container from '$lib/components/Layout/Container.svelte';
	import { page } from '$app/stores';
</script>

<Container>
	<div class="wrapper">
		<div class="status">
			{$page.status}
		</div>
		<h1>{$page.error?.message}</h1>
	</div>
</Container>

<style>
	.wrapper {
		padding: 1rem;
	}
	.status {
		font-size: 3rem;
		color: var(--theme-color-alert);
		font-weight: bold;
	}
	h1 {
		font-size: 2rem;
	}
</style>
