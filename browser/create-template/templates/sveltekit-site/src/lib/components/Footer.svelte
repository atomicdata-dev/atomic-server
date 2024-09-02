<script lang="ts">
	import Container from './Layout/Container.svelte';

	const year = new Date().getFullYear();
</script>

<footer>
	<Container>
		<p>© {year} Your Company</p>
	</Container>
</footer>

<style>
	footer {
		background-color: var(--theme-color-bg-2);
		color: var(--theme-color-text-light);
	}

	p {
		padding: 1rem;
	}
</style>
