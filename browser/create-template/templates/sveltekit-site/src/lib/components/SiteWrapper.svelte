<script lang="ts">
	import { core } from '@tomic/lib';
	import { getResource } from '@tomic/svelte';
	import { currentSubject } from '$lib/stores/currentSubject';
	import '../../styles/reset.css';

	let page = getResource(currentSubject);
</script>

<svelte:head>
	<title>{$page.title}</title>
	<meta content={$page.get(core.properties.description)} name="description" />
</svelte:head>
<slot />

<style>
	:root {
		--theme-color-bg: #fff;
		--theme-color-bg-1: #e3e3e3;
		--theme-color-bg-2: #ededed;
		--theme-color-accent: hsl(179, 58%, 37%);
		--theme-color-alert: hsl(356, 53%, 50%);
		--theme-color-text: #000;
		--theme-color-text-light: #555555;
		--theme-size-container-width: 900px;
		--theme-border-radius: 5px;
	}

	:global(body) {
		font-family: system-ui;
		background-color: var(--theme-color-bg);
		color: var(--theme-color-text);
		margin: 0px;
		min-height: 100vh;
	}

	:global([popover]) {
		margin: 0;
		padding: 0;
	}
</style>
