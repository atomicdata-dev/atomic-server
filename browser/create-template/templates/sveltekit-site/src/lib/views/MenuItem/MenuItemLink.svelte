<script lang="ts">
	import { unknownSubject, type Resource } from '@tomic/lib';
	import { website, type MenuItem } from '$lib/ontologies/website';
	import { getResource, getValue } from '@tomic/svelte';

	export let resource: Resource<MenuItem>;
	export let active = false;

	$: page = getResource(resource.props.linksTo ?? unknownSubject);
	$: path = getValue(page, website.properties.href);
</script>

<a href={$path} aria-current={active ? 'page' : 'false'}>{resource.title}</a>

<style>
	a {
		width: 100%;
		text-decoration: none;
		color: var(--theme-color-text);
		padding: 0.4rem;
		display: inline-flex;
		border-radius: var(--theme-border-radius);
		transition: background-color 100ms ease-in-out;

		&[aria-current='page'] {
			color: var(--theme-color-accent);
		}

		&:hover,
		&:focus-visible {
			background-color: var(--theme-color-bg-2);
		}
	}
</style>
