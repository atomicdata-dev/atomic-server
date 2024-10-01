<script lang="ts">
	import { unknownSubject, type Resource } from '@tomic/lib';
	import { website, type MenuItem } from '$lib/ontologies/website';
	import { getResource, getValue } from '@tomic/svelte';

	export let resource: Resource<MenuItem>;
	export let active = false;

	let href = '';

	$: page = getResource(resource.props.linksTo ?? unknownSubject);
	$: pageHrefValue = getValue(page, website.properties.href);

	// If the menu item has a linksTo prop we want the href value of the page it links to. If that doesn't exist we check for an external link.
	$: href = $pageHrefValue ?? resource.props.externalLink ?? '';
</script>

<a {href} aria-current={active ? 'page' : 'false'}>{resource.title}</a>

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
