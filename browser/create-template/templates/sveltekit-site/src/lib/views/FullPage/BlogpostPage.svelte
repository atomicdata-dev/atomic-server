<script lang="ts">
	import Container from '$lib/components/Layout/Container.svelte';
	import type { Blogpost } from '$lib/ontologies/website';
	import type { Resource } from '@tomic/lib';
	import { Image } from '@tomic/svelte';
	import SvelteMarkdown from 'svelte-markdown';
	import type { Readable } from 'svelte/store';

	export let resource: Readable<Resource<Blogpost>>;

	const formatter = new Intl.DateTimeFormat('default', {
		year: 'numeric',
		month: 'long',
		day: 'numeric'
	});

	$: date = formatter.format(new Date($resource.props.publishedAt));
</script>

<Container>
	<div class="blog-wrapper">
		<Image subject={$resource.props.coverImage} alt="" />
		<div class="content">
			<h1>{$resource.title}</h1>
			<p class="publish-date">
				{date}
			</p>
			<SvelteMarkdown source={$resource.props.description} />
		</div>
	</div>
</Container>

<style>
	.blog-wrapper {
		padding: 1rem;
		& > picture > img {
			width: 100%;
			height: 25rem;
			object-fit: cover;
			border-radius: var(--theme-border-radius);
		}
	}

	.publish-date {
		color: var(--theme-color-text-light);
		margin-bottom: 2rem;
	}
	.content {
		max-width: 70ch;
		margin: auto;
	}
</style>
