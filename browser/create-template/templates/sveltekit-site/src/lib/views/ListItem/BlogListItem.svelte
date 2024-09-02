<script lang="ts">
	import { type Blogpost } from '$lib/ontologies/website';
	import type { Resource } from '@tomic/lib';
	import { Image } from '@tomic/svelte';

	export let resource: Resource<Blogpost>;

	const formatter = new Intl.DateTimeFormat('default', {
		year: 'numeric',
		month: 'long',
		day: 'numeric'
	});

	$: date = formatter.format(new Date(resource.props.publishedAt));
</script>

<a class="card" href={resource.props.href}>
	<div class="image-wrapper">
		<Image subject={resource.props.coverImage} alt="" />
	</div>
	<div class="card-content">
		<div class="publish-date">{date}</div>
		<h2>{resource.title}</h2>
		<p>{resource.props.description.slice(0, 300)}...</p>
	</div>
</a>

<style>
	.card {
		--border-color: var(--theme-color-bg-1);
		text-decoration: none;
		color: var(--theme-color-text);
		display: block;
		border: 1px solid var(--border-color);
		border-radius: var(--theme-border-radius);
		overflow: clip;
		& img {
			aspect-ratio: 21 / 9;
			object-fit: cover;
			transition: transform 300ms ease-in-out;
		}

		&:hover {
			border-color: var(--theme-color-accent);
			& img {
				transform: scale(1.1);
			}
		}
	}

	.publish-date {
		color: var(--theme-color-text-light);
	}
	.image-wrapper {
		aspect-ratio: 21 / 9;
		overflow: clip;
	}

	.card-content {
		padding: 1rem;
		height: 15rem;
		overflow: clip;
		position: relative;
		&::after {
			content: '';
			pointer-events: none;
			position: absolute;
			inset: 0;
			background: linear-gradient(0deg, white 0%, transparent 100%);
		}
	}

	h2 {
		font-size: 1.2rem;
		margin: 0;
		text-wrap: balance;
	}

	p {
		color: black;
	}
</style>
