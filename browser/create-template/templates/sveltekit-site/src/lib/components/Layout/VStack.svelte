<script lang="ts">
	export let gap = '1rem';
	export let align = 'start';
	export let justify = 'start';
	export let height = 'auto';
</script>

<div
	style:--vstack-gap={gap}
	style:--vstack-align={align}
	style:--vstack-justify={justify}
	style:--vstack-height={height}
>
	<slot />
</div>

<style>
	div {
		display: flex;
		flex-direction: column;
		gap: var(--vstack-gap);
		align-items: var(--vstack-align);
		justify-content: var(--vstack-justify);
		height: var(--vstack-height);
		& > h1,
		& > h2,
		& > h3,
		& > h4,
		& > h5,
		& > h6 {
			margin: 0;
		}
	}
</style>
