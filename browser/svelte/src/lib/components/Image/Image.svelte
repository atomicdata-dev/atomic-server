<script lang="ts">
	import { getResource } from '$lib/stores/getResource.js';
	import { getValue } from '$lib/stores/getValue.js';
	import { server, type Server } from '@tomic/lib';
	import type { HTMLImgAttributes } from 'svelte/elements';
	import {
		buildSrcSet,
		DEFAULT_SIZES,
		imageFormatsWithBasicSupport,
		imageFormatsWithFullSupport,
		indicationToSizes,
		type SizeIndication
	} from './imageHelpers.js';

	enum Support {
		Full,
		Basic,
		None
	}
	interface $$Props extends HTMLImgAttributes {
		subject: string;
		alt: string;
		noBaseStyles?: boolean;
		quality?: number;
		sizeIndication?: SizeIndication;
	}

	export let subject: $$Props['subject'];
	export let alt: $$Props['alt'];
	export let noBaseStyles: $$Props['noBaseStyles'] = false;
	export let quality: number = 60;
	export let sizeIndication: $$Props['sizeIndication'] = undefined;

	let supported = Support.Full;

	let resource = getResource<Server.File>(subject);
	let downloadUrl = getValue(resource, server.properties.downloadUrl);
	let mimetype = getValue(resource, server.properties.mimetype);

	$: {
		if (imageFormatsWithFullSupport.has($mimetype!)) {
			supported = Support.Full;
		} else if (imageFormatsWithBasicSupport.has($mimetype!)) {
			supported = Support.Basic;
		} else {
			supported = Support.None;
		}
	}

	$: toSrcSet = buildSrcSet($downloadUrl);
</script>

{#if $resource.error}
	<p>{$resource.error.message}</p>
{:else if $resource.loading}
	<p>Loading...</p>
{:else if supported === Support.None}
	<p>Image format not supported</p>
{:else if supported === Support.Basic}
	<img
		src={$downloadUrl}
		class:base-styles={!noBaseStyles}
		{alt}
		height={$resource.props.imageHeight}
		width={$resource.props.imageWidth}
		{...$$restProps}
	/>
{:else if supported === Support.Full}
	<picture>
		<source
			srcSet={toSrcSet('avif', quality, DEFAULT_SIZES)}
			type="image/avif"
			sizes={indicationToSizes(sizeIndication)}
			height={$resource.props.imageHeight}
			width={$resource.props.imageWidth}
		/>
		<source
			srcSet={toSrcSet('webp', quality, DEFAULT_SIZES)}
			type="image/webp"
			sizes={indicationToSizes(sizeIndication)}
			height={$resource.props.imageHeight}
			width={$resource.props.imageWidth}
		/>
		<img
			src={$downloadUrl}
			class:base-styles={!noBaseStyles}
			{alt}
			height={$resource.props.imageHeight}
			width={$resource.props.imageWidth}
			{...$$restProps}
		/>
	</picture>
{/if}

<style>
	.base-styles {
		max-width: 100%;
		height: auto;
	}
</style>
