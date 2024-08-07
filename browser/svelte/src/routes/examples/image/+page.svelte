<script>
	import Image from '$lib/components/Image/Image.svelte';
</script>

<svelte:head>
	<title>Image Example</title>
</svelte:head>

<h1>Image example</h1>

<p>
	The {'<'}Image /{'>'} component renders a file resource as an image and optimizes it based on the screen
	size and supported image formats.
</p>

<div class="image-styler">
	<Image
		subject="https://atomicdata.dev/files/1722940350336-big_image_of_a_bonzai.jpg"
		alt="A bonzai tree that lost half its leaves"
	/>
</div>

<div class="image-row">
	<div>
		Quality: 60 (default)
		<Image
			subject="https://atomicdata.dev/files/1722940350336-big_image_of_a_bonzai.jpg"
			alt="A bonzai tree that lost half its leaves"
			loading="lazy"
			sizeIndication={{
				// For a viewport smaller than 1000px the images width will be about 50% of the viewport width
				'1000px': 50,
				// For a viewport larger than 1000px the images width will be about 500px because the container will not grow larger than 1000px
				default: '500px'
			}}
		/>
	</div>
	<div>
		Quality: 20
		<Image
			subject="https://atomicdata.dev/files/1722940350336-big_image_of_a_bonzai.jpg"
			alt="A bonzai tree that lost half its leaves"
			loading="lazy"
			quality={20}
			sizeIndication={{
				'1000px': 50,
				default: '500px'
			}}
		/>
	</div>
</div>

<style>
	.image-styler {
		display: contents;
		& img {
			border-radius: 15px;
		}
	}

	.image-row {
		display: flex;
		margin-top: 1rem;
		gap: 1rem;
	}
</style>
