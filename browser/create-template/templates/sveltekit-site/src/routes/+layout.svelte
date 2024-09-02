<script lang="ts">
	import Navbar from '$lib/components/Navbar.svelte';
	import SiteWrapper from '$lib/components/SiteWrapper.svelte';
	import Footer from '$lib/components/Footer.svelte';
	import VStack from '$lib/components/Layout/VStack.svelte';
</script>

<SiteWrapper>
	<VStack align="stretch" height="100vh">
		<header>
			<Navbar />
		</header>
		<main>
			<slot />
		</main>
		<Footer />
	</VStack>
</SiteWrapper>

<style>
	main {
		flex: 1;
	}
</style>
