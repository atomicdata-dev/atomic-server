<script lang="ts">
	import type { PageData } from './$types';
	import FullPageView from '$lib/views/FullPage/FullPageView.svelte';
	import { currentSubject } from '$lib/stores/currentSubject';

	export let data: PageData;

	$: subject = data.subject;

	$: $currentSubject = subject;
</script>

<FullPageView {subject} />
