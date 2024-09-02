<script lang="ts">
	import { website, type MenuItem } from '$lib/ontologies/website';
	import { generateId } from '$lib/utils';
	import { getResource, getValue } from '@tomic/svelte';
	import MenuItemLink from './MenuItemLink.svelte';
	import { unknownSubject } from '@tomic/lib';
	import type { FocusEventHandler } from 'svelte/elements';
	import { currentSubject } from '$lib/stores/currentSubject';

	/*
		This view renders a menu-item resource. A menu-item can have a linked-to property but also a sub-items property.
		If it has a links-to prop, we simply render a link that navigates to the href of the linked resource.
		If it has a sub-items prop, we render a button that toggles a popover in which we render this same view for all sub items.
	*/

	export let subject: string;

	/* A random id used to link the button to the popover */
	const id = generateId();

	let menuItem = getResource<MenuItem>(subject ?? unknownSubject);

	let popover: HTMLDivElement;
	let button: HTMLButtonElement;

	const closePopover = () => {
		popover?.hidePopover();
	};

	// When the popover loses focus we check if that focus moved outside of the popover or the button that toggles it.
	// If so we close the popover.
	const onFocusout: FocusEventHandler<HTMLButtonElement | HTMLDivElement> = (event) => {
		if (!event.relatedTarget || !event.currentTarget.contains(event.relatedTarget as Node)) {
			closePopover();
		}
	};

	$: subItems = getValue(menuItem, website.properties.subItems);
</script>

<svelte:document
	on:click={(e) => {
		if (!button?.contains(e.currentTarget) && !popover?.contains(e.currentTarget)) {
			closePopover();
		}
	}}
/>

{#if $subItems && $subItems.length > 0}
	<button bind:this={button} popovertarget={id} popovertargetaction="toggle">
		{$menuItem.title}
	</button>

	<div class="submenu" popover="manual" {id} bind:this={popover} on:focusout={onFocusout}>
		{#each $subItems as subItem}
			<ul>
				<li>
					<svelte:self subject={subItem} />
				</li>
			</ul>
		{/each}
	</div>
{:else}
	<!-- The resource does not have subitems so we just render a link -->
	<MenuItemLink resource={$menuItem} active={$currentSubject === $menuItem.props.linksTo} />
{/if}

<style>
	ul {
		padding: 0.5rem;
		list-style: none;
	}
	button {
		padding: 0.4rem;
		display: inline-flex;
		align-items: center;
		border-radius: var(--theme-border-radius);
		height: 100%;
		appearance: none;
		border: none;
		background: none;
		cursor: pointer;
		transition: background-color 100ms ease-in-out;
		anchor-name: --menu-item-anchor;
		&:hover,
		&:focus-visible {
			background-color: var(--theme-color-bg-2);
		}
	}

	.submenu {
		position-anchor: --menu-item-anchor;
		inset-area: bottom center;
		position-area: bottom center;
		width: max(20ch, anchor-size(width));
		border: 1px solid var(--theme-color-bg-1);
		border-radius: var(--theme-border-radius);
		box-shadow:
			0px 2.8px 2.2px rgba(0, 0, 0, 0.02),
			0px 6.7px 5.3px rgba(0, 0, 0, 0.028),
			0px 12.5px 10px rgba(0, 0, 0, 0.035),
			0px 22.3px 17.9px rgba(0, 0, 0, 0.042),
			0px 41.8px 33.4px rgba(0, 0, 0, 0.05),
			0px 100px 80px rgba(0, 0, 0, 0.07);
	}
</style>
