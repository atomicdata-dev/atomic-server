import { PUBLIC_WEBSITE_RESOURCE } from '$env/static/public';
import { writable } from 'svelte/store';

export const currentSubject = writable(PUBLIC_WEBSITE_RESOURCE);
