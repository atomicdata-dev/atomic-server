/**
 * The page is the Flutter app's embedded renderer: it shows one resource and
 * nothing around it (no navbar, sidebars or panels; the host app has its own).
 * Set once by `embed/embed.tsx` before anything renders.
 */
let embedded = false;

export function enableEmbedMode(): void {
  embedded = true;
}

export function isEmbedded(): boolean {
  return embedded;
}

export type HostColorScheme = 'light' | 'dark';

/** Fired on `window` when the host reports another system color scheme. */
export const HOST_COLOR_SCHEME_EVENT = 'atomic-embed-color-scheme';

let hostColorScheme: HostColorScheme | undefined;

/**
 * The host app's own light/dark mode. An Android web view only follows the
 * app's night mode for `prefers-color-scheme` when force-dark is configured, so
 * the host can tell the page instead (`atomicEmbed.setColorScheme`). "Auto" in
 * the settings then follows this; without a report it follows the media query.
 */
export function setHostColorScheme(scheme: HostColorScheme | undefined): void {
  hostColorScheme = scheme;
  window.dispatchEvent(new Event(HOST_COLOR_SCHEME_EVENT));
}

export function getHostColorScheme(): HostColorScheme | undefined {
  return hostColorScheme;
}
