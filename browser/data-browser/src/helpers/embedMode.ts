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
