/** Reports `document.documentElement`'s content height to the embedding
 * page via `postMessage` whenever it changes, so the copy-pasted `<iframe>`
 * snippet (`ShareLinkPanel.tsx`'s "Embed" view) can resize itself to fit —
 * there's no other way for a same-origin-restricted parent page to read an
 * iframe's content height directly. `'*'` as the target origin is safe here:
 * the embedding site is arbitrary by design, and a height number carries no
 * sensitive data (same choice `pluginRPC.tsx` makes for its own
 * `postMessage` calls). */
export function startEmbedResizeReporting(): () => void {
  const root = document.documentElement;

  const report = () => {
    window.parent.postMessage(
      { type: 'atomic-form-resize', height: root.scrollHeight },
      '*',
    );
  };

  const observer = new ResizeObserver(report);
  observer.observe(root);
  report();

  return () => observer.disconnect();
}
