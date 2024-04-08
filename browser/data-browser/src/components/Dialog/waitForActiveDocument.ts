/**
 * Waits for when the document becomes active again after it has been inert.
 * (Useful for waiting for a dialog to close before navigating to a new page)
 */
export function waitForActiveDocument(callback: () => void) {
  const observer = new MutationObserver(() => {
    if (!document.body.hasAttribute('inert')) {
      callback();
      observer.disconnect();
    }
  });

  observer.observe(document.body, {
    attributes: true,
    attributeFilter: ['inert'],
  });
}
