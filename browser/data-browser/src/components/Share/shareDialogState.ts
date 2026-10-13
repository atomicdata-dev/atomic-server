/**
 * Module-level switch for the Share dialog, in the same spirit as
 * `overlayState.ts`: action definitions (menu, command palette, AI tools) can
 * open it without importing the React tree. `ShareDialogHost` is the one
 * listener, mounted once in the app chrome.
 */

type Listener = (subject: string | undefined) => void;

const listeners = new Set<Listener>();

/** Opens the Share dialog for `subject`. */
export function openShareDialog(subject: string): void {
  listeners.forEach(listener => listener(subject));
}

export function closeShareDialog(): void {
  listeners.forEach(listener => listener(undefined));
}

export function subscribeShareDialog(listener: Listener): () => void {
  listeners.add(listener);

  return () => {
    listeners.delete(listener);
  };
}
