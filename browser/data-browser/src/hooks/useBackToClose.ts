import { useCallback, useEffect, useEffectEvent, useRef } from 'react';
import { useRouter } from '@tanstack/react-router';

/**
 * Makes the browser (or phone) Back button close a transient layer such as a
 * menu, instead of navigating away underneath it.
 *
 * While `open`, a history entry is pushed on the current page. Back pops that
 * entry, which calls `onClose`. When the layer closes by any other means
 * (Escape, click away) the entry is popped again, so Back doesn't land on a
 * dead step.
 *
 * An item that navigates (or opens something by navigating) changes the
 * location first. The entry then no longer belongs to the page on top, so it
 * is left alone instead of popped: popping would undo the navigation. That
 * leaves one extra step underneath, which is the price of not deferring the
 * item's own action. Without a router (tests, isolated stories) the hook
 * does nothing.
 */
export function useBackToClose(open: boolean, onClose: () => void) {
  const router = useRouter({ warn: false });
  const history = router?.history;
  const entry = useRef<string | undefined>(undefined);
  const entryHref = useRef<string | undefined>(undefined);
  const close = useEffectEvent(onClose);

  const ownsEntry = useCallback(
    () =>
      !!history &&
      !!entry.current &&
      history.location.state.backToClose === entry.current &&
      history.location.href === entryHref.current,
    [history],
  );

  useEffect(() => {
    if (!history) return;

    return history.subscribe(() => {
      if (entry.current && !ownsEntry()) {
        entry.current = undefined;
        close();
      }
    });
  }, [history, ownsEntry]);

  useEffect(() => {
    if (!history) return;

    if (open && !entry.current) {
      entry.current = crypto.randomUUID();
      entryHref.current = history.location.href;
      history.push(history.location.href, {
        ...history.location.state,
        backToClose: entry.current,
      });
    } else if (!open && entry.current) {
      const owned = ownsEntry();
      entry.current = undefined;

      if (owned) history.back();
    }
  }, [open, history, ownsEntry]);
}

declare module '@tanstack/react-router' {
  interface HistoryState {
    backToClose?: string;
  }
}
