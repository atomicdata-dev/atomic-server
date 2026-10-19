// @wc-ignore-file
import { useEffect, useState } from 'react';
import { useResource, useStore, type Store } from '@tomic/react';
import { useServerConnected } from './useServerConnected';

/**
 * Who signed the newest change, per resource and edit time. Holds the
 * in-flight lookup, so rows asking for the same resource share one request,
 * and only an answer: a lookup that learned nothing is dropped so the next
 * ask can try again.
 */
const lookups = new Map<string, Promise<string | undefined>>();

/**
 * The agent that signed the newest change of a resource, from the signed
 * envelopes the server (and this client) kept: one history-attribution read
 * per resource, cached per edit time. `undefined` while loading or when no
 * envelope says; it never guesses. Does nothing unless `enabled`, and never
 * asks about a resource the server may not have yet (offline, still loading,
 * or with edits waiting in the outbox), which would only answer 404.
 */
export function useLastEditor(
  subject: string,
  at: number | undefined,
  enabled: boolean,
): string | undefined {
  const store = useStore();
  const resource = useResource(subject, { allowIncomplete: true });
  const connected = useServerConnected();
  const key = `${subject}@${at}`;
  const ready =
    enabled && connected && !resource.loading && !resource.hasPendingCommits;
  const [loaded, setLoaded] = useState<{
    key: string;
    editor: string | undefined;
  }>();

  useEffect(() => {
    if (!ready) return;

    let cancelled = false;

    void lookup(store, subject, key).then(editor => {
      if (!cancelled) setLoaded({ key, editor });
    });

    return () => {
      cancelled = true;
    };
  }, [store, subject, key, ready]);

  return ready && loaded?.key === key ? loaded.editor : undefined;
}

function lookup(
  store: Store,
  subject: string,
  key: string,
): Promise<string | undefined> {
  let pending = lookups.get(key);

  if (!pending) {
    pending = lastEditor(store, subject).then(editor => {
      if (editor === undefined) lookups.delete(key);

      return editor;
    });
    lookups.set(key, pending);
  }

  return pending;
}

async function lastEditor(
  store: Store,
  subject: string,
): Promise<string | undefined> {
  try {
    const report = await store.getHistoryAttribution(subject);

    return report?.attributions
      .filter(a => !a.destroy)
      .reduce<(typeof report.attributions)[number] | undefined>(
        (best, a) => (!best || a.createdAt >= best.createdAt ? a : best),
        undefined,
      )?.signer;
  } catch {
    return undefined;
  }
}
