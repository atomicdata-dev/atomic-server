// @wc-ignore-file
import { useEffect, useState } from 'react';
import { useStore, type Store } from '@tomic/react';

/** Who signed the newest change, per resource and edit time. */
const cache = new Map<string, string | null>();

/**
 * The agent that signed the newest change of a resource, from the signed
 * envelopes the server (and this client) kept: one history-attribution read
 * per resource, cached per edit time. `undefined` while loading or when no
 * envelope says; it never guesses. Does nothing unless `enabled`.
 */
export function useLastEditor(
  subject: string,
  at: number | undefined,
  enabled: boolean,
): string | undefined {
  const store = useStore();
  const key = `${subject}@${at}`;
  const [loaded, setLoaded] = useState<{
    key: string;
    editor: string | null;
  }>();

  useEffect(() => {
    if (!enabled || cache.has(key)) return;

    let cancelled = false;

    void lookupLastEditor(store, subject).then(editor => {
      cache.set(key, editor);

      if (!cancelled) setLoaded({ key, editor });
    });

    return () => {
      cancelled = true;
    };
  }, [store, subject, key, enabled]);

  if (!enabled) return undefined;

  const editor = loaded?.key === key ? loaded.editor : cache.get(key);

  return editor ?? undefined;
}

async function lookupLastEditor(
  store: Store,
  subject: string,
): Promise<string | null> {
  try {
    const report = await store.getHistoryAttribution(subject);
    const newest = report?.attributions
      .filter(a => !a.destroy)
      .reduce<(typeof report.attributions)[number] | undefined>(
        (best, a) => (!best || a.createdAt >= best.createdAt ? a : best),
        undefined,
      );

    return newest?.signer ?? null;
  } catch {
    return null;
  }
}
