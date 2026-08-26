import { useCallback, useEffect, useRef, useState } from 'react';
import { useDebounce } from './useDebounce';

interface DraftString {
  /** The live value to bind an input to. */
  value: string;
  onChange: (next: string) => void;
}

/**
 * A text input backed by a resource property: types locally, commits on a
 * debounce, and **flushes on unmount**.
 *
 * The flush is the point. Committing per keystroke means a commit per
 * character, but a plain debounce silently drops the last edit whenever the
 * input goes away inside the debounce window — closing a popover, switching
 * to another field, navigating off. Anything editing a resource from a
 * dismissable surface needs both halves.
 *
 * `commit` is skipped for an empty string: these back required labels
 * (a Tag's `name`), where clearing the box is mid-edit rather than an intent
 * to store "".
 */
export function useDraftString(
  stored: string | undefined,
  commit: (value: string) => void,
  /** Re-seeds the draft when the edited resource changes under the input. */
  resetKey: string,
  delay = 150,
): DraftString {
  const [draft, setDraft] = useState(stored ?? '');
  const debounced = useDebounce(draft, delay);

  const commitIfChanged = useCallback(
    (value: string) => {
      if (value === '' || value === (stored ?? '')) return;

      commit(value);
    },
    [stored, commit],
  );

  // The unmount cleanup below runs once, so it would otherwise close over the
  // draft and commit from its very first render. Refs are written in effects,
  // not during render, so the React Compiler can still memoize this.
  const pending = useRef(draft);
  const latestCommit = useRef(commitIfChanged);

  useEffect(() => {
    pending.current = draft;
  }, [draft]);

  useEffect(() => {
    latestCommit.current = commitIfChanged;
  }, [commitIfChanged]);

  // What the draft was last seeded from. Distinguishes "the box still shows
  // what we put there" from "the user has typed something".
  const seeded = useRef(stored ?? '');

  useEffect(() => {
    seeded.current = stored ?? '';
    setDraft(stored ?? '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetKey]);

  // Adopt a late-arriving `stored`. The row can mount while its resource is
  // still loading — `stored` is `undefined`, so the draft seeds to `''` — and
  // `resetKey` (the subject) does NOT change when the value finally lands, so
  // without this the input stays empty for good. That is the post-reload
  // "empty Tag label" bug: the value is in the store, the component even
  // re-renders with it, but the draft never catches up.
  //
  // Only adopt while the box is untouched (`draft` is still exactly what we
  // seeded), so a value landing mid-typing never overwrites the user.
  useEffect(() => {
    const next = stored ?? '';

    if (next === seeded.current) return;

    // Our own debounced commit round-tripping back through the resource.
    // Re-baseline so a genuinely external change stays adoptable later.
    if (next === draft) {
      seeded.current = next;

      return;
    }

    if (draft !== seeded.current) return;

    seeded.current = next;
    setDraft(next);
  }, [stored, draft]);

  useEffect(() => {
    commitIfChanged(debounced);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  useEffect(
    () => () => {
      latestCommit.current(pending.current);
    },
    [],
  );

  return { value: draft, onChange: setDraft };
}
