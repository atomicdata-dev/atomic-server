/**
 * Partial-submission drafts: a half-filled form is kept in the visitor's
 * `localStorage` so closing the tab (or a stray reload) doesn't cost them
 * their answers.
 *
 * Deliberately **no draft token in the URL**. The draft already lives on the
 * device that will resume it, so a token would add a shareable secret, a
 * URL-rewriting step and a server-side store to buy nothing the device-local
 * key doesn't already give us. Cross-device resume is a different feature
 * (it needs server storage) and is explicitly out of scope here.
 *
 * The module is split so the interesting parts stay testable under vitest's
 * node environment: {@link encodeDraft} / {@link decodeDraft} are pure, and
 * every storage touch goes through a `Storage`-shaped object that tests can
 * hand in.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { FieldBlock, FormDefinition, FormValues } from './types.js';
import { isEmptyValue } from './conditions.js';
import { fieldBlocks } from './validation.js';

/** Bumped when {@link StoredDraft}'s shape changes incompatibly; older
 * payloads are dropped rather than migrated. */
export const DRAFT_VERSION = 1;

export const DRAFT_KEY_PREFIX = 'atomic-form-draft:';

/** Drafts stop being restored after this long. Long enough that "I'll finish
 * this tomorrow" works, short enough that a stale answer set doesn't lurk on
 * a shared device forever. */
export const DRAFT_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** How long the visitor may keep typing before the draft is written. Every
 * keystroke is a state update; writing on each one would mean a synchronous
 * `localStorage` round-trip per character. The flush on `pagehide` (see
 * {@link useFormDraft}) is what makes the delay safe. */
export const DRAFT_SAVE_DEBOUNCE_MS = 600;

/** The serialized payload. Keys are short because this is written on a timer
 * and read on every page load. */
export interface StoredDraft {
  v: number;
  /** Epoch ms, for the TTL check. */
  savedAt: number;
  pageIndex: number;
  /** `mapsTo` → the field's type at save time. A question whose type changed
   * since (short-text → number, say) would restore a value the input can't
   * render, so those entries are dropped on load. Recording the type is why
   * no separate definition fingerprint is needed. */
  types: Record<string, string>;
  values: FormValues;
}

/** What survived the load: the answers to seed the form with, and where the
 * visitor had got to. */
export interface RestoredDraft {
  values: FormValues;
  pageIndex: number;
  savedAt: number;
}

/** The storage key for one form. `scope` separates drafts that must not bleed
 * into one another on a shared device — currently the invite code, which
 * makes each private link its own one-time response. */
export function draftKey(id: string, scope?: string): string {
  return `${DRAFT_KEY_PREFIX}${id}${scope ? `:${scope}` : ''}`;
}

/** The answered subset of `values`, restricted to questions the definition
 * still has. Returns `undefined` when nothing is worth storing, which the
 * caller turns into a *removal* rather than an empty write — so "Start over"
 * and "cleared the last field" both leave no trace. */
export function encodeDraft(
  definition: FormDefinition,
  values: FormValues,
  pageIndex: number,
  now: number = Date.now(),
): string | undefined {
  const fields = new Map(fieldBlocks(definition).map(f => [f.mapsTo, f]));
  const kept: FormValues = {};
  const types: Record<string, string> = {};

  for (const [mapsTo, value] of Object.entries(values)) {
    const field = fields.get(mapsTo);

    if (!field || isEmptyValue(value)) continue;

    kept[mapsTo] = value;
    types[mapsTo] = field.type;
  }

  if (Object.keys(kept).length === 0) return undefined;

  const draft: StoredDraft = {
    v: DRAFT_VERSION,
    savedAt: now,
    pageIndex,
    types,
    values: kept,
  };

  return JSON.stringify(draft);
}

/** The inverse, defensive at every step: a payload from another version, an
 * expired one, a question that has since been deleted or retyped, or a page
 * that no longer exists are all dropped without taking the rest with them.
 * Returns `undefined` when nothing usable remains. */
export function decodeDraft(
  raw: string | null | undefined,
  definition: FormDefinition,
  now: number = Date.now(),
): RestoredDraft | undefined {
  if (!raw) return undefined;

  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }

  if (typeof parsed !== 'object' || parsed === null) return undefined;

  const draft = parsed as Partial<StoredDraft>;

  if (draft.v !== DRAFT_VERSION) return undefined;

  if (typeof draft.savedAt !== 'number' || now - draft.savedAt > DRAFT_TTL_MS) {
    return undefined;
  }

  if (typeof draft.values !== 'object' || draft.values === null) {
    return undefined;
  }

  const fields = new Map<string, FieldBlock>(
    fieldBlocks(definition).map(f => [f.mapsTo, f]),
  );
  const values: FormValues = {};

  for (const [mapsTo, value] of Object.entries(draft.values)) {
    const field = fields.get(mapsTo);

    if (!field || isEmptyValue(value)) continue;

    // The type check is the whole reason `types` is stored. Without it a
    // retyped question restores a value its input cannot render.
    if (draft.types?.[mapsTo] !== field.type) continue;

    values[mapsTo] = value;
  }

  if (Object.keys(values).length === 0) return undefined;

  const lastPage = Math.max(definition.pages.length - 1, 0);
  const pageIndex =
    typeof draft.pageIndex === 'number' && Number.isInteger(draft.pageIndex)
      ? Math.min(Math.max(draft.pageIndex, 0), lastPage)
      : 0;

  return { values, pageIndex, savedAt: draft.savedAt };
}

/** `localStorage`, or `undefined` where it isn't usable — Safari's private
 * mode, a browser configured to block site data, or a partitioned
 * third-party context (which an embedded form can be). Merely *reading* the
 * property throws in some of those, hence the try/catch around the access
 * itself. */
export function defaultDraftStorage(): Storage | undefined {
  try {
    return window.localStorage ?? undefined;
  } catch {
    return undefined;
  }
}

export function readDraft(
  storage: Storage | undefined,
  key: string,
  definition: FormDefinition,
  now?: number,
): RestoredDraft | undefined {
  if (!storage) return undefined;

  try {
    return decodeDraft(storage.getItem(key), definition, now);
  } catch {
    return undefined;
  }
}

export function writeDraft(
  storage: Storage | undefined,
  key: string,
  definition: FormDefinition,
  values: FormValues,
  pageIndex: number,
  now?: number,
): void {
  if (!storage) return;

  const payload = encodeDraft(definition, values, pageIndex, now);

  try {
    // No answers left → no draft. Keeps "Start over" and "cleared every
    // field" from leaving an empty husk behind.
    if (payload === undefined) {
      storage.removeItem(key);
    } else {
      storage.setItem(key, payload);
    }
  } catch {
    // Quota exceeded, or storage revoked mid-session. A dropped draft is
    // never worth breaking the form the visitor is actually filling in.
  }
}

export function removeDraft(storage: Storage | undefined, key: string): void {
  if (!storage) return;

  try {
    storage.removeItem(key);
  } catch {
    // See writeDraft.
  }
}

export interface FormDraft {
  /** The draft found at mount, if any. Read once, synchronously, so
   * FormRenderer can seed its `useState` initializers with it. */
  restored: RestoredDraft | undefined;
  /** Debounced write. Safe to call from an effect on every change. */
  save: (values: FormValues, pageIndex: number) => void;
  /** Drop the stored draft (successful submit, or "Start over"). */
  clear: () => void;
}

/**
 * Wires {@link readDraft} / {@link writeDraft} to a component's lifetime.
 *
 * `key` is `undefined` when drafts are off — the builder preview (which must
 * never touch a visitor's storage) and forms whose owner opted out. The hook
 * still runs so the rules of hooks hold; it just does nothing.
 */
export function useFormDraft(
  definition: FormDefinition,
  key: string | undefined,
  storage: Storage | undefined = undefined,
): FormDraft {
  // Resolved once: `defaultDraftStorage` touches `window`, so it must not run
  // during a server render, and re-resolving per render would be pointless.
  const [store] = useState<Storage | undefined>(
    () => storage ?? (key ? defaultDraftStorage() : undefined),
  );
  const [restored] = useState<RestoredDraft | undefined>(() =>
    key ? readDraft(store, key, definition) : undefined,
  );

  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  // The latest state the debounce is holding, so `pagehide` can flush it.
  // Written from `save` (an event/effect callback), never during render.
  const pending = useRef<{ values: FormValues; pageIndex: number } | undefined>(
    undefined,
  );
  // `definition` is stable for the life of a rendered form, but reading it
  // through a ref keeps the callbacks below from changing identity.
  const latest = useRef({ definition, key, store });
  useEffect(() => {
    latest.current = { definition, key, store };
  });

  const flush = useCallback(() => {
    const { definition: def, key: k, store: s } = latest.current;
    const next = pending.current;

    if (!k || !next) return;

    pending.current = undefined;
    clearTimeout(timer.current);
    writeDraft(s, k, def, next.values, next.pageIndex);
  }, []);

  const save = useCallback(
    (values: FormValues, pageIndex: number) => {
      if (!latest.current.key) return;

      pending.current = { values, pageIndex };
      clearTimeout(timer.current);
      timer.current = setTimeout(flush, DRAFT_SAVE_DEBOUNCE_MS);
    },
    [flush],
  );

  const clear = useCallback(() => {
    const { key: k, store: s } = latest.current;

    pending.current = undefined;
    clearTimeout(timer.current);

    if (k) removeDraft(s, k);
  }, []);

  // A tab closed (or backgrounded on mobile, where `pagehide` may be the last
  // event the page ever sees) inside the debounce window would otherwise lose
  // the very keystrokes the visitor just typed. `visibilitychange` covers the
  // iOS case where a backgrounded tab is discarded without `pagehide`.
  useEffect(() => {
    if (!key) return;

    const onHide = () => flush();

    const onVisibility = () => {
      if (document.visibilityState === 'hidden') flush();
    };

    window.addEventListener('pagehide', onHide);
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      window.removeEventListener('pagehide', onHide);
      document.removeEventListener('visibilitychange', onVisibility);
      flush();
      clearTimeout(timer.current);
    };
  }, [key, flush]);

  // Stable identity: FormRenderer keeps its save effect on
  // `[draft, values, pageIndex]`, and a fresh object every render would
  // restart the debounce timer on every render instead of every change.
  return useMemo(() => ({ restored, save, clear }), [restored, save, clear]);
}
