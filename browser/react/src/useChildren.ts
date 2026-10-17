import {
  canonicalizeScheme,
  commits,
  core,
  dataBrowser,
  isCommitSubject,
  orderChildren,
  StoreEvents,
} from '@tomic/lib';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useCollection } from './useCollection.js';
import { useStore } from './hooks.js';

const sameList = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((subject, i) => subject === b[i]);

/**
 * Returns the subjects of direct children of a resource.
 *
 * Server side, the live `parent=`/`sort_by=createdAt` Collection query
 * provides the candidate set (creation-time ordering). After that the
 * hook re-sorts client-side by the user-controllable
 * `dataBrowser.properties.sortOrder` (a fractional float written by
 * drag-and-drop). Resources without an explicit `sortOrder` fall back
 * to their `createdAt` timestamp as the implicit key — so a folder full
 * of legacy resources still displays in creation order, and a reorder
 * only needs to touch the single dragged resource (set its sortOrder to
 * the midpoint between its new neighbors).
 *
 * Pass `undefined` to disable fetching (e.g. for Tables/ChatRooms that show
 * children in their own UI).
 *
 * With `limit`, only the first `limit` children (in creation order) are read
 * and sorted, and `total` says how many there are. A list that is meant to be
 * scanned by eye, like the sidebar, never needs the rest, and loading all of
 * them cost seconds for a folder with a thousand children.
 */
export function useChildren(
  parentSubject: string | undefined,
  { limit }: { limit?: number } = {},
): {
  subjects: string[];
  loading: boolean;
  /** How many children the parent has, including those beyond `limit`. */
  total: number;
} {
  const store = useStore();
  const [subjects, setSubjects] = useState<string[]>([]);
  const [total, setTotal] = useState(0);
  const disabled = !parentSubject;

  // `subjectsRef` mirrors `subjects` for the `ResourceUpdated` listener
  // below — that listener subscribes once and reads the latest list
  // from the ref instead of being torn down + recreated on every
  // re-sort (which would race the optimistic re-render).
  const subjectsRef = useRef<string[]>([]);
  subjectsRef.current = subjects;

  const { collection, ready } = useCollection(
    {
      property: core.properties.parent,
      // `Collection.fetchPage` short-circuits when value is undefined, so
      // disabled hooks never hit the server. No sentinel needed.
      value: parentSubject,
      sort_by: commits.properties.createdAt,
      sort_desc: false,
    },
    { pageSize: limit ?? 500 },
  );

  /**
   * Sort a list of subjects by `sortOrder` (explicit) with `createdAt`
   * as the implicit fallback, breaking ties with the original index
   * (= server-side createdAt order). Awaits each resource so the
   * sortOrder value reflects the latest save before we read it.
   */
  const sortMembers = useCallback(
    async (members: readonly string[]): Promise<string[]> => {
      const keyed = await Promise.all(
        members.map(async (subject, index) => {
          // RESILIENT: a single child that fails to load (a fetch timeout /
          // transient error during the WS-reconnect race) must NOT reject the
          // whole `Promise.all` — that throws out of `extractMembers` and the
          // sidebar goes fully empty. Keep the member with no key instead;
          // `orderChildren` holds it in server position.
          try {
            const resource = await store.getResource(subject);
            const explicit = resource.get(dataBrowser.properties.sortOrder);
            const key =
              typeof explicit === 'number' ? explicit : resource.getCreatedAt();

            return { subject, key, index };
          } catch {
            return { subject, key: undefined, index };
          }
        }),
      );

      // Ordering lives in `@tomic/lib` (`orderChildren`) so it can be tested
      // directly: this package has no test setup, and the rule it encodes —
      // a member with neither `sortOrder` nor `createdAt` must not fall into
      // the array-index number space — is the whole bug.
      return orderChildren(keyed);
    },
    [store],
  );

  // Pull candidate set + initial sort from the collection.
  useEffect(() => {
    if (disabled) {
      setSubjects([]);

      return;
    }

    // Cancellation flag prevents a slow extract run from
    // `setSubjects(...stale)` after a fresh one already landed. The
    // collection-invalidate path can trigger overlapping runs when the
    // user creates resources faster than `waitForReady` resolves, and
    // the late writer used to overwrite the new data with the old.
    let cancelled = false;

    const extractMembers = async (attempt = 0) => {
      await collection.waitForReady();
      if (cancelled) return;

      // Resolve all members in parallel — `getMemberWithIndex` is a
      // worker round-trip per call, so a 200-child folder used to pay
      // 200× sequential RTT on cold open. Promise.all hands the worker
      // a batch which it can process while the UI thread is otherwise
      // idle.
      const memberCount =
        limit === undefined
          ? collection.totalMembers
          : Math.min(limit, collection.totalMembers);
      const resolved = await Promise.all(
        Array.from({ length: memberCount }, (_, i) =>
          collection.getMemberWithIndex(i),
        ),
      );
      if (cancelled) return;
      setTotal(collection.totalMembers);

      // A slot that comes back undefined means the cached page is older than
      // the member count it is being read against — `getMemberWithIndex` asks
      // page N for an index the server has since added and that page does not
      // hold. Accepting the short list silently loses a child forever (the
      // second device that unlocks a drive shows an empty sidebar until a
      // reload, `second-device-load.spec.ts`), so re-read the page instead.
      //
      // Only while this hook has never produced a list. Once children are on
      // screen, an undefined slot is far more likely to be one that just went
      // away — a delete leaves the count ahead of the page for a moment — and
      // re-fetching then pulls the deleted resource back into the store.
      if (
        subjectsRef.current.length === 0 &&
        resolved.some(member => member === undefined) &&
        attempt < 3
      ) {
        await collection.refresh();
        if (cancelled) return;

        return extractMembers(attempt + 1);
      }

      // Drop commit subjects: they leak into parent= queries when a resource
      // is created/updated, but they're never tree-children. Also dedupe —
      // collection refreshes can race, leaving the same subject indexed
      // twice across pages.
      const seen = new Set<string>();
      const candidates: string[] = [];

      for (const member of resolved) {
        if (
          member &&
          !isCommitSubject(member) &&
          !seen.has(canonicalizeScheme(member)) &&
          // A destroyed child can still come back in an answer to the
          // `parent=` query — the answer may have been computed before the
          // destroy landed — and rendering it again is not cosmetic: the row
          // asks the store for the resource. The store knows what it
          // destroyed, so this hook does not have to keep its own list (which
          // a freshly mounted hook, e.g. a folder re-expanded, would not
          // have).
          !store.isDestroyed(member)
        ) {
          const subject = canonicalizeScheme(member);
          seen.add(subject);
          candidates.push(subject);
        }
      }

      const sorted = await sortMembers(candidates);
      if (cancelled) return;
      setSubjects(sorted);
    };

    extractMembers();

    return () => {
      cancelled = true;
    };
  }, [collection, disabled, limit, sortMembers, store]);

  /**
   * Re-sort when any current child's `sortOrder` (or `createdAt`)
   * changes. Drag-and-drop writes `sortOrder` on the dragged resource
   * and `Resource.save()` emits `ResourceUpdated` — that's the signal
   * we hook here. The collection's own subject set hasn't changed (only
   * a property within an existing member), so `useCollection` doesn't
   * re-emit and the candidate-fetch effect above doesn't re-fire.
   *
   * The listener reads the current subject list from a ref instead of
   * a closed-over copy, so a re-sort that itself triggers a save
   * (rare, but possible via fan-out updates) re-evaluates against the
   * fresh list rather than reverting to the pre-sort order.
   */
  useEffect(() => {
    if (disabled) return;

    let cancelled = false;

    const unsubRemoved = store.on(StoreEvents.ResourceRemoved, subject => {
      const removed = canonicalizeScheme(subject);
      setSubjects(prev => {
        if (!prev.includes(removed)) return prev;

        setTotal(count => Math.max(0, count - 1));

        return prev.filter(s2 => s2 !== removed);
      });
    });

    const unsub = store.on(StoreEvents.ResourceUpdated, async resource => {
      const current = subjectsRef.current;
      const subject = canonicalizeScheme(resource.subject);

      if (!current.includes(subject)) {
        // A resource that names this parent but is not in the list means the
        // query was answered before it existed — a child created moments ago,
        // or a device that loaded the drive while the commit was still
        // landing. The collection has no reason of its own to ask again, so
        // the child stayed missing until a reload
        // (`server-only-fallback.spec.ts`).
        //
        // Add it here rather than re-reading the query: the server's index
        // lags a fresh commit, so a re-read can answer without the very
        // resource that prompted it and drop what the sidebar had already
        // shown.
        if (
          parentSubject &&
          canonicalizeScheme(
            String(resource.get(core.properties.parent) ?? ''),
          ) === canonicalizeScheme(parentSubject) &&
          // Same reason as the candidate filter above. This branch had no
          // such check, so a destroyed child that a stale answer hydrated
          // back into the store was re-added here even while the candidate
          // filter was dropping it.
          !store.isDestroyed(resource.subject)
        ) {
          // A full list stays as it is: the newcomer is the newest child, so
          // it belongs past the cut.
          if (limit !== undefined && current.length >= limit) {
            setTotal(count => count + 1);

            return;
          }

          const sorted = await sortMembers([...current, subject]);
          if (cancelled) return;

          setSubjects(prev => {
            // The list moved on while the sort awaited (a child trashed or
            // destroyed, a fresh query answer): `sorted` was built from the
            // old one and would put back what left. Keep what is there and
            // append the newcomer, which belongs last.
            if (prev !== current) {
              return prev.includes(subject) ||
                (limit !== undefined && prev.length >= limit)
                ? prev
                : [...prev, subject];
            }

            return sameList(prev, sorted) ? prev : sorted;
          });
        }

        return;
      }

      if (current.length === 0) {
        return;
      }

      const resorted = await sortMembers(current);
      if (cancelled) return;

      // Same as above: a re-sort that lands after the list changed under it
      // is stale, and writing it back made a trashed folder reappear in the
      // sidebar until the next reload.
      setSubjects(prev =>
        prev !== current || sameList(prev, resorted) ? prev : resorted,
      );
    });

    return () => {
      cancelled = true;
      unsub();
      unsubRemoved();
    };
  }, [collection, disabled, parentSubject, sortMembers, store]);

  // `useCollection` listens for `ResourceManuallyCreated` and routes
  // it through `applyResourceChange` for an optimistic add — no full
  // refetch needed. The previous duplicate listener here called
  // `invalidateCollection` instead, which races: invalidate clears
  // the optimistic page right back out while the underlying `/query`
  // refresh is still in flight.

  return {
    subjects: disabled ? [] : subjects,
    loading: disabled ? false : !ready,
    total: disabled ? 0 : total,
  };
}
