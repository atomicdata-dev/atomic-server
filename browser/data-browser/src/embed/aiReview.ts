// @wc-ignore-file
/**
 * The edits the model made in the app's AI chat, held for the person to keep
 * or undo. The holding and the undoing are the web chat's own (`AIChangesRuntime`
 * and `aiReviewPersistHold`); this only lists the held edits for the app and
 * forwards its choices.
 */
import type { Resource, Store } from '@tomic/react';
import { getChangedProps } from '../components/ResourceDiff/resourceDiffUtils';

export interface AiReviewItem {
  subject: string;
  title: string;
  /** A short line on what changed, e.g. `Changed name, text`. */
  summary: string;
}

export interface AiReview {
  /** The edits held now, in the order the model made them. */
  list(): Promise<AiReviewItem[]>;
  /** Saves the edits of [subject], or all of them. */
  accept(subject?: string): Promise<void>;
  /** Undoes the edits of [subject], or all of them. */
  revert(subject?: string): Promise<void>;
}

/** What `AIChangesRuntime` gives (`useAIChanges`). */
export interface AiChangesState {
  changes: string[];
  oldResources: Record<string, Resource>;
  revertResource: (subject: string) => void | Promise<void>;
  acceptChanges: (resource: Resource) => Promise<void>;
}

const MAX_NAMED = 3;

/** `Changed name, text` for the properties [before] and [after] differ in. */
export function summarise(
  before: Resource | undefined,
  after: Resource,
): string {
  const names = new Set<string>();

  for (const key of getChangedProps(before, after)) {
    names.add(
      key.includes('documentContent')
        ? 'text'
        : (key.split(/[/#]/).filter(Boolean).pop() ?? key),
    );
  }

  if (names.size === 0) return 'Changed';

  const list = [...names];
  const shown = list.slice(0, MAX_NAMED).join(', ');

  return list.length > MAX_NAMED
    ? `Changed ${shown} and ${list.length - MAX_NAMED} more`
    : `Changed ${shown}`;
}

/** The review of [state], over [store]. */
export function createAiReview(
  store: Pick<Store, 'getResource'>,
  state: AiChangesState,
): AiReview {
  const subjects = (only?: string) =>
    only === undefined
      ? [...state.changes]
      : state.changes.filter(s => s === only);

  return {
    async list() {
      return Promise.all(
        state.changes.map(async subject => {
          const current = await store.getResource(subject);

          return {
            subject,
            title: current.title || subject,
            summary: summarise(state.oldResources[subject], current),
          };
        }),
      );
    },
    async accept(only) {
      for (const subject of subjects(only)) {
        await state.acceptChanges(await store.getResource(subject));
      }
    },
    async revert(only) {
      for (const subject of subjects(only)) {
        await state.revertResource(subject);
      }
    },
  };
}
