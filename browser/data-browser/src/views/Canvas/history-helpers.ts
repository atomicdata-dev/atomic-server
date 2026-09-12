import { parseCanvasStrokes, type CanvasStroke, randomUUID } from '@tomic/lib';
import type { JSONValue } from '@tomic/lib';

/**
 * Pixels of horizontal pointer travel that map to scrubbing through the
 * entire history timeline. Matches Flutter's `_onUndoPanDelta`.
 */
export const SCRUB_PIXELS_PER_HISTORY = 300;
export const SCRUB_DRAG_THRESHOLD = 5;

/**
 * Maximum number of undo / redo snapshots retained per canvas. Each entry
 * is a JSON-serialised stroke list (a `CanvasStroke[]`), so the cap also
 * bounds `localStorage` use.
 */
export const UNDO_STACK_LIMIT = 200;

/** Maximum recoverable discarded branches kept per canvas. */
export const BRANCH_LIMIT = 20;

/**
 * How long the version overlay stays interactive after a scrub release, so
 * the user can still hover / click a branch thumbnail. Matches Flutter's
 * 3-second auto-dismiss.
 */
export const BRANCH_GRACE_MS = 3000;

export type StrokeSnapshot = CanvasStroke[];

export type HistoryStacks = {
  undo: StrokeSnapshot[];
  redo: StrokeSnapshot[];
};

/**
 * A version the user abandoned by editing after undoing — the leaf of a
 * discarded redo branch. Stored as a full stroke snapshot (matching
 * Flutter's `DiscardedBranch`) so it can be restored wholesale.
 */
export type DiscardedBranch = {
  id: string;
  strokes: StrokeSnapshot;
};

export type CanvasHistoryState = HistoryStacks & {
  branches: DiscardedBranch[];
  /**
   * Whether undo steps have already been reconstructed from the Loro
   * history for this canvas on this device. That reconstruction is
   * expensive, and it legitimately yields zero steps for a canvas with no
   * prior state — without this flag those canvases re-run it on every open.
   */
  bootstrapped: boolean;
};

const historyStorageKey = (subject: string) => `canvas-undo:${subject}`;

export function loadCanvasHistory(subject: string): CanvasHistoryState {
  try {
    const raw = localStorage.getItem(historyStorageKey(subject));

    if (!raw) return { undo: [], redo: [], branches: [], bootstrapped: false };

    const parsed = JSON.parse(raw) as Partial<CanvasHistoryState>;

    return {
      undo: Array.isArray(parsed.undo) ? parsed.undo : [],
      redo: Array.isArray(parsed.redo) ? parsed.redo : [],
      branches: Array.isArray(parsed.branches)
        ? parsed.branches.filter(
            b => b && typeof b.id === 'string' && Array.isArray(b.strokes),
          )
        : [],
      bootstrapped: parsed.bootstrapped === true,
    };
  } catch {
    return { undo: [], redo: [], branches: [], bootstrapped: false };
  }
}

export function saveCanvasHistory(
  subject: string,
  state: CanvasHistoryState,
): void {
  try {
    localStorage.setItem(historyStorageKey(subject), JSON.stringify(state));
  } catch {
    // Disabled / quota exceeded — undo simply doesn't persist this session.
  }
}

/** Shallow clone of a stroke list — paths copied so future mutations of
 *  the live array don't bleed into the snapshot. */
export function cloneStrokes(strokes: StrokeSnapshot): StrokeSnapshot {
  return strokes.map(s => ({
    color: s.color,
    width: s.width,
    path: s.path.map(p => [p[0], p[1]] as [number, number]),
  }));
}

/** Structural equality of two stroke lists (order-sensitive). */
export function strokesEqual(a: StrokeSnapshot, b: StrokeSnapshot): boolean {
  if (a.length !== b.length) return false;

  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * The full scrubbable timeline: every undo target, the current state, and
 * every redo target (nearest-future last on the redo stack, so reversed
 * here to read oldest → newest).
 */
export function timelineOf(
  stacks: HistoryStacks,
  current: StrokeSnapshot,
): StrokeSnapshot[] {
  return [...stacks.undo, current, ...[...stacks.redo].reverse()];
}

/**
 * Map a horizontal drag distance to a timeline index. Dragging the full
 * `SCRUB_PIXELS_PER_HISTORY` sweeps the entire timeline, so scrub speed is
 * proportional to history length (Flutter parity).
 */
export function scrubIndexFor(
  startIndex: number,
  dx: number,
  total: number,
): number {
  const idx = Math.round(startIndex + (dx / SCRUB_PIXELS_PER_HISTORY) * total);

  return Math.max(0, Math.min(total - 1, idx));
}

/**
 * Rebuild the undo / redo stacks for a given position on the timeline.
 * Everything before `index` becomes undoable, everything after becomes
 * redoable — so stepping after a scrub walks the same timeline instead of
 * discarding the future.
 */
export function stacksAt(
  timeline: StrokeSnapshot[],
  index: number,
): HistoryStacks {
  return {
    undo: timeline.slice(0, index),
    redo: timeline.slice(index + 1).reverse(),
  };
}

/**
 * Add `strokes` as a recoverable branch leaf. Empty and duplicate
 * snapshots are skipped; the oldest branch is dropped beyond
 * `BRANCH_LIMIT`. Returns a new array (input is not mutated).
 */
export function archiveBranch(
  branches: DiscardedBranch[],
  strokes: StrokeSnapshot,
): DiscardedBranch[] {
  if (strokes.length === 0) return branches;

  if (branches.some(b => strokesEqual(b.strokes, strokes))) return branches;

  const next = [
    ...branches,
    { id: randomUUID(), strokes: cloneStrokes(strokes) },
  ];

  return next.slice(-BRANCH_LIMIT);
}

/**
 * Reconstruct undo steps for a canvas that has Loro history but no local
 * snapshot state (first open on this device). `getLoroHistory()` now
 * yields one causally-ordered version per list edit (each mutation
 * commits with a unique `e-` token), but docs written before that fix —
 * and unmessaged ops in general — still collapse into one bucket, so
 * stay defensive: parse every version's strokeData, drop states
 * identical to the current one, and dedupe consecutive repeats. Every
 * surviving entry is a real, distinct prior state.
 */
export function bootstrapUndoSteps(
  versionStrokeData: (JSONValue | undefined)[],
  current: StrokeSnapshot,
): StrokeSnapshot[] {
  const steps: StrokeSnapshot[] = [];

  for (const raw of versionStrokeData) {
    const state = parseCanvasStrokes(raw);

    if (strokesEqual(state, current)) continue;

    if (steps.length > 0 && strokesEqual(steps[steps.length - 1], state)) {
      continue;
    }

    steps.push(state);
  }

  return steps.slice(-UNDO_STACK_LIMIT);
}
