import { useSyncExternalStore, type CSSProperties } from 'react';
import type { FieldType, FormBlock, FormStyling } from './types.js';

/**
 * The page-change animation, in two phases with different shapes.
 *
 * **Exit** moves the whole leaving page as one block: it zooms out, then
 * slides away and fades. It ends on its own `animationend`, so the content
 * swaps exactly when the old page has finished leaving, however long the
 * browser actually took; [PAGE_EXIT_MS] is only the deadline for an animation
 * that never reports back (one the browser dropped, a tab hidden throughout),
 * and must stay >= the CSS duration or a slow-but-healthy animation would be
 * cut short.
 *
 * **Enter** doesn't move at all: the arriving page's elements fade in one
 * after another (the stagger constants below). There is no whole-page
 * animation to listen to, so this phase runs on a clock — safe in a way the
 * exit phase isn't, because ending it only takes a class back off. Nothing
 * the visitor sees or can click waits on it.
 *
 * Both live in `style.css`; the numbers are duplicated here because JS owns
 * the phase changes. Worst case is an exit plus a fully staggered enter —
 * 180 + 175 + 160 = 515ms, near enough the ~500ms a visitor will sit through,
 * and a typical three-block page lands around 410ms.
 */
export const PAGE_EXIT_MS = 150;

/** Grace added on top of the exit's duration before it is force-completed. */
export const PAGE_PHASE_GRACE_MS = 250;

/** The animation-name prefix the *page-level* phases share; `animationend`
 * from anything else (a nested widget, or the staggered children themselves)
 * is ignored. */
export const PAGE_ANIMATION_PREFIX = 'atomic-form-page-';

/** Gap between one element's fade and the next one's, on a page short enough
 * to afford it. */
export const STAGGER_STEP_MS = 35;

/** The longest the cascade as a whole may take. A page with more elements
 * than fit at [STAGGER_STEP_MS] shortens its step to land inside this instead
 * of capping the delay: a cap would give every element past the cut the same
 * delay, so a question's later options would arrive alongside the question
 * below them — the cascade would stop reading as an order at all. */
export const STAGGER_WAVE_MS = 2000;

/** How long a single element takes to fade in. */
export const STAGGER_FADE_MS = 350;

/**
 * Marks an element as the `index`-th thing to fade in on the arriving page.
 * Pair with the `atomic-form-stagger` class.
 *
 * The index comes from whoever renders the ordered list — that component
 * already knows the order, which is why elements are told their position
 * rather than claiming one by registering: registration order is mount order,
 * and React mounts children before their parents, so a field's own parts
 * would take their turn before the field they sit in.
 */
export function staggerStyle(index: number): CSSProperties {
  return {
    '--atomic-form-stagger-index': index,
  } as CSSProperties;
}

/**
 * Goes on the element the staggered ones sit inside, telling them how many
 * steps the cascade has to fit — which is what lets each of them work out its
 * own delay from nothing but its index. This is the whole of the "page-wide
 * context": the container publishes the pacing, every element reads it by
 * inheritance, and nobody has to be told about anybody else.
 */
export function staggerSpanStyle(count: number): CSSProperties {
  return {
    // Never 0: the CSS divides by this.
    '--atomic-form-stagger-span': Math.max(count - 1, 1),
  } as CSSProperties;
}

/** The question types that lay their options out on the page. A dropdown's
 * options live in a menu that isn't open yet, so it takes a single slot like
 * any other field; the scale-shaped inputs (`likert`, `rating`,
 * `choice-matrix`) are deliberately left whole — they read as one control,
 * not as a list. */
const INLINE_OPTION_TYPES: FieldType[] = [
  'radio',
  'multi-select',
  'picture-choice',
];

/**
 * How many stagger slots a block occupies: one for itself, plus one per
 * option it lays out on the page. Options take the slots *after* their own
 * field rather than restarting from it, so the fade-in stays one wave running
 * down the page instead of a separate ripple inside every question.
 */
export function staggerSlots(block: FormBlock): number {
  if (block.kind !== 'field' || !INLINE_OPTION_TYPES.includes(block.type)) {
    return 1;
  }

  return 1 + (block.options.options?.length ?? 0);
}

/** How long the whole staggered fade-in takes for `count` elements: the last
 * one's delay plus its fade. Mirrors the `min()` the stylesheet does. */
export function enterEnvelopeMs(count: number): number {
  const lastDelay = Math.min(
    Math.max(count - 1, 0) * STAGGER_STEP_MS,
    STAGGER_WAVE_MS,
  );

  return lastDelay + STAGGER_FADE_MS;
}

export type TransitionDirection = 'forward' | 'back';

export interface PageTransition {
  /** `exit` still renders the *old* page; `enter` renders the new one. */
  phase: 'exit' | 'enter';
  direction: TransitionDirection;
  /** The page index being moved to, applied when the exit phase ends. */
  target: number;
}

/** Modifier class for `.atomic-form-blocks`, or `''` when at rest. Only the
 * exit is directional — the arriving page fades rather than moving, so there
 * is nothing for a direction to mean. */
export function transitionClass(transition: PageTransition | null): string {
  if (!transition) return '';

  return transition.phase === 'exit'
    ? `atomic-form-blocks-exit-${transition.direction}`
    : 'atomic-form-blocks-enter';
}

/**
 * When to end a phase: the fallback deadline for the exit (which normally
 * ends on its `animationend`), and the actual clock for the enter (which has
 * no whole-page animation to end on). `count` is how many elements are
 * fading in.
 */
export function phaseDeadlineMs(
  transition: PageTransition,
  count: number,
): number {
  return transition.phase === 'exit'
    ? PAGE_EXIT_MS + PAGE_PHASE_GRACE_MS
    : enterEnvelopeMs(count);
}

/**
 * Whether page changes should animate. Off unless the form opts in with
 * `animatePageTransitions: true` — a form built before this existed, or by
 * someone who never opened the switch, changes pages the way it always did.
 * Always off when the visitor's OS asks for reduced motion, which no form
 * setting may override.
 */
export function pageTransitionsEnabled(
  styling: FormStyling,
  reducedMotion: boolean,
): boolean {
  return styling.animatePageTransitions === true && !reducedMotion;
}

const REDUCED_MOTION_QUERY = '(prefers-reduced-motion: reduce)';

function subscribeReducedMotion(onChange: () => void): () => void {
  if (typeof window === 'undefined' || !window.matchMedia) return () => {};

  const mql = window.matchMedia(REDUCED_MOTION_QUERY);
  mql.addEventListener('change', onChange);

  return () => mql.removeEventListener('change', onChange);
}

function getReducedMotion(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return false;

  return window.matchMedia(REDUCED_MOTION_QUERY).matches;
}

/** Live `prefers-reduced-motion` state. Read in JS as well as CSS because the
 * animation is not purely decorative here: skipping it also has to skip the
 * pause before the next page's content appears. */
export function useReducedMotion(): boolean {
  return useSyncExternalStore(
    subscribeReducedMotion,
    getReducedMotion,
    () => false,
  );
}
