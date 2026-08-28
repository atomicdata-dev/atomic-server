import { describe, expect, it } from 'vitest';
import {
  PAGE_ANIMATION_PREFIX,
  PAGE_EXIT_MS,
  STAGGER_FADE_MS,
  STAGGER_STEP_MS,
  STAGGER_WAVE_MS,
  enterEnvelopeMs,
  pageTransitionsEnabled,
  phaseDeadlineMs,
  staggerSlots,
  staggerSpanStyle,
  staggerStyle,
  transitionClass,
} from './pageTransition.js';
import type { FieldOption, FieldType, FormStyling } from './types.js';

describe('transitionClass', () => {
  it('is empty at rest', () => {
    expect(transitionClass(null)).toBe('');
  });

  it('names the direction the page leaves in', () => {
    expect(
      transitionClass({ phase: 'exit', direction: 'forward', target: 1 }),
    ).toBe('atomic-form-blocks-exit-forward');
    expect(
      transitionClass({ phase: 'exit', direction: 'back', target: 0 }),
    ).toBe('atomic-form-blocks-exit-back');
  });

  it('drops the direction on the way in — the arriving page does not move', () => {
    expect(
      transitionClass({ phase: 'enter', direction: 'forward', target: 1 }),
    ).toBe('atomic-form-blocks-enter');
    expect(
      transitionClass({ phase: 'enter', direction: 'back', target: 0 }),
    ).toBe('atomic-form-blocks-enter');
  });
});

describe('pageTransitionsEnabled', () => {
  const styling = (s: FormStyling) => s;

  it('does not animate until a form opts in', () => {
    expect(pageTransitionsEnabled(styling({}), false)).toBe(false);
    expect(
      pageTransitionsEnabled(styling({ animatePageTransitions: false }), false),
    ).toBe(false);
  });

  it('animates for a form that asked for it', () => {
    expect(
      pageTransitionsEnabled(styling({ animatePageTransitions: true }), false),
    ).toBe(true);
  });

  it('never animates under reduced motion, even when the form asks for it', () => {
    expect(
      pageTransitionsEnabled(styling({ animatePageTransitions: true }), true),
    ).toBe(false);
    expect(pageTransitionsEnabled(styling({}), true)).toBe(false);
  });
});

describe('the staggered fade-in', () => {
  const index = (style: Record<string, unknown>) =>
    style['--atomic-form-stagger-index'];

  it('gives each element the next slot, never a shared one', () => {
    expect(index(staggerStyle(0))).toBe(0);
    expect(index(staggerStyle(3))).toBe(3);
    // The slot is the element's real place in the order however long the
    // page: two elements must never collide on one delay, or a question's
    // later options would arrive with the question below them.
    expect(index(staggerStyle(40))).toBe(40);
  });

  it('publishes a span the delay can be divided by, never zero', () => {
    const span = (count: number) =>
      staggerSpanStyle(count)['--atomic-form-stagger-span' as never];
    expect(span(6)).toBe(5);
    // A one-element (or empty) page still has to divide by something.
    expect(span(1)).toBe(1);
    expect(span(0)).toBe(1);
  });

  it('runs for one fade when there is only one element', () => {
    expect(enterEnvelopeMs(1)).toBe(STAGGER_FADE_MS);
    // An empty page still has to end its phase rather than hang on a clock
    // that never runs out.
    expect(enterEnvelopeMs(0)).toBe(STAGGER_FADE_MS);
  });

  it('spaces a short page at the full step', () => {
    expect(enterEnvelopeMs(3)).toBe(2 * STAGGER_STEP_MS + STAGGER_FADE_MS);
  });

  it('compresses a long page into the wave rather than capping it', () => {
    expect(enterEnvelopeMs(50)).toBe(STAGGER_WAVE_MS + STAGGER_FADE_MS);
    // However long the page, opening it costs the same.
    expect(enterEnvelopeMs(200)).toBe(enterEnvelopeMs(50));
  });
});

describe('staggerSlots', () => {
  const options = (count: number): FieldOption[] =>
    Array.from({ length: count }, (_, i) => ({
      value: `tag-${i}`,
      label: `Option ${i}`,
    }));

  const field = (type: FieldType, optionCount: number) =>
    ({
      kind: 'field',
      mapsTo: 'https://example.com/properties/q',
      label: 'Q',
      type,
      required: false,
      options: { options: options(optionCount) },
    }) as const;

  it('gives a block with nothing to lay out a single slot', () => {
    expect(staggerSlots({ kind: 'heading', text: 'Hi' })).toBe(1);
    expect(staggerSlots(field('short-text', 0))).toBe(1);
  });

  it('reserves a slot for every option a field puts on the page', () => {
    expect(staggerSlots(field('radio', 3))).toBe(4);
    expect(staggerSlots(field('multi-select', 2))).toBe(3);
    expect(staggerSlots(field('picture-choice', 5))).toBe(6);
  });

  it('leaves a dropdown whole — its options are behind a closed menu', () => {
    expect(staggerSlots(field('dropdown', 4))).toBe(1);
    expect(staggerSlots(field('dropdown-multi', 4))).toBe(1);
  });

  it('leaves the scale-shaped inputs whole — they read as one control', () => {
    expect(staggerSlots(field('likert', 0))).toBe(1);
    expect(staggerSlots(field('rating', 0))).toBe(1);
    expect(staggerSlots(field('choice-matrix', 0))).toBe(1);
  });
});

describe('phase timing', () => {
  const exit = { phase: 'exit', direction: 'forward', target: 1 } as const;
  const enter = { phase: 'enter', direction: 'forward', target: 1 } as const;

  it('keeps a page change within the ~500ms budget', () => {
    // Worst case: the longest exit plus a fully staggered fade-in.
    expect(PAGE_EXIT_MS + enterEnvelopeMs(50)).toBeLessThanOrEqual(520);
  });

  it('never cuts a running exit short', () => {
    expect(phaseDeadlineMs(exit, 3)).toBeGreaterThan(PAGE_EXIT_MS);
  });

  it('ends the fade-in exactly when the last element has faded', () => {
    expect(phaseDeadlineMs(enter, 3)).toBe(enterEnvelopeMs(3));
  });
});

describe('the animation-name prefix', () => {
  it('matches the page keyframes, and not the stagger', () => {
    // Guards the contract between `style.css` and the `animationend` filter:
    // the page's own exit must match, and the children's fade must not — one
    // of those ending early would strip the class off mid-stagger.
    expect('atomic-form-page-exit-up').toContain(PAGE_ANIMATION_PREFIX);
    expect('atomic-form-stagger-in').not.toContain(PAGE_ANIMATION_PREFIX);
  });
});
