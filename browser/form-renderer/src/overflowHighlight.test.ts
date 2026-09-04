import { afterEach, describe, expect, it, vi } from 'vitest';
import { highlightOverflow, OVERFLOW_HIGHLIGHT } from './overflowHighlight.js';

/** Stand-in for the real `Highlight`, which is a `Set` of ranges. */
class FakeHighlight extends Set<unknown> {}

/** A form control that can hand back a range over its own value, the way
 * Firefox and recent Chrome can. */
const control = (value: string, createValueRange?: unknown) =>
  ({ value, createValueRange }) as unknown as HTMLInputElement;

const valueRange = (start: number, end: number) => ({ start, end });

/** Both APIs present, as on a browser that supports them. Returns the
 * registry so a test can look at what was registered. */
const supportBrowser = () => {
  const highlights = new Map<string, Set<unknown>>();
  vi.stubGlobal('CSS', { highlights });
  vi.stubGlobal('Highlight', FakeHighlight);

  return highlights;
};

afterEach(() => {
  vi.unstubAllGlobals();
});

/**
 * The overflow colouring is decoration on top of the counter and the red
 * border, so what matters most here is that the browsers without these two
 * very new APIs get nothing rather than an exception. See
 * `overflowHighlight.ts`.
 */
describe('overflow highlight', () => {
  it('paints from the maximum to the end of the value', () => {
    const highlights = supportBrowser();
    const element = control('abcdefghij', valueRange);

    const clear = highlightOverflow(element, 8);

    const registered = highlights.get(OVERFLOW_HIGHLIGHT);
    expect([...(registered ?? [])]).toEqual([{ start: 8, end: 10 }]);

    clear?.();
    expect([...(registered ?? [])]).toEqual([]);
  });

  // The registry is keyed by name and document-wide: a second over-long
  // field must join the first one's Highlight, not replace it.
  it('shares one registry entry between fields', () => {
    const highlights = supportBrowser();

    highlightOverflow(control('abcd', valueRange), 2);
    highlightOverflow(control('abcdef', valueRange), 3);

    expect(highlights.size).toBe(1);
    expect([...(highlights.get(OVERFLOW_HIGHLIGHT) ?? [])]).toEqual([
      { start: 2, end: 4 },
      { start: 3, end: 6 },
    ]);
  });

  it('does nothing on a browser without the highlight API', () => {
    vi.stubGlobal('CSS', undefined);
    vi.stubGlobal('Highlight', undefined);

    expect(highlightOverflow(control('abcd', valueRange), 2)).toBeUndefined();
  });

  // Chrome shipped `CSS.highlights` years before `createValueRange`, so
  // "has the highlight API" does not imply "can range over a value".
  it('does nothing on a control without createValueRange', () => {
    const highlights = supportBrowser();

    expect(highlightOverflow(control('abcd'), 2)).toBeUndefined();
    expect(highlights.size).toBe(0);
  });

  it('swallows a throw from either API', () => {
    supportBrowser();
    const throwing = control('abcd', () => {
      throw new Error('not implemented');
    });

    expect(() => highlightOverflow(throwing, 2)).not.toThrow();
    expect(highlightOverflow(throwing, 2)).toBeUndefined();
  });
});
