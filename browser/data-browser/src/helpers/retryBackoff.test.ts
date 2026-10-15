import { describe, expect, it } from 'vitest';
import { retryDelayMs } from './retryBackoff';

describe('retryDelayMs', () => {
  it('doubles from 150ms up to the 5s ceiling', () => {
    expect([1, 2, 3, 4, 5, 6, 7].map(retryDelayMs)).toEqual([
      150, 300, 600, 1200, 2400, 4800, 5000,
    ]);
  });

  it('stays at 5s through the tenth failure, then jumps to 60s', () => {
    expect(retryDelayMs(10)).toBe(5000);
    expect(retryDelayMs(11)).toBe(60_000);
    expect(retryDelayMs(50)).toBe(60_000);
  });
});
