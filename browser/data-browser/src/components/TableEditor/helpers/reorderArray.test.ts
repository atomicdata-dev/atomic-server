import { reorderArray } from './reorderArray';
import { describe, it, expect } from 'vitest';

describe('reorderArray', () => {
  it('reorders elements correctly', () => {
    const start = [0, 1, 2, 3, 4];
    const out = reorderArray(start, 2, 3);
    const expected = [0, 1, 3, 2, 4];
    expect(out).toEqual(expected);
  });
});
