import { reorderArray } from './reorderArray';
import { expect, describe, it } from 'bun:test';

describe('reorderArray', () => {
  it('reorders ', async () => {
    const start = [0, 1, 2, 3, 4];
    const out = reorderArray(start, 2, 3);
    const expected = [0, 1, 3, 2, 4];
    expect(out).toStrictEqual(expected);
  });
});
