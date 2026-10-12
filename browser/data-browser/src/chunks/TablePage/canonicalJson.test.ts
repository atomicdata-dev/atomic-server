import { describe, expect, it } from 'vitest';
import { canonicalJson } from './canonicalJson';

describe('canonicalJson', () => {
  it('sorts keys at every level and drops whitespace', () => {
    expect(
      canonicalJson('{ "b": 2, "a": {"d": 1, "c": [ {"z":1,"y":2} ]} }'),
    ).toBe('{"a":{"c":[{"y":2,"z":1}],"d":1},"b":2}');
  });

  it('leaves invalid JSON alone', () => {
    expect(canonicalJson('{"a":')).toBeUndefined();
  });
});
