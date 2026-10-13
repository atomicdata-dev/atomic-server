import { describe, expect, it } from 'vitest';
import { untilDateToCommit } from './untilDraft';

describe('untilDateToCommit', () => {
  it('commits a valid changed date', () => {
    expect(untilDateToCommit('2026-11-21', '2026-11-09')).toBe('2026-11-21');
  });

  it('ignores no draft, empty and invalid intermediate values', () => {
    expect(untilDateToCommit(null, '2026-11-09')).toBeUndefined();
    expect(untilDateToCommit('', '2026-11-09')).toBeUndefined();
    expect(untilDateToCommit('2026-13-01', '2026-11-09')).toBeUndefined();
  });

  it('ignores an unchanged date', () => {
    expect(untilDateToCommit('2026-11-09', '2026-11-09')).toBeUndefined();
  });
});
