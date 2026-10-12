import { describe, expect, it } from 'vitest';
import { shortenSubjects } from './shortenSubjects';

describe('shortenSubjects', () => {
  it('leaves short text and short subjects alone', () => {
    expect(shortenSubjects('Could not save')).toBe('Could not save');
    expect(shortenSubjects('Failed: https://a.dev/x')).toBe(
      'Failed: https://a.dev/x',
    );
  });

  it('shortens long subjects in the middle of a sentence', () => {
    const did = `did:ad:${'a'.repeat(80)}`;
    const out = shortenSubjects(`Cannot read ${did} right now`);

    expect(out).toMatch(/^Cannot read did:ad:a+…a+ right now$/);
    expect(out.length).toBeLessThan(80);
  });
});
