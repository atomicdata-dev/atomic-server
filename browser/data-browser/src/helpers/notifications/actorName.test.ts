import { describe, it, expect } from 'vitest';
import { actorName } from './actorName';

describe('actorName', () => {
  it('keeps a real name', () => {
    expect(actorName('Ada', 'did:ad:agent:x')).toBe('Ada');
  });

  it.each([undefined, '', '  ', 'atomic:agent:JaeewcPF', 'did:ad:agent:abc'])(
    'falls back for %j',
    title => {
      expect(actorName(title)).toBeUndefined();
    },
  );

  it('falls back when the title is the subject', () => {
    expect(actorName('https://x.dev/a', 'https://x.dev/a')).toBeUndefined();
  });
});
