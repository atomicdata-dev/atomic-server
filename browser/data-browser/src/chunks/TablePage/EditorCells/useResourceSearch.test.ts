import { describe, expect, it } from 'vitest';
import { pastedSubject } from './useResourceSearch';

describe('pastedSubject', () => {
  it('accepts atomic: and did:ad: subjects', () => {
    const agent = 'atomic:agent:JaeewcPFRve6aYf9afTptbrvDhAwjyK8L2pnRkR8mVA';

    expect(pastedSubject(agent)).toBe(agent);
    expect(pastedSubject(` ${agent} `)).toBe(agent);
    expect(pastedSubject('did:ad:agent:abc')).toBe('did:ad:agent:abc');
  });

  it('accepts http(s) URLs', () => {
    expect(pastedSubject('https://example.com/a')).toBe(
      'https://example.com/a',
    );
  });

  it('ignores plain search text', () => {
    expect(pastedSubject('joep')).toBeUndefined();
    expect(pastedSubject('atomic design')).toBeUndefined();
    expect(pastedSubject('')).toBeUndefined();
  });
});
