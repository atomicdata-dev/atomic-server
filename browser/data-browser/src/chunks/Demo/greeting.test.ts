import { describe, expect, it } from 'vitest';
import { greetingFor } from './greeting';

describe('greetingFor', () => {
  it('uses the first name of a real name', () => {
    expect(greetingFor('Ada Lovelace')).toBe('Hi Ada! 👋 Welcome to the team');
  });

  it('does not read the guest placeholder back', () => {
    expect(greetingFor('Demo User')).toBe('Hi there! 👋 Welcome to the team');
  });

  it('copes with a missing or blank name', () => {
    expect(greetingFor(undefined)).toBe('Hi there! 👋 Welcome to the team');
    expect(greetingFor('   ')).toBe('Hi there! 👋 Welcome to the team');
  });
});
