import { describe, expect, it } from 'vitest';
import {
  findMentionTrigger,
  formatMention,
  insertMention,
} from './chatMention';

describe('findMentionTrigger', () => {
  it('finds an @ at the start and after whitespace', () => {
    expect(findMentionTrigger('@do', 3)).toEqual({
      start: 0,
      end: 3,
      query: 'do',
    });
    expect(findMentionTrigger('hi @', 4)).toEqual({
      start: 3,
      end: 4,
      query: '',
    });
  });

  it('ignores emails, closed queries and carets before the @', () => {
    expect(findMentionTrigger('joep@ontola.io', 14)).toBeUndefined();
    expect(findMentionTrigger('@doc then', 9)).toBeUndefined();
    expect(findMentionTrigger('hi @doc', 2)).toBeUndefined();
  });
});

describe('insertMention', () => {
  it('replaces the token with the stored mention format', () => {
    const text = 'see @do please';
    const trigger = findMentionTrigger(text, 7)!;
    const result = insertMention(text, trigger, 'https://x.test/a', 'My "doc"');

    expect(result.text).toBe(
      'see [@ id="https://x.test/a" label="My &quot;doc&quot;"]  please',
    );
    expect(result.text.slice(0, result.caret).endsWith('] ')).toBe(true);
  });

  it('does not let labels break out of the brackets', () => {
    expect(formatMention('a', 'b] [c')).toBe('[@ id="a" label="b   c"]');
  });
});
