import { describe, expect, it } from 'vitest';
import {
  findMentionTrigger,
  formatMention,
  insertMention,
  serializeMentions,
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
  it('replaces the token with @Label and a space', () => {
    const text = 'see @do please';
    const trigger = findMentionTrigger(text, 7)!;
    const result = insertMention(text, trigger, 'My [doc]\nx');

    expect(result.text).toBe('see @My  doc x  please');
    expect(result.text.slice(0, result.caret).endsWith('x ')).toBe(true);
    // The caret is behind the space, so the picker does not reopen.
    expect(findMentionTrigger(result.text, result.caret)).toBeUndefined();
  });

  it('does not let labels break out of the brackets', () => {
    expect(formatMention('a', 'b] [c')).toBe('[@ id="a" label="b   c"]');
  });
});

describe('serializeMentions', () => {
  const m = (id: string, label: string) => ({ id, label });

  it('replaces recorded mentions, longest label first', () => {
    expect(
      serializeMentions('hi @Ann Lee, @Ann!', [
        m('1', 'Ann'),
        m('2', 'Ann Lee'),
      ]),
    ).toBe('hi [@ id="2" label="Ann Lee"], [@ id="1" label="Ann"]!');
  });

  it('only replaces as often as recorded and at word starts', () => {
    expect(serializeMentions('@Ann @Ann a@Ann @Annie', [m('1', 'Ann')])).toBe(
      '[@ id="1" label="Ann"] @Ann a@Ann @Annie',
    );
  });

  it('leaves edited mentions and plain text alone', () => {
    expect(
      serializeMentions('@An x (a+b)', [m('1', 'Ann'), m('2', 'a+b')]),
    ).toBe('@An x (a+b)');
    expect(serializeMentions('x', [])).toBe('x');
  });
});
