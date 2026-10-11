import { describe, expect, it } from 'vitest';
import { entryText, findChatMatches, type ChatCandidate } from './chatMatches';

const candidates: ChatCandidate[] = [
  { subject: 'dm1', kind: 'dm', names: ['Alice Jansen'] },
  { subject: 'dm2', kind: 'dm', names: ['Bob', 'Carol'] },
  {
    subject: 'ai1',
    kind: 'ai',
    names: ['Trip planning'],
    texts: ['Book a flight to Lisbon'],
  },
  { subject: 'ai2', kind: 'ai', names: ['Untitled'], texts: ['alice said'] },
];

describe('findChatMatches', () => {
  it('matches member names case-insensitively', () => {
    expect(findChatMatches('ALICE', candidates)).toEqual([
      { subject: 'dm1', kind: 'dm', via: 'name' },
      { subject: 'ai2', kind: 'ai', via: 'message' },
    ]);
  });

  it('matches any member of a group', () => {
    expect(findChatMatches('car', candidates).map(m => m.subject)).toEqual([
      'dm2',
    ]);
  });

  it('matches AI chat titles and loaded message text', () => {
    expect(findChatMatches('lisbon', candidates)).toEqual([
      { subject: 'ai1', kind: 'ai', via: 'message' },
    ]);
    expect(findChatMatches('planning', candidates)[0]).toEqual({
      subject: 'ai1',
      kind: 'ai',
      via: 'name',
    });
  });

  it('matches a DM by text the local index found, with the text', () => {
    const found = new Map([['dm1', 'meet at the hangar']]);
    expect(findChatMatches('hangar', candidates, found)).toEqual([
      {
        subject: 'dm1',
        kind: 'dm',
        via: 'message',
        snippet: 'meet at the hangar',
      },
    ]);
  });

  it('lists name matches before message matches', () => {
    const [first] = findChatMatches('alice', candidates);
    expect(first.via).toBe('name');
  });

  it('finds nothing for an empty or blank query', () => {
    expect(findChatMatches('', candidates)).toEqual([]);
    expect(findChatMatches('   ', candidates)).toEqual([]);
  });
});

describe('entryText', () => {
  it('prefers t', () => {
    expect(entryText({ t: 'hello' })).toBe('hello');
  });

  it('joins the text parts only', () => {
    const parts = JSON.stringify([
      { type: 'reasoning', text: 'hmm' },
      { type: 'text', text: 'one' },
      { type: 'tool-x', input: {} },
      { type: 'text', text: 'two' },
    ]);
    expect(entryText({ t: '', parts })).toBe('one\ntwo');
  });

  it('survives bad JSON', () => {
    expect(entryText({ parts: '{nope' })).toBe('');
    expect(entryText({})).toBe('');
  });
});
