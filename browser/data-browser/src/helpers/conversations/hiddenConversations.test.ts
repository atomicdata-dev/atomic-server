import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getHiddenConversations,
  hideConversation,
  unhideConversation,
  withoutHidden,
} from './hiddenConversations';

const ME = 'did:ad:agent:me';
const OTHER = 'did:ad:agent:other';

describe('hidden conversations', () => {
  beforeEach(() => {
    const items = new Map<string, string>();

    vi.stubGlobal('localStorage', {
      getItem: (key: string) => items.get(key) ?? null,
      setItem: (key: string, value: string) => items.set(key, value),
    });
  });

  it('hides a conversation from the list', () => {
    hideConversation(ME, 'did:ad:a');

    expect(
      withoutHidden(['did:ad:a', 'did:ad:b'], getHiddenConversations(ME)),
    ).toEqual(['did:ad:b']);
  });

  it('brings it back when it is unhidden', () => {
    hideConversation(ME, 'did:ad:a');
    unhideConversation(ME, 'did:ad:a');

    expect(getHiddenConversations(ME)).toEqual([]);
  });

  it('keeps the set per account', () => {
    hideConversation(ME, 'did:ad:a');

    expect(getHiddenConversations(OTHER)).toEqual([]);
  });

  it('survives unreadable storage', () => {
    localStorage.setItem('atomic.hidden-conversations', '{nope');

    expect(getHiddenConversations(ME)).toEqual([]);
  });
});
