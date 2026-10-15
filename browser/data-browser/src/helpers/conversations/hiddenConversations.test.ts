import { beforeEach, describe, expect, it, vi } from 'vitest';
import { conversations, core } from '@tomic/react';
import {
  getHiddenConversations,
  leaveConversation,
  hideConversation,
  unhideConversation,
  withoutHidden,
} from './hiddenConversations';

vi.mock('../privateDrive', () => ({
  fetchPrivateDriveSubject: vi.fn(async () => 'did:ad:drive'),
}));
vi.mock('./conversationsEndpoint', () => ({
  fetchMemberOf: vi.fn(async () => ['did:ad:twin2']),
}));

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

describe('leaveConversation', () => {
  beforeEach(() => {
    const items = new Map<string, string>();

    vi.stubGlobal('localStorage', {
      getItem: (key: string) => items.get(key) ?? null,
      setItem: (key: string, value: string) => items.set(key, value),
    });
  });

  it('also leaves the twins that have the same members', async () => {
    const members: Record<string, string[]> = {
      'did:ad:chat': [ME, OTHER],
      'did:ad:twin': ['atomic:agent:me', 'atomic:agent:other'],
      'did:ad:twin2': [OTHER, ME],
      'did:ad:other-chat': [ME, 'did:ad:agent:third'],
    };
    const drive = {
      get: () => ['did:ad:chat', 'did:ad:twin', 'did:ad:other-chat'],
      set: vi.fn(),
      save: vi.fn(),
    };
    const store = {
      getAgent: () => ({ subject: ME }),
      getResource: vi.fn(async (subject: string) =>
        subject === 'did:ad:drive'
          ? drive
          : {
              error: undefined,
              get: (prop: string) =>
                prop === core.properties.read ? members[subject] : undefined,
            },
      ),
    };

    await leaveConversation(store as never, 'did:ad:chat');

    expect(getHiddenConversations(ME).sort()).toEqual([
      'did:ad:chat',
      'did:ad:twin',
      'did:ad:twin2',
    ]);
    expect(drive.set).toHaveBeenCalledWith(
      conversations.properties.conversations,
      ['did:ad:other-chat'],
    );
  });
});
