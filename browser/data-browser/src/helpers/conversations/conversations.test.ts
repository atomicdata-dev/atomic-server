import { beforeEach, describe, expect, it, vi } from 'vitest';
import { conversations, core } from '@tomic/react';
import { hasMembers, startConversation } from './conversations';

// The cryptography is wasm; what matters here is who ends up a member.
vi.mock('./conversationCrypto', () => ({
  encryptionKeyFor: vi.fn(async () => 'my-key'),
  addEpoch: vi.fn(async (members: { agent: string }[]) =>
    JSON.stringify(members.map(member => member.agent)),
  ),
  sealPayload: vi.fn(),
}));

const ME = 'did:ad:agent:me';
const OTHER = 'did:ad:agent:other';
const GENESIS = 'did:ad:conversation';

/**
 * A store that models the one rule these tests are about: a save of a resource
 * in a local-only drive stays on this device, any other save is queued for the
 * server. `events` records the order of registration and saves.
 */
function setup() {
  const localOnly = new Set<string>();
  const outbox: string[] = [];
  const events: string[] = [];
  const props = new Map<string, unknown>();

  const conversation = {
    subject: GENESIS,
    get: (property: string) => props.get(property),
    remove: (property: string) => props.delete(property),
    save: vi.fn(async () => {
      events.push('save');

      if (!localOnly.has(GENESIS)) outbox.push(GENESIS);
    }),
  };

  const store = {
    getAgent: () => ({ subject: ME }),
    registerLocalOnlyDrive: vi.fn((drive: string) => {
      events.push('register');
      localOnly.add(drive);
    }),
    isLocalOnlyDrive: (drive: string) => localOnly.has(drive),
    getResource: vi.fn(async () => ({
      error: undefined,
      get: () => 'my-key',
      set: vi.fn(),
      save: vi.fn(),
    })),
    fetchResourceFromServer: vi.fn(async (subject: string) => ({
      subject,
      get: () => 'their-key',
    })),
    newResource: vi.fn(async ({ propVals }: { propVals: object }) => {
      for (const [property, value] of Object.entries(propVals)) {
        props.set(property, value);
      }

      props.set(core.properties.write, [ME]);

      return conversation;
    }),
  };

  return { store, conversation, outbox, events, localOnly };
}

describe('startConversation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('a note to yourself', () => {
    it('has only you as a member', async () => {
      const { store, conversation } = setup();

      await startConversation(store as never, []);

      expect(hasMembers(conversation as never, [ME])).toBe(true);
      expect(conversation.get(core.properties.read)).toEqual([ME]);
      expect(conversation.get(conversations.properties.conversationKeys)).toBe(
        JSON.stringify([ME]),
      );
    });

    it('is browser-only before the first save, so no commit is queued', async () => {
      const { store, outbox, events, localOnly } = setup();

      await startConversation(store as never, []);

      expect(store.registerLocalOnlyDrive).toHaveBeenCalledExactlyOnceWith(
        GENESIS,
      );
      expect(localOnly.has(GENESIS)).toBe(true);
      expect(events).toEqual(['register', 'save', 'save']);
      expect(outbox).toEqual([]);
    });

    it('never asks a server for anyone, and gives up its drive-wide write', async () => {
      const { store, conversation } = setup();

      await startConversation(store as never, []);

      expect(store.fetchResourceFromServer).not.toHaveBeenCalled();
      expect(conversation.get(core.properties.write)).toBeUndefined();
    });
  });

  describe('a conversation with someone else', () => {
    it('is unchanged: two members, hosted, queued for the server', async () => {
      const { store, conversation, outbox, localOnly } = setup();

      await startConversation(store as never, [OTHER]);

      expect(hasMembers(conversation as never, [ME, OTHER])).toBe(true);
      expect(store.fetchResourceFromServer).toHaveBeenCalledExactlyOnceWith(
        OTHER,
      );
      expect(store.registerLocalOnlyDrive).not.toHaveBeenCalled();
      expect(localOnly.size).toBe(0);
      expect(outbox).toEqual([GENESIS, GENESIS]);
      expect(conversation.get(core.properties.write)).toBeUndefined();
    });

    it('does not count you twice', async () => {
      const { store, conversation } = setup();

      await startConversation(store as never, [OTHER, ME]);

      expect(conversation.get(core.properties.read)).toEqual([ME, OTHER]);
    });
  });

  it('refuses a non-empty list that is only yourself', async () => {
    const { store, outbox } = setup();

    await expect(startConversation(store as never, [ME])).rejects.toThrow(
      'Pick someone to message.',
    );
    expect(store.newResource).not.toHaveBeenCalled();
    expect(store.registerLocalOnlyDrive).not.toHaveBeenCalled();
    expect(outbox).toEqual([]);
  });
});
