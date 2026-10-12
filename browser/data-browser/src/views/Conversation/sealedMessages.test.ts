import { migratedEntryKey } from '@tomic/react';
import { describe, expect, it } from 'vitest';
import { toEntryId } from '../../helpers/chatLog';
import { resolveReplies } from './sealedMessages';

describe('resolveReplies', () => {
  // A reply sent before a message moved into the log names the old subject.
  const oldSubject = 'did:ad:oldsealedmessage';
  const page = 'did:ad:page';
  const moved = toEntryId(
    page,
    migratedEntryKey(1_700_000_000_000, oldSubject),
  );
  const fresh = toEntryId(page, '19f0a1b2c3d-0000000a');

  it('points a reply to a moved message at its entry', () => {
    const payloads = new Map([
      [fresh, { text: 'yes', replyTo: oldSubject }],
      [moved, { text: 'question' }],
    ]);
    const resolved = resolveReplies(payloads, [moved, fresh]);

    expect(resolved.get(fresh)?.replyTo).toBe(moved);
    expect(resolved.get(moved)).toEqual({ text: 'question' });
    // The opened payloads are not changed.
    expect(payloads.get(fresh)?.replyTo).toBe(oldSubject);
  });

  it('leaves entry ids, unknown subjects and unreadable messages alone', () => {
    const payloads = new Map<string, { text: string; replyTo?: string } | null>(
      [
        [fresh, { text: 'a', replyTo: moved }],
        [moved, { text: 'b', replyTo: 'did:ad:somethingelse' }],
        ['did:ad:locked', null],
      ],
    );
    const resolved = resolveReplies(payloads, [moved, fresh]);

    expect(resolved.get(fresh)?.replyTo).toBe(moved);
    expect(resolved.get(moved)?.replyTo).toBe('did:ad:somethingelse');
    expect(resolved.get('did:ad:locked')).toBeNull();
  });

  it('returns the same map when no entry is listed', () => {
    const payloads = new Map([
      ['did:ad:m', { text: 'x', replyTo: oldSubject }],
    ]);

    expect(resolveReplies(payloads, ['did:ad:m'])).toBe(payloads);
  });
});
