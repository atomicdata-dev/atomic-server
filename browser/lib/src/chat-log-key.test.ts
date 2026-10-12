import { describe, expect, it } from 'vitest';
import { migratedEntryKey, migratedKeyHash } from './chat-log.js';

describe('migratedEntryKey', () => {
  // The same vectors are in `migrated_key_is_the_same_in_both_spellings...`
  // in lib/src/chat_log.rs: both sides must make one key.
  it('is the same for both spellings and ignores query and fragment', () => {
    const want = '1a122ad6665-ba7816bf';

    for (const subject of [
      'did:ad:abc',
      'atomic:abc',
      'did:ad:abc?drive=did:ad:xyz',
      'atomic:abc#frag',
    ]) {
      expect(migratedEntryKey(0x1a122ad6665, subject), subject).toBe(want);
    }

    expect(migratedEntryKey(0x1a122ad6665, 'did:ad:abd')).not.toBe(want);
  });

  it('has a hash part that does not depend on the creation time', () => {
    expect(migratedKeyHash('did:ad:abc')).toBe('ba7816bf');
    expect(migratedKeyHash('atomic:abc?x=1')).toBe('ba7816bf');
    expect(migratedEntryKey(7, 'did:ad:abc').endsWith('-ba7816bf')).toBe(true);
  });
});
