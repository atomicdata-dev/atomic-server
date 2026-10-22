import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { fromBase64Url, isValidAppKey, sealIdentity } from './identityHandback';

// The Dart side opens the same vector (packages/atomic_flutter).
const vector = JSON.parse(
  readFileSync(
    resolve(
      __dirname,
      '../../../../../packages/atomic_flutter/test/fixtures/identity_handback_vector.json',
    ),
    'utf8',
  ),
) as Record<string, string>;

const payload = JSON.parse(vector.plaintext) as {
  secret: string;
  subject: string;
  drive: string | null;
};

describe('sealIdentity', () => {
  it('reproduces the shared vector', async () => {
    const sealed = await sealIdentity(vector.app_key, payload, {
      senderSeed: fromBase64Url(vector.sender_private),
      nonce: fromBase64Url(vector.nonce),
    });

    expect(sealed).toEqual({
      epk: vector.epk,
      nonce: vector.nonce,
      ciphertext: vector.ciphertext,
    });
  });

  it('seals differently every time', async () => {
    const a = await sealIdentity(vector.app_key, payload);
    const b = await sealIdentity(vector.app_key, payload);

    expect(a.epk).not.toEqual(b.epk);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
    expect(a.ciphertext).not.toContain(payload.secret);
  });

  it('refuses an app key that is not 32 bytes', async () => {
    await expect(sealIdentity('AAAA', payload)).rejects.toThrow();
    expect(isValidAppKey(vector.app_key)).toBe(true);
    expect(isValidAppKey('AAAA')).toBe(false);
    expect(isValidAppKey(null)).toBe(false);
  });
});
