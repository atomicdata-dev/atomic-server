import { describe, expect, it } from 'vitest';
import { encodeB64 } from '@tomic/lib';
import { base64ToBytes, randomBytes } from './bytes';

/** The encoder both modules carried before they used `encodeB64`. */
function legacyBytesToBase64(bytes: Uint8Array): string {
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

const SAMPLES = [
  new Uint8Array([]),
  new Uint8Array([0]),
  new Uint8Array([255, 254]),
  new Uint8Array([0, 1, 2]),
  new Uint8Array([251, 255, 191, 62, 63]),
  Uint8Array.from({ length: 256 }, (_, i) => i),
  randomBytes(32),
  randomBytes(33),
];

describe('bytes', () => {
  it.each(SAMPLES.map((s, i) => [i, s] as const))(
    'encodeB64 matches the legacy encoder and round-trips (%i)',
    (_i, bytes) => {
      expect(encodeB64(bytes)).toBe(legacyBytesToBase64(bytes));
      expect(Array.from(base64ToBytes(encodeB64(bytes)))).toEqual(
        Array.from(bytes),
      );
    },
  );

  it('base64ToBytes rejects malformed input', () => {
    expect(() => base64ToBytes('not base64!')).toThrow();
  });

  it('randomBytes returns the requested length', () => {
    expect(randomBytes(16)).toHaveLength(16);
  });
});
