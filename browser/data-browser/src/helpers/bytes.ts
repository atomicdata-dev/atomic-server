/**
 * Byte helpers shared by the key-wrapping code (`localDbKey`, `managed/recovery`,
 * `managed/driveCarryOver`). Encoding to standard padded base64 is `encodeB64`
 * from `@tomic/lib`; this module only holds what that does not cover.
 */

/**
 * Strict standard-base64 decode (`atob`): throws on malformed input, unlike
 * `@tomic/lib`'s lenient `decodeB64`, which accepts both alphabets and, under
 * Node, silently skips bad characters. Callers rely on the throw to reject a
 * corrupt stored record, and on the result owning a plain `ArrayBuffer`
 * (never a pooled `Buffer`) so it can go straight into WebCrypto.
 */
export function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  return bytes;
}
