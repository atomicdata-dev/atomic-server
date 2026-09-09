// @wc-ignore-file
// Native test substitute for the WASM boundary, using the same Argon2id algorithm.
import { argon2id } from '@noble/hashes/argon2.js';

export default async function init() {}
export function argon2idDeriveKey(
  code: string,
  salt: Uint8Array,
  m: number,
  t: number,
  p: number,
) {
  return argon2id(code, salt, { m, t, p, dkLen: 32 });
}
