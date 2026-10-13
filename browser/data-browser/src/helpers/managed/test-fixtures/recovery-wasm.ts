// @wc-ignore-file
// Native test substitute for the WASM boundary, using the same Argon2id algorithm.
import { argon2id } from '@noble/hashes/argon2.js';

export default async function init() {}
// Production cost (64 MiB, 3 passes) in pure JS takes seconds per call, and
// several calls per test exceeded the 30s budget on a loaded CI runner. The
// tests check that wrapping and unwrapping agree, not the cost, so a cheap
// setting (still Argon2id, still keyed by code and salt) is enough.
export function argon2idDeriveKey(
  code: string,
  salt: Uint8Array,
  _m: number,
  _t: number,
  p: number,
) {
  return argon2id(code, salt, { m: 64, t: 1, p, dkLen: 32 });
}
