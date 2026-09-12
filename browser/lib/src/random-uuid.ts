/**
 * A v4 UUID, in secure contexts and insecure ones alike.
 *
 * `crypto.randomUUID` is gated on a secure context, so over plain HTTP it is
 * undefined on anything but localhost — which is exactly how a self-hosted
 * server on a LAN gets reached (`http://homeassistant.local`,
 * `http://192.168.1.x`). Calling it there throws, and a throw on a path that
 * runs during drive load takes the whole first paint with it.
 *
 * `crypto.getRandomValues` carries no such gate, so the fallback is as random
 * as the real thing; only the convenience wrapper is missing. This replaced a
 * global `window.crypto.randomUUID = ...` patch in the data-browser entrypoint:
 * a polyfill hides the constraint from every future caller, and the callers
 * that matter live in this package anyway.
 */
export function randomUUID(): string {
  const c = globalThis.crypto;

  if (typeof c?.randomUUID === 'function') {
    return c.randomUUID();
  }

  const bytes = new Uint8Array(16);
  c.getRandomValues(bytes);

  // RFC 4122: version 4 in the high nibble of byte 6, variant 10x in byte 8.
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-');
}
