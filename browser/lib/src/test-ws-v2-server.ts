/**
 * The server's half of the v2 WebSocket codec, for tests only.
 *
 * The browser never sends AUTH_OK, ERROR, COMMIT_OK, CHALLENGE or SYNC_RESEND
 * and never reads another client's HELLO capabilities, so these live outside
 * `ws-v2.ts` and stay out of the shipped bundle. The tests use them to play
 * the server against `WSClient`, and `ws-v2.test.ts` pins them to the golden
 * vectors shared with `lib/src/sync/protocol.rs`.
 */
import { Tag } from './ws-v2.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function writeU16(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = (value >> 8) & 0xff;
  buf[offset + 1] = value & 0xff;
}

function readU16(buf: Uint8Array, offset: number): [number, number] {
  return [(buf[offset] << 8) | buf[offset + 1], offset + 2];
}

/** AUTH_OK: `[0x02] [caps_json_utf8]?` — the payload is omitted for an empty
 *  list, as the pre-2026-09 server did. */
export function encodeAuthOk(caps: readonly string[]): Uint8Array {
  const payload =
    caps.length > 0 ? encoder.encode(JSON.stringify(caps)) : new Uint8Array(0);
  const buf = new Uint8Array(1 + payload.length);
  buf[0] = Tag.AUTH_OK;
  buf.set(payload, 1);

  return buf;
}

/** ERROR: `[0x03] [request_id: u16] [code: u16] [message_utf8]`. */
export function encodeError(
  requestId: number,
  code: number,
  message: string,
): Uint8Array {
  const messageBytes = encoder.encode(message);
  const buf = new Uint8Array(5 + messageBytes.length);
  buf[0] = Tag.ERROR;
  writeU16(buf, 1, requestId);
  writeU16(buf, 3, code);
  buf.set(messageBytes, 5);

  return buf;
}

/** COMMIT_OK, legacy full form: `[0x14] [request_id: u16] [commit_json]`. */
export function encodeCommitOk(
  requestId: number,
  commitJson: string,
): Uint8Array {
  const payload = encoder.encode(commitJson);
  const buf = new Uint8Array(3 + payload.length);
  buf[0] = Tag.COMMIT_OK;
  writeU16(buf, 1, requestId);
  buf.set(payload, 3);

  return buf;
}

/** COMMIT_OK, slim form: `[0x14] [request_id: u16] [commit_id_utf8]`. What
 *  a server sends a client whose HELLO listed `commit-ok-slim`. */
export function encodeCommitOkSlim(
  requestId: number,
  commitId: string,
): Uint8Array {
  return encodeCommitOk(requestId, commitId);
}

/** COMMIT_OK, paced slim form:
 *  `[0x14] [request_id: u16] [commit_id_utf8] 0x00 [pace_ms: decimal]`. What
 *  a server sends a client whose HELLO listed `commit-ok-slim` and
 *  `commit-pace`. */
export function encodeCommitOkPaced(
  requestId: number,
  commitId: string,
  paceMs: number,
): Uint8Array {
  return encodeCommitOk(requestId, `${commitId}\0${paceMs}`);
}

/** CHALLENGE: `[0x42] [nonce_utf8]`. */
export function encodeChallenge(nonce: string): Uint8Array {
  const payload = encoder.encode(nonce);
  const buf = new Uint8Array(1 + payload.length);
  buf[0] = Tag.CHALLENGE;
  buf.set(payload, 1);

  return buf;
}

/** SYNC_RESEND: `[0x38] [drive_utf8]`. */
export function encodeSyncResend(drive: string): Uint8Array {
  const payload = encoder.encode(drive);
  const buf = new Uint8Array(1 + payload.length);
  buf[0] = Tag.SYNC_RESEND;
  buf.set(payload, 1);

  return buf;
}

/** The capability names after the display name in a HELLO payload (after
 *  the tag byte). Empty for a malformed frame or a peer that sent none. */
export function decodeHelloCaps(data: Uint8Array): string[] {
  if (data.length < 2) return [];
  const [len, off] = readU16(data, 0);
  const rest = data.subarray(off + len);
  if (rest.length === 0) return [];

  try {
    const parsed = JSON.parse(decoder.decode(rest));

    return Array.isArray(parsed)
      ? parsed.filter((c): c is string => typeof c === 'string')
      : [];
  } catch {
    return [];
  }
}
