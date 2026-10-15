/**
 * WebSocket Protocol v2: binary-first, unified messages.
 *
 * Frame format: [type: u8] [payload...]
 * All frames are binary WebSocket frames. No base64, no JSON for Loro bytes.
 *
 * **Canonical wire-format spec:** `docs/src/websockets.md`. When tags, flag
 * bits, or payload layouts change here, update that doc and the matching
 * Rust module (`lib/src/sync/protocol.rs`) in the same change.
 */

// ---- Message type tags ----

export const Tag = {
  AUTH: 0x01,
  AUTH_OK: 0x02,
  ERROR: 0x03,
  GET: 0x10,
  UPDATE: 0x11,
  DESTROY: 0x12,
  COMMIT: 0x13,
  COMMIT_OK: 0x14,
  /** One request for a list of subjects; answered by GET_MANY_RESULT.
   *  Only sent to a server whose AUTH_OK lists `get-many`. */
  GET_MANY: 0x15,
  /** One complete UPDATE or ERROR frame per requested subject, in order. */
  GET_MANY_RESULT: 0x16,
  SUB: 0x20,
  UNSUB: 0x21,
  SYNC: 0x30,
  SYNC_OK: 0x31,
  SYNC_DIFF: 0x32,
  SYNC_PUSH: 0x33,
  BLOB_REQUEST: 0x34,
  BLOB_RESPONSE: 0x35,
  /**
   * Reserved (do not reuse). Previously `QUERY_UPDATE` — retired in
   * `planning/sync.md` ("QUERY_UPDATE removed"). Drive-wide membership signals now
   * arrive as plain `UPDATE` (0x11) / `DESTROY` (0x12) frames.
   */
  QUERY_UPDATE_RESERVED: 0x36,
  /** Device name + capability list. Both peers send it on an Iroh stream
   *  after AUTH_OK; since 2026-09 a WebSocket client sends one on open too
   *  (`encodeHello`), listing the capabilities it speaks so the server can
   *  e.g. answer COMMIT with a slim COMMIT_OK. The server never sends it over
   *  WebSocket (its own list rides on AUTH_OK). */
  HELLO: 0x37,
  /** Presence / cursor / live-doc frames, both directions on both
   *  transports (`encodeEphemeral`, `EphemeralKind`). */
  EPHEMERAL: 0x40,
  /** Liveness probe. The server echoes it over WebSocket; see
   *  `WSClient`'s liveness timer. */
  KEEPALIVE: 0x41,
  /** Server → client, the first frame on a WebSocket, before the client has
   *  said anything: `[0x42] [nonce_utf8]`. A client that saw it signs
   *  `AUTH.requestedSubject` as `{origin}#{nonce}`, which makes the proof
   *  good on this connection only; a client that ignores it still
   *  authenticates on its timestamp. */
  CHALLENGE: 0x42,
  /** Server → client, the negative answer to a `SYNC` probe: `[0x38]
   *  [drive_utf8]`. The drive hashes differ; send the full version-vector
   *  `SYNC`. The positive answer is `SYNC_OK`. */
  SYNC_RESEND: 0x38,
} as const;

// ---- UPDATE flags ----

export const Flags = {
  /** Loro snapshot (1) vs delta (0) */
  SNAPSHOT: 0b0001,
  /** A commit ID follows the subject */
  HAS_COMMIT_ID: 0b0010,
  /** Subscription push (not a GET response) */
  PUSH: 0b0100,
} as const;

/** SYNC_PUSH flags. A SYNC_PUSH run is one or more chunks; only the
 *  final chunk has LAST set. Receivers must keep reading SYNC_PUSH
 *  frames until they see this bit. */
export const SyncPushFlags = {
  LAST: 0b0001,
  /** The frame carries a trailing envelope section after its entries: the
   *  retained signed commits (JSON-AD) of the pushed subjects. A decoder that
   *  predates the section stops after `count` entries and never reads it. */
  ENVELOPES: 0b0010,
} as const;

/** A signed envelope travelling with a SYNC_PUSH: the commit JSON-AD of
 *  `subject`. Verified by the receiver before it is kept. */
export interface SyncPushEnvelope {
  subject: string;
  json: string;
}

/**
 * Structured error codes on `ERROR` frames (mirrors `lib/src/sync/protocol.rs`
 * `error_code`; F5, planning/unified-sync.md). `UNKNOWN` means "no
 * structured classification" — callers fall back to message string
 * matching (`local-outbox.ts`'s `isTerminalCommitErrorMessage` /
 * `isUnrecoverableCommitErrorMessage`), which also covers older servers
 * that predate this field.
 */
export const ErrorCode = {
  UNKNOWN: 0,
  GENESIS_COLLISION: 1,
  MISSING_REQUIRED_PROPERTY: 2,
  UNAUTHORIZED_WRITE: 3,
  /** The commit names a class the server does not hold, so it cannot validate.
   *  Blocking rather than terminal: the write is well-formed and would apply
   *  once the class arrives, so it must not be discarded. */
  MISSING_CLASS: 4,
  /** A frame that needs an identity (SYNC_PUSH, EPHEMERAL,
   *  LORO_SYNC_SUBSCRIBE, ...) arrived before AUTH. Connection-level (`requestId`
   *  0); the socket stays open and the frame is simply not processed. */
  AUTH_REQUIRED: 5,
  /** Node policy refused a commit (enrollment/quota), or the server refused
   *  a SYNC_PUSH as a whole (no write right on the
   *  drive, quota, not enrolled). Nothing from the push landed, and no
   *  SYNC_OK follows for it. The message names the drive. */
  SYNC_REJECTED: 6,
  /** A subscription (SUB, LORO_SYNC_SUBSCRIBE, PRESENCE_SUBSCRIBE) was
   *  refused because the agent cannot read the subject or drive. Nothing was
   *  subscribed. */
  UNAUTHORIZED_READ: 7,
  /** An AUTH frame was refused: bad signature, unknown agent, a timestamp
   *  outside the accepted window, or a `requestedSubject` that does not
   *  name this server. Sign a fresh proof for the right origin; resending
   *  the same frame changes nothing. */
  AUTH_FAILED: 8,
  /** A COMMIT whose signature does not verify against its signer's key (or
   *  that carries none). Terminal for that envelope: the client must sign
   *  again; re-sending the same bytes changes nothing. */
  INVALID_SIGNATURE: 9,
  /** The commit's subject is itself a Commit (`did:ad:commit:<sig>` or the
   *  legacy `<server>/commits/<sig>`), which can never be edited. Terminal:
   *  drop the entry; nothing is lost, a Commit is whatever was signed. */
  IMMUTABLE_COMMIT: 10,
  /** The server rejected a stale Loro write; preserve the local edit and
   *  stop retrying until it can be based on current state. */
  CAUSALITY_CONFLICT: 11,
  /** The node is overloaded with writes (or this agent spent its write rate
   *  budget). The commit was refused before any work and nothing landed. The
   *  message carries `retry_after_ms=<n>` (see `retryAfterMsFromMessage`).
   *  Not a failure: keep the local state, wait, then send one merged delta. */
  BUSY: 12,
} as const;

/** The `retry_after_ms=<n>` hint of a BUSY error message (or an HTTP error
 *  description). `undefined` when the message carries none. Mirrors
 *  `retry_after_ms_from_message` in `lib/src/sync/protocol.rs`. */
export function retryAfterMsFromMessage(message: string): number | undefined {
  const match = /retry_after_ms=(\d+)/.exec(message);

  return match ? Number(match[1]) : undefined;
}

/** How long to wait before resending after a refusal that carries no usable
 *  hint (an HTTP 503 without `Retry-After`). */
export const DEFAULT_BUSY_RETRY_MS = 1000;

/** The retry delay (ms) a commit refusal asks for, or `undefined` when it is
 *  not a "busy" refusal. Recognises `ErrorCode.BUSY` and, for servers that
 *  predate it, the rate limiter's `Too many writes; retry after N seconds`
 *  text, which arrived with code `UNKNOWN`. */
export function busyRetryAfterMs(
  message: string,
  code?: number,
): number | undefined {
  if (code === ErrorCode.BUSY) {
    return retryAfterMsFromMessage(message) ?? DEFAULT_BUSY_RETRY_MS;
  }

  const legacy = /Too many writes; retry after (\d+) seconds/.exec(message);

  if (legacy) return Number(legacy[1]) * 1000;

  return undefined;
}

/** Capability names a server may advertise in its AUTH_OK payload (mirrors
 *  `protocol::CAPABILITIES` in `lib/src/sync/protocol.rs`). A server that
 *  sends none is the pre-2026-09 baseline. */
export type ServerCapability =
  | 'auth-max-age'
  | 'keepalive'
  /** Retired 2026-09: servers answered `RBSR_FP` range fingerprints. */
  | 'rbsr'
  | 'pull-from'
  | 'signed-destroy'
  | 'unsub'
  /** Sends `CHALLENGE` on connect and verifies `{origin}#{nonce}` proofs. */
  | 'auth-nonce'
  /** Answers COMMIT with `[request_id][commit_id]` for a client whose HELLO
   *  lists `commit-ok-slim`. */
  | 'commit-ok-slim'
  /** Reads a client `HELLO` over WebSocket. */
  | 'client-hello'
  /** Re-checks this connection's subscriptions when an AUTH changes its
   *  identity, dropping the ones it may no longer read. */
  | 'rebind-on-auth'
  /** The binary `SYNC` payload may carry `probe` and `subjects`; a probe is
   *  answered with `SYNC_OK` or `SYNC_RESEND`. */
  | 'sync-probe'
  /** Understands `atomic:` subjects on the wire. A peer that does not list
   *  it receives `did:ad:` subjects. */
  | 'canonical-scheme'
  | 'ephemeral'
  | 'get-many'
  /** Appends a `pace_ms` load hint to the slim COMMIT_OK of a client whose
   *  HELLO lists `commit-pace`, and may refuse commits with `BUSY`. */
  | 'commit-pace';

/** Capability names this client lists in the `HELLO` it sends on open
 *  (mirrors `protocol::CLIENT_CAPABILITIES`). */
export const CLIENT_CAPABILITIES: readonly string[] = [
  'commit-ok-slim',
  'canonical-scheme',
  'commit-pace',
];

/** What this client calls itself in its `HELLO`. Display only. */
export const CLIENT_HELLO_NAME = '@tomic/lib browser';

// ---- Low-level read/write helpers ----

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function writeU16(buf: Uint8Array, offset: number, value: number): number {
  buf[offset] = (value >> 8) & 0xff;
  buf[offset + 1] = value & 0xff;

  return offset + 2;
}

function readU16(buf: Uint8Array, offset: number): [number, number] {
  return [(buf[offset] << 8) | buf[offset + 1], offset + 2];
}

function writeU32(buf: Uint8Array, offset: number, value: number): number {
  buf[offset] = (value >> 24) & 0xff;
  buf[offset + 1] = (value >> 16) & 0xff;
  buf[offset + 2] = (value >> 8) & 0xff;
  buf[offset + 3] = value & 0xff;

  return offset + 4;
}

function readU32(buf: Uint8Array, offset: number): [number, number] {
  return [
    (buf[offset] << 24) |
      (buf[offset + 1] << 16) |
      (buf[offset + 2] << 8) |
      buf[offset + 3],
    offset + 4,
  ];
}

function readStr16(buf: Uint8Array, offset: number): [string, number] {
  const [len, off] = readU16(buf, offset);
  const str = decoder.decode(buf.subarray(off, off + len));

  return [str, off + len];
}

// ---- Encoding ----

export function encodeAuth(jsonPayload: string): Uint8Array {
  const payload = encoder.encode(jsonPayload);
  const buf = new Uint8Array(1 + payload.length);
  buf[0] = Tag.AUTH;
  buf.set(payload, 1);

  return buf;
}

/** HELLO: `[0x37] [name_len: u16] [name_utf8] [caps_json_utf8]`. The
 *  capability list is a trailing JSON array a pre-2026-09 receiver skips. */
export function encodeHello(name: string, caps: readonly string[]): Uint8Array {
  const nameBytes = encoder.encode(name).subarray(0, 0xffff);
  const capsBytes =
    caps.length > 0 ? encoder.encode(JSON.stringify(caps)) : new Uint8Array(0);
  const buf = new Uint8Array(3 + nameBytes.length + capsBytes.length);
  buf[0] = Tag.HELLO;
  writeU16(buf, 1, nameBytes.length);
  buf.set(nameBytes, 3);
  buf.set(capsBytes, 3 + nameBytes.length);

  return buf;
}

// The encoders for frames only a server sends (AUTH_OK, ERROR, COMMIT_OK,
// CHALLENGE, SYNC_RESEND) and the HELLO capability decoder live in
// `test-ws-v2-server.ts`: the tests use them to play the server, and the
// shipped bundle does not need them.

/** The nonce in a CHALLENGE payload (after the tag byte); `undefined` when
 *  empty. */
export function decodeChallenge(data: Uint8Array): string | undefined {
  if (data.length === 0) return undefined;

  return decoder.decode(data);
}

export function encodeGet(requestId: number, subject: string): Uint8Array {
  const subjectBytes = encoder.encode(subject);
  const buf = new Uint8Array(3 + subjectBytes.length);
  buf[0] = Tag.GET;
  writeU16(buf, 1, requestId);
  buf.set(subjectBytes, 3);

  return buf;
}

/** The AUTH_OK capability that says the server answers GET_MANY. */
export const CAP_GET_MANY = 'get-many';

/** The server reads a `SYNC` whose hash is version 2 and whose version
 *  vectors are sent per resource (`vvs`), instead of as a matrix with one
 *  column per peer in the drive. */
export const CAP_SPARSE_SYNC = 'sparse-sync';

/**
 * GET_MANY: `[0x15] [request_id: u16] [count: u16] ([subject_len: u16]
 * [subject_utf8])*`. Mirrors `protocol::encode_get_many`.
 */
export function encodeGetMany(
  requestId: number,
  subjects: readonly string[],
): Uint8Array {
  const encoded = subjects.map(s => encoder.encode(s));
  const buf = new Uint8Array(
    5 + encoded.reduce((sum, bytes) => sum + 2 + bytes.length, 0),
  );
  buf[0] = Tag.GET_MANY;
  let off = writeU16(buf, 1, requestId);
  off = writeU16(buf, off, subjects.length);

  for (const bytes of encoded) {
    off = writeU16(buf, off, bytes.length);
    buf.set(bytes, off);
    off += bytes.length;
  }

  return buf;
}

export interface DecodedGetMany {
  requestId: number;
  subjects: string[];
}

export interface DecodedGetManyResult {
  requestId: number;
  /** Complete UPDATE / ERROR frames (tag byte included), request order. */
  frames: Uint8Array[];
}

export function decodeGetMany(data: Uint8Array): DecodedGetMany | undefined {
  if (data.length < 4) return undefined;
  const [requestId, off1] = readU16(data, 0);
  const [count, off2] = readU16(data, off1);
  const subjects: string[] = [];
  let off = off2;

  for (let i = 0; i < count; i++) {
    if (data.length < off + 2) return undefined;
    const [len] = readU16(data, off);
    if (data.length < off + 2 + len) return undefined;
    let subject: string;
    [subject, off] = readStr16(data, off);
    subjects.push(subject);
  }

  return { requestId, subjects };
}

/**
 * GET_MANY_RESULT: `[0x16] [request_id: u16] [count: u16] ([frame_len: u32]
 * [frame])*`. Each inner frame is decoded with `decodeUpdate` /
 * `decodeError` after its own tag byte.
 */
export function decodeGetManyResult(
  data: Uint8Array,
): DecodedGetManyResult | undefined {
  if (data.length < 4) return undefined;
  const [requestId, off1] = readU16(data, 0);
  const [count, off2] = readU16(data, off1);
  const frames: Uint8Array[] = [];
  let off = off2;

  for (let i = 0; i < count; i++) {
    if (data.length < off + 4) return undefined;
    const [len, dataOff] = readU32(data, off);
    if (data.length < dataOff + len) return undefined;
    frames.push(data.subarray(dataOff, dataOff + len));
    off = dataOff + len;
  }

  return { requestId, frames };
}

export function encodeCommit(
  requestId: number,
  commitJson: string,
): Uint8Array {
  const payload = encoder.encode(commitJson);
  const buf = new Uint8Array(3 + payload.length);
  buf[0] = Tag.COMMIT;
  writeU16(buf, 1, requestId);
  buf.set(payload, 3);

  return buf;
}

export function encodeSub(driveSubject: string): Uint8Array {
  const payload = encoder.encode(driveSubject);
  const buf = new Uint8Array(1 + payload.length);
  buf[0] = Tag.SUB;
  buf.set(payload, 1);

  return buf;
}

/**
 * Binary SYNC (0x30): `[drive_len: u16] [drive] [hash_len: u16] [hash_utf8]
 * [json]`. `hash` is the hex drive hash as a string (what
 * `compute_drive_hash` / `computeDriveSyncState` produce), matching
 * `protocol::decode_sync`. The JSON tail is `{peers, resources}` plus,
 * optionally, `probe: true` (hash-first probe, answered with `SYNC_OK` or
 * `SYNC_RESEND`) and `subjects: [...]` (reconcile only these). Until
 * 2026-09-04 the browser sent the same JSON as the text frame `SYNC_VV`.
 */
export function encodeSync(
  driveSubject: string,
  hash: string,
  vvJson: string,
): Uint8Array {
  const driveBytes = encoder.encode(driveSubject);
  const hashBytes = encoder.encode(hash);
  const vvBytes = encoder.encode(vvJson);
  const buf = new Uint8Array(
    1 + 2 + driveBytes.length + 2 + hashBytes.length + vvBytes.length,
  );
  let off = 0;
  buf[off++] = Tag.SYNC;
  off = writeU16(buf, off, driveBytes.length);
  buf.set(driveBytes, off);
  off += driveBytes.length;
  off = writeU16(buf, off, hashBytes.length);
  buf.set(hashBytes, off);
  off += hashBytes.length;
  buf.set(vvBytes, off);

  return buf;
}

/** UNSUB (0x21): cancel a drive subscription made with `encodeSub`. */
export function encodeUnsub(driveSubject: string): Uint8Array {
  const driveBytes = encoder.encode(driveSubject);
  const buf = new Uint8Array(1 + driveBytes.length);
  buf[0] = Tag.UNSUB;
  buf.set(driveBytes, 1);

  return buf;
}

/** KEEPALIVE (0x41): payload-free liveness probe; the server echoes it. */
export function encodeKeepalive(): Uint8Array {
  return new Uint8Array([Tag.KEEPALIVE]);
}

/** The capability names in an AUTH_OK payload (bytes after the tag). Empty
 *  for a bare `[0x02]` from an older server. */
export function decodeAuthOk(data: Uint8Array): string[] {
  if (data.length === 0) return [];

  try {
    const parsed = JSON.parse(decoder.decode(data));

    return Array.isArray(parsed)
      ? parsed.filter((c): c is string => typeof c === 'string')
      : [];
  } catch {
    return [];
  }
}

export function encodeSyncPush(
  driveSubject: string,
  entries: Array<{ subject: string; loroBytes: Uint8Array }>,
  last = true,
  envelopes: SyncPushEnvelope[] = [],
): Uint8Array {
  const driveBytes = encoder.encode(driveSubject);
  const encodedEntries = entries.map(e => ({
    subjectBytes: encoder.encode(e.subject),
    loroBytes: e.loroBytes,
  }));
  const entrySize = encodedEntries.reduce(
    (sum, e) => sum + 2 + e.subjectBytes.length + 4 + e.loroBytes.length,
    0,
  );
  const encodedEnvelopes = envelopes.map(e => ({
    subjectBytes: encoder.encode(e.subject),
    jsonBytes: encoder.encode(e.json),
  }));
  const envelopeSize =
    encodedEnvelopes.length === 0
      ? 0
      : 2 +
        encodedEnvelopes.reduce(
          (sum, e) => sum + 2 + e.subjectBytes.length + 4 + e.jsonBytes.length,
          0,
        );

  const buf = new Uint8Array(
    1 + 2 + driveBytes.length + 1 + 2 + entrySize + envelopeSize,
  );
  let off = 0;
  buf[off++] = Tag.SYNC_PUSH;
  off = writeU16(buf, off, driveBytes.length);
  buf.set(driveBytes, off);
  off += driveBytes.length;
  let flags = last ? SyncPushFlags.LAST : 0;
  if (encodedEnvelopes.length > 0) flags |= SyncPushFlags.ENVELOPES;
  buf[off++] = flags;
  off = writeU16(buf, off, entries.length);

  for (const e of encodedEntries) {
    off = writeU16(buf, off, e.subjectBytes.length);
    buf.set(e.subjectBytes, off);
    off += e.subjectBytes.length;
    off = writeU32(buf, off, e.loroBytes.length);
    buf.set(e.loroBytes, off);
    off += e.loroBytes.length;
  }

  if (encodedEnvelopes.length > 0) {
    off = writeU16(buf, off, encodedEnvelopes.length);

    for (const e of encodedEnvelopes) {
      off = writeU16(buf, off, e.subjectBytes.length);
      buf.set(e.subjectBytes, off);
      off += e.subjectBytes.length;
      off = writeU32(buf, off, e.jsonBytes.length);
      buf.set(e.jsonBytes, off);
      off += e.jsonBytes.length;
    }
  }

  return buf;
}

export function encodeBlobRequest(hash: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + 32);
  buf[0] = Tag.BLOB_REQUEST;
  buf.set(hash, 1);

  return buf;
}

export function encodeBlobResponse(
  hash: Uint8Array,
  bytes: Uint8Array,
): Uint8Array {
  const buf = new Uint8Array(1 + 32 + bytes.length);
  buf[0] = Tag.BLOB_RESPONSE;
  buf.set(hash, 1);
  buf.set(bytes, 1 + 32);

  return buf;
}

// ---- Decoding ----

export interface DecodedUpdate {
  flags: number;
  requestId: number;
  subject: string;
  commitId: string | undefined;
  loroBytes: Uint8Array;
}

export interface DecodedGet {
  requestId: number;
  subject: string;
}

export interface DecodedCommit {
  requestId: number;
  commitJson: string;
}

export interface DecodedError {
  requestId: number;
  /** See {@link ErrorCode}. `ErrorCode.UNKNOWN` for frames from a
   *  pre-F5 server (no code byte pair — see {@link decodeError}). */
  code: number;
  message: string;
}

export interface DecodedSyncOk {
  drive: string;
}

export interface DecodedSyncDiff {
  drive: string;
  pull: string[];
  push: string[];
  remove: string[];
  /** Server oplog VV per pull subject — export updates since this. */
  pullFrom: Record<string, Record<string, number>>;
  /** Signed destroy commit JSON-AD per `remove` subject, when present. */
  removeCommits: Record<string, string>;
}

export interface DecodedSyncPushEntry {
  subject: string;
  loroBytes: Uint8Array;
}

export interface DecodedSyncPush {
  drive: string;
  entries: DecodedSyncPushEntry[];
  /** True iff this is the final chunk of a SYNC_PUSH run. Receivers
   *  loop reading SYNC_PUSH frames until they see `last === true`. */
  last: boolean;
  /** The `SyncPushFlags.ENVELOPES` section; empty when absent. */
  envelopes: SyncPushEnvelope[];
}

export interface DecodedBlobResponse {
  hash: Uint8Array;
  bytes: Uint8Array;
}

export function decodeUpdate(data: Uint8Array): DecodedUpdate | undefined {
  if (data.length < 6) return undefined;

  const flags = data[0];
  const [requestId, off1] = readU16(data, 1);
  const [subject, off2] = readStr16(data, off1);

  let commitId: string | undefined;
  let off = off2;

  if (flags & Flags.HAS_COMMIT_ID) {
    [commitId, off] = readStr16(data, off);
  }

  const loroBytes = data.subarray(off);

  return { flags, requestId, subject, commitId, loroBytes };
}

export function decodeGet(data: Uint8Array): DecodedGet | undefined {
  if (data.length < 3) return undefined;
  const [requestId, off] = readU16(data, 0);
  const subject = decoder.decode(data.subarray(off));

  return { requestId, subject };
}

export function decodeCommit(data: Uint8Array): DecodedCommit | undefined {
  if (data.length < 3) return undefined;
  const [requestId, off] = readU16(data, 0);
  const commitJson = decoder.decode(data.subarray(off));

  return { requestId, commitJson };
}

export interface DecodedCommitOk {
  requestId: number;
  /** The server's id for the applied commit. */
  commitId: string;
  /** The full commit JSON-AD; only present for the legacy full form, which
   *  a server sends to a client whose HELLO did not list `commit-ok-slim`. */
  commitJson?: string;
  /** The node's write-load hint: the least number of milliseconds to leave
   *  between commits of one resource. Absent when the server sent none (an
   *  older server, or a client that did not list `commit-pace`). */
  paceMs?: number;
}

/** A COMMIT_OK payload (after the tag byte) in either form: the legacy full
 *  commit JSON (its `@id` is the commit id) or, when this client asked for
 *  it, the bare commit id. `undefined` for a truncated frame or JSON without
 *  an `@id`. */
export function decodeCommitOk(data: Uint8Array): DecodedCommitOk | undefined {
  const raw = decodeCommit(data);
  if (!raw) return undefined;
  const body = raw.commitJson.trim();
  if (body.length === 0) return undefined;

  if (body.startsWith('{')) {
    try {
      const parsed = JSON.parse(body) as { '@id'?: unknown };
      const id = parsed['@id'];
      if (typeof id !== 'string' || id.length === 0) return undefined;

      return {
        requestId: raw.requestId,
        commitId: id,
        commitJson: raw.commitJson,
      };
    } catch {
      return undefined;
    }
  }

  // Paced slim form: `<commit id> NUL <pace_ms decimal>`.
  const nul = body.indexOf('\0');

  if (nul >= 0) {
    const pace = Number(body.slice(nul + 1));

    return {
      requestId: raw.requestId,
      commitId: body.slice(0, nul),
      paceMs: Number.isFinite(pace) && pace >= 0 ? pace : undefined,
    };
  }

  return { requestId: raw.requestId, commitId: body };
}

export function decodeError(data: Uint8Array): DecodedError | undefined {
  if (data.length < 4) return undefined;
  const [requestId, off1] = readU16(data, 0);
  const [code, off2] = readU16(data, off1);
  const message = decoder.decode(data.subarray(off2));

  // A pre-F5 server has no code field — its message bytes start where we
  // just read `code` from, so this client misreads the message's first 2
  // bytes as `code` and drops them from the text. Accepted tradeoff
  // (planning/unified-sync.md F5): cosmetically garbled, not a hard break.
  // That garbled `code` is an ARBITRARY value, not necessarily `UNKNOWN`
  // (0) — callers (`local-outbox.ts`'s `isTerminalCommitError` /
  // `isUnrecoverableCommitError`) MUST only trust codes in their known set
  // and treat everything else (not just literal `UNKNOWN`) as unclassified,
  // or a garbled nonzero code could be read as "recognized, not terminal"
  // and permanently skip the string-matching fallback.
  return { requestId, code, message };
}

export function decodeSyncOk(data: Uint8Array): DecodedSyncOk | undefined {
  const [drive] = readStr16(data, 0);

  return drive ? { drive } : undefined;
}

export function decodeSyncDiff(data: Uint8Array): DecodedSyncDiff | undefined {
  const [drive, off] = readStr16(data, 0);
  const json = decoder.decode(data.subarray(off));

  try {
    const {
      pull,
      push,
      remove = [],
      pullFrom = {},
      removeCommits = {},
    } = JSON.parse(json);

    return { drive, pull, push, remove, pullFrom, removeCommits };
  } catch {
    return undefined;
  }
}

/** Chunking thresholds — keep each WS frame under legacy 64 KiB limits. */
/** Chunking thresholds for `encodeSyncPushChunks`. The entry cap matches the
 *  Rust sender (`protocol::SYNC_PUSH_MAX_ENTRIES`). The byte cap is a
 *  sender-side choice: the Rust sender closes a chunk at 1 MiB, the browser
 *  at 48 KiB so a slow uplink shows progress per chunk. Receivers accept
 *  either; the protocol only requires that the final chunk carry `LAST`. */
const SYNC_PUSH_MAX_ENTRIES = 100;
const SYNC_PUSH_MAX_BYTES = 48 * 1024;

/** Split entries into multiple SYNC_PUSH frames (last chunk flagged).
 *  `envelopes` maps a subject to its retained signed commits (JSON-AD); each
 *  chunk carries the envelopes of the subjects in it, counted against the
 *  same byte budget. */
export function encodeSyncPushChunks(
  driveSubject: string,
  entries: Array<{ subject: string; loroBytes: Uint8Array }>,
  envelopes: Record<string, string[]> = {},
): Uint8Array[] {
  if (entries.length === 0) {
    return [encodeSyncPush(driveSubject, [], true)];
  }

  const envelopeBytes = (subject: string): number =>
    (envelopes[subject] ?? []).reduce(
      (sum, json) =>
        sum +
        2 +
        encoder.encode(subject).length +
        4 +
        encoder.encode(json).length,
      0,
    );

  const chunks: Uint8Array[] = [];
  let start = 0;

  while (start < entries.length) {
    let end = start;
    let bytesAcc = 0;

    while (end < entries.length && end - start < SYNC_PUSH_MAX_ENTRIES) {
      const e = entries[end];
      const entryBytes =
        2 +
        encoder.encode(e.subject).length +
        4 +
        e.loroBytes.length +
        envelopeBytes(e.subject);

      if (end > start && bytesAcc + entryBytes > SYNC_PUSH_MAX_BYTES) {
        break;
      }

      bytesAcc += entryBytes;
      end += 1;
    }

    const last = end >= entries.length;
    const slice = entries.slice(start, end);
    const chunkEnvelopes: SyncPushEnvelope[] = slice.flatMap(e =>
      (envelopes[e.subject] ?? []).map(json => ({
        subject: e.subject,
        json,
      })),
    );
    chunks.push(encodeSyncPush(driveSubject, slice, last, chunkEnvelopes));
    start = end;
  }

  return chunks;
}

export function decodeSyncPush(data: Uint8Array): DecodedSyncPush | undefined {
  const [drive, off1] = readStr16(data, 0);
  if (off1 >= data.length) return undefined;
  const flags = data[off1];
  const last = (flags & SyncPushFlags.LAST) !== 0;
  const [count, off2] = readU16(data, off1 + 1);
  const entries: DecodedSyncPushEntry[] = [];
  let off = off2;

  for (let i = 0; i < count; i++) {
    const [subject, sOff] = readStr16(data, off);
    const [bytesLen, bOff] = readU32(data, sOff);
    const loroBytes = data.subarray(bOff, bOff + bytesLen);
    entries.push({ subject, loroBytes });
    off = bOff + bytesLen;
  }

  const envelopes: SyncPushEnvelope[] = [];

  if ((flags & SyncPushFlags.ENVELOPES) !== 0 && off + 2 <= data.length) {
    const [envCount, eOff] = readU16(data, off);
    off = eOff;

    for (let i = 0; i < envCount; i++) {
      if (off + 2 > data.length) break;
      const [subject, sOff] = readStr16(data, off);
      if (sOff + 4 > data.length) break;
      const [jsonLen, jOff] = readU32(data, sOff);
      const json = decoder.decode(data.subarray(jOff, jOff + jsonLen));
      envelopes.push({ subject, json });
      off = jOff + jsonLen;
    }
  }

  return { drive, entries, last, envelopes };
}

export function decodeBlobRequest(data: Uint8Array): Uint8Array | undefined {
  if (data.length < 32) return undefined;

  return data.slice(0, 32);
}

export function decodeBlobResponse(
  data: Uint8Array,
): DecodedBlobResponse | undefined {
  if (data.length < 32) return undefined;
  const hash = data.slice(0, 32);
  const bytes = data.slice(32);

  return { hash, bytes };
}

export function decodeSubject(data: Uint8Array): string {
  return decoder.decode(data);
}

/** The drive named by a SYNC_RESEND payload (after the tag byte). */
export function decodeSyncResend(data: Uint8Array): string | undefined {
  if (data.length === 0) return undefined;

  return decoder.decode(data);
}

/** The `kind` byte of an EPHEMERAL frame (`protocol::ephemeral_kind`): which
 *  live-collaboration channel it belongs to. */
export const EphemeralKind = {
  /** Cursors and selections for one resource (`subscribeLoroEphemeral`). */
  LORO: 0,
  /** Drive-scoped presence, who is where (`subscribePresence`). */
  PRESENCE: 1,
  /** The ops of an edit in progress, before a save (`subscribeLoroSync`). */
  DOC: 2,
} as const;

export interface DecodedEphemeral {
  kind: number;
  /** The resource, or the drive for `PRESENCE`. */
  subject: string;
  /** The agent the server attributed the frame to. */
  agent: string;
  payload: Uint8Array;
}

/**
 * EPHEMERAL (0x40): `[kind: u8] [subject_len: u16] [subject] [agent_len: u16]
 * [agent] [payload]`. Both directions over WebSocket since 2026-09-04, in
 * place of the text frames `LORO_SYNC_UPDATE`, `LORO_EPHEMERAL_UPDATE` and
 * `PRESENCE_UPDATE` (base64 JSON). Client-sent frames may leave `agent`
 * empty: the server attributes them to the authenticated identity.
 */
export function encodeEphemeral(
  kind: number,
  subject: string,
  agent: string,
  payload: Uint8Array,
): Uint8Array {
  const subjectBytes = encoder.encode(subject);
  const agentBytes = encoder.encode(agent);
  const buf = new Uint8Array(
    1 + 1 + 2 + subjectBytes.length + 2 + agentBytes.length + payload.length,
  );
  let off = 0;
  buf[off++] = Tag.EPHEMERAL;
  buf[off++] = kind & 0xff;
  off = writeU16(buf, off, subjectBytes.length);
  buf.set(subjectBytes, off);
  off += subjectBytes.length;
  off = writeU16(buf, off, agentBytes.length);
  buf.set(agentBytes, off);
  off += agentBytes.length;
  buf.set(payload, off);

  return buf;
}

/** Decode an EPHEMERAL payload (after the tag byte); `undefined` if
 *  truncated. */
export function decodeEphemeral(
  data: Uint8Array,
): DecodedEphemeral | undefined {
  if (data.length < 3) return undefined;
  const kind = data[0];
  const [subjectLen, subjectOff] = readU16(data, 1);
  if (data.length < subjectOff + subjectLen + 2) return undefined;
  const [subject, agentLenOff] = readStr16(data, 1);
  const [agentLen, agentOff] = readU16(data, agentLenOff);
  if (data.length < agentOff + agentLen) return undefined;
  const [agent, payloadOff] = readStr16(data, agentLenOff);

  return { kind, subject, agent, payload: data.subarray(payloadOff) };
}

// ---- Debug logging ----

const TAG_NAMES: Record<number, string> = {
  [Tag.AUTH]: 'AUTH',
  [Tag.AUTH_OK]: 'AUTH_OK',
  [Tag.ERROR]: 'ERROR',
  [Tag.GET]: 'GET',
  [Tag.UPDATE]: 'UPDATE',
  [Tag.DESTROY]: 'DESTROY',
  [Tag.COMMIT]: 'COMMIT',
  [Tag.COMMIT_OK]: 'COMMIT_OK',
  [Tag.GET_MANY]: 'GET_MANY',
  [Tag.GET_MANY_RESULT]: 'GET_MANY_RESULT',
  [Tag.SUB]: 'SUB',
  [Tag.UNSUB]: 'UNSUB',
  [Tag.SYNC]: 'SYNC',
  [Tag.SYNC_OK]: 'SYNC_OK',
  [Tag.SYNC_DIFF]: 'SYNC_DIFF',
  [Tag.SYNC_PUSH]: 'SYNC_PUSH',
  [Tag.BLOB_REQUEST]: 'BLOB_REQUEST',
  [Tag.BLOB_RESPONSE]: 'BLOB_RESPONSE',
  [Tag.QUERY_UPDATE_RESERVED]: 'QUERY_UPDATE_RESERVED',
  [Tag.HELLO]: 'HELLO',
  [Tag.EPHEMERAL]: 'EPHEMERAL',
  [Tag.KEEPALIVE]: 'KEEPALIVE',
  [Tag.CHALLENGE]: 'CHALLENGE',
  [Tag.SYNC_RESEND]: 'SYNC_RESEND',
};

/**
 * Format bytes to kb for debug headlines. e.g. `128 -> "0.13kb"`, `2048 -> "2kb"`.
 */
function formatBytes(n: number): string {
  const kb = n / 1024;
  if (kb === 0) return '0kb';
  const formatted =
    kb < 0.1 ? kb.toFixed(3) : kb < 10 ? kb.toFixed(2) : kb.toFixed(1);

  return `${formatted.replace(/\.?0+$/, '')}kb`;
}

/**
 * Decoded payload for an inspectable frame. The `details` field is meant for
 * `console.debug`-level inspection (browsers hide debug logs unless the
 * "Verbose" log level is enabled, so this is opt-in noise).
 *
 * Lazy: `details` is a getter so we only pay the decode cost (e.g. building
 * a Resource from a loro snapshot) when the user actually expands the group.
 */
export interface FrameDebugInfo {
  headline: string;
  details?: () => unknown;
}

/**
 * A human-readable headline for a binary frame plus a lazy `details`
 * function for inspecting the frame's payload contents (subject, decoded
 * fields, snapshot byte length, etc.), for the `ws-debug` console log. UPDATE frames also expose the raw
 * loro snapshot bytes so callers that want to materialize the resource
 * (e.g. to show the contained propvals) can do so without re-decoding.
 */
export function debugFrameInfo(
  data: Uint8Array,
  direction: '→' | '←',
): FrameDebugInfo {
  if (data.length === 0) return { headline: `${direction} (empty)` };

  const tag = data[0];
  const name = TAG_NAMES[tag] ?? `0x${tag.toString(16)}`;
  const payload = data.subarray(1);

  switch (tag) {
    case Tag.AUTH:
      return {
        headline: `${direction} AUTH (${formatBytes(payload.length)})`,
        details: () => ({ payloadBytes: payload.length }),
      };

    case Tag.AUTH_OK:
      return { headline: `${direction} AUTH_OK` };

    case Tag.ERROR: {
      const msg = decodeError(payload);

      return {
        headline: msg
          ? `${direction} ERROR #${msg.requestId}: ${msg.message}`
          : `${direction} ERROR (${formatBytes(payload.length)})`,
        details: () => msg ?? { rawBytes: payload.length },
      };
    }

    case Tag.GET: {
      const msg = decodeGet(payload);

      return {
        headline: msg
          ? `${direction} GET #${msg.requestId} ${msg.subject}`
          : `${direction} GET (${formatBytes(payload.length)})`,
        details: () => msg ?? { rawBytes: payload.length },
      };
    }

    case Tag.GET_MANY: {
      const msg = decodeGetMany(payload);

      return {
        headline: msg
          ? `${direction} GET_MANY #${msg.requestId} (${msg.subjects.length} subjects)`
          : `${direction} GET_MANY (${formatBytes(payload.length)})`,
        details: () => msg ?? { rawBytes: payload.length },
      };
    }

    case Tag.GET_MANY_RESULT: {
      const msg = decodeGetManyResult(payload);

      return {
        headline: msg
          ? `${direction} GET_MANY_RESULT #${msg.requestId} (${msg.frames.length} entries, ${formatBytes(payload.length)})`
          : `${direction} GET_MANY_RESULT (${formatBytes(payload.length)})`,
        details: () =>
          msg
            ? {
                requestId: msg.requestId,
                entries: msg.frames.map(f => TAG_NAMES[f[0]] ?? f[0]),
              }
            : { rawBytes: payload.length },
      };
    }

    case Tag.COMMIT:

    case Tag.COMMIT_OK: {
      const msg = decodeCommit(payload);

      return {
        headline: msg
          ? `${direction} ${name} #${msg.requestId} (${formatBytes(msg.commitJson.length)})`
          : `${direction} ${name} (${formatBytes(payload.length)})`,
        details: () => msg ?? { rawBytes: payload.length },
      };
    }

    case Tag.UPDATE: {
      const msg = decodeUpdate(payload);

      if (!msg) {
        return {
          headline: `${direction} UPDATE (${formatBytes(payload.length)})`,
          details: () => ({ rawBytes: payload.length }),
        };
      }

      const flags: string[] = [];

      if (msg.flags & Flags.SNAPSHOT) flags.push('snapshot');
      if (msg.flags & Flags.PUSH) flags.push('push');
      if (msg.commitId) flags.push(`commit=${msg.commitId.slice(0, 20)}…`);

      return {
        headline: `${direction} UPDATE ${msg.subject} [${flags.join(', ')}] (${formatBytes(msg.loroBytes.length)})`,
        details: () => ({
          subject: msg.subject,
          flags: msg.flags,
          flagNames: flags,
          commitId: msg.commitId,
          loroBytes: msg.loroBytes.length,
          loroSnapshot: msg.loroBytes,
        }),
      };
    }

    case Tag.DESTROY: {
      const subject = decoder.decode(payload.subarray(2));

      return {
        headline: `${direction} DESTROY ${subject}`,
        details: () => ({ subject }),
      };
    }

    case Tag.SUB:

    case Tag.UNSUB: {
      const subject = decoder.decode(payload);

      return {
        headline: `${direction} ${name} ${subject}`,
        details: () => ({ subject }),
      };
    }

    case Tag.SYNC_OK: {
      const msg = decodeSyncOk(payload);

      return {
        headline: `${direction} SYNC_OK ${msg?.drive ?? ''}`,
        details: () => msg ?? { rawBytes: payload.length },
      };
    }

    case Tag.SYNC_DIFF: {
      const msg = decodeSyncDiff(payload);

      return {
        headline: msg
          ? `${direction} SYNC_DIFF ${msg.drive} (pull=${msg.pull.length}, push=${msg.push.length})`
          : `${direction} SYNC_DIFF (${formatBytes(payload.length)})`,
        details: () => msg ?? { rawBytes: payload.length },
      };
    }

    case Tag.SYNC_PUSH: {
      const msg = decodeSyncPush(payload);

      return {
        headline: msg
          ? `${direction} SYNC_PUSH ${msg.drive} (${msg.entries.length} resources${msg.last ? ', last' : ''}, ${formatBytes(payload.length)})`
          : `${direction} SYNC_PUSH (${formatBytes(payload.length)})`,
        details: () => msg ?? { rawBytes: payload.length },
      };
    }

    case Tag.BLOB_REQUEST:
      return {
        headline: `${direction} BLOB_REQUEST (${formatBytes(payload.length)})`,
        details: () => ({ rawBytes: payload.length }),
      };

    case Tag.BLOB_RESPONSE:
      return {
        headline: `${direction} BLOB_RESPONSE (${formatBytes(payload.length)})`,
        details: () => ({ rawBytes: payload.length }),
      };

    default:
      return {
        headline: `${direction} ${name} (${formatBytes(payload.length)})`,
        details: () => ({ tag, rawBytes: payload.length }),
      };
  }
}
