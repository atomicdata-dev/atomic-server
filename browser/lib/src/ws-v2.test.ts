import { describe, it } from 'vitest';
import { decodeError, ErrorCode, Tag } from './ws-v2.js';

function frame(requestId: number, code: number, message: string): Uint8Array {
  const messageBytes = new TextEncoder().encode(message);
  const buf = new Uint8Array(5 + messageBytes.length);
  buf[0] = Tag.ERROR;
  buf[1] = (requestId >> 8) & 0xff;
  buf[2] = requestId & 0xff;
  buf[3] = (code >> 8) & 0xff;
  buf[4] = code & 0xff;
  buf.set(messageBytes, 5);

  return buf;
}

describe('decodeError (F5: planning/unified-sync.md)', () => {
  it('decodes requestId, code, and message', ({ expect }) => {
    const encoded = frame(42, ErrorCode.UNAUTHORIZED_WRITE, 'No write right');
    // decodeError receives the payload AFTER the tag byte, matching how
    // `handleBinary` slices frames in websockets.ts.
    const decoded = decodeError(encoded.subarray(1));

    expect(decoded).toEqual({
      requestId: 42,
      code: ErrorCode.UNAUTHORIZED_WRITE,
      message: 'No write right',
    });
  });

  it('decodes an UNKNOWN code the same way as any other', ({ expect }) => {
    const encoded = frame(1, ErrorCode.UNKNOWN, 'Invalid GET frame');
    const decoded = decodeError(encoded.subarray(1));

    expect(decoded?.code).toBe(ErrorCode.UNKNOWN);
    expect(decoded?.message).toBe('Invalid GET frame');
  });

  it('returns undefined for a too-short payload', ({ expect }) => {
    // Below the [requestId: u16][code: u16] minimum (4 bytes).
    expect(decodeError(new Uint8Array([0, 1, 0]))).toBeUndefined();
  });
});

// ---- Cross-implementation golden vectors ----
//
// `protocol_vectors.json` is written by the Rust codec
// (`cargo test -p atomic_lib print_wire_vectors -- --ignored --nocapture`)
// into `lib/src/sync/protocol_vectors.json`; the copy next to this file is
// what CI's browser-only container can reach, and a Rust test
// (`wire_vectors::browser_copy_is_identical`) fails when the two drift.
// Every frame this codec can encode must come out byte-identical; every
// frame it decodes must yield the recorded fields. A failure here means the
// two implementations drifted: fix the codec, or regenerate the vectors
// deliberately (both copies) and update `docs/src/websockets.md` in the same
// change.

import { readFileSync } from 'node:fs';
import {
  decodeAuthOk,
  decodeChallenge,
  decodeCommit,
  decodeCommitOk,
  decodeHelloCaps,
  encodeAuthOk,
  encodeChallenge,
  encodeCommitOk,
  encodeCommitOkSlim,
  encodeError,
  encodeHello,
  decodeGet,
  decodeSubject,
  decodeSyncDiff,
  decodeSyncOk,
  decodeSyncResend,
  encodeSyncResend,
  decodeEphemeral,
  encodeEphemeral,
  EphemeralKind,
  decodeSyncPush,
  decodeUpdate,
  decodeBlobRequest,
  decodeBlobResponse,
  encodeBlobRequest,
  encodeBlobResponse,
  encodeCommit,
  encodeGet,
  encodeKeepalive,
  encodeSub,
  encodeSync,
  encodeSyncPush,
  encodeUnsub,
  Flags,
} from './ws-v2.js';

const vectors: Record<string, Uint8Array> = Object.fromEntries(
  (
    JSON.parse(
      readFileSync(new URL('./protocol_vectors.json', import.meta.url), 'utf8'),
    ).vectors as Array<{ name: string; hex: string }>
  ).map(v => [v.name, hexToBytes(v.hex)]),
);

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);

  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  return out;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

const payload = (name: string) => vectors[name].subarray(1);

describe('wire vectors shared with lib/src/sync/protocol.rs', () => {
  it('has the frames this codec is tested against', ({ expect }) => {
    for (const name of [
      'auth_ok_caps',
      'error',
      'get',
      'update_delta_push',
      'destroy',
      'commit',
      'commit_ok',
      'sub',
      'unsub',
      'sync',
      'sync_ok',
      'sync_diff',
      'sync_push_last',
      'blob_request',
      'blob_response',
      'keepalive',
      'commit_ok_slim',
      'challenge',
      'sync_probe',
      'sync_filtered',
      'sync_resend',
      'hello_caps',
      'hello_bare',
      'ephemeral_presence',
    ]) {
      expect(vectors[name], name).toBeDefined();
    }
  });

  it('encodes byte-identically to Rust', ({ expect }) => {
    expect(toHex(encodeGet(1, 'did:ad:x'))).toBe(toHex(vectors.get));
    expect(toHex(encodeCommit(9, '{"a":1}'))).toBe(toHex(vectors.commit));
    expect(toHex(encodeSub('did:ad:d'))).toBe(toHex(vectors.sub));
    expect(toHex(encodeUnsub('did:ad:d'))).toBe(toHex(vectors.unsub));
    expect(toHex(encodeKeepalive())).toBe(toHex(vectors.keepalive));
    expect(toHex(encodeHello('Dev 🚀', ['keepalive']))).toBe(
      toHex(vectors.hello_caps),
    );
    expect(toHex(encodeHello('Dev', []))).toBe(toHex(vectors.hello_bare));
    expect(toHex(encodeChallenge('0badf00d'))).toBe(toHex(vectors.challenge));
    expect(toHex(encodeSyncResend('did:ad:d'))).toBe(
      toHex(vectors.sync_resend),
    );
    expect(decodeSyncResend(payload('sync_resend'))).toBe('did:ad:d');
    expect(toHex(encodeAuthOk(['keepalive', 'unsub']))).toBe(
      toHex(vectors.auth_ok_caps),
    );
    expect(toHex(encodeAuthOk([]))).toBe(toHex(vectors.auth_ok_bare));
    expect(
      toHex(
        encodeError(
          7,
          ErrorCode.UNAUTHORIZED_READ,
          'SUB refused for did:ad:d: no',
        ),
      ),
    ).toBe(toHex(vectors.error));
    expect(toHex(encodeCommitOk(9, '{"a":1}'))).toBe(toHex(vectors.commit_ok));
    expect(toHex(encodeCommitOkSlim(9, 'did:ad:commit:abc'))).toBe(
      toHex(vectors.commit_ok_slim),
    );
    expect(decodeHelloCaps(payload('hello_caps'))).toEqual(['keepalive']);
    expect(decodeHelloCaps(payload('hello_bare'))).toEqual([]);
    expect(toHex(encodeBlobRequest(new Uint8Array(32).fill(0xab)))).toBe(
      toHex(vectors.blob_request),
    );
    expect(
      toHex(
        encodeBlobResponse(
          new Uint8Array(32).fill(0xab),
          new Uint8Array([9, 9]),
        ),
      ),
    ).toBe(toHex(vectors.blob_response));
    expect(
      toHex(
        encodeSyncPush(
          'did:ad:d',
          [{ subject: 'did:ad:x', loroBytes: new Uint8Array([1, 2]) }],
          true,
        ),
      ),
    ).toBe(toHex(vectors.sync_push_last));
  });

  it('encodes SYNC with the length-prefixed hex hash Rust decodes', ({
    expect,
  }) => {
    // The JSON tail is whatever Rust serialised; take it from the vector so
    // this pins the framing (drive, hash_len, hash) and not key ordering.
    const syncFrame = vectors.sync;
    const driveLen = (syncFrame[1] << 8) | syncFrame[2];
    const hashOff = 3 + driveLen;
    const hashLen = (syncFrame[hashOff] << 8) | syncFrame[hashOff + 1];
    const jsonOff = hashOff + 2 + hashLen;
    const vvJson = new TextDecoder().decode(syncFrame.subarray(jsonOff));

    expect(new TextDecoder().decode(syncFrame.subarray(3, 3 + driveLen))).toBe(
      'did:ad:d',
    );
    expect(
      new TextDecoder().decode(syncFrame.subarray(hashOff + 2, jsonOff)),
    ).toBe('abc123');
    expect(toHex(encodeSync('did:ad:d', 'abc123', vvJson))).toBe(
      toHex(syncFrame),
    );

    // The probe and the filtered form are the same framing with a richer
    // JSON tail; the browser builds that tail itself.
    for (const name of ['sync_probe', 'sync_filtered']) {
      const rich = vectors[name];
      const dl = (rich[1] << 8) | rich[2];
      const ho = 3 + dl;
      const hl = (rich[ho] << 8) | rich[ho + 1];
      const tail = new TextDecoder().decode(rich.subarray(ho + 2 + hl));
      expect(toHex(encodeSync('did:ad:d', 'abc123', tail))).toBe(toHex(rich));
      const json = JSON.parse(tail) as { probe?: boolean; subjects?: string[] };
      if (name === 'sync_probe') expect(json.probe).toBe(true);
      else expect(json.subjects).toEqual(['did:ad:x']);
    }
  });

  it('decodes the recorded frames', ({ expect }) => {
    expect(decodeAuthOk(payload('auth_ok_caps'))).toEqual([
      'keepalive',
      'unsub',
    ]);
    expect(decodeAuthOk(payload('auth_ok_bare'))).toEqual([]);

    expect(decodeError(payload('error'))).toEqual({
      requestId: 7,
      code: ErrorCode.UNAUTHORIZED_READ,
      message: 'SUB refused for did:ad:d: no',
    });

    expect(decodeGet(payload('get'))).toEqual({
      requestId: 1,
      subject: 'did:ad:x',
    });

    const update = decodeUpdate(payload('update_delta_push'));
    expect(update?.flags).toBe(Flags.HAS_COMMIT_ID | Flags.PUSH);
    expect(update?.subject).toBe('did:ad:x');
    expect(update?.commitId).toBe('did:ad:commit:abc');
    expect([...(update?.loroBytes ?? [])]).toEqual([1, 2, 3]);

    const snapshot = decodeUpdate(payload('update_snapshot'));
    expect(snapshot?.flags).toBe(Flags.SNAPSHOT);
    expect(snapshot?.requestId).toBe(5);
    expect(snapshot?.commitId).toBeUndefined();

    // DESTROY: [request_id: u16] [subject]; `handleBinary` skips the id.
    expect(decodeSubject(payload('destroy').subarray(2))).toBe('did:ad:x');

    expect(decodeCommit(payload('commit_ok'))).toEqual({
      requestId: 9,
      commitJson: '{"a":1}',
    });

    // Both COMMIT_OK forms decode to the same shape; the legacy vector has no
    // `@id`, which is a malformed ack rather than an id-less one.
    expect(decodeCommitOk(payload('commit_ok'))).toBeUndefined();
    expect(decodeCommitOk(payload('commit_ok_slim'))).toEqual({
      requestId: 9,
      commitId: 'did:ad:commit:abc',
    });
    const legacy = new TextEncoder().encode(
      '{"@id":"did:ad:commit:full","https://atomicdata.dev/properties/signature":"s"}',
    );
    const legacyFrame = new Uint8Array(2 + legacy.length);
    legacyFrame[1] = 9;
    legacyFrame.set(legacy, 2);
    expect(decodeCommitOk(legacyFrame)).toEqual({
      requestId: 9,
      commitId: 'did:ad:commit:full',
      commitJson: new TextDecoder().decode(legacy),
    });

    expect(decodeChallenge(payload('challenge'))).toBe('0badf00d');
    expect(decodeChallenge(new Uint8Array(0))).toBeUndefined();

    expect(decodeSyncOk(payload('sync_ok'))).toEqual({ drive: 'did:ad:d' });

    expect(decodeSyncDiff(payload('sync_diff'))).toEqual({
      drive: 'did:ad:d',
      pull: ['did:ad:y'],
      push: ['did:ad:x'],
      remove: ['did:ad:z'],
      pullFrom: { 'did:ad:y': { p1: 2 } },
      removeCommits: {},
    });

    const push = decodeSyncPush(payload('sync_push_last'));
    expect(push?.drive).toBe('did:ad:d');
    expect(push?.last).toBe(true);
    expect(push?.entries.map(e => e.subject)).toEqual(['did:ad:x']);

    expect([...(decodeBlobRequest(payload('blob_request')) ?? [])]).toEqual(
      new Array(32).fill(0xab),
    );
    const blob = decodeBlobResponse(payload('blob_response'));
    expect([...(blob?.bytes ?? [])]).toEqual([9, 9]);
  });

  it('EPHEMERAL round-trips and matches the recorded frame', ({ expect }) => {
    const eph = decodeEphemeral(payload('ephemeral_presence'));
    expect(eph?.kind).toBe(EphemeralKind.PRESENCE);
    expect(eph?.subject).toBe('did:ad:d');
    expect(eph?.agent).toBe('did:ad:agent:a');
    expect([...(eph?.payload ?? [])]).toEqual([7]);
    expect(
      toHex(
        encodeEphemeral(
          EphemeralKind.PRESENCE,
          'did:ad:d',
          'did:ad:agent:a',
          new Uint8Array([7]),
        ),
      ),
    ).toBe(toHex(vectors.ephemeral_presence));

    // A client frame leaves the agent empty; the server stamps it.
    const mine = encodeEphemeral(
      EphemeralKind.DOC,
      'did:ad:doc',
      '',
      new Uint8Array([1, 2, 3]),
    );
    expect(decodeEphemeral(mine.subarray(1))).toEqual({
      kind: EphemeralKind.DOC,
      subject: 'did:ad:doc',
      agent: '',
      payload: new Uint8Array([1, 2, 3]),
    });
    expect(decodeEphemeral(mine.subarray(1, 6))).toBeUndefined();
  });
});
