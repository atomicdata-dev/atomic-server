import { afterEach, describe, expect, it, vi } from 'vitest';
import { getPublicKey, hashes, sign } from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { decodeB64 } from './base64.js';
import {
  driveToPkarrKey,
  encodeZ32,
  parsePkarrPacket,
  resolveDriveOrigins,
  toPublicHttpsOrigin,
} from './pkarr.js';

hashes.sha512 = sha512;

// Built by `discovery::tests::print_ts_fixture` in lib/src/discovery.rs: the
// Rust code signs a packet with `_atomic_nodes` and `_atomic_http` records.
// Regenerate with
// `cargo test -p atomic_lib --features db-redb,discovery --lib print_ts_fixture -- --ignored --nocapture`.
const DID =
  'did:ad:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQg';
const Z32 = 'rfjxtwc5xrq1etj1emoi6mimp15h96u5pjxpgyrz1a8ypgrb5cjy';
const RUST_PACKET_HEX =
  '2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db121df8bc2804be2e819cd661180fee39e3' +
  '58e2cc157a94d2199bcb50074fe9ac7532cc2d8d40c6856cb78fe795a9afe300fc8c13208be900090d5521d35849bb04' +
  '00065d7a7dc68ca60000800000000002000000000d5f61746f6d69635f6e6f6465733472666a78747763357872713165' +
  '746a31656d6f69366d696d7031356839367535706a78706779727a316138797067726235636a7900001000010000012c' +
  '0045445b2261616161616161616161616161616161616161616161616161616161616161616161616161616161616161' +
  '616161616161616161616161616161616161616161225d0c5f61746f6d69635f68747470c01a0010000100000e100042' +
  '415b2268747470733a2f2f61746f6d69632e6578616d706c652e636f6d222c2268747470733a2f2f7265706c6963612e' +
  '6578616d706c652e6f72673a38343433225d';

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g)!.map(h => parseInt(h, 16)));
}

const rustPacket = fromHex(RUST_PACKET_HEX);

/** The body a relay serves: the packet without its leading public key. */
const relayBody = (packet: Uint8Array) => packet.slice(32);

function dnsName(labels: string[]): number[] {
  const out: number[] = [];

  for (const label of labels) {
    const bytes = [...new TextEncoder().encode(label)];

    out.push(bytes.length, ...bytes);
  }

  return [...out, 0];
}

/** Build a signed packet in TS: one TXT record per `[label, text]`. */
function buildPacket(
  seed: Uint8Array,
  records: Array<[string, string]>,
  { compress = false } = {},
): Uint8Array {
  const publicKey = getPublicKey(seed);
  const z32 = encodeZ32(publicKey);
  const dns: number[] = [0, 0, 0x84, 0, 0, 0, 0, records.length, 0, 0, 0, 0];

  records.forEach(([label, text], i) => {
    if (compress && i > 0) {
      // Point back at the owner name of the first record's `<z32>` suffix.
      const firstSuffix = 12 + 1 + records[0][0].length;
      const bytes = [...new TextEncoder().encode(label)];

      dns.push(
        bytes.length,
        ...bytes,
        0xc0 | (firstSuffix >> 8),
        firstSuffix & 255,
      );
    } else {
      dns.push(...dnsName([label, z32]));
    }

    const data = [...new TextEncoder().encode(text)];
    const chunks: number[] = [];

    for (let p = 0; p < data.length; p += 255) {
      const part = data.slice(p, p + 255);

      chunks.push(part.length, ...part);
    }

    dns.push(
      0,
      16,
      0,
      1,
      0,
      0,
      1,
      44,
      chunks.length >> 8,
      chunks.length & 255,
      ...chunks,
    );
  });

  const timestamp = new Uint8Array(8);

  new DataView(timestamp.buffer).setBigUint64(0, 1_700_000_000_000_000n);

  const dnsBytes = Uint8Array.from(dns);
  const signable = new TextEncoder().encode(
    `3:seqi${1_700_000_000_000_000n}e1:v${dnsBytes.length}:`,
  );
  const message = new Uint8Array(signable.length + dnsBytes.length);

  message.set(signable);
  message.set(dnsBytes, signable.length);

  const signature = sign(message, seed);

  return Uint8Array.from([
    ...publicKey,
    ...signature,
    ...timestamp,
    ...dnsBytes,
  ]);
}

const seed = new Uint8Array(32).fill(7);
const seedKey = getPublicKey(seed);

describe('driveToPkarrKey', () => {
  it('derives the same z-base-32 key as the Rust code', () => {
    expect(driveToPkarrKey(DID)?.z32).toBe(Z32);
    expect(driveToPkarrKey(DID.replace('did:ad:', 'atomic:'))?.z32).toBe(Z32);
    expect(driveToPkarrKey(`${DID}?drive=https://x.example`)?.z32).toBe(Z32);
  });

  it('uses the first 32 bytes of the genesis signature as the seed', () => {
    const signature = decodeB64(DID.slice('did:ad:'.length));

    expect(driveToPkarrKey(DID)?.publicKey).toEqual(
      getPublicKey(signature.slice(0, 32)),
    );
  });

  it('rejects what is not a drive', () => {
    expect(driveToPkarrKey('did:ad:agent:abc')).toBeUndefined();
    expect(driveToPkarrKey('did:ad:commit:abc')).toBeUndefined();
    expect(driveToPkarrKey('https://example.com/drive')).toBeUndefined();
    expect(driveToPkarrKey('did:ad:tooshort')).toBeUndefined();
  });
});

describe('parsePkarrPacket', () => {
  const key = driveToPkarrKey(DID)!.publicKey;

  it('opens a packet built by the Rust code', () => {
    expect(parsePkarrPacket(rustPacket, key)).toEqual({
      _atomic_nodes: ['aa'.repeat(32)],
      _atomic_http: [
        'https://atomic.example.com',
        'https://replica.example.org:8443',
      ],
    });
  });

  it('opens the relay form without the leading key', () => {
    expect(
      parsePkarrPacket(relayBody(rustPacket), key)?._atomic_http,
    ).toHaveLength(2);
  });

  it('rejects a tampered packet', () => {
    const tampered = rustPacket.slice();

    tampered[tampered.length - 5] ^= 1;
    expect(parsePkarrPacket(tampered, key)).toBeUndefined();
  });

  it('rejects a packet signed by another key', () => {
    const other = buildPacket(seed, [
      ['_atomic_http', '["https://a.example.com"]'],
    ]);

    expect(parsePkarrPacket(other, key)).toBeUndefined();
    expect(parsePkarrPacket(relayBody(other), key)).toBeUndefined();
  });

  it('reads a packet built in TS, with name compression and long TXT values', () => {
    const origins = Array.from(
      { length: 12 },
      (_, i) => `https://node-${i}.example.com`,
    );
    const packet = buildPacket(
      seed,
      [
        ['_atomic_http', JSON.stringify(origins)],
        ['_atomic_nodes', '["bb"]'],
      ],
      { compress: true },
    );

    expect(JSON.stringify(origins).length).toBeGreaterThan(255);
    expect(parsePkarrPacket(packet, seedKey)).toEqual({
      _atomic_http: origins,
      _atomic_nodes: ['bb'],
    });
  });

  it('survives garbage', () => {
    expect(parsePkarrPacket(new Uint8Array(0), key)).toBeUndefined();
    expect(parsePkarrPacket(new Uint8Array(5000), key)).toBeUndefined();
    expect(parsePkarrPacket(new Uint8Array(200).fill(1), key)).toBeUndefined();
  });
});

describe('toPublicHttpsOrigin', () => {
  it('keeps public https origins and drops the rest', () => {
    expect(toPublicHttpsOrigin('https://Atomic.Example.com/path')).toBe(
      'https://atomic.example.com',
    );
    expect(toPublicHttpsOrigin('https://atomic.example.com:8443')).toBe(
      'https://atomic.example.com:8443',
    );

    for (const bad of [
      'http://atomic.example.com',
      'https://localhost',
      'https://foo.localhost',
      'https://127.0.0.1',
      'https://192.168.1.4:9884',
      'https://[::1]',
      'https://intranet',
      'https://printer.local',
      'https://user:pw@atomic.example.com',
      'javascript:alert(1)',
      'not a url',
      42,
      null,
    ]) {
      expect(toPublicHttpsOrigin(bad)).toBeUndefined();
    }
  });
});

describe('resolveDriveOrigins', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('asks the relay under the drive key and returns the https origins', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response(relayBody(rustPacket), { status: 200 }));

    vi.stubGlobal('fetch', fetchMock);

    expect(await resolveDriveOrigins(DID)).toEqual([
      'https://atomic.example.com',
      'https://replica.example.org:8443',
    ]);
    expect(fetchMock.mock.calls[0][0]).toBe(
      `https://dns.iroh.link/pkarr/${Z32}`,
    );
  });

  it('drops origins nobody could reach, even when the signature is fine', async () => {
    const bad = buildPacket(seed, [
      [
        '_atomic_http',
        '["http://a.example.com","https://127.0.0.1","https://ok.example.com"]',
      ],
    ]);
    const did = `did:ad:${Buffer.from([...seed, ...new Uint8Array(32)]).toString('base64url')}`;

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(relayBody(bad), { status: 200 })),
    );

    expect(await resolveDriveOrigins(did)).toEqual(['https://ok.example.com']);
  });

  it('returns [] for a 404, a network error and a non-drive subject', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response('', { status: 404 })),
    );
    expect(await resolveDriveOrigins(DID)).toEqual([]);

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
    expect(await resolveDriveOrigins(DID)).toEqual([]);

    const fetchMock = vi.fn();

    vi.stubGlobal('fetch', fetchMock);
    expect(await resolveDriveOrigins('did:ad:agent:abc')).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('gives up after the timeout instead of hanging', async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise((_resolve, reject) => {
            init.signal?.addEventListener('abort', () =>
              reject(new Error('aborted')),
            );
          }),
      ),
    );

    const pending = resolveDriveOrigins(DID, { timeoutMs: 6000 });

    await vi.advanceTimersByTimeAsync(6001);
    expect(await pending).toEqual([]);
  });
});
