import { describe, expect, it } from 'vitest';
import { signAsync, getPublicKeyAsync } from '@noble/ed25519';
import { encodeB64Url } from './base64.js';
import {
  parseSignedPacket,
  pkarrKeyForDrive,
  resolveDriveOrigins,
  resolveDriveRecord,
  signable,
  txtRecordsOf,
  z32Encode,
} from './pkarr.js';

/** A drive DID whose genesis signature is 64 bytes of `byte`. */
const fakeDrive = (byte: number): string =>
  `did:ad:${encodeB64Url(new Uint8Array(64).fill(byte))}`;

/** A DNS packet with one TXT answer, the way pkarr builds it. */
function txtPacket(name: string, text: string): Uint8Array {
  const encoder = new TextEncoder();
  const out: number[] = [0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];

  for (const label of name.split('.')) {
    const bytes = encoder.encode(label);
    out.push(bytes.length, ...bytes);
  }

  out.push(0);
  out.push(0, 16, 0, 1, 0, 0, 1, 0x2c);

  const textBytes = encoder.encode(text);
  const chunks: number[] = [];

  for (let i = 0; i < textBytes.length; i += 255) {
    const chunk = textBytes.slice(i, i + 255);
    chunks.push(chunk.length, ...chunk);
  }

  out.push(chunks.length >> 8, chunks.length & 0xff, ...chunks);

  return new Uint8Array(out);
}

async function relayPayload(
  seed: Uint8Array,
  packet: Uint8Array,
  timestamp = 1_700_000_000_000_000n,
): Promise<Uint8Array> {
  const signature = await signAsync(signable(timestamp, packet), seed);
  const out = new Uint8Array(72 + packet.length);
  out.set(signature);
  new DataView(out.buffer).setBigUint64(64, timestamp);
  out.set(packet, 72);

  return out;
}

describe('pkarr', () => {
  it('derives the same relay key as the Rust side', async () => {
    // Pinned in `lib/src/discovery.rs`, `keypair_matches_browser_vector`.
    expect(await pkarrKeyForDrive(fakeDrive(0x42))).toBe(
      'rfjxtwc5xrq1etj1emoi6mimp15h96u5pjxpgyrz1a8ypgrb5cjy',
    );
  });

  it('ignores a routing hint on the DID and refuses non-drives', async () => {
    expect(await pkarrKeyForDrive(`${fakeDrive(0x42)}?drive=x`)).toBe(
      await pkarrKeyForDrive(fakeDrive(0x42)),
    );
    await expect(pkarrKeyForDrive('did:ad:agent:abc')).rejects.toThrow();
    await expect(pkarrKeyForDrive('https://example.org/')).rejects.toThrow();
  });

  it('writes z-base-32', () => {
    expect(z32Encode(new Uint8Array([]))).toBe('');
    expect(z32Encode(new Uint8Array([0xff]))).toBe('9h');
    expect(z32Encode(new TextEncoder().encode('hello'))).toBe('pb1sa5dx');
  });

  it('reads TXT records, joining the character strings', () => {
    const long = 'x'.repeat(300);
    const records = txtRecordsOf(txtPacket('_atomic_http', long));

    expect(records).toEqual([{ name: '_atomic_http', text: long }]);
  });

  it('accepts a packet signed with the drive key and rejects a tampered one', async () => {
    const seed = new Uint8Array(32).fill(7);
    const publicKey = await getPublicKeyAsync(seed);
    const packet = txtPacket('_atomic_nodes', '["n1"]');
    const payload = await relayPayload(seed, packet);

    expect(await parseSignedPacket(publicKey, payload)).toEqual([
      { name: '_atomic_nodes', text: '["n1"]' },
    ]);

    const tampered = payload.slice();
    tampered[tampered.length - 3] ^= 1;
    await expect(parseSignedPacket(publicKey, tampered)).rejects.toThrow(
      /signature/,
    );
  });

  it('resolves a drive to its origins through the relay', async () => {
    const drive = fakeDrive(0x42);
    const seed = new Uint8Array(64).fill(0x42).slice(0, 32);
    const packet = new Uint8Array([
      ...txtPacket('_atomic_nodes', '["node-a"]'),
    ]);
    // Two answers: splice the second record onto the first packet.
    const second = txtPacket('_atomic_http', '["https://a.example.org","http://localhost:9883"]');
    const combined = new Uint8Array(packet.length + second.length - 12);
    combined.set(packet);
    combined.set(second.slice(12), packet.length);
    combined[7] = 2;

    const payload = await relayPayload(seed, combined);
    const calls: string[] = [];
    const fetchFn = (async (input: string | URL | Request) => {
      calls.push(String(input));

      return new Response(new Blob([payload as BlobPart]), { status: 200 });
    }) as typeof fetch;

    expect(await resolveDriveRecord(drive, 'https://relay.test/pkarr/', fetchFn)).toEqual({
      nodeIds: ['node-a'],
      origins: ['https://a.example.org', 'http://localhost:9883'],
    });
    expect(calls).toEqual([
      'https://relay.test/pkarr/rfjxtwc5xrq1etj1emoi6mimp15h96u5pjxpgyrz1a8ypgrb5cjy',
    ]);
  });

  it('answers nothing when the relay has no record', async () => {
    const fetchFn = (async () =>
      new Response(null, { status: 404 })) as typeof fetch;

    expect(await resolveDriveOrigins(fakeDrive(1), undefined, fetchFn)).toEqual([]);
  });
});
