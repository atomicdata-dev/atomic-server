/**
 * Finding a drive's nodes through pkarr, from a browser.
 *
 * Every node that serves a drive publishes a small signed DNS packet to a
 * pkarr relay, keyed by a keypair anyone can derive from the drive's DID
 * (the Rust side is `lib/src/discovery.rs`). The packet holds two TXT
 * records, each a JSON array of strings:
 *
 *   `_atomic_nodes`  Iroh NodeIDs, for peers that speak Iroh.
 *   `_atomic_http`   http(s) origins, for clients like this one.
 *
 * So a link that names the drive is enough to find somewhere to fetch from:
 * derive the key, ask the relay, take an origin. The relay is plain HTTPS
 * with CORS, no library needed. The signature is checked here, so a relay
 * cannot hand back a record it did not get from someone holding the derived
 * key. That key is public by design; trust in the data itself comes from
 * commit signatures, not from who announced the node.
 */
import { sha512 } from '@noble/hashes/sha2.js';
import { getPublicKeyAsync, hashes, verifyAsync } from '@noble/ed25519';
import { decodeB64 } from './base64.js';

hashes.sha512 = sha512;

/** The relay both the server and the desktop app use. */
export const DEFAULT_PKARR_RELAY = 'https://dns.iroh.link/pkarr';

const NODES_RECORD = '_atomic_nodes';
const HTTP_RECORD = '_atomic_http';

/** What the drive's pkarr record says, verified. */
export interface DriveRecord {
  /** Iroh NodeIDs serving the drive. */
  nodeIds: string[];
  /** http(s) origins serving the drive. */
  origins: string[];
}

/**
 * The pkarr public key for a drive, as the relay path segment (z-base-32).
 *
 * A drive's `did:ad:<sig>` carries its 64-byte genesis signature; the first
 * 32 bytes seed an ed25519 keypair. Same derivation as the Rust
 * `drive_did_to_pkarr_keypair`, so a browser finds what a server published.
 */
export async function pkarrKeyForDrive(driveDid: string): Promise<string> {
  const seed = pkarrSeedForDrive(driveDid);
  const publicKey = await getPublicKeyAsync(seed);

  return z32Encode(publicKey);
}

function pkarrSeedForDrive(driveDid: string): Uint8Array {
  if (!driveDid.startsWith('did:ad:')) {
    throw new Error(`Not a did:ad DID: ${driveDid}`);
  }

  const raw = driveDid.slice('did:ad:'.length);

  if (raw.startsWith('agent:') || raw.startsWith('commit:')) {
    throw new Error(`Not a drive DID: ${driveDid}`);
  }

  const genesis = raw.split('?')[0];
  const sig = decodeB64(genesis);

  if (sig.length !== 64) {
    throw new Error(
      `Expected a 64-byte genesis signature, got ${sig.length} bytes`,
    );
  }

  return sig.slice(0, 32);
}

/**
 * Read and verify a drive's record from the relay. Resolves to `undefined`
 * when nothing was published for the drive.
 */
export async function resolveDriveRecord(
  driveDid: string,
  relay: string = DEFAULT_PKARR_RELAY,
  fetchFn: typeof fetch = fetch,
): Promise<DriveRecord | undefined> {
  const seed = pkarrSeedForDrive(driveDid);
  const publicKey = await getPublicKeyAsync(seed);
  const response = await fetchFn(
    `${relay.replace(/\/$/, '')}/${z32Encode(publicKey)}`,
  );

  if (response.status === 404) {
    return undefined;
  }

  if (!response.ok) {
    throw new Error(`pkarr relay answered ${response.status}`);
  }

  const payload = new Uint8Array(await response.arrayBuffer());
  const records = await parseSignedPacket(publicKey, payload);

  return {
    nodeIds: jsonList(records, NODES_RECORD),
    origins: jsonList(records, HTTP_RECORD),
  };
}

/** The http(s) origins a drive can be fetched from, in published order. */
export async function resolveDriveOrigins(
  driveDid: string,
  relay: string = DEFAULT_PKARR_RELAY,
  fetchFn: typeof fetch = fetch,
): Promise<string[]> {
  const record = await resolveDriveRecord(driveDid, relay, fetchFn);

  return record?.origins ?? [];
}

function jsonList(records: TxtRecord[], name: string): string[] {
  for (const record of records) {
    if (!record.name.includes(name)) continue;

    try {
      const parsed: unknown = JSON.parse(record.text);

      if (
        Array.isArray(parsed) &&
        parsed.every(item => typeof item === 'string')
      ) {
        return parsed as string[];
      }
    } catch {
      // Not ours; the next record may be.
    }
  }

  return [];
}

// --- z-base-32, the alphabet pkarr keys are written in -------------------

const Z32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769';

/** z-base-32 encoding, as used for pkarr public keys. */
export function z32Encode(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      out += Z32_ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    out += Z32_ALPHABET[(buffer << (5 - bits)) & 31];
  }

  return out;
}

// --- The relay payload: signature, timestamp, DNS packet ------------------

export interface TxtRecord {
  name: string;
  text: string;
}

/**
 * Parse a relay payload, `<64 bytes signature><8 bytes timestamp><DNS
 * packet>`, and verify the signature under `publicKey`. Returns the TXT
 * records in the packet.
 */
export async function parseSignedPacket(
  publicKey: Uint8Array,
  payload: Uint8Array,
): Promise<TxtRecord[]> {
  if (payload.length < 72) {
    throw new Error('pkarr payload too short');
  }

  const signature = payload.slice(0, 64);
  const timestamp = new DataView(
    payload.buffer,
    payload.byteOffset + 64,
    8,
  ).getBigUint64(0);
  const packet = payload.slice(72);

  const valid = await verifyAsync(
    signature,
    signable(timestamp, packet),
    publicKey,
  );

  if (!valid) {
    throw new Error('pkarr record signature does not match the drive key');
  }

  return txtRecordsOf(packet);
}

/** The bytes pkarr signs: a bencoded `seq` and `v`, as in BEP 44. */
export function signable(timestamp: bigint, packet: Uint8Array): Uint8Array {
  const head = new TextEncoder().encode(
    `3:seqi${timestamp.toString()}e1:v${packet.length}:`,
  );
  const out = new Uint8Array(head.length + packet.length);
  out.set(head);
  out.set(packet, head.length);

  return out;
}

const TYPE_TXT = 16;

/** The TXT records in a DNS packet's answer section. */
export function txtRecordsOf(packet: Uint8Array): TxtRecord[] {
  const view = new DataView(packet.buffer, packet.byteOffset, packet.length);
  const questions = view.getUint16(4);
  const answers = view.getUint16(6);
  let offset = 12;
  const records: TxtRecord[] = [];

  for (let i = 0; i < questions; i++) {
    offset = readName(packet, offset).next + 4;
  }

  for (let i = 0; i < answers; i++) {
    const name = readName(packet, offset);
    offset = name.next;
    const type = view.getUint16(offset);
    const length = view.getUint16(offset + 8);
    const dataStart = offset + 10;
    offset = dataStart + length;

    if (type !== TYPE_TXT) continue;

    let text = '';
    let cursor = dataStart;

    while (cursor < dataStart + length) {
      const size = packet[cursor];
      text += new TextDecoder().decode(
        packet.slice(cursor + 1, cursor + 1 + size),
      );
      cursor += 1 + size;
    }

    records.push({ name: name.value, text });
  }

  return records;
}

/** A DNS name at `offset`, following compression pointers. */
function readName(
  packet: Uint8Array,
  offset: number,
): { value: string; next: number } {
  const labels: string[] = [];
  let cursor = offset;
  let next: number | undefined;
  let hops = 0;

  for (;;) {
    const size = packet[cursor];

    if (size === 0) {
      cursor += 1;
      break;
    }

    if ((size & 0xc0) === 0xc0) {
      if (hops++ > 16) throw new Error('DNS name pointer loop');

      const pointer = ((size & 0x3f) << 8) | packet[cursor + 1];
      next ??= cursor + 2;
      cursor = pointer;
      continue;
    }

    labels.push(new TextDecoder().decode(packet.slice(cursor + 1, cursor + 1 + size)));
    cursor += 1 + size;
  }

  return { value: labels.join('.'), next: next ?? cursor };
}
