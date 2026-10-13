/**
 * Find where a drive is hosted from its DID alone, through the pkarr relay.
 *
 * Mirror of `lib/src/discovery.rs`: the drive DID's 64-byte genesis signature
 * has its first 32 bytes used as an ed25519 seed. The public key of that
 * keypair, z-base-32 encoded, is the pkarr key. Servers hosting the drive
 * publish a signed DNS packet under it; the `_atomic_http` TXT record holds a
 * JSON array of their public https origins. Anyone who knows the DID can
 * derive the key, so the record is not authority over the data, only a hint
 * about where to look. Commit signatures remain the trust anchor.
 *
 * Browsers cannot dial Iroh (`_atomic_nodes`), but the relay speaks plain
 * https with `access-control-allow-origin: *`, so a tab can read this.
 */
import { sha512 } from '@noble/hashes/sha2.js';
import { getPublicKey, hashes, verify } from '@noble/ed25519';
import { decodeB64 } from './base64.js';
import { identifierBody } from './subject.js';

// Match `genesis.ts`: the synchronous noble API needs sha512 installed.
hashes.sha512 = sha512;

export const PKARR_RELAY_URL = 'https://dns.iroh.link/pkarr';
export const PKARR_HTTP_LABEL = '_atomic_http';
export const PKARR_NODES_LABEL = '_atomic_nodes';

const Z32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769';
/** A pkarr packet is at most 1000 bytes of DNS plus 104 of framing. */
const MAX_PACKET_BYTES = 1104;
const HEADER_BYTES = 104;
const DEFAULT_TIMEOUT_MS = 6_000;

/** z-base-32 without padding, as pkarr writes public keys. */
export function encodeZ32(bytes: Uint8Array): string {
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

    buffer &= (1 << bits) - 1;
  }

  if (bits > 0) {
    out += Z32_ALPHABET[(buffer << (5 - bits)) & 31];
  }

  return out;
}

/**
 * The pkarr keypair of a drive, derived like `drive_did_to_pkarr_keypair`.
 * `undefined` for anything that is not a drive DID (agents, commits, URLs).
 */
export function driveToPkarrKey(
  driveDid: string,
): { publicKey: Uint8Array; z32: string } | undefined {
  const body = identifierBody(driveDid);

  // Agent, commit, blob... identifiers carry a `kind:` prefix; a drive does not.
  if (!body || body.includes(':')) return undefined;

  let signature: Uint8Array;

  try {
    signature = decodeB64(body);
  } catch {
    return undefined;
  }

  if (signature.length !== 64) return undefined;

  const publicKey = getPublicKey(signature.slice(0, 32));

  return { publicKey, z32: encodeZ32(publicKey) };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Normalise an announced origin, or `undefined` when it is not one a stranger
 * could reach: not https, `localhost`, an IP address, a bare single-label or
 * `.local` host. The record is public and writable by anyone who knows the DID,
 * so a client must not be pointed at a LAN address by it.
 */
export function toPublicHttpsOrigin(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;

  let url: URL;

  try {
    url = new URL(raw.trim());
  } catch {
    return undefined;
  }

  if (url.protocol !== 'https:' || url.username || url.password) {
    return undefined;
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '');

  if (
    host.startsWith('[') ||
    /^\d+(\.\d+){3}$/.test(host) ||
    !host.includes('.') ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal')
  ) {
    return undefined;
  }

  return url.origin;
}

/** Read a DNS name starting at `offset`; returns its labels and the offset after it. */
function readName(
  data: Uint8Array,
  offset: number,
): { labels: string[]; next: number } | undefined {
  const labels: string[] = [];
  let pos = offset;
  let next: number | undefined;
  let jumps = 0;

  for (;;) {
    if (pos >= data.length) return undefined;

    const len = data[pos];

    if (len === 0) {
      return { labels, next: next ?? pos + 1 };
    }

    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= data.length || ++jumps > 16) return undefined;

      next ??= pos + 2;
      pos = ((len & 0x3f) << 8) | data[pos + 1];
      continue;
    }

    if (len > 63 || pos + 1 + len > data.length) return undefined;

    labels.push(
      new TextDecoder().decode(data.subarray(pos + 1, pos + 1 + len)),
    );
    pos += 1 + len;
  }
}

/** All TXT records of a DNS message as `{ labels, text }`; malformed input gives `[]`. */
function readTxtRecords(
  dns: Uint8Array,
): Array<{ labels: string[]; text: string }> {
  const view = new DataView(dns.buffer, dns.byteOffset, dns.byteLength);

  if (dns.length < 12) return [];

  const questions = view.getUint16(4);
  const answers = view.getUint16(6);
  let pos = 12;
  const records: Array<{ labels: string[]; text: string }> = [];

  for (let i = 0; i < questions; i++) {
    const name = readName(dns, pos);

    if (!name) return records;

    pos = name.next + 4;
  }

  for (let i = 0; i < answers; i++) {
    const name = readName(dns, pos);

    if (!name || name.next + 10 > dns.length) return records;

    const type = view.getUint16(name.next);
    const rdLength = view.getUint16(name.next + 8);
    const start = name.next + 10;
    const end = start + rdLength;

    if (end > dns.length) return records;

    if (type === 16) {
      const parts: Uint8Array[] = [];
      let p = start;

      while (p < end) {
        const len = dns[p];

        if (p + 1 + len > end) break;

        parts.push(dns.subarray(p + 1, p + 1 + len));
        p += 1 + len;
      }

      const joined = new Uint8Array(
        parts.reduce((n, part) => n + part.length, 0),
      );
      let at = 0;

      for (const part of parts) {
        joined.set(part, at);
        at += part.length;
      }

      records.push({
        labels: name.labels,
        text: new TextDecoder().decode(joined),
      });
    }

    pos = end;
  }

  return records;
}

function signable(timestamp: Uint8Array, dns: Uint8Array): Uint8Array {
  // BEP44 style: `3:seqi<timestamp>e1:v<len>:<dns>`, as `pkarr::signable`.
  const ts = new DataView(
    timestamp.buffer,
    timestamp.byteOffset,
    8,
  ).getBigUint64(0);
  const head = new TextEncoder().encode(`3:seqi${ts}e1:v${dns.length}:`);
  const out = new Uint8Array(head.length + dns.length);

  out.set(head);
  out.set(dns, head.length);

  return out;
}

/**
 * Check and open a pkarr SignedPacket, returning the string lists in its TXT
 * records by label (`_atomic_http`, `_atomic_nodes`). Accepts the full form
 * (`public key, signature, timestamp, DNS`) and the relay's body, which
 * leaves the public key off. The signature is verified against
 * `expectedKey` either way; anything that fails gives `undefined`.
 */
export function parsePkarrPacket(
  bytes: Uint8Array,
  expectedKey: Uint8Array,
): Record<string, string[]> | undefined {
  if (bytes.length > MAX_PACKET_BYTES) return undefined;

  let body = bytes;

  if (
    bytes.length >= HEADER_BYTES &&
    sameBytes(bytes.subarray(0, 32), expectedKey)
  ) {
    body = bytes.subarray(32);
  }

  if (body.length < HEADER_BYTES - 32) return undefined;

  const signature = body.subarray(0, 64);
  const timestamp = body.subarray(64, 72);
  const dns = body.subarray(72);

  try {
    if (!verify(signature, signable(timestamp, dns), expectedKey)) {
      return undefined;
    }
  } catch {
    return undefined;
  }

  const lists: Record<string, string[]> = {};

  for (const { labels, text } of readTxtRecords(dns)) {
    const label = labels[0];

    if (label !== PKARR_HTTP_LABEL && label !== PKARR_NODES_LABEL) continue;

    // Names are `<label>.<z32 key>`; ignore a record filed under another key.
    if (labels.length !== 2 || labels[1] !== encodeZ32(expectedKey)) continue;

    try {
      const parsed: unknown = JSON.parse(text);

      if (Array.isArray(parsed)) {
        lists[label] = parsed.filter((v): v is string => typeof v === 'string');
      }
    } catch {
      // A garbled record is skipped; the others still count.
    }
  }

  return lists;
}

export type ResolveDriveOriginsOptions = {
  timeoutMs?: number;
  relayUrl?: string;
};

/**
 * The public https origins of servers that announced they host `driveDid`,
 * read from the pkarr relay. Never throws and never waits longer than
 * `timeoutMs` (6 s): any failure (offline, unknown drive, bad signature,
 * malformed packet) is `[]`. Unprobed hints only: the caller should check
 * each one is actually a node before using it.
 */
export async function resolveDriveOrigins(
  driveDid: string,
  options: ResolveDriveOriginsOptions = {},
): Promise<string[]> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, relayUrl = PKARR_RELAY_URL } =
    options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const key = driveToPkarrKey(driveDid);

    if (!key) return [];

    const res = await fetch(`${relayUrl}/${key.z32}`, {
      credentials: 'omit',
      signal: controller.signal,
    });

    if (!res.ok) return [];

    const lists = parsePkarrPacket(
      new Uint8Array(await res.arrayBuffer()),
      key.publicKey,
    );
    const origins = new Set<string>();

    for (const raw of lists?.[PKARR_HTTP_LABEL] ?? []) {
      const origin = toPublicHttpsOrigin(raw);

      if (origin) origins.add(origin);
    }

    return [...origins];
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}
