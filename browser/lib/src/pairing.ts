/**
 * Device-pairing envelope: the payload behind the `atomic:pair` QR code /
 * deep link (see `planning/device-pairing.md`).
 *
 * **A pairing code is routing only.** It says where to reach a node and which
 * drives to sync; it grants nothing. The dialed peer still has to prove it
 * holds the same agent key over AUTH before a single resource crosses. So the
 * code is safe to show on screen, print, or paste — and a tampered one can at
 * worst make a device dial a stranger who then fails AUTH.
 *
 * Wire form is a plain, readable URI:
 *
 *     atomic:pair?v=1&node=did:ad:node:<64 hex>&drives=*
 *
 * `atomic:` is the transport and `did:ad:node:` is the identity — they nest
 * rather than compete, so a node is written the same way here as everywhere
 * else. No `//`: there is no authority part, and Atomic's other identifiers
 * (`did:ad:…`) have none either. The scheme has to be one the app registers, because a QR scanned by
 * the system camera must launch it; `did:` can't serve that role (iOS
 * registers bare schemes, so claiming `did` would claim `did:key` and
 * `did:web` too). And a bare DID has nowhere to carry `drives` — the field
 * that tells a freshly signed-in device *which* drive to pull.
 *
 * Multi-drive envelopes repeat the parameter: `&drives=a&drives=b`.
 *
 * A code never carries an agent secret. It cannot: the private key is stored
 * non-extractable (`helpers/agentStorage.ts`), so no device can read its own
 * secret back out to put in a QR. A code that claims to carry one is refused
 * rather than imported — otherwise any link or poster could hand a fresh
 * install an attacker's identity, and everything written on it would sync to
 * the attacker. Provisioning an identity to a new device belongs on the
 * authenticated Iroh channel, behind an on-screen confirm; a new device signs
 * in by entering its secret.
 */
export type PairingEnvelope = {
  v: 1;
  /** Iroh node identity of the issuing device: `did:ad:node:<64 hex>`. */
  node: string;
  /** Optional http(s) fast path (LAN/WS) — a routing hint, never identity. */
  url?: string;
  /** Which drives this pairing syncs. `"*"` = all of the agent's drives. */
  drives: '*' | string[];
};

export const PAIRING_URI_PREFIX = 'atomic:pair?';

/**
 * The form codes were minted in before the double slash was dropped. Still
 * accepted on decode, never produced: a QR printed last month must keep
 * working.
 */
const LEGACY_PAIRING_URI_PREFIX = 'atomic://pair?';

const NODE_DID_PREFIX = 'did:ad:node:';

/**
 * Why decoding failed. `unsupported-version` deserves its own UI ("update the
 * app") — per the plan, an unknown `v` must never be best-effort parsed.
 */
export class PairingEnvelopeError extends Error {
  public constructor(
    public readonly code: 'unsupported-version' | 'malformed',
    message: string,
  ) {
    super(message);
    this.name = 'PairingEnvelopeError';
  }
}

function isValidNodeDid(value: unknown): value is string {
  if (typeof value !== 'string' || !value.startsWith(NODE_DID_PREFIX)) {
    return false;
  }

  const raw = value.slice(NODE_DID_PREFIX.length);

  return /^[0-9a-f]{64}$/i.test(raw);
}

function isValidUrl(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }

  try {
    const parsed = new URL(value);

    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function isValidDrives(value: unknown): value is '*' | string[] {
  if (value === '*') {
    return true;
  }

  return (
    Array.isArray(value) &&
    value.length > 0 &&
    // `*` means *all* drives; listing it alongside named ones is a
    // contradiction, not a drive whose subject happens to be an asterisk.
    value.every(
      entry => typeof entry === 'string' && entry.length > 0 && entry !== '*',
    )
  );
}

/** Throws {@link PairingEnvelopeError} unless every field is well-formed. */
function assertValid(envelope: PairingEnvelope): PairingEnvelope {
  if (envelope.v !== 1) {
    throw new PairingEnvelopeError(
      'unsupported-version',
      'This pairing code was made by a newer version of Atomic — update this app to use it.',
    );
  }

  if (!isValidNodeDid(envelope.node)) {
    throw new PairingEnvelopeError(
      'malformed',
      'Pairing code carries an invalid node identity.',
    );
  }

  if (envelope.url !== undefined && !isValidUrl(envelope.url)) {
    throw new PairingEnvelopeError(
      'malformed',
      'Pairing code carries an invalid server URL.',
    );
  }

  if (!isValidDrives(envelope.drives)) {
    throw new PairingEnvelopeError(
      'malformed',
      'Pairing code does not say which drives to sync.',
    );
  }

  return envelope;
}

/**
 * Percent-encode a query value, but leave `:` and `*` alone. Both are legal in
 * a query per RFC 3986, and keeping them literal is the whole point: an
 * escaped `did%3Aad%3Anode%3A…` would be no more readable than the base64 blob
 * this format replaced.
 */
function encodeValue(value: string): string {
  return encodeURIComponent(value).replace(/%3A/gi, ':').replace(/%2A/gi, '*');
}

/** Serialize an envelope into its `atomic:pair?…` QR / deep-link form. */
export function encodePairingEnvelope(envelope: PairingEnvelope): string {
  // Round-trip through the validator so we can never mint a QR this module
  // would refuse to scan.
  assertValid(envelope);

  const params = [`v=${envelope.v}`, `node=${encodeValue(envelope.node)}`];

  if (envelope.url !== undefined) {
    params.push(`url=${encodeURIComponent(envelope.url)}`);
  }

  if (envelope.drives === '*') {
    params.push('drives=*');
  } else {
    for (const drive of envelope.drives) {
      params.push(`drives=${encodeValue(drive)}`);
    }
  }

  return `${PAIRING_URI_PREFIX}${params.join('&')}`;
}

/**
 * Parse and strictly validate a scanned/pasted pairing code. Accepts the full
 * `atomic:pair?…` URI (or the older `atomic://pair?…`), or a bare `did:ad:node:…` (routing-only, all drives)
 * for someone who copied just the node identity. Throws
 * {@link PairingEnvelopeError} — check `code === 'unsupported-version'` to
 * show an "update the app" message instead of a generic scan error.
 */
export function decodePairingEnvelope(input: string): PairingEnvelope {
  const trimmed = input.trim();

  if (trimmed.startsWith(NODE_DID_PREFIX)) {
    return assertValid({ v: 1, node: trimmed, drives: '*' });
  }

  const prefix = trimmed.startsWith(PAIRING_URI_PREFIX)
    ? PAIRING_URI_PREFIX
    : trimmed.startsWith(LEGACY_PAIRING_URI_PREFIX)
      ? LEGACY_PAIRING_URI_PREFIX
      : undefined;

  if (prefix === undefined) {
    throw new PairingEnvelopeError(
      'malformed',
      'Not a pairing code: expected an atomic:pair link.',
    );
  }

  const params = new URLSearchParams(trimmed.slice(prefix.length));

  const version = params.get('v');

  // An unknown version must never be best-effort parsed. A missing one is
  // simply not our format.
  if (version !== null && version !== '1') {
    throw new PairingEnvelopeError(
      'unsupported-version',
      'This pairing code was made by a newer version of Atomic — update this app to use it.',
    );
  }

  if (version === null) {
    throw new PairingEnvelopeError('malformed', 'Pairing code has no version.');
  }

  // A pairing code never carries an identity (see the type doc). Refuse the
  // whole code rather than ignoring the field: a device that silently accepted
  // an attacker's secret would sync everything the user then wrote to the
  // attacker's node, and `atomic:` links can be fired by any app or web page
  // — not only by the camera.
  if (params.has('secret')) {
    throw new PairingEnvelopeError(
      'malformed',
      'This code tries to hand over an account. Pairing codes only say where to reach a device — refusing it.',
    );
  }

  const drives = params.getAll('drives');
  const url = params.get('url');

  return assertValid({
    v: 1,
    node: params.get('node') as string,
    ...(url !== null ? { url } : {}),
    drives:
      drives.length === 1 && drives[0] === '*'
        ? '*'
        : (drives as string[] | '*'),
  });
}
