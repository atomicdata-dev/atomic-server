import { describe, expect, it } from 'vitest';
import {
  decodePairingEnvelope,
  encodePairingEnvelope,
  PairingEnvelopeError,
  PAIRING_URI_PREFIX,
  type PairingEnvelope,
} from './pairing.js';

const NODE = `did:ad:node:${'ab'.repeat(32)}`;

const allDrives: PairingEnvelope = {
  v: 1,
  node: NODE,
  url: 'http://192.168.0.153:9883',
  drives: '*',
};

const namedDrives: PairingEnvelope = {
  v: 1,
  node: NODE,
  drives: ['did:ad:drive1', 'did:ad:drive2'],
};

/** Build a URI from raw query params, bypassing the encoder's validation. */
function uriOf(params: Record<string, string | string[] | undefined>): string {
  const parts: string[] = [];

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined) continue;

    for (const entry of Array.isArray(value) ? value : [value]) {
      parts.push(`${key}=${entry}`);
    }
  }

  return `${PAIRING_URI_PREFIX}${parts.join('&')}`;
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof PairingEnvelopeError) {
      return error.code;
    }

    throw error;
  }

  throw new Error('expected the decode to throw');
}

describe('pairing envelope', () => {
  it('round-trips an envelope with a url hint', () => {
    const uri = encodePairingEnvelope(allDrives);
    expect(uri.startsWith(PAIRING_URI_PREFIX)).toBe(true);
    expect(decodePairingEnvelope(uri)).toEqual(allDrives);
  });

  it('round-trips a named-drive envelope', () => {
    expect(decodePairingEnvelope(encodePairingEnvelope(namedDrives))).toEqual(
      namedDrives,
    );
  });

  it('writes the node identity the way the rest of the app writes it', () => {
    // The whole point of the readable form: no base64, no percent-escaped
    // colons. A human reading the copied code sees a did:ad:node: identity.
    expect(encodePairingEnvelope(namedDrives)).toContain(`node=${NODE}`);
  });

  it('repeats the parameter for a multi-drive envelope', () => {
    expect(encodePairingEnvelope(namedDrives)).toContain(
      'drives=did:ad:drive1&drives=did:ad:drive2',
    );
  });

  it('accepts a bare node DID as a code for every drive', () => {
    expect(decodePairingEnvelope(`  ${NODE}  `)).toEqual({
      v: 1,
      node: NODE,
      drives: '*',
    });
  });

  it('round-trips a url hint through percent-encoding', () => {
    const decoded = decodePairingEnvelope(encodePairingEnvelope(allDrives));
    expect(decoded.url).toBe('http://192.168.0.153:9883');
  });

  // A pairing code is routing only. A code carrying an identity must be
  // refused outright, not parsed-and-ignored: any app or web page can fire an
  // `atomic:` link, and a device that adopted the sender's agent would sync
  // everything its owner then wrote to the sender's node.
  it('refuses a code that tries to hand over an account', () => {
    expect(
      codeOf(() =>
        decodePairingEnvelope(
          uriOf({ v: '1', node: NODE, drives: '*', secret: 'c2VjcmV0' }),
        ),
      ),
    ).toBe('malformed');
  });

  it('refuses a smuggled secret even when it is empty', () => {
    expect(
      codeOf(() =>
        decodePairingEnvelope(
          uriOf({ v: '1', node: NODE, drives: '*', secret: '' }),
        ),
      ),
    ).toBe('malformed');
  });

  it('never emits a secret parameter', () => {
    expect(encodePairingEnvelope(allDrives)).not.toContain('secret');
  });

  it('rejects an unknown version with its own error code', () => {
    expect(
      codeOf(() =>
        decodePairingEnvelope(uriOf({ v: '2', node: NODE, drives: '*' })),
      ),
    ).toBe('unsupported-version');
  });

  it('rejects a missing version as malformed', () => {
    expect(
      codeOf(() => decodePairingEnvelope(uriOf({ node: NODE, drives: '*' }))),
    ).toBe('malformed');
  });

  it('rejects garbage and truncated payloads as malformed', () => {
    expect(codeOf(() => decodePairingEnvelope('not a code'))).toBe('malformed');
    expect(codeOf(() => decodePairingEnvelope('https://example.com'))).toBe(
      'malformed',
    );
  });

  it('rejects invalid node identities', () => {
    for (const node of [
      'did:ad:agent:abc',
      `did:ad:node:${'zz'.repeat(32)}`,
      'did:ad:node:abcdef',
      undefined,
    ]) {
      expect(
        codeOf(() =>
          decodePairingEnvelope(uriOf({ v: '1', node, drives: '*' })),
        ),
      ).toBe('malformed');
    }
  });

  it('rejects non-http urls', () => {
    expect(
      codeOf(() =>
        decodePairingEnvelope(
          uriOf({
            v: '1',
            node: NODE,
            drives: '*',
            url: encodeURIComponent('ftp://x.example'),
          }),
        ),
      ),
    ).toBe('malformed');
  });

  it('rejects empty or contradictory drive lists', () => {
    for (const drives of [undefined, ['*', 'did:ad:drive1']]) {
      expect(
        codeOf(() =>
          decodePairingEnvelope(uriOf({ v: '1', node: NODE, drives })),
        ),
      ).toBe('malformed');
    }
  });

  it('refuses to encode an envelope it would not decode', () => {
    expect(() =>
      encodePairingEnvelope({ ...namedDrives, node: 'did:ad:node:short' }),
    ).toThrow(PairingEnvelopeError);
  });
});

describe('the older double-slash form', () => {
  it('is still decoded, so codes minted before the change keep working', () => {
    const modern = encodePairingEnvelope(allDrives);
    const legacy = modern.replace('atomic:pair?', 'atomic://pair?');

    expect(modern.startsWith('atomic:pair?')).toBe(true);
    expect(decodePairingEnvelope(legacy)).toEqual(decodePairingEnvelope(modern));
  });
});
