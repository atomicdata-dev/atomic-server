import { looksLikePairingUri } from '@tomic/lib';
import { normalizeServerUrl } from './serverUrl';

/**
 * What someone typed or pasted into the "Add a device" box.
 *
 * One box takes both kinds of thing a device can be reached by: a pairing code
 * (a device you carry) or an address (an always-on device). The person should
 * not have to say which, so it is decided here.
 */
export type ConnectInput =
  | { kind: 'empty' }
  /** A pairing code or deep link, to hand to the pairing flow as typed. */
  | { kind: 'code'; code: string }
  /** An address, already given a scheme. */
  | { kind: 'server'; url: string }
  | { kind: 'invalid' };

export function classifyConnectInput(raw: string): ConnectInput {
  const input = raw.trim();

  if (!input) return { kind: 'empty' };

  if (looksLikePairingUri(input)) return { kind: 'code', code: input };

  // An address has no spaces, and an identifier with another scheme is not one.
  if (/\s/.test(input) || /^(atomic|did):/i.test(input)) {
    return { kind: 'invalid' };
  }

  try {
    const url = new URL(normalizeServerUrl(input));

    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) {
      return { kind: 'invalid' };
    }

    return { kind: 'server', url: normalizeServerUrl(input) };
  } catch {
    return { kind: 'invalid' };
  }
}
