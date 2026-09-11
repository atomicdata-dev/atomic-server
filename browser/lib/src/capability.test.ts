import { describe, expect, it } from 'vitest';
import {
  CAPABILITY_APP_PATH,
  CAPABILITY_URI_PREFIX,
  CapabilityLinkError,
  decodeCapabilityLink,
  encodeCapabilityLink,
  encodeCapabilityWebLink,
  type CapabilityLink,
} from './capability.js';

const SUBJECT = 'did:ad:LQ3OzC0m9m3mZ4Hn7rY2jvbVQ5Wf8k1PpX9dY6c2Q0s';
const CAP = btoa(JSON.stringify({ privateKey: 'k', subject: 'did:ad:agent:p' }));

const link: CapabilityLink = {
  v: 1,
  subject: SUBJECT,
  cap: CAP,
  url: 'https://node.example.org',
};

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof CapabilityLinkError) return e.code;
    throw e;
  }

  throw new Error('expected a CapabilityLinkError');
}

describe('capability links', () => {
  it('round-trips the atomic: form', () => {
    const encoded = encodeCapabilityLink(link);

    expect(encoded.startsWith(CAPABILITY_URI_PREFIX)).toBe(true);
    expect(decodeCapabilityLink(encoded)).toEqual(link);
  });

  it('round-trips the web form under /app/open', () => {
    const encoded = encodeCapabilityWebLink(link, 'https://app.example.org');

    expect(encoded.startsWith(`https://app.example.org${CAPABILITY_APP_PATH}?`)).toBe(true);
    expect(decodeCapabilityLink(encoded)).toEqual(link);
  });

  it('has no double slash, like every other atomic identifier', () => {
    expect(encodeCapabilityLink(link).startsWith('atomic:open?')).toBe(true);
    expect(encodeCapabilityLink(link)).not.toContain('//');
  });

  it('still decodes the older double-slash form', () => {
    const legacy = encodeCapabilityLink(link).replace('atomic:open?', 'atomic://open?');

    expect(decodeCapabilityLink(legacy)).toEqual(link);
  });

  it('decodes a bare query string, which is what a route handler holds', () => {
    const query = encodeCapabilityLink(link).slice(CAPABILITY_URI_PREFIX.length);

    expect(decodeCapabilityLink(query)).toEqual(link);
    expect(decodeCapabilityLink(`?${query}`)).toEqual(link);
  });

  it('keeps the secret intact through URL encoding', () => {
    const awkward = { ...link, cap: 'a+b/c==&d?e' };

    expect(decodeCapabilityLink(encodeCapabilityLink(awkward)).cap).toBe(awkward.cap);
  });

  it('omits url when there is none', () => {
    const { url: _url, ...bare } = link;
    const encoded = encodeCapabilityLink(bare);

    expect(encoded).not.toContain('url=');
    expect(decodeCapabilityLink(encoded)).toEqual({ ...bare, url: undefined });
  });

  it('refuses an unknown version rather than guessing', () => {
    expect(codeOf(() => decodeCapabilityLink(`${CAPABILITY_URI_PREFIX}v=2&subject=${SUBJECT}&cap=${CAP}`))).toBe(
      'unsupported-version',
    );
    expect(codeOf(() => encodeCapabilityLink({ ...link, v: 2 as 1 }))).toBe('unsupported-version');
  });

  it('refuses a link with no subject or no secret', () => {
    expect(codeOf(() => decodeCapabilityLink(`${CAPABILITY_URI_PREFIX}v=1&cap=${CAP}`))).toBe('malformed');
    expect(codeOf(() => decodeCapabilityLink(`${CAPABILITY_URI_PREFIX}v=1&subject=${SUBJECT}`))).toBe('malformed');
  });

  it('refuses a routing url that is not a bare origin', () => {
    expect(codeOf(() => encodeCapabilityLink({ ...link, url: 'https://node.example.org/path' }))).toBe(
      'malformed',
    );
    expect(codeOf(() => encodeCapabilityLink({ ...link, url: 'ftp://node.example.org' }))).toBe('malformed');
  });

  it('refuses a web link under the wrong path', () => {
    expect(codeOf(() => decodeCapabilityLink(`https://app.example.org/app/share?v=1&subject=${SUBJECT}&cap=${CAP}`))).toBe(
      'malformed',
    );
  });
});
