/**
 * Capability links: a URL that carries the right to open one resource.
 *
 * Whoever holds the link can open the resource, with no account and no
 * invitation to accept. The right travels in the link itself, the way a
 * NextGraph nuri carries its read key, but built from what Atomic already
 * has: a freshly minted agent, granted on the target, whose secret is the
 * capability (`issueCapabilityLink`). Revoking the link is revoking that
 * agent (`revokeAccessAgent`), and it shows up in the App keys list like any
 * other key, named after the resource it opens.
 *
 * Wire form, readable and copyable, the same `atomic:open?subject=…` link the
 * desktop app already opens resources with, plus the capability:
 *
 *     atomic:open?v=1&subject=<subject>&cap=<secret>&url=<node>
 *
 * or, so that a plain browser can open it, the same query under an app's
 * `/app/open` path:
 *
 *     https://example.org/app/open?v=1&subject=<subject>&cap=<secret>&url=<node>
 *
 * No `//` after the scheme: there is no authority part, and Atomic's
 * identifiers (`did:ad:…`) have none either. `subject` is the resource to
 * open. `cap` is the agent secret, the capability.
 * `url` is a routing hint: where the resource can be fetched from by a client
 * that does not have it. It grants nothing on its own; the node still checks
 * the agent's rights on the resource.
 *
 * Contrast with `pairing.ts`: a pairing code is routing only and carries no
 * secret by design. A capability link is the opposite: it is the secret. Treat
 * it like a password for that one resource, because that is what it is.
 */

export type CapabilityLink = {
  v: 1;
  /** The resource the link opens. */
  subject: string;
  /** The agent secret that carries the right. Base64 JSON, see `Agent.buildSecret`. */
  cap: string;
  /** Optional http(s) origin the resource can be fetched from. Routing only. */
  url?: string;
};

export const CAPABILITY_URI_PREFIX = 'atomic:open?';

/** Accepted on decode only, for links minted before the double slash went. */
const LEGACY_CAPABILITY_URI_PREFIX = 'atomic://open?';

/** Path under an app origin that opens a capability link in a plain browser. */
export const CAPABILITY_APP_PATH = '/app/open';

export class CapabilityLinkError extends Error {
  public constructor(
    public readonly code: 'unsupported-version' | 'malformed',
    message: string,
  ) {
    super(message);
    this.name = 'CapabilityLinkError';
  }
}

const isHttpOrigin = (value: string): boolean => {
  try {
    const url = new URL(value);

    return (
      (url.protocol === 'http:' || url.protocol === 'https:') &&
      url.pathname === '/' &&
      url.search === '' &&
      url.hash === ''
    );
  } catch {
    return false;
  }
};

function queryOf(link: CapabilityLink): string {
  const params = new URLSearchParams();
  params.set('v', String(link.v));
  params.set('subject', link.subject);
  params.set('cap', link.cap);

  if (link.url !== undefined) {
    params.set('url', link.url);
  }

  return params.toString();
}

function validate(link: CapabilityLink): void {
  if (link.v !== 1) {
    throw new CapabilityLinkError(
      'unsupported-version',
      `Unsupported capability link version ${String(link.v)}`,
    );
  }

  if (!link.subject || /[\s<>"]/.test(link.subject)) {
    throw new CapabilityLinkError('malformed', 'Missing or invalid subject');
  }

  if (!link.cap) {
    throw new CapabilityLinkError('malformed', 'Missing capability secret');
  }

  if (link.url !== undefined && !isHttpOrigin(link.url)) {
    throw new CapabilityLinkError(
      'malformed',
      'url must be a bare http(s) origin with no path, query or hash',
    );
  }
}

/** The `atomic:open?…` form. */
export function encodeCapabilityLink(link: CapabilityLink): string {
  validate(link);

  return `${CAPABILITY_URI_PREFIX}${queryOf(link)}`;
}

/** The `https://<app origin>/app/open?…` form, for browsers. */
export function encodeCapabilityWebLink(
  link: CapabilityLink,
  appOrigin: string,
): string {
  validate(link);

  if (!isHttpOrigin(appOrigin)) {
    throw new CapabilityLinkError(
      'malformed',
      'appOrigin must be an http(s) origin',
    );
  }

  return `${appOrigin.replace(/\/$/, '')}${CAPABILITY_APP_PATH}?${queryOf(link)}`;
}

/**
 * Parses either form (and the older `atomic://open?…`), or a bare query
 * string (`v=1&subject=…`), which is what a route handler holds after the
 * router has stripped the path.
 */
export function decodeCapabilityLink(input: string): CapabilityLink {
  const trimmed = input.trim();
  let query: string;

  if (trimmed.startsWith(CAPABILITY_URI_PREFIX)) {
    query = trimmed.slice(CAPABILITY_URI_PREFIX.length);
  } else if (trimmed.startsWith(LEGACY_CAPABILITY_URI_PREFIX)) {
    query = trimmed.slice(LEGACY_CAPABILITY_URI_PREFIX.length);
  } else if (/^https?:\/\//.test(trimmed)) {
    let parsed: URL;

    try {
      parsed = new URL(trimmed);
    } catch {
      throw new CapabilityLinkError('malformed', 'Not a valid URL');
    }

    if (!parsed.pathname.endsWith(CAPABILITY_APP_PATH)) {
      throw new CapabilityLinkError(
        'malformed',
        `A web capability link opens under ${CAPABILITY_APP_PATH}`,
      );
    }

    query = parsed.search.replace(/^\?/, '');
  } else {
    query = trimmed.replace(/^\?/, '');
  }

  const params = new URLSearchParams(query);
  const version = params.get('v');

  if (version === null) {
    throw new CapabilityLinkError('malformed', 'Missing version');
  }

  if (version !== '1') {
    throw new CapabilityLinkError(
      'unsupported-version',
      `Unsupported capability link version ${version}`,
    );
  }

  const link: CapabilityLink = {
    v: 1,
    subject: params.get('subject') ?? '',
    cap: params.get('cap') ?? '',
    url: params.get('url') ?? undefined,
  };

  validate(link);

  return link;
}
