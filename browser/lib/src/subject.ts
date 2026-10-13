/**
 * Branded subject identifier. A valid `Subject` is either:
 *
 * - an Atomic identifier: `atomic:{genesis}` (canonical) or `did:ad:{genesis}`
 *   (legacy alias), including `agent` / `commit` / `blob` / `node` kinds
 * - or an absolute HTTP(S) URL
 *
 * The brand makes `Subject` source-incompatible with `string` so the type
 * checker catches "I have a string and I think it's a subject" mistakes
 * at the boundary instead of letting them ride into store / WS / outbox
 * paths and re-surface as runtime errors.
 *
 * Adoption is incremental:
 *
 * 1. New code should accept / return `Subject` directly.
 * 2. At ingress (HTTP fetch, WS frame decode, parsed JSON-AD), use
 *    {@link asSubject} to validate and brand.
 * 3. Existing `string`-typed APIs can migrate one signature at a time;
 *    the compiler will surface the cast sites that need either a real
 *    `asSubject(...)` validation or an `as Subject` assertion (only for
 *    values already known to be well-formed).
 *
 * See `planning/subject-types-end-to-end.md` and `planning/atomic-scheme.md`.
 */
declare const SubjectBrand: unique symbol;

export type Subject = string & { readonly [SubjectBrand]: true };

export const ATOMIC_PREFIX = 'atomic:';
export const ATOMIC_AGENT_PREFIX = 'atomic:agent:';
export const ATOMIC_COMMIT_PREFIX = 'atomic:commit:';
export const ATOMIC_BLOB_PREFIX = 'atomic:blob:';
export const ATOMIC_NODE_PREFIX = 'atomic:node:';
export const ATOMIC_PROPERTY_PREFIX = 'atomic:prop:';
export const ATOMIC_LENS_PREFIX = 'atomic:lens:';

/** Legacy scheme, accepted forever. New code emits {@link ATOMIC_PREFIX}. */
export const DID_AD_PREFIX = 'did:ad:';
export const DID_AD_AGENT_PREFIX = 'did:ad:agent:';
export const DID_AD_COMMIT_PREFIX = 'did:ad:commit:';
export const DID_AD_BLOB_PREFIX = 'did:ad:blob:';
export const DID_AD_NODE_PREFIX = 'did:ad:node:';
export const DID_AD_PROPERTY_PREFIX = 'did:ad:prop:';
export const DID_AD_LENS_PREFIX = 'did:ad:lens:';

const HTTP_RE = /^https?:\/\//;

export type IdentifierKind =
  | 'resource'
  | 'agent'
  | 'commit'
  | 'blob'
  | 'node'
  | 'property'
  | 'lens'
  | 'other';

export function isLegacyAtomicLink(raw: string): boolean {
  return raw.startsWith('atomic://');
}

const IDENTIFIER_HTTP_ENDPOINTS = new Set(['/did', '/resource', '/atomic']);

/** `/did`, `/resource`, `/atomic` — resolve via `?subject=`. */
export function isIdentifierHttpEndpoint(path: string): boolean {
  return IDENTIFIER_HTTP_ENDPOINTS.has(path);
}

/** Path-form identifier: `/atomic:{genesis}` or `/did:ad:{genesis}`. */
export function isIdentifierPathForm(path: string): boolean {
  if (!path.startsWith('/')) {
    return false;
  }

  return isAtomicIdentifier(path.slice(1));
}

/** Request path that resolves an Atomic identifier rather than an HTTP resource. */
export function isIdentifierResolutionPath(path: string): boolean {
  const bare = path.split(/[?#]/)[0];

  return isIdentifierHttpEndpoint(bare) || isIdentifierPathForm(bare);
}

export function startsWithAtomicScheme(raw: string): boolean {
  return raw.startsWith(ATOMIC_PREFIX) && !isLegacyAtomicLink(raw);
}

/**
 * True for the client's `_new:…` placeholder subject, however the store or
 * server has since spelled it (`_new:x`, `internal:/_new:x`,
 * `https://host/_new:x`). A placeholder names something that never reached a
 * server, so there is nothing to delete there.
 */
export function isNewPlaceholderSubject(raw: string): boolean {
  return /^(?:[a-z][a-z0-9+.-]*:\/\/[^/]+\/|internal:\/|\/)?_new:/i.test(raw);
}

export function isAtomicIdentifier(raw: string): boolean {
  return startsWithAtomicScheme(raw) || raw.startsWith(DID_AD_PREFIX);
}

function identifierRest(raw: string): string | undefined {
  if (startsWithAtomicScheme(raw)) {
    return raw.slice(ATOMIC_PREFIX.length);
  }

  if (raw.startsWith(DID_AD_PREFIX)) {
    return raw.slice(DID_AD_PREFIX.length);
  }

  return undefined;
}

export function identifierBody(raw: string): string | undefined {
  const rest = identifierRest(raw);

  return rest?.split(/[?#]/)[0];
}

/** Rewrite `did:ad:` → `atomic:`. Other strings are unchanged. */
export function canonicalizeScheme(raw: string): string {
  if (raw.startsWith(DID_AD_PREFIX)) {
    return ATOMIC_PREFIX + raw.slice(DID_AD_PREFIX.length);
  }

  return raw;
}

export const CAP_CANONICAL_SCHEME = 'canonical-scheme';

/** Rewrite `atomic:` → `did:ad:` for a peer that predates the rename. */
export function toLegacyScheme(raw: string): string {
  if (startsWithAtomicScheme(raw)) {
    return DID_AD_PREFIX + raw.slice(ATOMIC_PREFIX.length);
  }

  return raw;
}

/** Emit `atomic:` when the peer listed {@link CAP_CANONICAL_SCHEME}, else `did:ad:`. */
export function emitSubjectForCaps(
  subject: string,
  caps: readonly string[],
): string {
  return caps.includes(CAP_CANONICAL_SCHEME)
    ? canonicalizeScheme(subject)
    : toLegacyScheme(subject);
}

export function schemeAlias(raw: string): string | undefined {
  const rest = identifierRest(raw);

  if (rest === undefined) {
    return undefined;
  }

  return startsWithAtomicScheme(raw)
    ? DID_AD_PREFIX + rest
    : ATOMIC_PREFIX + rest;
}

export function identifierKind(raw: string): IdentifierKind | undefined {
  const body = identifierBody(raw);

  if (body === undefined) {
    return undefined;
  }

  if (body.startsWith('agent:')) {
    return body.length > 'agent:'.length ? 'agent' : 'other';
  }

  if (body.startsWith('commit:')) {
    return body.length > 'commit:'.length ? 'commit' : 'other';
  }

  if (body.startsWith('blob:')) {
    return body.length > 'blob:'.length ? 'blob' : 'other';
  }

  if (body.startsWith('node:')) {
    return body.length > 'node:'.length ? 'node' : 'other';
  }

  if (body.startsWith('prop:')) {
    return body.length > 'prop:'.length ? 'property' : 'other';
  }

  if (body.startsWith('lens:')) {
    return body.length > 'lens:'.length ? 'lens' : 'other';
  }

  if (body.length > 0 && !body.includes(':')) {
    return 'resource';
  }

  return 'other';
}

export function isAgentSubject(raw: string): boolean {
  return identifierKind(raw) === 'agent';
}

export function isBlobSubject(raw: string): boolean {
  return identifierKind(raw) === 'blob';
}

export function isNodeSubject(raw: string): boolean {
  return identifierKind(raw) === 'node';
}

export function isPropertySubject(raw: string): boolean {
  return identifierKind(raw) === 'property';
}

export function isLensSubject(raw: string): boolean {
  return identifierKind(raw) === 'lens';
}

export function isResourceSubject(raw: string): boolean {
  return identifierKind(raw) === 'resource';
}

export function agentPublicKey(raw: string): string | undefined {
  const body = identifierBody(raw);

  return body?.startsWith('agent:') && body.length > 'agent:'.length
    ? body.slice('agent:'.length)
    : undefined;
}

export function commitSignature(raw: string): string | undefined {
  const body = identifierBody(raw);

  return body?.startsWith('commit:') && body.length > 'commit:'.length
    ? body.slice('commit:'.length)
    : undefined;
}

export function blobHashHex(raw: string): string | undefined {
  const body = identifierBody(raw);

  return body?.startsWith('blob:') && body.length > 'blob:'.length
    ? body.slice('blob:'.length)
    : undefined;
}

export function nodeId(raw: string): string | undefined {
  const body = identifierBody(raw);

  return body?.startsWith('node:') && body.length > 'node:'.length
    ? body.slice('node:'.length)
    : undefined;
}

export function propertySubject(hashHex: string): string {
  return ATOMIC_PROPERTY_PREFIX + hashHex;
}

export function lensSubject(hashHex: string): string {
  return ATOMIC_LENS_PREFIX + hashHex;
}

export function agentSubject(pubkey: string): string {
  return ATOMIC_AGENT_PREFIX + pubkey;
}

/**
 * The agent a pre-DID `https://server/agents/{pubkey}` subject stands for.
 *
 * Old resources name their author by that URL. It is a different resource from
 * the agent's current profile: it keeps whatever name the person had back
 * then, and nothing a later rename touches. Anything that shows an author
 * therefore has to go through the key to the live profile. Any other subject,
 * including a DID agent, is returned unchanged.
 */
export function currentAgentSubject(subject: string): string {
  const legacy = subject.match(/^https?:\/\/[^/]+\/agents\/([^/?#]+)$/);

  return legacy ? agentSubject(decodeURIComponent(legacy[1])) : subject;
}

export function resourceSubject(genesisSig: string): string {
  return ATOMIC_PREFIX + genesisSig;
}

export function commitSubject(signature: string): string {
  return ATOMIC_COMMIT_PREFIX + signature;
}

export function blobSubject(hashHex: string): string {
  return ATOMIC_BLOB_PREFIX + hashHex;
}

const CONTENT_ADDRESSED_DOWNLOAD = /\/download\/files\/([0-9a-f]{64})$/i;

/**
 * The blob a content-addressed download URL (`<origin>/download/files/<hash>`,
 * what `Store.uploadFiles` writes as a File's `downloadURL`) serves, or
 * `undefined` for any other URL.
 *
 * Places that keep only the URL, like an image in a document, use it to find
 * the bytes in the local blob store. Those bytes may be the only copy: a
 * browser-only drive never sends them to the server the URL names.
 */
export function blobSubjectFromDownloadUrl(url: string): string | undefined {
  let pathname: string;

  try {
    pathname = new URL(url, 'http://localhost').pathname;
  } catch {
    return undefined;
  }

  const hash = CONTENT_ADDRESSED_DOWNLOAD.exec(pathname)?.[1];

  return hash ? blobSubject(hash.toLowerCase()) : undefined;
}

export function nodeSubject(id: string): string {
  return ATOMIC_NODE_PREFIX + id;
}

/**
 * Strip query/fragment and rewrite `did:ad:` → `atomic:`. Other strings are
 * unchanged. Use this instead of `startsWith('did:')` / `startsWith('atomic:')`
 * when comparing identity.
 */
export function canonicalIdentifier(raw: string): string {
  if (!isAtomicIdentifier(raw)) {
    return raw;
  }

  return canonicalizeScheme(raw.split(/[?#]/)[0]);
}

/**
 * Validate a raw string and brand it as a `Subject`. Throws if the
 * input is not an Atomic identifier or HTTP(S) URL. Use at system boundaries.
 */
export function asSubject(raw: string): Subject {
  if (!isValidSubject(raw)) {
    throw new InvalidSubjectError(raw);
  }

  return raw as Subject;
}

/**
 * Non-throwing variant — returns `undefined` for invalid input. Useful
 * for places that need to handle malformed identifiers gracefully (e.g.
 * surfacing a user-facing error toast).
 */
export function tryAsSubject(raw: string): Subject | undefined {
  return isValidSubject(raw) ? (raw as Subject) : undefined;
}

/**
 * True iff `raw` is shaped like a subject (Atomic identifier or HTTP(S) URL).
 * Does not perform deeper structural validation — that's the parser's job.
 */
export function isValidSubject(raw: string): boolean {
  if (typeof raw !== 'string' || raw.length === 0) return false;

  return isAtomicIdentifier(raw) || HTTP_RE.test(raw);
}

/** True iff this subject is an Atomic identifier (vs an HTTP URL). */
export function isDidSubject(subject: Subject | string): boolean {
  return isAtomicIdentifier(subject);
}

/** True iff this subject is an HTTP(S) URL (vs an Atomic identifier). */
export function isHttpSubject(subject: Subject | string): boolean {
  return HTTP_RE.test(subject);
}

/**
 * If `raw` is an Atomic identifier, return it with query/fragment stripped
 * (canonical `atomic:` form). If it is an HTTP(S) URL that *names* a
 * resource — the path form `https://host/did:ad:…` / `https://host/atomic:…`
 * or the `/did` / `/resource` / `/atomic` endpoint — return that identifier.
 * Otherwise `undefined`.
 */
export function extractDidSubject(raw: string): string | undefined {
  if (isAtomicIdentifier(raw)) {
    return canonicalizeScheme(raw.split(/[?#]/)[0]);
  }

  if (!HTTP_RE.test(raw)) {
    return undefined;
  }

  try {
    const url = new URL(raw);
    const path = url.pathname.replace(/\/$/, '') || '/';

    if (isIdentifierPathForm(path)) {
      return canonicalizeScheme(path.slice(1));
    }

    if (isIdentifierHttpEndpoint(path)) {
      const subject = url.searchParams.get('subject');

      if (subject && isAtomicIdentifier(subject)) {
        return canonicalizeScheme(subject.split(/[?#]/)[0]);
      }
    }
  } catch {
    return undefined;
  }

  return undefined;
}

/**
 * True when `requested` and `received` name the same resource: exact
 * match, same URL ignoring query params, or one is an HTTP alias of
 * the other's identifier (`https://host/did:ad:x` vs `atomic:x`).
 */
export function subjectsReferToSameResource(
  requested: string,
  received: string,
): boolean {
  if (requested === received) {
    return true;
  }

  const requestedNoParams = requested.split('?')[0];
  const receivedNoParams = received.split('?')[0];

  if (requestedNoParams === receivedNoParams) {
    return true;
  }

  if (
    canonicalizeScheme(requestedNoParams) ===
    canonicalizeScheme(receivedNoParams)
  ) {
    return (
      isAtomicIdentifier(requestedNoParams) &&
      isAtomicIdentifier(receivedNoParams)
    );
  }

  const requestedDid = extractDidSubject(requested);
  const receivedDid = extractDidSubject(received);

  return (
    requestedDid !== undefined &&
    receivedDid !== undefined &&
    requestedDid === receivedDid
  );
}

export class InvalidSubjectError extends Error {
  constructor(public readonly raw: string) {
    super(`Invalid subject: ${JSON.stringify(raw)}`);
    this.name = 'InvalidSubjectError';
  }
}
