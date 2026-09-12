/**
 * Branded subject identifier. A valid `Subject` is either:
 *
 * - a DID, currently of the form `did:ad:<base64-signing-key>`
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
 * See `planning/subject-types-end-to-end.md` for the migration plan.
 */
declare const SubjectBrand: unique symbol;

export type Subject = string & { readonly [SubjectBrand]: true };

const DID_PREFIX = 'did:ad:';
const HTTP_RE = /^https?:\/\//;

/**
 * Validate a raw string and brand it as a `Subject`. Throws if the
 * input is not a DID or HTTP(S) URL. Use at system boundaries.
 *
 * @example
 * ```ts
 * const s = asSubject('https://atomicdata.dev/things/42');
 * // s: Subject — type-compatible with `string`, but enforces shape.
 * ```
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
 * True iff `raw` is shaped like a subject (DID or HTTP(S) URL). Does
 * not perform deeper structural validation — that's the parser's job.
 */
export function isValidSubject(raw: string): boolean {
  if (typeof raw !== 'string' || raw.length === 0) return false;

  return raw.startsWith(DID_PREFIX) || HTTP_RE.test(raw);
}

/** True iff this subject is a DID (vs an HTTP URL). */
export function isDidSubject(subject: Subject): boolean {
  return subject.startsWith(DID_PREFIX);
}

/** True iff this subject is an HTTP(S) URL (vs a DID). */
export function isHttpSubject(subject: Subject): boolean {
  return HTTP_RE.test(subject);
}

/**
 * If `raw` is a `did:ad:` subject, return it with query/fragment stripped.
 * If it is an HTTP(S) URL that *names* a DID resource — the path form
 * `https://host/did:ad:…` (an address-bar / copy-paste URL) or the
 * `/did` endpoint `https://host/did?subject=did:ad:…` — return that DID.
 * Otherwise `undefined`.
 *
 * The server always serialises a DID resource's `@id` as the DID itself,
 * even when the resource was fetched through one of these HTTP aliases.
 * Callers comparing a requested subject against `@id` should use
 * {@link subjectsReferToSameResource} rather than string equality.
 */
export function extractDidSubject(raw: string): string | undefined {
  if (raw.startsWith(DID_PREFIX)) {
    return raw.split(/[?#]/)[0];
  }

  if (!HTTP_RE.test(raw)) {
    return undefined;
  }

  try {
    const url = new URL(raw);
    const path = url.pathname.replace(/\/$/, '') || '/';

    // Path form: https://host/did:ad:…
    if (path.startsWith(`/${DID_PREFIX}`) && !path.slice(1).includes('/')) {
      return path.slice(1);
    }

    // Endpoint form: https://host/did?subject=did:ad:…
    if (path === '/did') {
      const subject = url.searchParams.get('subject');

      if (subject?.startsWith(DID_PREFIX)) {
        return subject.split(/[?#]/)[0];
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
 * the other's DID (`https://host/did:ad:x` vs `did:ad:x`).
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
