// Provides functionality to interact with an Atomic Server.
// Send requests to the server and receive responses.

import { hasBrowserAPI } from './hasBrowserAPI.js';
import {
  checkAuthenticationCookie,
  setCookieAuthentication,
  signRequest,
  legacyAgentForRequest,
} from './authentication.js';
import {
  AtomicError,
  ErrorType,
  NOT_AVAILABLE_LOCALLY_MESSAGE,
} from './error.js';
import { busyRetryAfterMs, DEFAULT_BUSY_RETRY_MS, ErrorCode } from './ws-v2.js';
import { pageRequestSignal } from './page-request-signal.js';
// Import directly from the modules to avoid a circular dep through `./index.js`
// — under some bundlers the re-exported binding lands as `undefined` at runtime
// (TypeError: serializeDeterministically is not a function), which surfaces in
// the upload-roundtrip integration test.
import type { Agent } from './agent.js';
import {
  type Commit,
  serializeDeterministically,
  parseCommitJSON,
  learnServerClock,
} from './commit.js';
import { JSONADParser } from './parse.js';
import { Resource } from './resource.js';
import { extractDidSubject, isAtomicIdentifier } from './subject.js';
import {
  recordServerVersionFromResponse,
  shouldSkipDidAuthForLegacyServer,
  warnDidAuthCompatibility,
} from './serverCapabilities.js';

/**
 * One key-value pair per HTTP Header. Since we need to support both browsers
 * and Node, we won't use the native Headers object here.
 */
export interface HeadersObject {
  [key: string]: string;
}

export type FileLike = { blob: Blob; name: string };
export type FileOrFileLike = File | FileLike;

const isFileLike = (file: FileOrFileLike): file is FileLike =>
  'blob' in file && 'name' in file;

const JSON_AD_MIME = 'application/ad+json';

interface FetchResourceOptions extends ParseOpts {
  /**
   * if the HTTP request needs to be signed by an agent, pass the agent here.
   */
  signInfo?: {
    agent: Agent;
    serverURL: string;
  };
  /**
   * Pass a server URL if you want to use the `/path` endpoint to indirectly
   * fetch through that server.
   */
  from?: string;
  method?: 'GET' | 'POST';
  /** The body is only used combined with the `POST` method */
  body?: ArrayBuffer | string;
  /**
   * The backend server URL, used for resolving DID subjects when no signInfo
   * is available (e.g. before the agent has been loaded from IndexedDB).
   */
  serverURL?: string;
}

export interface ParseOpts {
  /** Skips processing nested resources, even if they have an @id */
  noNested?: boolean;
}

/** Contains one or more Resources */
interface HTTPResourceResult {
  cancelled?: boolean;
  resource: Resource;
  createdResources: Resource[];
}

/** Contains a `fetch` instance, provides methods to GET and POST several types */
/** Response header of `POST /commit`: the node's write-load hint in ms. */
const PACE_HEADER = 'X-Atomic-Pace-Ms';
const RETRY_AFTER_MS_HEADER = 'X-Atomic-Retry-After-Ms';

/** The delay a 429/503 asks for: the precise millisecond header, else the
 *  standard `Retry-After` (seconds), else the hint in the body, else a
 *  default. */
function retryAfterMsOf(response: Response, message: string): number {
  const exact = Number(response.headers?.get(RETRY_AFTER_MS_HEADER));

  if (response.headers?.get(RETRY_AFTER_MS_HEADER) && Number.isFinite(exact)) {
    return exact;
  }

  const secs = Number(response.headers?.get('Retry-After'));

  if (response.headers?.get('Retry-After') && Number.isFinite(secs)) {
    return secs * 1000;
  }

  return busyRetryAfterMs(message, ErrorCode.BUSY) ?? DEFAULT_BUSY_RETRY_MS;
}

export class Client {
  private __fetchOverride?: typeof fetch;
  /** Called with the `X-Atomic-Pace-Ms` hint of every acknowledged
   *  `POST /commit`. The store points it at the outbox. */
  public paceListener?: (paceMs: number) => void;

  public constructor(fetchOverride?: typeof fetch) {
    if (fetchOverride) {
      this.setFetch(fetchOverride);
    }
  }

  /** Throws an error if the subject is not valid */
  public static tryValidSubject(subject: string | undefined): void {
    if (typeof subject !== 'string') {
      throw new Error(`Subject is not a string: ${subject}`);
    }

    if (
      subject.startsWith('http') ||
      isAtomicIdentifier(subject) ||
      subject.startsWith('internal:')
    ) {
      if (subject.startsWith('http') || subject.startsWith('internal:')) {
        try {
          new URL(subject);

          return;
        } catch (e) {
          throw new Error(`Not a valid URL: ${subject}. ${e}`);
        }
      }

      return;
    }

    // Relative path validation
    // Allow empty string for root. Allow ?, =, &, % for collections/search.
    // Must start with '/' to distinguish from arbitrary text (e.g. search queries).
    if (subject !== '' && !subject.match(/^\/[a-zA-Z0-9/._\-:?=&%]*$/)) {
      throw new Error(
        `Not a valid Relative Subject: ${subject}. This should be a slug-like string without spaces.`,
      );
    }
  }

  /** Returns true if the given subject is valid */
  public static isValidSubject(subject: unknown): boolean {
    if (typeof subject !== 'string') return false;

    try {
      Client.tryValidSubject(subject);

      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * True when `subject` is an HTTP(S) URL with no path, query, or hash —
   * i.e. a server origin, not a drive. `https://example.com` and
   * `https://example.com/` match; `https://example.com/drives/foo` does not.
   *
   * `Store.setDrive` treats a bare origin as `setServerUrl`. An HTTP
   * subject with a path is a real (legacy) drive and must not move the
   * home server.
   */
  public static isBareHttpOrigin(subject: string): boolean {
    if (!subject.startsWith('http://') && !subject.startsWith('https://')) {
      return false;
    }

    try {
      const url = new URL(subject);

      return (
        (url.pathname === '/' || url.pathname === '') &&
        !url.search &&
        !url.hash
      );
    } catch {
      return false;
    }
  }

  /**
   * True when `subject` is an HTTP(S) URL that names a resource (has a
   * path, query, or hash), not a server origin.
   */
  public static isHttpDriveSubject(subject: string): boolean {
    if (!subject.startsWith('http://') && !subject.startsWith('https://')) {
      return false;
    }

    try {
      new URL(subject);

      return !Client.isBareHttpOrigin(subject);
    } catch {
      return false;
    }
  }

  /**
   * Removes query params from the URL if it can build a URL. Will return the
   * normal URL if things go wrong.
   */
  // TODO: Not sure about this. Was done because `new Commit()` failed with `unknown-subject`.
  public static removeQueryParamsFromURL(subject: string): string {
    return subject?.split('?')[0];
  }

  public setFetch(fetchOverride: typeof fetch) {
    this.__fetchOverride = fetchOverride.bind(globalThis);
  }

  /**
   * Fetches and Parses a Resource. Can fetch through another atomic server if you
   * pass the `from` argument, which should be the baseURL of an Atomic Server.
   * Returns a tuple of the requested resource and a list of all resources found in the response.
   */
  public async fetchResourceHTTP(
    subject: string,
    opts: FetchResourceOptions = {},
  ): Promise<HTTPResourceResult> {
    const { signInfo, from, body: bodyReq, method, serverURL } = opts;
    const signal = pageRequestSignal();
    let createdResources: Resource[] = [];
    const parser = new JSONADParser();
    let resource = new Resource(subject);

    try {
      Client.tryValidSubject(subject);
      let requestHeaders: HeadersObject = {
        Accept: JSON_AD_MIME,
      };

      if (method === 'POST' && !bodyReq) {
        requestHeaders['Content-Length'] = '0';
      }

      let url = subject;
      const wrappedDid = extractDidSubject(subject);

      if (isAtomicIdentifier(subject)) {
        // We can't fetch identifiers directly, so we use /resource (aliases /atomic, /did).
        const baseUrl = didResolutionBaseUrl(signInfo?.serverURL, serverURL);

        if (!baseUrl) {
          throw new AtomicError(
            `Cannot fetch ${subject}: no server URL to resolve this DID against. ` +
              `Pass serverURL to fetchResourceHTTP, call store.setServerUrl(), ` +
              `or (for @tomic/cli) set "serverUrl" in atomic.config.json.`,
          );
        }

        url = `${baseUrl}/resource?subject=${encodeURIComponent(subject)}`;
      } else if (wrappedDid && wrappedDid !== subject) {
        // `https://host/did:ad:…` / `https://host/atomic:…` is an HTTP alias,
        // not the resource's identity. Fetch via /resource so the response
        // `@id` (the identifier) matches what JSON-AD actually contains.
        url = `${new URL(subject).origin}/resource?subject=${encodeURIComponent(wrappedDid)}`;
      }

      // Through the own server's `/path` proxy, the request goes to that
      // server, not to the subject's origin. Build the URL first: the
      // server checks the signature against the URL it receives.
      if (from !== undefined) {
        url = proxyPathUrl(from, subject);
      }

      // Checks on the requested URL for a proxied fetch, on the subject
      // otherwise (a DID is still fetched with signature headers).
      const authTarget = from !== undefined ? url : subject;

      // Sign exactly the URL being fetched (not the raw DID subject, nor
      // the external subject behind a proxy): the server verifies the
      // signature against the full HTTP URL of the request.
      if (signInfo) {
        const legacy = legacyAgentForRequest(url, signInfo.agent);

        if (legacy) {
          requestHeaders = await signRequest(
            url,
            signInfo.agent,
            requestHeaders,
            legacy,
          );
        } else if (
          shouldSkipDidAuthForLegacyServer(url, signInfo.agent.subject)
        ) {
          warnDidAuthCompatibility(url);
        } else if (!isOwnServerUrl(url, signInfo.serverURL)) {
          // A foreign origin (shared vocabulary on GitHub Pages, another
          // host's classes) gets a plain GET. The `x-atomic-*` headers are
          // not CORS-safelisted, so signing forces a preflight, which static
          // hosts refuse (Pages answers 405). Such an origin cannot check our
          // Agent anyway: public data is all it can serve us.
        } else if (!authTarget.startsWith('https://atomicdata.dev')) {
          // Cookies only work in browsers for same-origin requests right now
          // https://github.com/atomicdata-dev/atomic-data-browser/issues/253
          if (
            hasBrowserAPI() &&
            authTarget.startsWith(window.location.origin)
          ) {
            if (!checkAuthenticationCookie()) {
              // Await: the request that follows depends on this cookie.
              // Without the await, the first call after `setAgent`
              // race-conditions a 401 because the cookie hasn't been
              // installed yet (the next request reads
              // `checkAuthenticationCookie()` and re-installs anyway,
              // but the first response is already a stale 401).
              await setCookieAuthentication(signInfo.serverURL, signInfo.agent);
            }
          } else {
            requestHeaders = await signRequest(
              url,
              signInfo.agent,
              requestHeaders,
            );
          }
        }
      }

      // A throwing `fetch` (server down, DNS, CORS) is a different kind of
      // failure from any status code: it carries no information about the
      // resource, only about the connection. Typing it as such lets the
      // Store keep local state instead of overwriting it with this
      // failure, and retry the resource when the connection returns.
      let response: Response;

      try {
        response = await this.fetch(url, {
          headers: requestHeaders,
          method: method ?? 'GET',
          body: bodyReq,
          signal,
        });
      } catch (e) {
        throw new AtomicError(
          `Could not reach ${url}: ${e instanceof Error ? e.message : e}`,
          ErrorType.Transport,
        );
      }

      recordServerVersionFromResponse(url, response);
      const body = await response.text();

      if (response.status === 200) {
        // An origin that runs no node (a portal, a static host) answers every
        // path with its index.html. For an identifier that means "nothing
        // here", not "a broken resource": say so, so the UI can offer the
        // vault instead of a JSON parse error.
        if (isAtomicIdentifier(subject) && /^\s*</.test(body)) {
          throw new AtomicError(
            NOT_AVAILABLE_LOCALLY_MESSAGE,
            ErrorType.Transport,
          );
        }

        try {
          const json = JSON.parse(body);

          // /path represents the fetched resource under its request URL.
          // Restore the requested identity only for that exact proxy alias.
          if (
            from !== undefined &&
            json &&
            !Array.isArray(json) &&
            json['@id'] === url
          ) {
            json['@id'] = subject;
          }

          if (opts.noNested) {
            resource = json;
          } else {
            const resources = parser.parse(json, subject);

            if (resources.length === 0) {
              throw new AtomicError(
                `Could not parse JSON from fetching ${subject}. Is it an Atomic Data resource?`,
              );
            }

            // For array responses, find the resource matching the requested
            // subject (or its DID, when the request used an HTTP alias).
            // Falls back to the last item (the convention for non-array
            // responses).
            resource =
              resources.find(r => r.subject === subject) ??
              (wrappedDid
                ? resources.find(r => r.subject === wrappedDid)
                : undefined) ??
              (resources.at(-1) as Resource);
            createdResources.push(...resources);
          }
        } catch (e) {
          throw new AtomicError(
            `Could not parse JSON from fetching ${subject}. Is it an Atomic Data resource? Error message: ${e.message}`,
          );
        }
      } else if (response.status === 401) {
        throw new AtomicError(body, ErrorType.Unauthorized);
      } else if (response.status >= 500) {
        throw new AtomicError(body, ErrorType.Server);
      } else if (response.status === 404) {
        throw new AtomicError(body, ErrorType.NotFound);
      } else {
        throw new AtomicError(body);
      }
    } catch (e) {
      if (signal?.aborted)
        return { resource, createdResources: [], cancelled: true };
      resource.setError(e);
      createdResources = [resource];
      console.error(subject, e);
    }

    resource.loading = false;
    createdResources.forEach(r => (r.loading = false));

    return { resource, createdResources };
  }

  /** Posts a Commit to some endpoint. Returns the Commit created by the server. */
  public async postCommit(
    commit: Commit,
    /** URL to post to, e.g. https://atomicdata.dev/commit */
    endpoint: string,
  ): Promise<Commit> {
    // `true`: keep the genesis subject in the network body so the server uses
    // the real (cert-minted) DID instead of re-deriving it from the signature.
    const serialized = serializeDeterministically({ ...commit }, true);
    const requestHeaders = new Headers();
    requestHeaders.set('Content-Type', 'application/ad+json');
    let response: Response;

    try {
      response = await this.fetch(endpoint, {
        headers: requestHeaders,
        method: 'POST',
        body: serialized,
      });
    } catch (e) {
      throw new AtomicError(`Posting Commit to ${endpoint} failed: ${e}`);
    }

    const body = await response.text();

    if (response.status !== 200) {
      learnServerClock(body);

      // 429 (write rate limit) and 503 (node overloaded) both mean "nothing
      // was attempted, wait this long". Not worth the error logs below.
      if (response.status === 429 || response.status === 503) {
        const error = new AtomicError(body, ErrorType.Server, ErrorCode.BUSY);
        error.retryAfterMs = retryAfterMsOf(response, error.message);
        throw error;
      }

      console.error('[postCommit] Server error body:', body);
      console.error('[postCommit] Commit sent:', serialized);
      throw new AtomicError(body, ErrorType.Server);
    }

    const pace = Number(response.headers?.get(PACE_HEADER));

    if (response.headers?.get(PACE_HEADER) && Number.isFinite(pace)) {
      this.paceListener?.(pace);
    }

    return parseCommitJSON(body);
  }

  /**
   * Uploads files to the `/upload` endpoint of the Store. Signs the Headers using
   * the given agent.
   * Returns the newly created resources
   */
  public async uploadFiles(
    files: FileOrFileLike[],
    serverUrl: string,
    agent: Agent,
    parent: string,
  ): Promise<Resource[]> {
    const parser = new JSONADParser();
    const formData = new FormData();

    files.map(file => {
      if (isFileLike(file)) {
        formData.append('assets', file.blob, file.name);
      } else {
        formData.append('assets', file, file.name);
      }
    });

    const uploadURL = new URL(`${serverUrl}/upload`);
    uploadURL.searchParams.set('parent', parent);

    // TODO: Use cookie authentication here if possible
    // https://github.com/atomicdata-dev/atomic-data-browser/issues/253
    const signedHeaders = await signRequest(uploadURL.toString(), agent, {});

    const options = {
      method: 'POST',
      body: formData,
      headers: signedHeaders,
    };

    const resp = await this.fetch(uploadURL.toString(), options);

    const body = await resp.text();

    if (resp.status !== 200) {
      throw Error(body);
    }

    const json = JSON.parse(body);
    const resources = parser.parse(json);

    return resources;
  }

  private fetch(...params: Parameters<typeof fetch>): ReturnType<typeof fetch> {
    if (this.__fetchOverride) {
      return this.__fetchOverride(...params);
    }

    return fetch(...params);
  }
}

/**
 * The URL of `subject` behind `server`'s `/path` proxy. The server fetches
 * (and keeps) an external subject on first use, so this reaches vocabulary
 * whose own host is down or refuses the browser.
 */
export function proxyPathUrl(server: string, subject: string): string {
  const url = new URL(`${server.replace(/\/$/, '')}/path`);
  url.searchParams.set('path', subject);

  return url.href;
}

/**
 * Whether `url` is served by the user's own server, so that a request to it
 * may carry the Agent's signature: the store's server URL, a drive on one of
 * its subdomains (`https://{drive}.{server host}`), or the page's own origin.
 * Anything else is a foreign origin, which gets unsigned requests.
 */
export function isOwnServerUrl(url: string, serverURL?: string): boolean {
  let target: URL;

  try {
    target = new URL(url);
  } catch {
    // A relative URL resolves against the page, which is ours.
    return true;
  }

  if (hasBrowserAPI() && target.origin === window.location.origin) {
    return true;
  }

  if (!serverURL) return false;

  let server: URL;

  try {
    server = new URL(serverURL);
  } catch {
    return false;
  }

  if (target.origin === server.origin) return true;

  // Subdomain drives: same scheme and port, host one or more labels deeper.
  return (
    target.protocol === server.protocol &&
    target.port === server.port &&
    target.hostname.endsWith(`.${server.hostname}`)
  );
}

/** Origin used to turn an identifier into `GET {origin}/resource?subject=`. */
function didResolutionBaseUrl(
  ...candidates: Array<string | undefined>
): string | undefined {
  for (const candidate of candidates) {
    if (candidate) {
      return candidate.replace(/\/$/, '');
    }
  }

  if (hasBrowserAPI()) {
    const fromWindow = (window as unknown as Record<'atomicServerUrl', string>)
      .atomicServerUrl;

    return fromWindow || window.location.origin;
  }

  return undefined;
}
