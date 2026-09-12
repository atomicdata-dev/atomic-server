// Provides functionality to interact with an Atomic Server.
// Send requests to the server and receive responses.

import { hasBrowserAPI } from './hasBrowserAPI.js';
import {
  checkAuthenticationCookie,
  setCookieAuthentication,
  signRequest,
} from './authentication.js';
import { AtomicError, ErrorType } from './error.js';
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
} from './commit.js';
import { JSONADParser } from './parse.js';
import { Resource } from './resource.js';
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
export class Client {
  private __fetchOverride?: typeof fetch;

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
      subject.startsWith('did:ad:') ||
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

      if (subject.startsWith('did:')) {
        // We can't fetch DIDs directly, so we use the server's /did endpoint.
        const baseUrl =
          signInfo?.serverURL ||
          serverURL ||
          (window as unknown as Record<'atomicServerUrl', string>)
            .atomicServerUrl ||
          window.location.origin;
        url = `${baseUrl}/did?subject=${encodeURIComponent(subject)}`;
      }

      // Sign the request with the actual URL being fetched (not the raw DID
      // subject) since the server verifies against the full HTTP URL.
      if (signInfo) {
        if (shouldSkipDidAuthForLegacyServer(url, signInfo.agent.subject)) {
          warnDidAuthCompatibility(url);
        } else if (!subject.startsWith('https://atomicdata.dev')) {
          // Cookies only work in browsers for same-origin requests right now
          // https://github.com/atomicdata-dev/atomic-data-browser/issues/253
          if (hasBrowserAPI() && subject.startsWith(window.location.origin)) {
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

      if (from !== undefined) {
        const newURL = new URL(`${from}/path`);
        newURL.searchParams.set('path', subject);
        url = newURL.href;
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

            // For array responses, find the resource matching the requested subject.
            // Falls back to the last item (the convention for non-array responses).
            resource =
              resources.find(r => r.subject === subject) ??
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
      } else if (response.status === 500) {
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
      console.error('[postCommit] Server error body:', body);
      console.error('[postCommit] Commit sent:', serialized);
      throw new AtomicError(body, ErrorType.Server);
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
