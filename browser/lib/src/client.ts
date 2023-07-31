// Provides functionality to interact with an Atomic Server.
// Send requests to the server and receive responses.

import { hasBrowserAPI } from './hasBrowserAPI.js';
import {
  Agent,
  AtomicError,
  checkAuthenticationCookie,
  Commit,
  ErrorType,
  JSONADParser,
  parseCommitJSON,
  Resource,
  serializeDeterministically,
  setCookieAuthentication,
  signRequest,
} from './index.js';

// Works both in node and the browser
import fetch from 'cross-fetch';

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
}

export interface ParseOpts {
  /** Skips processing nested resources, even if they have an @id */
  noNested?: boolean;
}

/** Contains one or more Resources */
interface HTTPResourceResult {
  resource: Resource;
  createdResources: Resource[];
}

/** Contains a `fetch` instance, provides methods to GET and POST several types */
export class Client {
  private __fetchOverride?: typeof fetch;

  public constructor(fetchOverride?: typeof fetch) {
    this.__fetchOverride = fetchOverride;
  }

  private get fetch() {
    const fetchFunction = this.__fetchOverride ?? fetch;

    if (typeof fetchFunction === 'undefined') {
      throw new AtomicError(
        `No fetch available, If the current environment doesn't have a fetch implementation you can pass one yourself.`,
      );
    }

    return fetchFunction;
  }

  /** Throws an error if the subject is not valid */
  public static tryValidSubject(subject: string | undefined): void {
    try {
      new URL(subject as string);
    } catch (e) {
      throw new Error(`Not a valid URL: ${subject}. ${e}`);
    }
  }

  /** Returns true if the given subject is valid */
  public static isValidSubject(subject: string | undefined): boolean {
    if (typeof subject !== 'string') return false;

    try {
      Client.tryValidSubject(subject);

      return true;
    } catch (e) {
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
    this.__fetchOverride = fetchOverride;
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
    const { signInfo, from, body: bodyReq } = opts;
    let createdResources: Resource[] = [];
    const parser = new JSONADParser();
    let resource = new Resource(subject);

    try {
      Client.tryValidSubject(subject);
      const requestHeaders: HeadersObject = {};
      requestHeaders['Accept'] = JSON_AD_MIME;

      if (signInfo) {
        // Cookies only work in browsers for same-origin requests right now
        // https://github.com/atomicdata-dev/atomic-data-browser/issues/253
        if (hasBrowserAPI() && subject.startsWith(window.location.origin)) {
          if (!checkAuthenticationCookie()) {
            setCookieAuthentication(signInfo.serverURL, signInfo.agent);
          }
        } else {
          await signRequest(subject, signInfo.agent, requestHeaders);
        }
      }

      let url = subject;

      if (from !== undefined) {
        const newURL = new URL(`${from}/path`);
        newURL.searchParams.set('path', subject);
        url = newURL.href;
      }

      const response = await this.fetch(url, {
        headers: requestHeaders,
        method: bodyReq ? 'POST' : 'GET',
        body: bodyReq,
      });
      const body = await response.text();

      if (response.status === 200) {
        try {
          const json = JSON.parse(body);

          if (opts.noNested) {
            resource = json;
          } else {
            const [parsedResource, parsedCreatedResources] = parser.parseObject(
              json,
              subject,
            );

            resource = parsedResource;
            createdResources.push(...parsedCreatedResources);
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
      resource.setError(e);
      createdResources = [resource];
      console.error(subject, e);
    }

    resource.loading = false;

    return { resource, createdResources };
  }

  /** Posts a Commit to some endpoint. Returns the Commit created by the server. */
  public async postCommit(
    commit: Commit,
    /** URL to post to, e.g. https://atomicdata.dev/commit */
    endpoint: string,
  ): Promise<Commit> {
    const serialized = serializeDeterministically({ ...commit });
    const requestHeaders: HeadersInit = new Headers();
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
    const [resources] = parser.parseArray(json);

    return resources;
  }

  // /** Instructs an Atomic Server to fetch a URL and get its JSON-AD */
  // public async importJsonAdUrl(
  //   /** The URL of the JSON-AD to import */
  //   jsonAdUrl: string,
  //   /** Importer URL. Servers tend to have one at `example.com/import` */
  //   importerUrl: string,
  // ): Promise<HTTPResourceResult> {
  //   const url = new URL(importerUrl);
  //   url.searchParams.set('url', jsonAdUrl);

  //   return this.fetchResourceHTTP(url.toString());
  // }

  // /** Instructs an Atomic Server to fetch a URL and get its JSON-AD */
  // public async importJsonAdString(
  //   /** The JSON-AD to import */
  //   jsonAdString: string,
  //   /** Importer URL. Servers tend to have one at `example.com/import` */
  //   importerUrl: string,
  // ): Promise<HTTPResourceResult> {
  //   const url = new URL(importerUrl);

  //   return this.fetchResourceHTTP(url.toString(), {
  //     body: jsonAdString,
  //   });
  // }
}
