// @wc-ignore-file
import { signRequest, errorMessageFromResponse, type Store } from '@tomic/lib';

export interface WebsitePackage {
  version: 1;
  files: Record<string, string>;
  assets?: Record<string, string>;
  metadata?: { renderer: string; project: string; config: unknown };
}
export interface HostingStatus {
  url: string;
  deployment?: string;
  state: null | {
    project: string;
    drive: string;
    revision: number;
    active: string | null;
    deployments: string[];
    versions?: Record<string, number>;
    history: { deployment: string | null; actor: string; at: number }[];
  };
}
/** Sign only the configured Atomic API origin. Never give a website the agent or its keys. */
export async function hostingRequest<T>(
  store: Store,
  project: string,
  path = '',
  body?: unknown,
): Promise<T> {
  const agent = store.getAgent();
  const drive = store.getDrive();
  if (!agent || !drive) throw new Error('Sign in to your drive to publish.');
  const url = new URL(`/website-hosting${path}`, store.getServerUrl());
  url.searchParams.set('project', project);
  url.searchParams.set('drive', drive);
  const payload = body === undefined ? undefined : JSON.stringify(body);
  // A POST is signed over its method and exact body; a GET stays version 1.
  const headers = await signRequest(
    url.toString(),
    agent,
    {},
    payload === undefined ? undefined : { method: 'POST', body: payload },
  );
  const result = await fetch(url, {
    method: payload === undefined ? 'GET' : 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    credentials: 'omit',
    redirect: 'error',
    body: payload,
  });
  if (!result.ok)
    throw new Error(
      errorMessageFromResponse(await result.text(), result.status),
    );

  return result.json() as Promise<T>;
}

/** Compare delivered bytes and image hashes, ignoring authoring metadata and timestamps. */
export function sameWebsiteOutput(
  a: WebsitePackage,
  b: WebsitePackage,
): boolean {
  const same = (left: Record<string, string>, right: Record<string, string>) =>
    Object.keys(left).length === Object.keys(right).length &&
    Object.entries(left).every(
      ([key, value]) => Object.hasOwn(right, key) && right[key] === value,
    );

  return same(a.files, b.files) && same(a.assets ?? {}, b.assets ?? {});
}
