// @wc-ignore-file
import { getIntegrationProxy } from '@helpers/integrationProxy';
import { savedConnectionKey } from '../../../../../integrations/localthought/settings';
import { type Store } from '@tomic/react';

export const platformName = (id: string) =>
  id
    .split(/[-_]/)
    .filter(Boolean)
    .map(word => `${word[0]?.toUpperCase() ?? ''}${word.slice(1)}`)
    .join(' ');
import {
  BrowserIntegrations,
  type Engine,
} from '../../../../../integrations/localthought/browser';
import { wasmJsUrl, wasmBinaryUrl } from '../../helpers/wasmUrls';
let loaded: Promise<Engine> | undefined;

async function engine(): Promise<Engine> {
  return (loaded ??= (async () => {
    const url = wasmJsUrl();
    const module = await import(/* @vite-ignore */ url);
    await module.default({ module_or_path: wasmBinaryUrl() });
    if (typeof module.fetchIntegration !== 'function')
      throw new Error('Rebuild the WASM bundle and reload Atomic');

    return module;
  })().catch(error => {
    loaded = undefined;
    throw error;
  }));
}

export const browserIntegrations = (origin = getIntegrationProxy()) =>
  new BrowserIntegrations(localStorage, engine, origin);
export async function proxyRequest<T>(
  store: Store,
  action: string,
  body: {
    origin?: string;
    drive: string;
    platform?: string;
    returnUrl?: string;
    state?: string;
    connectionCode?: string;
    connection?: string;
    constants?: Record<string, string>;
    selection?: {
      query_overrides: { path: string; values: Record<string, unknown> }[];
    };
  },
): Promise<T> {
  const actor = store.getAgent()?.subject;
  if (!actor) throw new Error('Sign in before connecting an account');
  const client = browserIntegrations(body.origin);
  if (action === 'start')
    return (await client.start(
      body.drive,
      actor,
      body.platform!,
      body.returnUrl!,
    )) as T;
  if (action === 'finish')
    return (await client.finish(
      body.drive,
      actor,
      body.state!,
      body.connectionCode!,
    )) as T;
  if (action === 'fetch')
    return client.fetchRecords(
      body.drive,
      actor,
      body.connection!,
      body.constants ?? {},
      body.selection,
    );
  throw new Error('Unknown browser integration action');
}
export interface SavedConnection {
  connection: string;
  /** Keep imported tables stable when reauthorizing account scopes. */
  installationConnection?: string;
  platform: string;
  drive: string;
  actor: string;
}
export const connectionKey = (
  drive: string,
  actor: string,
  platform: string,
  origin = getIntegrationProxy(),
) => savedConnectionKey(origin, drive, actor, platform);
