// @wc-ignore-file
import { type Store } from '@tomic/react';

export const platformName = (id: string) =>
  ({
    'github-issues': 'GitHub issues',
    'google-calendar': 'Google Calendar',
    pets: 'Pets',
  })[id] ?? id;
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

export const browserIntegrations = () =>
  new BrowserIntegrations(
    localStorage,
    engine,
    import.meta.env.VITE_INTEGRATION_PROXY_URL || undefined,
  );
export async function proxyRequest<T>(
  store: Store,
  action: string,
  body: {
    drive: string;
    platform?: string;
    returnUrl?: string;
    tenantSecret?: string;
    state?: string;
    connectionCode?: string;
    connection?: string;
    constants?: Record<string, string>;
    calendarRange?: { start: string; end: string; series?: boolean };
  },
): Promise<T> {
  const actor = store.getAgent()?.subject;
  if (!actor) throw new Error('Sign in before connecting an account');
  const client = browserIntegrations();
  if (action === 'start')
    return (await client.start(
      body.drive,
      actor,
      body.platform!,
      body.returnUrl!,
      body.tenantSecret!,
    )) as T;
  if (action === 'finish')
    return client.finish(
      body.drive,
      actor,
      body.state!,
      body.connectionCode!,
    ) as T;
  if (action === 'fetch')
    return client.fetchRecords(
      body.drive,
      actor,
      body.connection!,
      body.constants ?? {},
      body.calendarRange,
    );
  throw new Error('Unknown browser integration action');
}
export interface SavedConnection {
  connection: string;
  /** Keep imported tables stable when reauthorizing Calendar write access. */
  installationConnection?: string;
  platform: string;
  drive: string;
  actor: string;
}
export const connectionKey = (drive: string, actor: string, platform: string) =>
  `localthought-browser:${JSON.stringify([drive, actor, platform])}`;
