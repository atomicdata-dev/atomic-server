// @wc-ignore-file
import { signRequest, type Store } from '@tomic/react';

export const platformName = (id: string) =>
  ({
    'github-issues': 'GitHub issues',
    'google-calendar': 'Google Calendar',
    pets: 'Pets',
  })[id] ?? id;
export async function proxyRequest<T>(
  store: Store,
  action: string,
  body: object,
): Promise<T> {
  const agent = store.getAgent();
  if (!agent) throw new Error('Sign in before connecting an account');
  const url = `${store.getServerUrl()}/integration-proxy/${action}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      ...(await signRequest(url, agent, {})),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(await response.text());

  return response.json();
}
export interface SavedConnection {
  connection: string;
  platform: string;
  drive: string;
  actor: string;
}
export const connectionKey = (drive: string, actor: string, platform: string) =>
  `localthought:${JSON.stringify([drive, actor, platform])}`;
