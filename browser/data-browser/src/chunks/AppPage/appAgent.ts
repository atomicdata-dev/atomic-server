import {
  errorMessageFromResponse,
  signRequest,
  type Store,
} from '@tomic/react';

/**
 * Hands an app's freshly minted key to the node, once.
 *
 * The node needs it because an app that imports at 3am has nobody to ask for
 * a credential — whatever signs its writes has to be openable unattended. It
 * is posted rather than stored in a resource: a resource syncs, and the drive
 * it would live on can later be shared or replicated somewhere less trusted.
 *
 * Nothing keeps a copy here. If this fails the app still exists and still
 * works when you are present; what it cannot do is write as itself, which is
 * what the caller is told.
 */
export async function handOverAppKey(
  store: Store,
  options: { drive: string; app: string; secret: string },
): Promise<void> {
  const agent = store.getAgent();

  if (!agent) throw new Error('Sign in to give an app its key');

  const url = `${store.getServerUrl()}/app-agent`;
  const payload = JSON.stringify({
    drive: options.drive,
    app: options.app,
    secret: options.secret,
  });
  const headers = await signRequest(
    url,
    agent,
    {},
    { method: 'POST', body: payload },
  );

  const response = await fetch(url, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: payload,
  });

  if (!response.ok) {
    throw new Error(
      errorMessageFromResponse(await response.text(), response.status),
    );
  }
}

/**
 * The agent an app acts as (`atomic:agent:…` or the older `did:ad:agent:…`),
 * as the node that holds its key reports it. Integration-proxy connections
 * are delegated to this agent (ontola/atomic-plugins#54).
 *
 * Only apps made with `createApp` have one today. An installed catalog plugin
 * gets its own identity in a later step (#54 decision 2); until then it cannot
 * be given a proxy connection, and this says so rather than guessing.
 */
export async function appAgentOf(
  store: Store,
  options: { drive: string; app: string },
): Promise<string> {
  const agent = store.getAgent();

  if (!agent) throw new Error('Sign in to use integration connections.');

  const url = new URL('/app-agent', store.getServerUrl());
  url.searchParams.set('drive', options.drive);
  url.searchParams.set('app', options.app);
  const headers = await signRequest(url.href, agent, {});
  const response = await fetch(url.href, { headers });

  if (!response.ok) {
    throw new Error(
      errorMessageFromResponse(await response.text(), response.status),
    );
  }

  const info = (await response.json()) as { agent?: unknown } | null;

  if (typeof info?.agent !== 'string' || !info.agent) {
    throw new Error(
      'This app has no identity of its own yet, so it cannot be given an integration connection.',
    );
  }

  return info.agent;
}
