import { errorMessageFromResponse, signRequest, type Store } from '@tomic/react';

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
  const headers = await signRequest(url, agent, {});

  const response = await fetch(url, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      drive: options.drive,
      app: options.app,
      secret: options.secret,
    }),
  });

  if (!response.ok) {
    throw new Error(
      errorMessageFromResponse(await response.text(), response.status),
    );
  }
}
