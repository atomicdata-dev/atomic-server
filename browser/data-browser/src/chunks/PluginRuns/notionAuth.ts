// @wc-ignore-file
import { signRequest, type Store } from '@tomic/lib';

export interface NotionConnection {
  id: string;
  name: string;
  workspace: string;
}
export interface NotionDatabase {
  id: string;
  name: string;
  icon: string;
}
export async function notionAuth<T>(
  store: Store,
  operation: string,
  body: unknown,
): Promise<T> {
  const agent = store.getAgent();
  if (!agent) throw new Error('Sign in to connect Notion');
  const url = `${store.getServerUrl()}/integration-oauth/notion/${operation}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      ...(await signRequest(url, agent, {})),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const text = await response.text();

    try {
      const data = JSON.parse(text);
      throw new Error(
        data.message ??
          data['https://atomicdata.dev/properties/description'] ??
          text,
      );
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error(text);
      throw error;
    }
  }

  return response.json();
}
export function waitForNotion(
  popup: Window,
  origin: string,
  state: string,
  signal: AbortSignal,
): Promise<{ code: string | null; error: string | null }> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      window.removeEventListener('message', message);
      clearInterval(timer);
      signal.removeEventListener('abort', abort);
      popup.close();
    };

    const abort = () => {
      cleanup();
      reject(new Error('Notion sign-in cancelled. You can try again.'));
    };

    const message = (event: MessageEvent) => {
      if (
        event.origin !== origin ||
        event.source !== popup ||
        event.data?.type !== 'atomic-notion-oauth' ||
        event.data.state !== state
      )
        return;
      cleanup();
      resolve({ code: event.data.code, error: event.data.error });
    };

    const deadline = Date.now() + 10 * 60 * 1000;
    const timer = setInterval(() => {
      if (popup.closed || Date.now() > deadline) abort();
    }, 500);
    window.addEventListener('message', message);
    signal.addEventListener('abort', abort);
    if (signal.aborted) abort();
  });
}

/** Only the host polls the authorization service. Browser polling returns a
 * pending marker or a public connection, never an OAuth credential or proof. */
export async function waitForManagedNotion(
  store: Store,
  drive: string,
  state: string,
  popup: Window,
  signal: AbortSignal,
): Promise<NotionConnection> {
  const deadline = Date.now() + 10 * 60 * 1000;
  const cancelled = () =>
    signal.aborted || popup.closed || Date.now() >= deadline;

  try {
    while (!cancelled()) {
      const result = await notionAuth<NotionConnection | { pending: true }>(
        store,
        'finish',
        { drive, state },
      );
      if (signal.aborted)
        throw new Error('Notion sign-in cancelled. You can try again.');
      if (!('pending' in result)) return result;
      await new Promise<void>(resolve => {
        const done = () => {
          clearTimeout(timer);
          signal.removeEventListener('abort', done);
          resolve();
        };

        const timer = setTimeout(done, 1000);
        signal.addEventListener('abort', done, { once: true });
        if (signal.aborted) done();
      });
    }

    throw new Error('Notion sign-in cancelled or expired. You can try again.');
  } finally {
    popup.close();
  }
}
