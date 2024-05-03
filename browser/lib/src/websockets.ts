import { createAuthentication } from './authentication.js';
import { parseAndApplyCommit } from './index.js';
import { JSONADParser } from './parse.js';
import type { Resource } from './resource.js';
import type { Store } from './store.js';

/** Opens a Websocket Connection at `/ws` for the current Drive */
export function startWebsocket(url: string, store: Store): WebSocket {
  const wsURL = new URL(url);

  // Default to a secure WSS connection, but allow WS for unsecured server connections
  if (wsURL.protocol === 'http:') {
    wsURL.protocol = 'ws';
  } else {
    wsURL.protocol = 'wss';
  }

  wsURL.pathname = '/ws';
  const client = new WebSocket(wsURL.toString());
  client.onopen = _e => handleOpen(store, client);
  client.onmessage = (ev: MessageEvent) => handleMessage(ev, store);
  client.onerror = handleError;

  // client.onclose = handleClose;
  return client;
}

function handleOpen(store: Store, client: WebSocket) {
  // Make sure user is authenticated before sending any messages
  authenticate(client, store).then(() => {
    // Subscribe to all existing messages
    // TODO: Add a way to subscribe to multiple resources in one request
    for (const subject of store.subscribers.keys()) {
      store.subscribeWebSocket(subject);
    }
  });
}

function handleMessage(ev: MessageEvent, store: Store) {
  if (ev.data.startsWith('COMMIT ')) {
    const commit = ev.data.slice(7);
    parseAndApplyCommit(commit, store);
  } else if (ev.data.startsWith('ERROR ')) {
    store.notifyError(ev.data.slice(6));
  } else if (ev.data.startsWith('RESOURCE ')) {
    const resources = parseResourceMessage(ev);
    store.addResources(resources);
  } else {
    console.warn('Unknown websocket message:', ev);
  }
}

function handleError(ev: Event) {
  console.error('websocket error:', ev);
}

function parseResourceMessage(ev: MessageEvent): Resource[] {
  const resourceJSON: string = ev.data.slice(9);
  const parsed = JSON.parse(resourceJSON);
  const parser = new JSONADParser();
  const [_, resources] = parser.parseObject(parsed);

  return resources;
}

/**
 * Authenticates current Agent over current WebSocket. Doesn't do anything if
 * there is no agent
 */
export async function authenticate(
  client: WebSocket,
  store: Store,
  fetchAll = false,
) {
  const agent = store.getAgent();

  if (!agent || !agent.subject) {
    return;
  }

  if (
    !client.url.startsWith('ws://localhost') &&
    agent?.subject?.startsWith('http://localhost')
  ) {
    console.warn(
      `Can't authenticate localhost Agent over websocket with remote server ${client.url} because the server will nog be able to retrieve your Agent and verify your public key.`,
    );

    return;
  }

  const json = await createAuthentication(client.url, agent);
  client.send('AUTHENTICATE ' + JSON.stringify(json));

  // Maybe this should happen after the authentication is confirmed?
  fetchAll &&
    store.resources.forEach(r => {
      if (r.isUnauthorized() || r.loading) {
        store.fetchResourceFromServer(r.subject);
      }
    });
}

const defaultTimeout = 5000;

/** Sends a GET message for some resource over websockets. */
export async function fetchWebSocket(
  client: WebSocket,
  subject: string,
): Promise<Resource> {
  return new Promise((resolve, reject) => {
    client.addEventListener('message', function listener(ev) {
      const timeoutId = setTimeout(() => {
        client.removeEventListener('message', listener);
        reject(
          new Error(
            `Request for subject "${subject}" timed out after ${defaultTimeout}ms.`,
          ),
        );
      }, defaultTimeout);

      if (ev.data.startsWith('RESOURCE ')) {
        parseResourceMessage(ev).forEach(resource => {
          // if it is the requested subject, return the resource
          if (resource.subject === subject) {
            clearTimeout(timeoutId);
            client.removeEventListener('message', listener);
            resolve(resource);
          }
        });
      }
    });
    client.send('GET ' + subject);
  });
}
