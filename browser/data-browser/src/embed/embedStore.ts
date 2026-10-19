import {
  Agent,
  NativeClientDb,
  NativeCryptoProvider,
  Store,
  type ClientDbWorker,
  type NativeChannel,
} from '@tomic/react';

/**
 * The embed's store: the host app (Rust `atomic_lib`) is its only database and
 * holds the agent's key. There is no server, so nothing is fetched over HTTP
 * and no auth cookie is made (`noServer`): the host signs commits of its agent
 * and nothing else, and a refused signature used to fail the very resource the
 * page had just read. Edits go to the host (`commitTransport`), which keeps and
 * syncs them.
 */
export async function createEmbedStore(
  channel: NativeChannel,
): Promise<{ store: Store; db: NativeClientDb }> {
  const db = new NativeClientDb(channel);
  const agentSubject = (await channel
    .call('agent', [])
    .catch(() => undefined)) as string | undefined;

  const store = new Store({
    // Never used: nothing here connects. A valid origin is all the store wants.
    serverUrl: 'https://embed.invalid',
    connect: false,
    noServer: true,
    agent: agentSubject
      ? new Agent(new NativeCryptoProvider(channel), agentSubject)
      : undefined,
    // Without this the store, having no server, would only ever save edits
    // offline, into a page database nobody keeps: the typing was gone once
    // the page closed.
    commitTransport: db.commitTransport,
  });

  store.setClientDb(db as unknown as ClientDbWorker);
  await db.waitForInit();

  return { store, db };
}
