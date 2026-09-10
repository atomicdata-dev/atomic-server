import {
  Agent,
  BrowserPeerSync,
  ClientDbWorker,
  LoroLoader,
  Store,
  core,
  server,
} from '../../lib/src/index.js';

export async function openPeer(secret?: string) {
  await LoroLoader.initializeLoro();

  if (!secret) {
    const keys = await Agent.generateKeyPair();
    secret = Agent.buildSecret(
      keys.privateKey,
      `did:ad:agent:${keys.publicKey}`,
    );
  }

  const agent = await Agent.fromSecret(secret);
  const store = new Store({ serverUrl: 'http://127.0.0.1:1', agent });
  store.injectFetch(async () => {
    throw new Error('AtomicServer data requests disabled in peer acceptance');
  });
  const db = new ClientDbWorker(
    '/wasm/pkg/atomic_wasm.js',
    '/browser/lib/src/client-db.worker.ts',
    { dbName: 'peer-acceptance.redb' },
  );
  await db.init('http://127.0.0.1:1');
  await db.populate();
  store.setClientDb(db);
  await Promise.all(
    Object.values(core.properties).map(async subject => {
      const data = await db.getResourceWithSnapshot(subject);
      if (data.snapshot)
        store.applyIncoming({
          subject,
          loroBytes: data.snapshot,
          source: 'peer-sync',
        });
    }),
  );

  return { agent, store, db, secret };
}

export async function createDrive(store: Store) {
  const agent = store.getAgent()!;
  const drive = await store.newResource({
    isA: server.classes.drive,
    noParent: true,
    propVals: {
      [core.properties.name]: 'Peer workspace',
      [core.properties.read]: [agent.subject!],
      [core.properties.write]: [agent.subject!],
    },
  });
  store.registerLocalOnlyDrive(drive.subject);
  store.setDrive(drive.subject);
  await drive.save();
  await store.getClientDb()!.flush();

  return drive.subject;
}
export { BrowserPeerSync, core };
export { generateInviteToken } from '../../lib/src/invites.js';
