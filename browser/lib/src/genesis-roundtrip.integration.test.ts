import { describe, it, expect } from 'vitest';
import { Store } from './store.js';
import { Agent } from './agent.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { server } from './ontologies/server.js';
import { core } from './ontologies/core.js';
import { applyImportReferences } from './import-reference-review.js';
import { identifierBody, isAtomicIdentifier } from './subject.js';

/**
 * Round-trip proof for cert-minting-at-creation: a drive whose `did:ad:` was
 * minted from a browser-built genesis certificate must be ACCEPTED by a live
 * atomic-server via its cert path (Path 1). Runs the real Store + real fetch
 * (no mocks) against a server on localhost:9883.
 *
 * Skips if no server is reachable, so it never fails the normal suite. Run
 * explicitly: `pnpm vitest run src/genesis-roundtrip.integration.test.ts`.
 */
const SERVER = process.env.ATOMIC_SERVER_URL ?? 'http://localhost:9883';

async function serverUp(): Promise<boolean> {
  try {
    // Any HTTP response means the server is up (a bare GET / returns 404
    // application/ad+json on atomic-server). Only a network error means down.
    await fetch(SERVER);

    return true;
  } catch {
    return false;
  }
}

describe('genesis cert round-trip against a live server', () => {
  it.each(['http', 'ws'])(
    'confirms an edited application reference after a %s refresh',
    async mode => {
      if (!(await serverUp())) return;
      const store = new Store({ serverUrl: SERVER });
      store.setServerConnected(true);
      const keys = await Agent.generateKeyPair();
      const agent = new Agent(
        new JSCryptoProvider(keys.privateKey),
        `did:ad:agent:${keys.publicKey}`,
      );
      store.setAgent(agent);
      const drive = await store.newResource({
        noParent: true,
        isA: server.classes.drive,
        propVals: {
          [core.properties.write]: [agent.subject],
          [core.properties.read]: [agent.subject],
        },
      });
      await drive.save();
      const prop = await store.newResource({
        parent: drive.subject,
        isA: core.classes.property,
        propVals: {
          [core.properties.shortname]: 'linked-project',
          [core.properties.name]: 'Project',
          [core.properties.description]: 'Project reference',
          [core.properties.datatype]:
            'https://atomicdata.dev/datatypes/atomicURL',
        },
      });
      await prop.save();
      const before = await store.newResource({ parent: drive.subject });
      const after = await store.newResource({ parent: drive.subject });
      await before.save();
      await after.save();
      const row = await store.newResource({
        parent: drive.subject,
        propVals: { [prop.subject]: before.subject },
      });
      await row.save();

      if (mode === 'ws') {
        store.setServerConnected(false);
        localStorage.removeItem('ws-disconnected');
        await store.reconnect(10_000);
      }

      const outcomes = await applyImportReferences(
        {
          read: subject => store.readServerSnapshot(subject),
          write: async (subject, values) => {
            const resource = await store.fetchResourceFromServer(subject, {
              noWebSocket: mode === 'http',
            });
            for (const [p, v] of Object.entries(values))
              await resource.set(p, v as never);
            await resource.save();
          },
        },
        [
          {
            subject: row.subject,
            property: prop.subject,
            before: before.subject,
            after: after.subject,
          },
        ],
      );
      if (mode === 'ws') store.disconnect();
      expect(outcomes).toEqual([{ subject: row.subject, status: 'confirmed' }]);
      expect((await store.readServerSnapshot(row.subject))[prop.subject]).toBe(
        after.subject,
      );
    },
    30_000,
  );

  it('a browser cert-minted drive genesis is accepted by the server', async () => {
    if (!(await serverUp())) {
      console.warn(`[skip] no atomic-server at ${SERVER}`);

      return;
    }

    const store = new Store({ serverUrl: SERVER });
    store.setServerConnected(true);

    const keys = await Agent.generateKeyPair();
    const agentDID = `did:ad:agent:${keys.publicKey}`;
    store.setAgent(new Agent(new JSCryptoProvider(keys.privateKey), agentDID));

    const drive = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: {
        [core.properties.name]: 'cert-roundtrip test',
        [core.properties.write]: [agentDID],
        [core.properties.read]: [agentDID],
      },
    });

    // Minted from a cert, from birth, and the cert verifies against the DID.
    expect(isAtomicIdentifier(drive.subject)).toBe(true);
    const propval = drive.get(
      'https://atomicdata.dev/properties/genesis',
    ) as string;
    expect(propval).toBeTypeOf('string');
    const { decodeGenesisCert, verifyGenesisCert } =
      await import('./genesis.js');
    const { decodeB64 } = await import('./base64.js');
    const cert = decodeGenesisCert(decodeB64(propval));
    expect(await verifyGenesisCert(cert, identifierBody(drive.subject)!)).toBe(
      true,
    );

    // The real gate: POST the genesis to the live server. If the server's
    // cert verification (Path 1) rejected it, this would throw / drain-fail.
    const result = await drive.save();
    expect(['posted', 'persisted']).toContain(result);

    // Definitive proof it crossed to the server: fetch it back as the owner.
    const fresh = new Store({ serverUrl: SERVER });
    fresh.setServerConnected(true);
    fresh.setAgent(store.getAgent()!);
    const fetched = await fresh.getResource(drive.subject);
    expect(fetched.error).toBeUndefined();
    expect(fetched.get(core.properties.name)).toBe('cert-roundtrip test');
  }, 30_000);
});
