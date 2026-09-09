import { describe, it, vi } from 'vitest';
import { Agent } from './agent.js';
import { JSCryptoProvider } from './CryptoProvider.js';
import { decodeB64 } from './base64.js';
import {
  decodeGenesisCert,
  domainSeparatorNonce,
  PERSONAL_DRIVE_PURPOSE,
  privateDriveSubject,
} from './genesis.js';
import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import { Store } from './store.js';
import { testStore } from './test-store.js';

const GENESIS = 'https://atomicdata.dev/properties/genesis';
const FAVORITES = 'https://atomicdata.dev/properties/favorites';
const PERSONAL_DRIVE_NONCE_HEX = '5f62397980dc34a685e5ee57fa0ac058';

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

describe('deterministic personal drive', () => {
  it('does not fetch an agent from an origin explicitly configured without a node', async ({
    expect,
  }) => {
    const { store, agentDID } = await testStore();
    store.setServerUrl(store.getServerUrl(), { connect: false });
    const profile = store.getResourceLoading(agentDID, { newResource: true });
    await profile.set(core.properties.name, 'Local person', false);
    const fetch = vi.spyOn(store, 'fetchResourceFromServer');
    await store.createDrive('Home', { personal: true });
    expect(fetch.mock.calls.some(([subject]) => subject === agentDID)).toBe(
      false,
    );
    expect(profile.get(core.properties.name)).toBe('Local person');
  });

  it('createDrive({ personal: true }) uses the derived DID and cert', async ({
    expect,
  }) => {
    const { store, agentDID } = await testStore();
    const agent = store.getAgent()!;
    const expected = await agent.privateDriveSubject();

    const drive = await store.createDrive('Home', { personal: true });

    expect(drive.subject).toBe(expected);
    expect(drive.get(core.properties.name)).toBe('Home');
    expect(drive.get(core.properties.write)).toEqual([agentDID]);

    const cert = decodeGenesisCert(decodeB64(drive.get(GENESIS) as string));
    expect(cert.createdAt).toBe(0);
    expect(hex(cert.nonce)).toBe(PERSONAL_DRIVE_NONCE_HEX);
    expect(hex(domainSeparatorNonce(PERSONAL_DRIVE_PURPOSE))).toBe(
      PERSONAL_DRIVE_NONCE_HEX,
    );
  });

  it('the same key on two stores mints the same personal-drive subject', async ({
    expect,
  }) => {
    const keys = await Agent.generateKeyPair();
    const expected = await privateDriveSubject(decodeB64(keys.privateKey));

    const make = async () => {
      const store = new Store({ serverUrl: 'https://example.com' });
      store.setServerConnected(true);
      store.setAgent(
        new Agent(
          new JSCryptoProvider(keys.privateKey),
          `did:ad:agent:${keys.publicKey}`,
        ),
      );
      store.injectFetch(async () => {
        throw new Error('test: network disabled');
      });
      vi.spyOn(store, 'getProperty').mockRejectedValue(
        new Error('test: property validation skipped'),
      );

      (
        store as unknown as {
          client: { postCommit: (c: unknown) => Promise<unknown> };
        }
      ).client.postCommit = async (commit: unknown) => {
        return { ...(commit as object), id: 'https://example.com/commits/x' };
      };

      return store.createDrive('Home', { personal: true });
    };

    const a = await make();
    const b = await make();
    expect(a.subject).toBe(expected);
    expect(b.subject).toBe(expected);
    expect(a.subject).toBe(b.subject);
  });

  it('a second createDrive(personal) on the same store returns the same resource', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const first = await store.createDrive('Home', { personal: true });
    const second = await store.ensurePrivateDrive('Other name');
    expect(second.subject).toBe(first.subject);
    expect(second).toBe(first);
  });

  it('does not rename a personal drive the user has titled', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const drive = await store.createDrive('Home', { personal: true });

    await drive.set(core.properties.name, "Joep's stuff", false);
    await drive.save();

    // Boot and sign-in both call this; neither may rewrite what is there.
    const again = await store.ensurePrivateDrive('My drive');

    expect(again.subject).toBe(drive.subject);
    expect(again.get(core.properties.name)).toBe("Joep's stuff");
  });

  it('an additional drive is recorded on the derived personal drive', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const extra = await store.createDrive('Project', { personal: false });
    const personal = await store.ensurePrivateDrive();
    const listed = personal.getSubjects(server.properties.drives);
    expect(listed).toContain(extra.subject);
    expect(extra.subject).not.toBe(personal.subject);
  });

  it('unions lists from a previous random-DID home onto the derived drive', async ({
    expect,
  }) => {
    const { store, agentDID } = await testStore();
    const agent = store.getAgent()!;

    const oldHome = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: {
        [core.properties.name]: 'Old home',
        [core.properties.write]: [agentDID],
      },
    });
    await oldHome.save();

    const leftover = 'did:ad:leftover-workspace';
    const starred = 'did:ad:starred-doc';
    oldHome.push(server.properties.drives, [leftover], true);
    oldHome.push(FAVORITES, [starred], true);
    await oldHome.save();

    const agentResource = store.getResourceLoading(agentDID, {
      newResource: true,
    });
    await agentResource.set(
      core.properties.personalDrive,
      oldHome.subject,
      false,
    );
    await agentResource.set(core.properties.isA, [core.classes.agent], false);

    const derived = await store.ensurePrivateDrive('Home');

    expect(derived.subject).toBe(await agent.privateDriveSubject());
    expect(derived.subject).not.toBe(oldHome.subject);

    const listed = derived.getSubjects(server.properties.drives);
    expect(listed).toContain(oldHome.subject);
    expect(listed).toContain(leftover);
    expect(derived.getSubjects(FAVORITES)).toContain(starred);
  });

  it('falls back to the pointer on the Agent resource when the key cannot derive', async ({
    expect,
  }) => {
    // A keypair restored from a record that predates `Agent.privateDrive`:
    // non-deterministic signer, nothing cached.
    const { store, agentDID } = await testStore();
    const agent = store.getAgent()!;
    const home = await agent.privateDriveSubject();
    agent.privateDrive = undefined;
    vi.spyOn(agent, 'privateDriveSubject').mockRejectedValue(
      new Error('signs non-deterministically'),
    );

    const agentResource = store.getResourceLoading(agentDID, {
      newResource: true,
    });
    await agentResource.set(core.properties.personalDrive, home, false);
    await agentResource.set(core.properties.isA, [core.classes.agent], false);

    expect(await store.privateDriveSubject()).toBe(home);
    // Cached for the session: no second lookup needed.
    expect(agent.privateDrive).toBe(home);

    const drive = await store.ensurePrivateDrive('Home');
    expect(drive.subject).toBe(home);
  });

  it('still fails when neither the key nor the Agent resource knows the home', async ({
    expect,
  }) => {
    const { store } = await testStore();
    const agent = store.getAgent()!;
    agent.privateDrive = undefined;
    vi.spyOn(agent, 'privateDriveSubject').mockRejectedValue(
      new Error('signs non-deterministically'),
    );

    await expect(store.privateDriveSubject()).rejects.toThrow(
      'signs non-deterministically',
    );
  });

  it('unions lists from the home named in the agent secret when the Agent resource has no pointer', async ({
    expect,
  }) => {
    const { store, agentDID } = await testStore();
    const agent = store.getAgent()!;

    const oldHome = await store.newResource({
      isA: server.classes.drive,
      noParent: true,
      propVals: {
        [core.properties.name]: 'Old home',
        [core.properties.write]: [agentDID],
      },
    });
    await oldHome.save();

    const leftover = 'did:ad:secret-only-workspace';
    const starred = 'did:ad:secret-only-doc';
    oldHome.push(server.properties.drives, [leftover], true);
    oldHome.push(FAVORITES, [starred], true);
    await oldHome.save();

    // No `privateDrive` on the Agent resource — the shape of a self-hosted
    // account whose server never wrote one. `initialDrive`, which travels with
    // the secret rather than with any server's data, is the only record left.
    const agentResource = store.getResourceLoading(agentDID, {
      newResource: true,
    });
    await agentResource.set(core.properties.isA, [core.classes.agent], false);
    agent.initialDrive = oldHome.subject;

    const derived = await store.ensurePrivateDrive('Home');

    expect(derived.subject).toBe(await agent.privateDriveSubject());
    expect(derived.subject).not.toBe(oldHome.subject);

    const listed = derived.getSubjects(server.properties.drives);
    expect(listed).toContain(oldHome.subject);
    expect(listed).toContain(leftover);
    expect(derived.getSubjects(FAVORITES)).toContain(starred);
  });

  it('adopts a legacy drive list hosted on another origin', async ({
    expect,
  }) => {
    const { store, agentDID } = await testStore();
    const agent = store.getAgent()!;

    // The shape of a pre-DID account: the drives live on the server being
    // migrated away from, while this client points at the new home. Under an
    // origin check these are all dropped and the user arrives with nothing.
    const legacy = store.getResourceLoading(
      'https://atomicdata.dev/agents/QmExample=',
      { newResource: true },
    );
    await legacy.set(core.properties.isA, [core.classes.agent], false);
    await legacy.set(core.properties.name, 'joep.io', false);
    await legacy.set(
      server.properties.drives,
      [
        'https://atomicdata.dev/drive/xzpv34r5ibr',
        'https://staging.atomicdata.dev/drive/ckggjb1d3md',
        'http://localhost:9883/01j71grbnyq2w9',
      ],
      false,
    );

    const didAgent = store.getResourceLoading(agentDID, { newResource: true });
    await didAgent.set(core.properties.isA, [core.classes.agent], false);

    await (
      store as unknown as {
        adoptLegacyDriveList: (
          a: unknown,
          l: unknown,
          d: unknown,
        ) => Promise<void>;
      }
    ).adoptLegacyDriveList(agent, legacy, didAgent);

    const derived = await store.getResource(await agent.privateDriveSubject());
    const listed = derived.getSubjects(server.properties.drives);

    expect(listed).toContain('https://atomicdata.dev/drive/xzpv34r5ibr');
    // A different origin from the legacy agent, so still dropped — this is the
    // class that made a hosted app fetch from the user's own machine.
    expect(listed).not.toContain('http://localhost:9883/01j71grbnyq2w9');
    expect(listed).not.toContain(
      'https://staging.atomicdata.dev/drive/ckggjb1d3md',
    );
  });
});
