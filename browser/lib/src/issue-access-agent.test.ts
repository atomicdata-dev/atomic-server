import { describe, expect, it } from 'vitest';
import { Agent } from './agent.js';
import {
  grantAccessAgent,
  grantedTargetsOf,
  isRevokedAccessAgentName,
  issueAccessAgent,
  revokeAccessAgent,
} from './issue-access-agent.js';
import { core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import { server } from './ontologies/server.js';
import { testStore } from './test-store.js';

async function createWorkspace(
  store: Awaited<ReturnType<typeof testStore>>['store'],
  owner: string,
  name: string,
) {
  const drive = await store.newResource({
    noParent: true,
    isA: server.classes.drive,
    propVals: {
      [core.properties.name]: name,
      [core.properties.read]: [owner],
      [core.properties.write]: [owner],
    },
  });
  await drive.save();

  return drive;
}

describe('issueAccessAgent', () => {
  it('mints a new agent without switching the signed-in session', async () => {
    const { store, agentDID } = await testStore();
    const drive = await createWorkspace(store, agentDID, 'Notes');

    const issued = await issueAccessAgent(store, {
      name: 'Raycast',
      write: false,
      targets: [drive.subject],
    });

    expect(store.getAgent()?.subject).toBe(agentDID);
    expect(issued.subject).toMatch(/^did:ad:agent:/);
    expect(issued.subject).not.toBe(agentDID);

    const profile = await store.getResource(issued.subject);
    expect(profile.get(core.properties.name)).toBe('Raycast');
    expect(profile.get(core.properties.isA)).toEqual([core.classes.agent]);
    expect(profile.get(core.properties.publicKey)).toBeTruthy();

    const read = drive.get(core.properties.read) as string[];
    const write = drive.get(core.properties.write) as string[];
    expect(read).toContain(issued.subject);
    expect(write).not.toContain(issued.subject);
    expect(write).toContain(agentDID);
  });

  it('parents the key and clears `new` so the App keys list can see it', async () => {
    const { store, agentDID } = await testStore();
    const drive = await createWorkspace(store, agentDID, 'Notes');
    const folder = await store.newResource({
      parent: drive.subject,
      propVals: {
        [core.properties.name]: 'App keys',
      },
    });
    await folder.save();

    const issued = await issueAccessAgent(store, {
      name: 'Raycast',
      write: false,
      targets: [drive.subject],
      parent: folder.subject,
    });

    const profile = await store.getResource(issued.subject);
    expect(profile.new).toBe(false);
    expect(profile.get(core.properties.parent)).toBe(folder.subject);
    expect(profile.get(core.properties.name)).toBe('Raycast');
  });

  it('round-trips the secret to a working agent', async () => {
    const { store, agentDID } = await testStore();
    const drive = await createWorkspace(store, agentDID, 'Notes');

    const issued = await issueAccessAgent(store, {
      name: 'CLI',
      write: true,
      targets: [drive.subject],
    });

    const fromSecret = Agent.fromSecret(issued.secret, 'js');
    expect(fromSecret.subject).toBe(issued.subject);
    expect(await fromSecret.sign('hello')).toMatch(/./);

    const write = drive.get(core.properties.write) as string[];
    expect(write).toContain(issued.subject);
  });

  it('refuses to mint without a name, targets, or a signed-in agent', async () => {
    const { store, agentDID } = await testStore();
    const drive = await createWorkspace(store, agentDID, 'Notes');

    await expect(
      issueAccessAgent(store, {
        name: '   ',
        write: false,
        targets: [drive.subject],
      }),
    ).rejects.toThrow('name');

    await expect(
      issueAccessAgent(store, {
        name: 'Raycast',
        write: false,
        targets: [],
      }),
    ).rejects.toThrow('resource');

    store.setAgent(undefined);
    await expect(
      issueAccessAgent(store, {
        name: 'Raycast',
        write: false,
        targets: [drive.subject],
      }),
    ).rejects.toThrow('signed out');
  });
});

describe('grantAccessAgent and revokeAccessAgent', () => {
  it('adds an existing key to another workspace and later removes it', async () => {
    const { store, agentDID } = await testStore();
    const notes = await createWorkspace(store, agentDID, 'Notes');
    const photos = await createWorkspace(store, agentDID, 'Photos');

    const issued = await issueAccessAgent(store, {
      name: 'Raycast',
      write: false,
      targets: [notes.subject],
    });

    await grantAccessAgent(store, issued.subject, [photos.subject], false);
    expect(photos.get(core.properties.read) as string[]).toContain(
      issued.subject,
    );

    await revokeAccessAgent(store, issued.subject, [
      notes.subject,
      photos.subject,
    ]);

    expect(notes.get(core.properties.read) as string[]).not.toContain(
      issued.subject,
    );
    expect(photos.get(core.properties.read) as string[]).not.toContain(
      issued.subject,
    );
    expect(notes.get(core.properties.write) as string[]).toContain(agentDID);

    const profile = await store.getResource(issued.subject);
    expect(profile.get(core.properties.name)).toBe('Raycast (revoked)');
    expect(isRevokedAccessAgentName('Raycast (revoked)')).toBe(true);
    expect(isRevokedAccessAgentName('Raycast')).toBe(false);
  });

  it('grants a folder without putting the key on the workspace', async () => {
    const { store, agentDID } = await testStore();
    const drive = await createWorkspace(store, agentDID, 'Notes');
    const folder = await store.newResource({
      parent: drive.subject,
      isA: dataBrowser.classes.folder,
      propVals: {
        [core.properties.name]: 'Project notes',
        [core.properties.write]: [agentDID],
      },
    });
    await folder.save();

    const issued = await issueAccessAgent(store, {
      name: 'Raycast',
      write: false,
      targets: [folder.subject],
    });

    expect(folder.get(core.properties.read) as string[]).toContain(
      issued.subject,
    );
    expect(drive.get(core.properties.read) as string[]).not.toContain(
      issued.subject,
    );
    expect(await grantedTargetsOf(store, issued.subject)).toEqual([
      folder.subject,
    ]);

    // Revoke with no caller list — the recorded folder grant must still die.
    const report = await revokeAccessAgent(store, issued.subject, []);
    expect(report.revoked).toEqual([folder.subject]);
    expect(report.failed).toEqual([]);

    const afterFolder = await store.getResource(folder.subject);
    expect(afterFolder.get(core.properties.read) as string[]).not.toContain(
      issued.subject,
    );
    expect(await grantedTargetsOf(store, issued.subject)).toEqual([]);
  });
});

describe('revokeAccessAgent reports what it actually did', () => {
  it('does not claim success while a workspace still grants the key', async () => {
    const { store, agentDID } = await testStore();
    const reachable = await createWorkspace(store, agentDID, 'Notes');
    const issued = await issueAccessAgent(store, {
      name: 'Raycast',
      write: true,
      targets: [reachable.subject],
    });

    // A workspace this device cannot load — the shape of a drive on a server
    // that is down, or one the session no longer has rights to read.
    const unreachable = 'did:ad:workspace-that-cannot-be-loaded';

    const report = await revokeAccessAgent(store, issued.subject, [
      reachable.subject,
      unreachable,
    ]);

    expect(report.revoked).toEqual([reachable.subject]);
    expect(report.failed.map(f => f.target)).toEqual([unreachable]);

    // The key must NOT be labelled revoked while a target was left unchecked:
    // the label is what the user trusts when they stop worrying about it.
    const agentResource = await store.getResource(issued.subject);
    expect(
      isRevokedAccessAgentName(
        (agentResource.get(core.properties.name) as string) ?? '',
      ),
    ).toBe(false);
  });

  it('marks the key revoked once every target is confirmed clear', async () => {
    const { store, agentDID } = await testStore();
    const one = await createWorkspace(store, agentDID, 'Notes');
    const two = await createWorkspace(store, agentDID, 'Projects');
    const issued = await issueAccessAgent(store, {
      name: 'Raycast',
      write: true,
      targets: [one.subject, two.subject],
    });

    const report = await revokeAccessAgent(store, issued.subject, [
      one.subject,
      two.subject,
    ]);

    expect(report.failed).toEqual([]);
    expect(report.revoked.sort()).toEqual([one.subject, two.subject].sort());

    for (const drive of [one, two]) {
      const after = await store.getResource(drive.subject);
      expect(after.getSubjects(core.properties.read)).not.toContain(
        issued.subject,
      );
      expect(after.getSubjects(core.properties.write)).not.toContain(
        issued.subject,
      );
    }

    const agentResource = await store.getResource(issued.subject);
    expect(
      isRevokedAccessAgentName(
        (agentResource.get(core.properties.name) as string) ?? '',
      ),
    ).toBe(true);
  });

  it('reports a target that never granted the key as untouched', async () => {
    const { store, agentDID } = await testStore();
    const granted = await createWorkspace(store, agentDID, 'Notes');
    const other = await createWorkspace(store, agentDID, 'Unrelated');
    const issued = await issueAccessAgent(store, {
      name: 'Raycast',
      write: false,
      targets: [granted.subject],
    });

    const report = await revokeAccessAgent(store, issued.subject, [
      granted.subject,
      other.subject,
    ]);

    expect(report.revoked).toEqual([granted.subject]);
    expect(report.untouched).toEqual([other.subject]);
    expect(report.failed).toEqual([]);
  });
});
