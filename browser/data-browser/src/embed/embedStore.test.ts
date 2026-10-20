// @vitest-environment jsdom
// @wc-ignore-file
import { expect, it } from 'vitest';
import { core, dataBrowser, server, type NativeChannel } from '@tomic/react';
import { fetchPluginList } from '../components/CustomViewProvider';
import { hasBasicInstanceHandler } from '../components/forms/NewForm/useNewResourceUI';
import {
  adoptDriveOf,
  createEmbedStore,
  registerEmbedActions,
} from './embedStore';

const AGENT = 'atomic:agent:pZyZYvKoOcwczHXJoYvYctgrHXn2pZ7qfeWMyoUfQ_8';
const DRIVE = 'atomic:50cViRzEn58gVUYWYypS4CRIFwx4AvFVtNjxLMCc5tg4p0DLZmnD2YV';
const driveJsonAd = JSON.stringify({
  '@id': DRIVE,
  [core.properties.isA]: [server.classes.drive],
  [core.properties.name]: "Tester's Drive",
});

/** The app's side, as `atomic_lib::host::embed` answers: it signs a commit
 * of its agent and refuses anything else. */
function host() {
  const refused: string[] = [];
  const channel: NativeChannel = {
    async call(method, args) {
      switch (method) {
        case 'init':
          return true;
        case 'agent':
          return AGENT;
        case 'sign':
          refused.push(args[0] as string);
          throw new Error('only commits are signed');
        case 'getResourcesWithSnapshots':
          return (args[0] as string[]).map(s => ({
            jsonAd: s === DRIVE ? driveJsonAd : null,
            snapshot: null,
          }));
        case 'query':
          return { subjects: [], resources: [], count: 0 };
        case 'outboxEntries':
          return [];
        default:
          return null;
      }
    },
  };

  return { channel, refused };
}

// Seen on a fresh account: the drive page showed its raw subject and "Empty",
// with "[Auth] cookie installation failed: only commits are signed" in the log.
it('makes no auth cookie and never asks the host to sign a request', async () => {
  const { channel, refused } = host();
  const { store } = await createEmbedStore(channel);

  expect(store.getAgent()?.subject).toBe(AGENT);
  expect(store.noServer).toBe(true);

  const drive = await store.getResource(DRIVE);
  // What the drive page's plugin lookup does on its second pass.
  await store.fetchResourceFromServer(DRIVE);
  await new Promise(r => setTimeout(r, 20));

  expect(drive.error).toBeUndefined();
  expect(store.getResourceLoading(DRIVE).get(core.properties.name)).toBe(
    "Tester's Drive",
  );
  expect(refused).toEqual([]);
  expect(document.cookie).not.toContain('atomic_session');
});

it('lists no server plugins, without signing a request', async () => {
  const { channel, refused } = host();
  const { store } = await createEmbedStore(channel);
  const [views, manifests] = await fetchPluginList(store, DRIVE);

  expect(views.size).toBe(0);
  expect(manifests.size).toBe(0);
  expect(refused).toEqual([]);
});

it('makes a document, folder or chat room without a form, like the web app', () => {
  registerEmbedActions();

  for (const c of [
    dataBrowser.classes.documentV2,
    dataBrowser.classes.folder,
    dataBrowser.classes.chatroom,
  ]) {
    expect(hasBasicInstanceHandler(c)).toBe(true);
  }
});

// A table lists its rows by parent and class, which the host answers from its
// per-drive index. The page had no current drive, so it never asked and the
// table looked empty.
it('follows the drive of what it shows, so a table can ask for its rows', async () => {
  const TABLE = `${DRIVE}-table`;
  const channel: NativeChannel = {
    async call(method, args) {
      switch (method) {
        case 'init':
          return true;
        case 'agent':
          return AGENT;
        case 'getResourcesWithSnapshots':
          return (args[0] as string[]).map(s => ({
            jsonAd:
              s === DRIVE
                ? driveJsonAd
                : s === TABLE
                  ? JSON.stringify({
                      '@id': TABLE,
                      [core.properties.isA]: [dataBrowser.classes.table],
                      [core.properties.name]: 'Tasks',
                      [core.properties.parent]: DRIVE,
                    })
                  : null,
            snapshot: null,
          }));
        case 'outboxEntries':
          return [];
        default:
          return null;
      }
    },
  };
  const { store } = await createEmbedStore(channel);

  expect(store.getDrive()).toBeFalsy();
  await adoptDriveOf(store, TABLE);
  expect(store.getDrive()).toBe(DRIVE);
});
