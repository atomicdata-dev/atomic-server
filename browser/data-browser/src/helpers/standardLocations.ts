import { ai, core, dataBrowser, type Store } from '@tomic/react';
import {
  aiChatsFolderCert,
  decodeB64,
  isNotFound,
  isNotAvailableLocally,
} from '@tomic/lib';

/**
 * Standard locations are well-known resources inside a Drive (the Comments
 * folder, the default ontology, the tag list, …) that clients find by
 * following a dedicated property on the Drive itself — never by name or by
 * guessing subjects. This helper is the generic get-or-create for such a
 * pointer: read the property, or create the resource and set the pointer.
 *
 * Creation is client-side and signed by the current agent (requires write on
 * the drive). Two clients racing on first use can each create a resource and
 * LWW decides which pointer wins — harmless as long as the standard location
 * is a container/anchor rather than the source of truth (e.g. comments are
 * found via their `about` property, not by enumerating the Comments folder).
 */
export async function getOrCreateDriveLocation(
  store: Store,
  driveSubject: string,
  pointerProperty: string,
  create: { isA: string; name: string },
): Promise<string> {
  const drive = await store.getResource(driveSubject);
  const existing = drive.get(pointerProperty) as string | undefined;

  if (existing) {
    // A pointer to a deleted/broken resource should not be returned —
    // recreate instead (the stale pointer gets overwritten below).
    const target = await store.getResource(existing);

    if (!target.error) {
      return existing;
    }
  }

  const resource = await store.newResource({
    parent: driveSubject,
    isA: create.isA,
    propVals: { [core.properties.name]: create.name },
  });
  await resource.save();
  store.notifyResourceManuallyCreated(resource);

  await drive.set(pointerProperty, resource.subject);
  await drive.save();

  return resource.subject;
}

/** The Drive's Comments folder: default parent (= rights anchor) for comment Messages. */
export async function getOrCreateCommentsFolder(
  store: Store,
  driveSubject: string,
): Promise<string> {
  return getOrCreateDriveLocation(
    store,
    driveSubject,
    dataBrowser.properties.commentsFolder,
    { isA: dataBrowser.classes.folder, name: /* @wc-ignore */ 'Comments' },
  );
}

/** The Drive's Trash folder: where "Delete" in the sidebar parks resources. */
export async function getOrCreateTrashFolder(
  store: Store,
  driveSubject: string,
): Promise<string> {
  return getOrCreateDriveLocation(
    store,
    driveSubject,
    dataBrowser.properties.trashFolder,
    { isA: dataBrowser.classes.folder, name: /* @wc-ignore */ 'Trash' },
  );
}

/** Coalesce first use in one store; independent devices derive the same DID. */
const aiFolderRequests = new WeakMap<Store, Map<string, Promise<string>>>();

/**
 * How long a drive that cannot be read is asked about before the failure is
 * reported. The personal home is derived from the agent's key and initialized
 * on the server on first use, and a read inside that window comes back
 * not-found. Measured on CI, that window is 5.2 to 8.8 seconds (the same one
 * `sign-in-without-data`'s home wait was sized against in 191a69d), so this
 * leaves room beyond it rather than matching it.
 */
const DRIVE_READ_PATIENCE_MS = 15_000;

/**
 * The drive the chats folder belongs to, asked for again while it cannot be
 * read.
 *
 * One failed read is not the answer "this drive cannot hold a chat", and it
 * used to be treated as one: `getResource` hands the same errored resource
 * back for as long as the tab is open, so a single read landing in the home's
 * initialization window left the AI sidebar unable to save anything at all,
 * with one toast and nothing asking again.
 *
 * Every pass after the first goes to the SERVER, which is the only thing that
 * can change the answer, and which also heals the resource every other reader
 * of this drive shares. A drive that genuinely cannot be read still reports
 * that, just later.
 */
async function readDriveForChats(store: Store, driveSubject: string) {
  const first = await store.getResource(driveSubject);

  if (!first.error) return first;

  let drive = first;
  let wait = 250;
  const until = Date.now() + DRIVE_READ_PATIENCE_MS;

  while (drive.error && Date.now() < until) {
    await new Promise(resolve => setTimeout(resolve, wait));
    wait = Math.min(wait * 2, 2_000);

    try {
      drive = await store.fetchResourceFromServer(driveSubject);
    } catch {
      // Keep the resource we have: its error is the one reported by the caller.
    }
  }

  return drive;
}

export async function getOrCreateAiChatsFolder(
  store: Store,
  driveSubject: string,
): Promise<string> {
  const agent = store.getAgent();
  if (!agent) throw new Error('Sign in to create an AI chat.');
  let requests = aiFolderRequests.get(store);

  if (!requests) {
    requests = new Map();
    aiFolderRequests.set(store, requests);
  }

  const key = `${agent.subject}\0${driveSubject}`;
  const pending = requests.get(key);
  if (pending) return pending;
  const request = ensureAiChatsFolder(store, driveSubject);
  requests.set(key, request);

  try {
    return await request;
  } finally {
    requests.delete(key);
  }
}

async function ensureAiChatsFolder(
  store: Store,
  driveSubject: string,
): Promise<string> {
  const agent = store.getAgent()!;
  const drive = await readDriveForChats(store, driveSubject);
  if (drive.error) throw drive.error;
  let subject: string;

  try {
    subject = await agent.aiChatsFolderSubject(driveSubject);
  } catch (error) {
    // Older non-extractable sessions cannot derive a stable DID. Reuse their
    // existing folder until sign-in refreshes the cached identity; never mint
    // a random replacement when the pointer hasn't synced yet.
    const pointer = drive.get(ai.properties.aiChatsFolder) as
      | string
      | undefined;

    if (pointer) {
      const existing = await store.getResource(pointer);
      if (!existing.error && existing.hasClasses(dataBrowser.classes.folder))
        return pointer;
    }

    throw error;
  }

  if (store.isDestroyed(subject)) {
    throw new Error(
      'The AI Chats folder was deleted. Restore it before creating a chat.',
    );
  }

  const existing = await store.getResource(subject);

  if (existing.error) {
    if (!isNotFound(existing.error) && !isNotAvailableLocally(existing.error))
      throw existing.error;
    const folder = await store.newResource({
      subject,
      genesisCert: aiChatsFolderCert(
        decodeB64(await agent.getPublicKey()),
        driveSubject,
      ),
      parent: driveSubject,
      isA: dataBrowser.classes.folder,
      propVals: { [core.properties.name]: /* @wc-ignore */ 'AI Chats' },
    });
    await folder.save();
    store.notifyResourceManuallyCreated(folder);
  } else if (!existing.hasClasses(dataBrowser.classes.folder)) {
    throw new Error('The AI Chats location is not a folder.');
  }

  if (drive.get(ai.properties.aiChatsFolder) !== subject) {
    await drive.set(ai.properties.aiChatsFolder, subject);
    await drive.save();
  }

  return subject;
}

/** The Drive's Meetings folder: home for Meeting resources, so live and
 *  past meetings don't clutter the drive root. */
export async function getOrCreateMeetingsFolder(
  store: Store,
  driveSubject: string,
): Promise<string> {
  return getOrCreateDriveLocation(
    store,
    driveSubject,
    dataBrowser.properties.meetingsFolder,
    { isA: dataBrowser.classes.folder, name: /* @wc-ignore */ 'Meetings' },
  );
}

/** The Drive's follow-sessions ChatRoom: while an agent is being followed,
 *  their client logs which resources they visit here (issue #1229). */
export async function getOrCreateFollowSessionsChatroom(
  store: Store,
  driveSubject: string,
): Promise<string> {
  return getOrCreateDriveLocation(
    store,
    driveSubject,
    dataBrowser.properties.followSessionsChatroom,
    {
      isA: dataBrowser.classes.chatroom,
      name: /* @wc-ignore */ 'Follow sessions',
    },
  );
}
