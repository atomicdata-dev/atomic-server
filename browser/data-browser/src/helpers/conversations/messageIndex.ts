// @wc-ignore-file
import { core, server, Datatype, type Store } from '@tomic/react';

/**
 * Local search over DM text. Messages are sealed on the server, so the only
 * place their words can be searched is this device, after it has decrypted
 * them. Each decrypted message is copied into one small resource in a hidden
 * local-only drive: the local full-text index treats it like any resource, and
 * `registerLocalOnlyDrive` keeps it out of the outbox, sync and the server.
 * The drive is in no drive list, so no switcher, sidebar or backup lists it.
 */

/** Not in any ontology: these resources never leave the device. */
const SOURCE = 'https://atomicdata.dev/properties/localSourceMessage';
const CONVERSATION = 'https://atomicdata.dev/properties/localConversation';
const DATATYPES = {
  [SOURCE]: Datatype.ATOMIC_URL,
  [CONVERSATION]: Datatype.ATOMIC_URL,
};
const DRIVE_KEY = 'atomic.messageSearchDrive.';

const requested = new Set<string>();

async function indexDrive(store: Store): Promise<string | undefined> {
  const agent = store.getAgent()?.subject;

  if (!agent) return undefined;

  try {
    const known = localStorage.getItem(DRIVE_KEY + agent);

    if (known && store.isLocalOnlyDrive(known)) return known;
  } catch {
    // No storage: fall through and make a drive for this session.
  }

  const drive = await store.newResource({
    isA: server.classes.drive,
    noParent: true,
    propVals: { [core.properties.name]: 'Message search' },
  });

  // Before the first save: registration is what keeps it out of the outbox.
  store.registerLocalOnlyDrive(drive.subject);
  await drive.save();

  try {
    localStorage.setItem(DRIVE_KEY + agent, drive.subject);
  } catch {
    // Searchable this session only.
  }

  return drive.subject;
}

/** Remember the decrypted `text` of `message`, once. */
export async function indexMessage(
  store: Store,
  message: string,
  conversation: string,
  text: string,
): Promise<void> {
  if (!text.trim() || requested.has(message)) return;

  requested.add(message);

  try {
    const drive = await indexDrive(store);

    if (!drive) return;

    const [existing] = await store.search('', {
      parents: drive,
      filters: { [SOURCE]: message },
      limit: 1,
    });

    if (existing) return;

    const copy = await store.newResource({
      parent: drive,
      propVals: {
        [core.properties.name]: text,
        [SOURCE]: message,
        [CONVERSATION]: conversation,
      },
      propDatatypes: DATATYPES,
    });

    await copy.save();
  } catch (error) {
    requested.delete(message);
    store.notifyError(error);
  }
}

export interface MessageMatch {
  conversation: string;
  /** The text of a message that matched. */
  text: string;
}

/** The conversations with a decrypted message matching `query`, best first. */
export async function searchMessages(
  store: Store,
  query: string,
): Promise<MessageMatch[]> {
  const drive = await indexDrive(store);

  if (!drive || !query.trim()) return [];

  const hits = await store.search(query, { parents: drive, limit: 30 });
  const found = new Map<string, MessageMatch>();

  for (const hit of hits) {
    const copy = await store.getResource(hit);
    const conversation = copy.get(CONVERSATION) as string | undefined;
    const text = copy.get(core.properties.name) as string | undefined;

    if (conversation && text && !found.has(conversation)) {
      found.set(conversation, { conversation, text });
    }
  }

  return [...found.values()];
}

/** Forget the local text of a conversation this device no longer shows. */
export async function forgetConversation(
  store: Store,
  conversation: string,
): Promise<void> {
  const drive = await indexDrive(store);

  if (!drive) return;

  const copies = await store.search('', {
    parents: drive,
    filters: { [CONVERSATION]: conversation },
    limit: 10_000,
  });

  await Promise.all(
    copies.map(async copy => {
      const resource = await store.getResource(copy);
      requested.delete(resource.get(SOURCE) as string);
      await resource.destroy();
    }),
  );
}
