// @wc-ignore-file
import {
  core,
  server,
  Datatype,
  type Resource,
  type Store,
} from '@tomic/react';

/**
 * Local search over DM text. Messages are sealed on the server, so the only
 * place their words can be searched is this device, after it has decrypted
 * them. Decrypted messages are copied, as lines of text, into chunks of up to
 * `CHUNK_SIZE` messages (one resource per chunk, like a ChatLog page) in a
 * hidden local-only drive: the local full-text index treats a chunk like any
 * resource, and
 * `registerLocalOnlyDrive` keeps it out of the outbox, sync and the server.
 * The drive is in no drive list, so no switcher, sidebar or backup lists it.
 */

/** Not in any ontology: these resources never leave the device. */
const CONVERSATION = 'https://atomicdata.dev/properties/localConversation';
/** The message subjects of a chunk, in line order: line i is message i. */
const SOURCES = 'https://atomicdata.dev/properties/localSourceMessages';
const CHUNK = 'https://atomicdata.dev/properties/localChunk';
const DATATYPES = {
  [SOURCES]: Datatype.RESOURCEARRAY,
  [CONVERSATION]: Datatype.ATOMIC_URL,
  [CHUNK]: Datatype.INTEGER,
};

/** The same size as a ChatLog page (planning/chat-log.md). */
export const CHUNK_SIZE = 256;
const DRIVE_KEY = 'atomic.messageSearchDrive.';

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
    // Rights for this agent only: without them the copies cannot be removed
    // again (`forgetConversation`), since destroy checks write on the parents.
    propVals: {
      [core.properties.name]: 'Message search',
      [core.properties.write]: [agent],
      [core.properties.read]: [agent],
    },
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

interface Chunk {
  resource: Resource;
  sources: string[];
  lines: string[];
}

interface ConversationState {
  chunks: Chunk[];
  known: Set<string>;
}

/** Per conversation, what this session knows of its chunks. */
const states = new Map<string, Promise<ConversationState>>();
/** Per conversation, the end of the writes queued so far. */
const queues = new Map<string, Promise<void>>();

/**
 * The subject of chunk `index` of `conversation`: an `atomic:` identifier like
 * any other (64 bytes, base64url), taken from a hash so the same chunk always
 * gets the same name. A DID may not carry a path, so it cannot be built from
 * the drive's subject.
 */
async function chunkSubject(
  conversation: string,
  index: number,
): Promise<string> {
  const data = new TextEncoder().encode(`chunk\n${conversation}\n${index}`);
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-512', data));
  const base64 = btoa(String.fromCharCode(...hash));

  return `atomic:${base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}

/** One line per message: a newline would shift every line after it. */
const toLine = (text: string) => text.replace(/\s*\n\s*/g, ' ').trim();

async function loadState(
  store: Store,
  drive: string,
  conversation: string,
): Promise<ConversationState> {
  // One local lookup per conversation and session. After that the chunks are
  // addressed by subject, so a new message is a single update.
  const found = await store.search('', {
    parents: drive,
    filters: { [CONVERSATION]: conversation },
    limit: 10_000,
  });
  const chunks: Chunk[] = [];

  for (const subject of found) {
    const resource = await store.getResource(subject);
    const sources = (resource.get(SOURCES) as string[] | undefined) ?? [];
    const text = (resource.get(core.properties.name) as string) ?? '';

    chunks[Number(resource.get(CHUNK) ?? chunks.length)] = {
      resource,
      sources,
      lines: text.split('\n'),
    };
  }

  const dense = chunks.filter(Boolean);

  return { chunks: dense, known: new Set(dense.flatMap(c => c.sources)) };
}

const stateOf = (store: Store, drive: string, conversation: string) => {
  let state = states.get(conversation);

  if (!state) {
    state = loadState(store, drive, conversation);
    states.set(conversation, state);
    state.catch(() => states.delete(conversation));
  }

  return state;
};

interface Pending {
  message: string;
  line: string;
}

/** Per conversation, messages waiting for the next flush. */
const pending = new Map<string, Pending[]>();

/**
 * Append every pending line of `conversation`: one `set` and one `save` per
 * chunk touched, whatever the number of messages.
 */
async function flush(store: Store, conversation: string): Promise<void> {
  const items = pending.get(conversation) ?? [];

  pending.delete(conversation);

  const drive = items.length > 0 ? await indexDrive(store) : undefined;

  if (!drive) return;

  const state = await stateOf(store, drive, conversation);
  const fresh: Pending[] = [];

  for (const item of items) {
    if (!state.known.has(item.message)) {
      state.known.add(item.message);
      fresh.push(item);
    }
  }

  while (fresh.length > 0) {
    const open = state.chunks.at(-1);

    if (open && open.sources.length < CHUNK_SIZE) {
      const taken = fresh.splice(0, CHUNK_SIZE - open.sources.length);

      open.sources.push(...taken.map(t => t.message));
      open.lines.push(...taken.map(t => t.line));
      await open.resource.set(
        SOURCES,
        open.sources,
        false,
        Datatype.RESOURCEARRAY,
      );
      await open.resource.set(
        core.properties.name,
        open.lines.join('\n'),
        false,
        Datatype.STRING,
      );
      await open.resource.save();
    } else {
      const taken = fresh.splice(0, CHUNK_SIZE);
      const index = state.chunks.length;
      const resource = await store.newResource({
        // Deterministic: the chunk of a conversation has one name.
        subject: await chunkSubject(conversation, index),
        parent: drive,
        propVals: {
          [core.properties.name]: taken.map(t => t.line).join('\n'),
          [SOURCES]: taken.map(t => t.message),
          [CONVERSATION]: conversation,
          [CHUNK]: index,
        },
        propDatatypes: DATATYPES,
      });

      await resource.save();
      state.chunks.push({
        resource,
        sources: taken.map(t => t.message),
        lines: taken.map(t => t.line),
      });
    }
  }
}

/**
 * Remember the decrypted `text` of `message`, once. This only queues it: all
 * messages queued in the same tick (a conversation opening) are written
 * together, so opening 50 messages is one save. Resolves once they are saved.
 */
export function indexMessage(
  store: Store,
  message: string,
  conversation: string,
  text: string,
): Promise<void> {
  const line = toLine(text);

  if (!line) return Promise.resolve();

  const list = pending.get(conversation);

  if (list) {
    list.push({ message, line });
  } else {
    pending.set(conversation, [{ message, line }]);
  }

  // Writes of one conversation take turns: they all update the open chunk.
  // The first message of a tick schedules the flush; the rest ride along.
  const previous = queues.get(conversation) ?? Promise.resolve();
  const next = previous.then(async () => {
    try {
      await flush(store, conversation);
    } catch (error) {
      // Start from what is on disk the next time.
      states.delete(conversation);
      store.notifyError(error);
    }
  });

  queues.set(conversation, next);

  return next;
}

export interface MessageMatch {
  conversation: string;
  /** The message whose line matched. */
  message: string;
  /** The text of that message. */
  text: string;
}

/** The line of `lines` that best fits `query`: all words, else any word. */
function bestLine(lines: string[], query: string): number {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const lower = lines.map(l => l.toLowerCase());
  const all = lower.findIndex(l => words.every(w => l.includes(w)));

  if (all !== -1) return all;

  const any = lower.findIndex(l => words.some(w => l.includes(w)));

  return any === -1 ? 0 : any;
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
    const chunk = await store.getResource(hit);
    const conversation = chunk.get(CONVERSATION) as string | undefined;
    const text = chunk.get(core.properties.name) as string | undefined;
    const sources = (chunk.get(SOURCES) as string[] | undefined) ?? [];

    if (!conversation || !text || found.has(conversation)) continue;

    const lines = text.split('\n');
    const i = bestLine(lines, query);

    found.set(conversation, {
      conversation,
      message: sources[i] ?? '',
      text: lines[i],
    });
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

  // After any write still queued, so none recreates a chunk.
  await queues.get(conversation);
  states.delete(conversation);

  const chunks = await store.search('', {
    parents: drive,
    filters: { [CONVERSATION]: conversation },
    limit: 10_000,
  });

  await Promise.all(
    chunks.map(async chunk => (await store.getResource(chunk)).destroy()),
  );
}
