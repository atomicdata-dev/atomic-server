import {
  conversations,
  core,
  Datatype,
  server,
  type Agent,
  type Resource,
  type Store,
} from '@tomic/react';
import {
  addEpoch,
  encryptionKeyFor,
  sealPayload,
  type ConversationMember,
} from './conversationCrypto';

/**
 * Starting, finding and posting in encrypted conversations (DMs and group
 * chats). A conversation is a drive of its own: its members can read it and
 * append to it, and nobody can change it, its creator included, because a
 * `write` on the drive would reach every message in it. Each message is
 * writable by its author only. Messages are SealedMessages, so its host
 * stores ciphertext. See
 * `planning/encrypted-conversations.md`.
 */

const APPEND = 'https://atomicdata.dev/properties/append';

/** Thrown when someone can't be messaged yet. */
export class NoEncryptionKeyError extends Error {
  constructor(public readonly agent: string) {
    super(
      'This person has no encryption key yet. They need to open Atomic once before you can message them.',
    );
  }
}

function requireSubject(agent: Agent | undefined): string {
  if (!agent?.subject) {
    throw new Error('Sign in to use messages.');
  }

  return agent.subject;
}

/**
 * Publishes the agent's `encryptionKey` on its Agent resource, so others can
 * start a conversation with it. Does nothing when it is already there. The key
 * is derived from the agent's own key, so every device publishes the same one.
 */
export async function ensureEncryptionKey(
  store: Store,
  agent: Agent,
): Promise<string> {
  const subject = requireSubject(agent);
  const key = await encryptionKeyFor(agent);
  const agentResource = await store.getResource(subject);

  if (agentResource.error) {
    throw agentResource.error;
  }

  if (agentResource.get(conversations.properties.encryptionKey) !== key) {
    await agentResource.set(conversations.properties.encryptionKey, key, false);
    await agentResource.save();
  }

  return key;
}

/** Someone's `encryptionKey`, read fresh from their Agent resource. */
async function memberFor(
  store: Store,
  agent: string,
): Promise<ConversationMember> {
  const resource = await store.fetchResourceFromServer(agent);
  const key = resource.get(conversations.properties.encryptionKey);

  if (typeof key !== 'string' || key === '') {
    throw new NoEncryptionKeyError(agent);
  }

  return { agent, encryptionKey: key };
}

/** Whether `conversation` has exactly these members. */
export function hasMembers(conversation: Resource, members: string[]): boolean {
  const read = conversation.get(core.properties.read);

  if (!Array.isArray(read) || read.length !== new Set(members).size) {
    return false;
  }

  return members.every(member => read.includes(member));
}

/**
 * Creates a conversation between the signed-in agent and `others`, and
 * returns it saved. The caller lists it on the private drive.
 *
 * An empty `others` is a note to yourself. Nobody else needs a host for it, so
 * it stays on this device like a browser-only drive and never reaches a server
 * (a managed node would refuse it as "not enrolled" anyway). A non-empty
 * `others` that holds nothing but yourself is a mistake and throws.
 */
export async function startConversation(
  store: Store,
  others: string[],
): Promise<Resource> {
  const agent = store.getAgent();
  const me = requireSubject(agent);
  const memberSubjects = [me, ...others.filter(other => other !== me)];
  const noteToSelf = others.length === 0;

  if (memberSubjects.length < 2 && !noteToSelf) {
    throw new Error('Pick someone to message.');
  }

  // Publish our own key first: the others need it to add us to a later epoch.
  const myKey = await ensureEncryptionKey(store, agent!);
  const members = [
    { agent: me, encryptionKey: myKey },
    ...(await Promise.all(
      memberSubjects.slice(1).map(other => memberFor(store, other)),
    )),
  ];
  const keyring = await addEpoch(members);

  const conversation = await store.newResource({
    isA: [conversations.classes.conversation, server.classes.drive],
    noParent: true,
    propVals: {
      // Stored data, not UI text: the page shows the members instead.
      [core.properties.name]: /* @wc-ignore */ 'Conversation',
      [core.properties.read]: memberSubjects,
      [APPEND]: memberSubjects,
      [conversations.properties.conversationKeys]: keyring,
    },
    // `append` and the keyring are not in the cached ontology on first use.
    propDatatypes: {
      [APPEND]: Datatype.RESOURCEARRAY,
      [conversations.properties.conversationKeys]: Datatype.STRING,
    },
  });

  // Before the first save: registration is what keeps the genesis out of the
  // outbox. `makeDriveLocal` is for a drive a server may already hold, and
  // verifies its copy against that server first; this one does not exist yet.
  if (noteToSelf) store.registerLocalOnlyDrive(conversation.subject);

  await conversation.save();
  // The server grants the creator `write` at genesis. Give it up, or the
  // creator could rewrite what the others said.
  conversation.remove(core.properties.write);
  await conversation.save();

  return conversation;
}

/** Encrypts `text` and posts it in `conversation`. */
export async function sendSealedMessage(
  store: Store,
  conversation: Resource,
  text: string,
  replyTo?: string,
): Promise<void> {
  const agent = store.getAgent();
  const me = requireSubject(agent);
  const keyring = conversation.get(conversations.properties.conversationKeys);

  if (typeof keyring !== 'string') {
    throw new Error('This conversation has no keys, so nothing can be sent.');
  }

  const sealed = await sealPayload(agent!, keyring, conversation.subject, {
    text,
    replyTo,
  });

  const message = await store.newResource({
    parent: conversation.subject,
    isA: conversations.classes.sealedMessage,
    propVals: {
      [conversations.properties.sealed]: sealed,
      // Members may only append; the message stays writable by its author.
      [core.properties.write]: [me],
    },
  });

  await message.save();
  store.notifyResourceManuallyCreated(message);
}
