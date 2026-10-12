/* -----------------------------------
 * Hand-maintained, in the shape @tomic/cli generates.
 *
 * The `conversations` ontology is defined in `lib/defaults/conversations.json`
 * and bootstrapped by every server, but its Ontology resource does not exist on
 * atomicdata.dev, so `ad-generate ontologies` cannot produce this file. Keep it
 * in sync with `lib/defaults/conversations.json` by hand until it is published.
 * -------------------------------- */

import type { OntologyBaseObject, BaseProps } from '../index.js';

export const conversations = {
  classes: {
    conversation: 'https://atomicdata.dev/classes/Conversation',
    sealedMessage: 'https://atomicdata.dev/classes/SealedMessage',
  },
  properties: {
    encryptionKey: 'https://atomicdata.dev/properties/encryptionKey',
    conversationKeys: 'https://atomicdata.dev/properties/conversationKeys',
    sealed: 'https://atomicdata.dev/properties/sealed',
    conversations: 'https://atomicdata.dev/properties/conversations',
  },
  __classDefs: {
    ['https://atomicdata.dev/classes/Conversation']: [
      'https://atomicdata.dev/properties/conversationKeys',
      'https://atomicdata.dev/properties/read',
      'https://atomicdata.dev/properties/append',
    ],
    ['https://atomicdata.dev/classes/SealedMessage']: [
      'https://atomicdata.dev/properties/parent',
      'https://atomicdata.dev/properties/sealed',
    ],
  },
} as const satisfies OntologyBaseObject;

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace Conversations {
  export type Conversation = typeof conversations.classes.conversation;
  export type SealedMessage = typeof conversations.classes.sealedMessage;
}

declare module '../index.js' {
  interface Classes {
    [conversations.classes.conversation]: {
      requires: BaseProps | typeof conversations.properties.conversationKeys;
      // `append` too, but no ontology here maps it to a name yet.
      recommends: 'https://atomicdata.dev/properties/read';
    };
    [conversations.classes.sealedMessage]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/parent'
        | typeof conversations.properties.sealed;
      recommends: never;
    };
  }

  interface PropTypeMapping {
    [conversations.properties.encryptionKey]: string;
    [conversations.properties.conversationKeys]: string;
    [conversations.properties.sealed]: string;
    [conversations.properties.conversations]: string[];
  }

  interface PropSubjectToNameMapping {
    [conversations.properties.encryptionKey]: 'encryptionKey';
    [conversations.properties.conversationKeys]: 'conversationKeys';
    [conversations.properties.sealed]: 'sealed';
    [conversations.properties.conversations]: 'conversations';
  }
}
