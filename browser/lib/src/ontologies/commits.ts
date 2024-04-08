/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
 * -------------------------------- */

import type { BaseProps } from '../index.js';

export const commits = {
  classes: {
    commit: 'https://atomicdata.dev/classes/Commit',
  },
  properties: {
    subject: 'https://atomicdata.dev/properties/subject',
    createdAt: 'https://atomicdata.dev/properties/createdAt',
    lastCommit: 'https://atomicdata.dev/properties/lastCommit',
    previousCommit: 'https://atomicdata.dev/properties/previousCommit',
    signer: 'https://atomicdata.dev/properties/signer',
    set: 'https://atomicdata.dev/properties/set',
    push: 'https://atomicdata.dev/properties/push',
    remove: 'https://atomicdata.dev/properties/remove',
    destroy: 'https://atomicdata.dev/properties/destroy',
    signature: 'https://atomicdata.dev/properties/signature',
  },
} as const;

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace Commits {
  export type Commit = typeof commits.classes.commit;
}

declare module '../index.js' {
  interface Classes {
    [commits.classes.commit]: {
      requires:
        | BaseProps
        | typeof commits.properties.createdAt
        | typeof commits.properties.signature
        | typeof commits.properties.signer
        | typeof commits.properties.subject;
      recommends:
        | typeof commits.properties.destroy
        | typeof commits.properties.remove
        | typeof commits.properties.set;
    };
  }

  interface PropTypeMapping {
    [commits.properties.subject]: string;
    [commits.properties.createdAt]: number;
    [commits.properties.lastCommit]: string;
    [commits.properties.previousCommit]: string;
    [commits.properties.signer]: string;
    [commits.properties.set]: string;
    [commits.properties.push]: string;
    [commits.properties.remove]: string[];
    [commits.properties.destroy]: boolean;
    [commits.properties.signature]: string;
  }

  interface PropSubjectToNameMapping {
    [commits.properties.subject]: 'subject';
    [commits.properties.createdAt]: 'createdAt';
    [commits.properties.lastCommit]: 'lastCommit';
    [commits.properties.previousCommit]: 'previousCommit';
    [commits.properties.signer]: 'signer';
    [commits.properties.set]: 'set';
    [commits.properties.push]: 'push';
    [commits.properties.remove]: 'remove';
    [commits.properties.destroy]: 'destroy';
    [commits.properties.signature]: 'signature';
  }
}
