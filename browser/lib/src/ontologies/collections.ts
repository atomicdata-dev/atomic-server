/* -----------------------------------
 * GENERATED WITH ATOMIC-GENERATE
 * -------------------------------- */

import { BaseProps } from '../index.js';

export const collections = {
  classes: {
    collection: 'https://atomicdata.dev/classes/Collection',
  },
  properties: {
    members: 'https://atomicdata.dev/properties/collection/members',
    currentPage: 'https://atomicdata.dev/properties/collection/currentPage',
    pageSize: 'https://atomicdata.dev/properties/collection/pageSize',
    property: 'https://atomicdata.dev/properties/collection/property',
    totalMembers: 'https://atomicdata.dev/properties/collection/totalMembers',
    totalPages: 'https://atomicdata.dev/properties/collection/totalPages',
    value: 'https://atomicdata.dev/properties/collection/value',
    sortBy: 'https://atomicdata.dev/properties/collection/sortBy',
    sortDesc: 'https://atomicdata.dev/properties/collection/sortDesc',
    includeExternal:
      'https://atomicdata.dev/properties/collection/includeExternal',
  },
} as const;

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace Collections {
  export type Collection = typeof collections.classes.collection;
}

declare module '../index.js' {
  interface Classes {
    [collections.classes.collection]: {
      requires: BaseProps;
      recommends:
        | 'https://atomicdata.dev/properties/name'
        | 'https://atomicdata.dev/properties/description'
        | typeof collections.properties.currentPage
        | typeof collections.properties.members
        | typeof collections.properties.pageSize
        | typeof collections.properties.property
        | typeof collections.properties.sortBy
        | typeof collections.properties.sortDesc
        | typeof collections.properties.totalMembers
        | typeof collections.properties.totalPages
        | typeof collections.properties.value
        | typeof collections.properties.includeExternal
        | 'https://atomicdata.dev/properties/incomplete';
    };
  }

  interface PropTypeMapping {
    [collections.properties.members]: string[];
    [collections.properties.currentPage]: number;
    [collections.properties.pageSize]: number;
    [collections.properties.property]: string;
    [collections.properties.totalMembers]: number;
    [collections.properties.totalPages]: number;
    [collections.properties.value]: string;
    [collections.properties.sortBy]: string;
    [collections.properties.sortDesc]: boolean;
    [collections.properties.includeExternal]: boolean;
  }

  interface PropSubjectToNameMapping {
    [collections.properties.members]: 'members';
    [collections.properties.currentPage]: 'currentPage';
    [collections.properties.pageSize]: 'pageSize';
    [collections.properties.property]: 'property';
    [collections.properties.totalMembers]: 'totalMembers';
    [collections.properties.totalPages]: 'totalPages';
    [collections.properties.value]: 'value';
    [collections.properties.sortBy]: 'sortBy';
    [collections.properties.sortDesc]: 'sortDesc';
    [collections.properties.includeExternal]: 'includeExternal';
  }
}
