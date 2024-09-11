/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
 * -------------------------------- */

import type { BaseProps } from '../index.js';

export const core = {
  classes: {
    class: 'https://atomicdata.dev/classes/Class',
    property: 'https://atomicdata.dev/classes/Property',
    agent: 'https://atomicdata.dev/classes/Agent',
    datatype: 'https://atomicdata.dev/classes/Datatype',
    ontology: 'https://atomicdata.dev/class/ontology',
  },
  properties: {
    allowsOnly: 'https://atomicdata.dev/properties/allowsOnly',
    classtype: 'https://atomicdata.dev/properties/classtype',
    datatype: 'https://atomicdata.dev/properties/datatype',
    description: 'https://atomicdata.dev/properties/description',
    incomplete: 'https://atomicdata.dev/properties/incomplete',
    isA: 'https://atomicdata.dev/properties/isA',
    isDynamic: 'https://atomicdata.dev/properties/isDynamic',
    name: 'https://atomicdata.dev/properties/name',
    parent: 'https://atomicdata.dev/properties/parent',
    read: 'https://atomicdata.dev/properties/read',
    recommends: 'https://atomicdata.dev/properties/recommends',
    requires: 'https://atomicdata.dev/properties/requires',
    shortname: 'https://atomicdata.dev/properties/shortname',
    write: 'https://atomicdata.dev/properties/write',
    publicKey: 'https://atomicdata.dev/properties/publicKey',
    instances: 'https://atomicdata.dev/properties/instances',
    properties: 'https://atomicdata.dev/properties/properties',
    classes: 'https://atomicdata.dev/properties/classes',
    isLocked: 'https://atomicdata.dev/properties/isLocked',
    localId: 'https://atomicdata.dev/properties/localId',
  },
} as const;

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace Core {
  export type Class = typeof core.classes.class;
  export type Property = typeof core.classes.property;
  export type Agent = typeof core.classes.agent;
  export type Datatype = typeof core.classes.datatype;
  export type Ontology = typeof core.classes.ontology;
}

declare module '../index.js' {
  interface Classes {
    [core.classes.class]: {
      requires:
        | BaseProps
        | typeof core.properties.shortname
        | typeof core.properties.description;
      recommends:
        | typeof core.properties.recommends
        | typeof core.properties.requires;
    };
    [core.classes.property]: {
      requires:
        | BaseProps
        | typeof core.properties.shortname
        | typeof core.properties.datatype
        | typeof core.properties.description;
      recommends:
        | typeof core.properties.classtype
        | typeof core.properties.isDynamic
        | typeof core.properties.isLocked
        | typeof core.properties.allowsOnly;
    };
    [core.classes.agent]: {
      requires: BaseProps | typeof core.properties.publicKey;
      recommends:
        | typeof core.properties.name
        | typeof core.properties.description
        | 'https://atomicdata.dev/properties/drives';
    };
    [core.classes.datatype]: {
      requires:
        | BaseProps
        | typeof core.properties.shortname
        | typeof core.properties.description;
      recommends: never;
    };
    [core.classes.ontology]: {
      requires:
        | BaseProps
        | typeof core.properties.description
        | typeof core.properties.shortname;
      recommends:
        | typeof core.properties.classes
        | typeof core.properties.properties
        | typeof core.properties.instances;
    };
  }

  interface PropTypeMapping {
    [core.properties.allowsOnly]: string[];
    [core.properties.classtype]: string;
    [core.properties.datatype]: string;
    [core.properties.description]: string;
    [core.properties.incomplete]: boolean;
    [core.properties.isA]: string[];
    [core.properties.isDynamic]: boolean;
    [core.properties.name]: string;
    [core.properties.parent]: string;
    [core.properties.read]: string[];
    [core.properties.recommends]: string[];
    [core.properties.requires]: string[];
    [core.properties.shortname]: string;
    [core.properties.write]: string[];
    [core.properties.publicKey]: string;
    [core.properties.instances]: string[];
    [core.properties.properties]: string[];
    [core.properties.classes]: string[];
    [core.properties.isLocked]: boolean;
    [core.properties.localId]: string;
  }

  interface PropSubjectToNameMapping {
    [core.properties.allowsOnly]: 'allowsOnly';
    [core.properties.classtype]: 'classtype';
    [core.properties.datatype]: 'datatype';
    [core.properties.description]: 'description';
    [core.properties.incomplete]: 'incomplete';
    [core.properties.isA]: 'isA';
    [core.properties.isDynamic]: 'isDynamic';
    [core.properties.name]: 'name';
    [core.properties.parent]: 'parent';
    [core.properties.read]: 'read';
    [core.properties.recommends]: 'recommends';
    [core.properties.requires]: 'requires';
    [core.properties.shortname]: 'shortname';
    [core.properties.write]: 'write';
    [core.properties.publicKey]: 'publicKey';
    [core.properties.instances]: 'instances';
    [core.properties.properties]: 'properties';
    [core.properties.classes]: 'classes';
    [core.properties.isLocked]: 'isLocked';
    [core.properties.localId]: 'localId';
  }
}
