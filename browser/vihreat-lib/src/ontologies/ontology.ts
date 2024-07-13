/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
 * -------------------------------- */

import type { BaseProps } from '@tomic/lib';

export const ontology = {
  classes: {
    program: 'http://localhost:9883/o/Program',
    title: 'http://localhost:9883/o/Title',
    paragraph: 'http://localhost:9883/o/Paragraph',
    actionitem: 'http://localhost:9883/o/ActionItem',
  },
  properties: {
    title: 'http://localhost:9883/o/title',
    subtitle: 'http://localhost:9883/o/subtitle',
    elements: 'http://localhost:9883/o/elements',
    approvedon: 'http://localhost:9883/o/approvedOn',
    updatedon: 'http://localhost:9883/o/updatedOn',
    retiredon: 'http://localhost:9883/o/retiredOn',
    staleon: 'http://localhost:9883/o/staleOn',
    text: 'http://localhost:9883/o/text',
    titlelevel: 'http://localhost:9883/o/titleLevel',
  },
} as const;

export type Program = typeof ontology.classes.program;
export type Title = typeof ontology.classes.title;
export type Paragraph = typeof ontology.classes.paragraph;
export type Actionitem = typeof ontology.classes.actionitem;

declare module '@tomic/lib' {
  interface Classes {
    [ontology.classes.program]: {
      requires:
        | BaseProps
        | typeof ontology.properties.title
        | typeof ontology.properties.elements;
      recommends:
        | typeof ontology.properties.subtitle
        | typeof ontology.properties.approvedon
        | typeof ontology.properties.updatedon
        | typeof ontology.properties.retiredon
        | typeof ontology.properties.staleon;
    };
    [ontology.classes.title]: {
      requires:
        | BaseProps
        | typeof ontology.properties.text
        | typeof ontology.properties.titlelevel;
      recommends: never;
    };
    [ontology.classes.paragraph]: {
      requires: BaseProps | typeof ontology.properties.text;
      recommends: never;
    };
    [ontology.classes.actionitem]: {
      requires: BaseProps | typeof ontology.properties.text;
      recommends: never;
    };
  }

  interface PropTypeMapping {
    [ontology.properties.title]: string;
    [ontology.properties.subtitle]: string;
    [ontology.properties.elements]: string[];
    [ontology.properties.approvedon]: string;
    [ontology.properties.updatedon]: string;
    [ontology.properties.retiredon]: string;
    [ontology.properties.staleon]: string;
    [ontology.properties.text]: string;
    [ontology.properties.titlelevel]: number;
  }

  interface PropSubjectToNameMapping {
    [ontology.properties.title]: 'title';
    [ontology.properties.subtitle]: 'subtitle';
    [ontology.properties.elements]: 'elements';
    [ontology.properties.approvedon]: 'approvedon';
    [ontology.properties.updatedon]: 'updatedon';
    [ontology.properties.retiredon]: 'retiredon';
    [ontology.properties.staleon]: 'staleon';
    [ontology.properties.text]: 'text';
    [ontology.properties.titlelevel]: 'titlelevel';
  }
}
