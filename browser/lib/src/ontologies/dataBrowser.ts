/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
 * -------------------------------- */

import { BaseProps } from '../index.js';

export const dataBrowser = {
  classes: {
    chatroom: 'https://atomicdata.dev/classes/ChatRoom',
    document: 'https://atomicdata.dev/classes/Document',
    bookmark: 'https://atomicdata.dev/class/Bookmark',
    paragraph: 'https://atomicdata.dev/classes/elements/Paragraph',
    message: 'https://atomicdata.dev/classes/Message',
    importer: 'https://atomicdata.dev/classes/Importer',
    folder: 'https://atomicdata.dev/classes/Folder',
    article: 'https://atomicdata.dev/classes/Article',
    displayStyle: 'https://atomicdata.dev/class/DisplayStyle',
    dateFormat: 'https://atomicdata.dev/classes/DateFormat',
    numberFormat: 'https://atomicdata.dev/classes/NumberFormat',
    rangeProperty: 'https://atomicdata.dev/classes/RangeProperty',
    floatRangeProperty: 'https://atomicdata.dev/classes/FloatRangeProperty',
    formattedNumber: 'https://atomicdata.dev/classes/FormattedNumber',
    selectProperty: 'https://atomicdata.dev/classes/SelectProperty',
    formattedDate: 'https://atomicdata.dev/classes/FormattedDate',
    table: 'https://atomicdata.dev/classes/Table',
    tag: 'https://atomicdata.dev/classes/Tag',
  },
  properties: {
    subResources: 'https://atomicdata.dev/properties/subresources',
    displayStyle: 'https://atomicdata.dev/property/display-style',
    publishedAt: 'https://atomicdata.dev/properties/published-at',
    elements: 'https://atomicdata.dev/properties/documents/elements',
    messages: 'https://atomicdata.dev/properties/messages',
    nextPage: 'https://atomicdata.dev/properties/nextPage',
    replyTo: 'https://atomicdata.dev/properties/replyTo',
    url: 'https://atomicdata.dev/property/url',
    preview: 'https://atomicdata.dev/property/preview',
    imageUrl: 'https://atomicdata.dev/properties/imageUrl',
    max: 'https://atomicdata.dev/properties/max',
    min: 'https://atomicdata.dev/properties/min',
    maxFloat: 'https://atomicdata.dev/properties/maxFloat',
    minFloat: 'https://atomicdata.dev/properties/minFloat',
    numberFormatting: 'https://atomicdata.dev/properties/numberFormatting',
    decimalPlaces: 'https://atomicdata.dev/properties/decimalPlaces',
    dateFormat: 'https://atomicdata.dev/properties/dateFormat',
    tableColumnWidths: 'https://atomicdata.dev/properties/tableColumnWidths',
    customNodePositioning:
      'https://atomicdata.dev/properties/custom-node-positioning',
    color: 'https://atomicdata.dev/properties/color',
    emoji: 'https://atomicdata.dev/properties/emoji',
    tags: 'https://atomicdata.dev/properties/tags',
  },
} as const;

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace DataBrowser {
  export type Chatroom = typeof dataBrowser.classes.chatroom;
  export type Document = typeof dataBrowser.classes.document;
  export type Bookmark = typeof dataBrowser.classes.bookmark;
  export type Paragraph = typeof dataBrowser.classes.paragraph;
  export type Message = typeof dataBrowser.classes.message;
  export type Importer = typeof dataBrowser.classes.importer;
  export type Folder = typeof dataBrowser.classes.folder;
  export type Article = typeof dataBrowser.classes.article;
  export type DisplayStyle = typeof dataBrowser.classes.displayStyle;
  export type DateFormat = typeof dataBrowser.classes.dateFormat;
  export type NumberFormat = typeof dataBrowser.classes.numberFormat;
  export type RangeProperty = typeof dataBrowser.classes.rangeProperty;
  export type FloatRangeProperty =
    typeof dataBrowser.classes.floatRangeProperty;
  export type FormattedNumber = typeof dataBrowser.classes.formattedNumber;
  export type SelectProperty = typeof dataBrowser.classes.selectProperty;
  export type FormattedDate = typeof dataBrowser.classes.formattedDate;
  export type Table = typeof dataBrowser.classes.table;
  export type Tag = typeof dataBrowser.classes.tag;
}

declare module '../index.js' {
  interface Classes {
    [dataBrowser.classes.chatroom]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends: typeof dataBrowser.properties.messages;
    };
    [dataBrowser.classes.document]: {
      requires: BaseProps;
      recommends:
        | typeof dataBrowser.properties.elements
        | 'https://atomicdata.dev/properties/name';
    };
    [dataBrowser.classes.bookmark]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof dataBrowser.properties.url;
      recommends:
        | typeof dataBrowser.properties.preview
        | 'https://atomicdata.dev/properties/description'
        | typeof dataBrowser.properties.imageUrl;
    };
    [dataBrowser.classes.paragraph]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/description'
        | 'https://atomicdata.dev/properties/parent';
      recommends: never;
    };
    [dataBrowser.classes.message]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/description'
        | 'https://atomicdata.dev/properties/parent';
      recommends: never;
    };
    [dataBrowser.classes.importer]: {
      requires: BaseProps;
      recommends: never;
    };
    [dataBrowser.classes.folder]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof dataBrowser.properties.displayStyle;
      recommends: typeof dataBrowser.properties.subResources;
    };
    [dataBrowser.classes.article]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/description'
        | 'https://atomicdata.dev/properties/name';
      recommends:
        | typeof dataBrowser.properties.tags
        | typeof dataBrowser.properties.publishedAt;
    };
    [dataBrowser.classes.displayStyle]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends: never;
    };
    [dataBrowser.classes.dateFormat]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/shortname';
      recommends: never;
    };
    [dataBrowser.classes.numberFormat]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/shortname';
      recommends: typeof dataBrowser.properties.decimalPlaces;
    };
    [dataBrowser.classes.rangeProperty]: {
      requires: BaseProps;
      recommends:
        | typeof dataBrowser.properties.min
        | typeof dataBrowser.properties.max;
    };
    [dataBrowser.classes.floatRangeProperty]: {
      requires: BaseProps;
      recommends:
        | typeof dataBrowser.properties.minFloat
        | typeof dataBrowser.properties.maxFloat;
    };
    [dataBrowser.classes.formattedNumber]: {
      requires: BaseProps | typeof dataBrowser.properties.numberFormatting;
      recommends: typeof dataBrowser.properties.decimalPlaces;
    };
    [dataBrowser.classes.selectProperty]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/allowsOnly';
      recommends: typeof dataBrowser.properties.max;
    };
    [dataBrowser.classes.formattedDate]: {
      requires: BaseProps | typeof dataBrowser.properties.dateFormat;
      recommends: never;
    };
    [dataBrowser.classes.table]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/classtype'
        | 'https://atomicdata.dev/properties/name';
      recommends: never;
    };
    [dataBrowser.classes.tag]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/shortname';
      recommends:
        | typeof dataBrowser.properties.color
        | typeof dataBrowser.properties.emoji;
    };
  }

  interface PropTypeMapping {
    [dataBrowser.properties.subResources]: string[];
    [dataBrowser.properties.displayStyle]: string;
    [dataBrowser.properties.publishedAt]: string;
    [dataBrowser.properties.elements]: string[];
    [dataBrowser.properties.messages]: string[];
    [dataBrowser.properties.nextPage]: string;
    [dataBrowser.properties.replyTo]: string;
    [dataBrowser.properties.url]: string;
    [dataBrowser.properties.preview]: string;
    [dataBrowser.properties.imageUrl]: string;
    [dataBrowser.properties.max]: number;
    [dataBrowser.properties.min]: number;
    [dataBrowser.properties.maxFloat]: number;
    [dataBrowser.properties.minFloat]: number;
    [dataBrowser.properties.numberFormatting]: string;
    [dataBrowser.properties.decimalPlaces]: number;
    [dataBrowser.properties.dateFormat]: string;
    [dataBrowser.properties.tableColumnWidths]: string;
    [dataBrowser.properties.customNodePositioning]: string;
    [dataBrowser.properties.color]: string;
    [dataBrowser.properties.emoji]: string;
    [dataBrowser.properties.tags]: string[];
  }

  interface PropSubjectToNameMapping {
    [dataBrowser.properties.subResources]: 'subResources';
    [dataBrowser.properties.displayStyle]: 'displayStyle';
    [dataBrowser.properties.publishedAt]: 'publishedAt';
    [dataBrowser.properties.elements]: 'elements';
    [dataBrowser.properties.messages]: 'messages';
    [dataBrowser.properties.nextPage]: 'nextPage';
    [dataBrowser.properties.replyTo]: 'replyTo';
    [dataBrowser.properties.url]: 'url';
    [dataBrowser.properties.preview]: 'preview';
    [dataBrowser.properties.imageUrl]: 'imageUrl';
    [dataBrowser.properties.max]: 'max';
    [dataBrowser.properties.min]: 'min';
    [dataBrowser.properties.maxFloat]: 'maxFloat';
    [dataBrowser.properties.minFloat]: 'minFloat';
    [dataBrowser.properties.numberFormatting]: 'numberFormatting';
    [dataBrowser.properties.decimalPlaces]: 'decimalPlaces';
    [dataBrowser.properties.dateFormat]: 'dateFormat';
    [dataBrowser.properties.tableColumnWidths]: 'tableColumnWidths';
    [dataBrowser.properties.customNodePositioning]: 'customNodePositioning';
    [dataBrowser.properties.color]: 'color';
    [dataBrowser.properties.emoji]: 'emoji';
    [dataBrowser.properties.tags]: 'tags';
  }
}
