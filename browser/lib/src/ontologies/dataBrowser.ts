/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
 * -------------------------------- */

import type { BaseProps } from '../index.js';

export const dataBrowser = {
  classes: {
    article: 'https://atomicdata.dev/classes/Article',
    bookmark: 'https://atomicdata.dev/class/Bookmark',
    chatroom: 'https://atomicdata.dev/classes/ChatRoom',
    currencyProperty:
      'https://atomicdata.dev/ontology/data-browser/class/currency-property',
    dateFormat: 'https://atomicdata.dev/classes/DateFormat',
    displayStyle: 'https://atomicdata.dev/class/DisplayStyle',
    document: 'https://atomicdata.dev/classes/Document',
    floatRangeProperty: 'https://atomicdata.dev/classes/FloatRangeProperty',
    folder: 'https://atomicdata.dev/classes/Folder',
    formattedDate: 'https://atomicdata.dev/classes/FormattedDate',
    formattedNumber: 'https://atomicdata.dev/classes/FormattedNumber',
    importer: 'https://atomicdata.dev/classes/Importer',
    message: 'https://atomicdata.dev/classes/Message',
    numberFormat: 'https://atomicdata.dev/classes/NumberFormat',
    paragraph: 'https://atomicdata.dev/classes/elements/Paragraph',
    rangeProperty: 'https://atomicdata.dev/classes/RangeProperty',
    selectProperty: 'https://atomicdata.dev/classes/SelectProperty',
    table: 'https://atomicdata.dev/classes/Table',
    tag: 'https://atomicdata.dev/classes/Tag',
    template: 'https://atomicdata.dev/ontology/data-browser/class/template',
  },
  properties: {
    color: 'https://atomicdata.dev/properties/color',
    currency: 'https://atomicdata.dev/ontology/data-browser/property/currency',
    customNodePositioning:
      'https://atomicdata.dev/properties/custom-node-positioning',
    dateFormat: 'https://atomicdata.dev/properties/dateFormat',
    decimalPlaces: 'https://atomicdata.dev/properties/decimalPlaces',
    displayStyle: 'https://atomicdata.dev/property/display-style',
    elements: 'https://atomicdata.dev/properties/documents/elements',
    emoji: 'https://atomicdata.dev/properties/emoji',
    image: 'https://atomicdata.dev/ontology/data-browser/property/image',
    imageUrl: 'https://atomicdata.dev/properties/imageUrl',
    max: 'https://atomicdata.dev/properties/max',
    maxFloat: 'https://atomicdata.dev/properties/maxFloat',
    messages: 'https://atomicdata.dev/properties/messages',
    min: 'https://atomicdata.dev/properties/min',
    minFloat: 'https://atomicdata.dev/properties/minFloat',
    nextPage: 'https://atomicdata.dev/properties/nextPage',
    numberFormatting: 'https://atomicdata.dev/properties/numberFormatting',
    preview: 'https://atomicdata.dev/property/preview',
    publishedAt: 'https://atomicdata.dev/properties/published-at',
    replyTo: 'https://atomicdata.dev/properties/replyTo',
    resources:
      'https://atomicdata.dev/ontology/data-browser/property/resources',
    subResources: 'https://atomicdata.dev/properties/subresources',
    tableColumnWidths: 'https://atomicdata.dev/properties/tableColumnWidths',
    tags: 'https://atomicdata.dev/properties/tags',
    url: 'https://atomicdata.dev/property/url',
  },
} as const;

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace DataBrowser {
  export type Article = typeof dataBrowser.classes.article;
  export type Bookmark = typeof dataBrowser.classes.bookmark;
  export type Chatroom = typeof dataBrowser.classes.chatroom;
  export type CurrencyProperty = typeof dataBrowser.classes.currencyProperty;
  export type DateFormat = typeof dataBrowser.classes.dateFormat;
  export type DisplayStyle = typeof dataBrowser.classes.displayStyle;
  export type Document = typeof dataBrowser.classes.document;
  export type FloatRangeProperty =
    typeof dataBrowser.classes.floatRangeProperty;
  export type Folder = typeof dataBrowser.classes.folder;
  export type FormattedDate = typeof dataBrowser.classes.formattedDate;
  export type FormattedNumber = typeof dataBrowser.classes.formattedNumber;
  export type Importer = typeof dataBrowser.classes.importer;
  export type Message = typeof dataBrowser.classes.message;
  export type NumberFormat = typeof dataBrowser.classes.numberFormat;
  export type Paragraph = typeof dataBrowser.classes.paragraph;
  export type RangeProperty = typeof dataBrowser.classes.rangeProperty;
  export type SelectProperty = typeof dataBrowser.classes.selectProperty;
  export type Table = typeof dataBrowser.classes.table;
  export type Tag = typeof dataBrowser.classes.tag;
  export type Template = typeof dataBrowser.classes.template;
}

declare module '../index.js' {
  interface Classes {
    [dataBrowser.classes.article]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/description'
        | 'https://atomicdata.dev/properties/name';
      recommends:
        | typeof dataBrowser.properties.tags
        | typeof dataBrowser.properties.publishedAt;
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
    [dataBrowser.classes.chatroom]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends: typeof dataBrowser.properties.messages;
    };
    [dataBrowser.classes.currencyProperty]: {
      requires: BaseProps | typeof dataBrowser.properties.currency;
      recommends: never;
    };
    [dataBrowser.classes.dateFormat]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/shortname';
      recommends: never;
    };
    [dataBrowser.classes.displayStyle]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends: never;
    };
    [dataBrowser.classes.document]: {
      requires: BaseProps;
      recommends:
        | typeof dataBrowser.properties.elements
        | 'https://atomicdata.dev/properties/name';
    };
    [dataBrowser.classes.floatRangeProperty]: {
      requires: BaseProps;
      recommends:
        | typeof dataBrowser.properties.minFloat
        | typeof dataBrowser.properties.maxFloat;
    };
    [dataBrowser.classes.folder]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof dataBrowser.properties.displayStyle;
      recommends: typeof dataBrowser.properties.subResources;
    };
    [dataBrowser.classes.formattedDate]: {
      requires: BaseProps | typeof dataBrowser.properties.dateFormat;
      recommends: never;
    };
    [dataBrowser.classes.formattedNumber]: {
      requires: BaseProps | typeof dataBrowser.properties.numberFormatting;
      recommends: typeof dataBrowser.properties.decimalPlaces;
    };
    [dataBrowser.classes.importer]: {
      requires: BaseProps;
      recommends: never;
    };
    [dataBrowser.classes.message]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/description'
        | 'https://atomicdata.dev/properties/parent';
      recommends: never;
    };
    [dataBrowser.classes.numberFormat]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/shortname';
      recommends: never;
    };
    [dataBrowser.classes.paragraph]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/description'
        | 'https://atomicdata.dev/properties/parent';
      recommends: never;
    };
    [dataBrowser.classes.rangeProperty]: {
      requires: BaseProps;
      recommends:
        | typeof dataBrowser.properties.min
        | typeof dataBrowser.properties.max;
    };
    [dataBrowser.classes.selectProperty]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/allowsOnly';
      recommends: typeof dataBrowser.properties.max;
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
    [dataBrowser.classes.template]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | 'https://atomicdata.dev/properties/description'
        | typeof dataBrowser.properties.image
        | typeof dataBrowser.properties.resources;
      recommends: never;
    };
  }

  interface PropTypeMapping {
    [dataBrowser.properties.color]: string;
    [dataBrowser.properties.currency]: string;
    [dataBrowser.properties.customNodePositioning]: string;
    [dataBrowser.properties.dateFormat]: string;
    [dataBrowser.properties.decimalPlaces]: number;
    [dataBrowser.properties.displayStyle]: string;
    [dataBrowser.properties.elements]: string[];
    [dataBrowser.properties.emoji]: string;
    [dataBrowser.properties.image]: string;
    [dataBrowser.properties.imageUrl]: string;
    [dataBrowser.properties.max]: number;
    [dataBrowser.properties.maxFloat]: number;
    [dataBrowser.properties.messages]: string[];
    [dataBrowser.properties.min]: number;
    [dataBrowser.properties.minFloat]: number;
    [dataBrowser.properties.nextPage]: string;
    [dataBrowser.properties.numberFormatting]: string;
    [dataBrowser.properties.preview]: string;
    [dataBrowser.properties.publishedAt]: number;
    [dataBrowser.properties.replyTo]: string;
    [dataBrowser.properties.resources]: string[];
    [dataBrowser.properties.subResources]: string[];
    [dataBrowser.properties.tableColumnWidths]: string;
    [dataBrowser.properties.tags]: string[];
    [dataBrowser.properties.url]: string;
  }

  interface PropSubjectToNameMapping {
    [dataBrowser.properties.color]: 'color';
    [dataBrowser.properties.currency]: 'currency';
    [dataBrowser.properties.customNodePositioning]: 'customNodePositioning';
    [dataBrowser.properties.dateFormat]: 'dateFormat';
    [dataBrowser.properties.decimalPlaces]: 'decimalPlaces';
    [dataBrowser.properties.displayStyle]: 'displayStyle';
    [dataBrowser.properties.elements]: 'elements';
    [dataBrowser.properties.emoji]: 'emoji';
    [dataBrowser.properties.image]: 'image';
    [dataBrowser.properties.imageUrl]: 'imageUrl';
    [dataBrowser.properties.max]: 'max';
    [dataBrowser.properties.maxFloat]: 'maxFloat';
    [dataBrowser.properties.messages]: 'messages';
    [dataBrowser.properties.min]: 'min';
    [dataBrowser.properties.minFloat]: 'minFloat';
    [dataBrowser.properties.nextPage]: 'nextPage';
    [dataBrowser.properties.numberFormatting]: 'numberFormatting';
    [dataBrowser.properties.preview]: 'preview';
    [dataBrowser.properties.publishedAt]: 'publishedAt';
    [dataBrowser.properties.replyTo]: 'replyTo';
    [dataBrowser.properties.resources]: 'resources';
    [dataBrowser.properties.subResources]: 'subResources';
    [dataBrowser.properties.tableColumnWidths]: 'tableColumnWidths';
    [dataBrowser.properties.tags]: 'tags';
    [dataBrowser.properties.url]: 'url';
  }
}
