/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
 * -------------------------------- */

import type { OntologyBaseObject, BaseProps, JSONObject } from '../index.js';

export const dataBrowser = {
  classes: {
    article: 'https://atomicdata.dev/classes/Article',
    bookmark: 'https://atomicdata.dev/class/Bookmark',
    chatroom: 'https://atomicdata.dev/classes/ChatRoom',
    chatLog: 'https://atomicdata.dev/classes/ChatLog',
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
    followEvent: 'https://atomicdata.dev/classes/FollowEvent',
    meeting: 'https://atomicdata.dev/classes/Meeting',
    numberFormat: 'https://atomicdata.dev/classes/NumberFormat',
    paragraph: 'https://atomicdata.dev/classes/elements/Paragraph',
    rangeProperty: 'https://atomicdata.dev/classes/RangeProperty',
    selectProperty: 'https://atomicdata.dev/classes/SelectProperty',
    table: 'https://atomicdata.dev/classes/Table',
    view: 'https://atomicdata.dev/classes/View',
    dashboard: 'https://atomicdata.dev/classes/Dashboard',
    block: 'https://atomicdata.dev/classes/Block',
    tag: 'https://atomicdata.dev/classes/Tag',
    template: 'https://atomicdata.dev/ontology/data-browser/class/template',
    documentV2: 'https://atomicdata.dev/classes/DocumentV2',
    plainText: 'https://atomicdata.dev/classes/PlainText',
  },
  properties: {
    about: 'https://atomicdata.dev/properties/about',
    color: 'https://atomicdata.dev/properties/color',
    commentsFolder: 'https://atomicdata.dev/properties/commentsFolder',
    trashFolder: 'https://atomicdata.dev/properties/trashFolder',
    trashedFrom: 'https://atomicdata.dev/properties/trashedFrom',
    coverImage: 'https://atomicdata.dev/properties/coverImage',
    coverImageFocus: 'https://atomicdata.dev/properties/coverImageFocus',
    followSessionsChatroom:
      'https://atomicdata.dev/properties/followSessionsChatroom',
    currentMeetings: 'https://atomicdata.dev/properties/currentMeetings',
    meetingsFolder: 'https://atomicdata.dev/properties/meetingsFolder',
    meetingStartedAt: 'https://atomicdata.dev/properties/meetingStartedAt',
    meetingEndedAt: 'https://atomicdata.dev/properties/meetingEndedAt',
    meetingLeader: 'https://atomicdata.dev/properties/meetingLeader',
    currency: 'https://atomicdata.dev/ontology/data-browser/property/currency',
    customNodePositioning:
      'https://atomicdata.dev/properties/custom-node-positioning',
    dateFormat: 'https://atomicdata.dev/properties/dateFormat',
    decimalPlaces: 'https://atomicdata.dev/properties/decimalPlaces',
    displayStyle: 'https://atomicdata.dev/property/display-style',
    elements: 'https://atomicdata.dev/properties/documents/elements',
    emoji: 'https://atomicdata.dev/properties/emoji',
    icon: 'https://atomicdata.dev/properties/icon',
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
    sortOrder: 'https://atomicdata.dev/properties/sortOrder',
    subResources: 'https://atomicdata.dev/properties/subresources',
    tableColumnWidths: 'https://atomicdata.dev/properties/tableColumnWidths',
    tableViews: 'https://atomicdata.dev/properties/table-views',
    tableDefaultView: 'https://atomicdata.dev/properties/table-default-view',
    tableRowDefaults: 'https://atomicdata.dev/properties/table-row-defaults',
    viewKind: 'https://atomicdata.dev/properties/view-kind',
    viewFilters: 'https://atomicdata.dev/properties/view-filters',
    viewSortBy: 'https://atomicdata.dev/properties/view-sort-by',
    viewSortDesc: 'https://atomicdata.dev/properties/view-sort-desc',
    viewColumns: 'https://atomicdata.dev/properties/view-columns',
    viewGroupBy: 'https://atomicdata.dev/properties/view-group-by',
    viewEndProp: 'https://atomicdata.dev/properties/view-end-prop',
    viewTimerExclusive:
      'https://atomicdata.dev/properties/view-timer-exclusive',
    viewSplitLanguages:
      'https://atomicdata.dev/properties/view-split-languages',
    viewDerivedColumns:
      'https://atomicdata.dev/properties/view-derived-columns',
    viewColumnOrder: 'https://atomicdata.dev/properties/view-column-order',
    viewAggregates: 'https://atomicdata.dev/properties/view-aggregates',
    viewRowActions: 'https://atomicdata.dev/properties/view-row-actions',
    viewQuickAdd: 'https://atomicdata.dev/properties/view-quick-add',
    viewDashboard: 'https://atomicdata.dev/properties/view-dashboard',
    viewGroupByColumn: 'https://atomicdata.dev/properties/view-group-by-column',
    viewGroupGranularity:
      'https://atomicdata.dev/properties/view-group-granularity',
    dashboardBlocks: 'https://atomicdata.dev/properties/dashboard-blocks',
    dashboardLayout: 'https://atomicdata.dev/properties/dashboard-layout',
    blockKind: 'https://atomicdata.dev/properties/block-kind',
    blockSource: 'https://atomicdata.dev/properties/block-source',
    blockView: 'https://atomicdata.dev/properties/block-view',
    blockQuery: 'https://atomicdata.dev/properties/block-query',
    blockAggregate: 'https://atomicdata.dev/properties/block-aggregate',
    blockChartSpec: 'https://atomicdata.dev/properties/block-chart-spec',
    blockQuickAdd: 'https://atomicdata.dev/properties/block-quick-add',
    tags: 'https://atomicdata.dev/properties/tags',
    tagList: 'https://atomicdata.dev/ontology/data-browser/property/tag-list',
    url: 'https://atomicdata.dev/property/url',
    documentContent: 'https://atomicdata.dev/properties/documentContent',
  },
  __classDefs: {
    ['https://atomicdata.dev/classes/Article']: [
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/tags',
      'https://atomicdata.dev/properties/published-at',
    ],
    ['https://atomicdata.dev/class/Bookmark']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/property/url',
      'https://atomicdata.dev/property/preview',
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/imageUrl',
    ],
    ['https://atomicdata.dev/classes/ChatRoom']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/messages',
    ],
    ['https://atomicdata.dev/classes/ChatLog']: [
      'https://atomicdata.dev/properties/parent',
      'https://atomicdata.dev/properties/about',
    ],
    ['https://atomicdata.dev/ontology/data-browser/class/currency-property']: [
      'https://atomicdata.dev/ontology/data-browser/property/currency',
    ],
    ['https://atomicdata.dev/classes/DateFormat']: [
      'https://atomicdata.dev/properties/shortname',
    ],
    ['https://atomicdata.dev/class/DisplayStyle']: [
      'https://atomicdata.dev/properties/name',
    ],
    ['https://atomicdata.dev/classes/Document']: [
      'https://atomicdata.dev/properties/documents/elements',
      'https://atomicdata.dev/properties/name',
    ],
    ['https://atomicdata.dev/classes/FloatRangeProperty']: [
      'https://atomicdata.dev/properties/minFloat',
      'https://atomicdata.dev/properties/maxFloat',
    ],
    ['https://atomicdata.dev/classes/Folder']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/property/display-style',
      'https://atomicdata.dev/properties/subresources',
    ],
    ['https://atomicdata.dev/classes/FormattedDate']: [
      'https://atomicdata.dev/properties/dateFormat',
    ],
    ['https://atomicdata.dev/classes/FormattedNumber']: [
      'https://atomicdata.dev/properties/numberFormatting',
      'https://atomicdata.dev/properties/decimalPlaces',
    ],
    ['https://atomicdata.dev/classes/Importer']: [],
    ['https://atomicdata.dev/classes/Message']: [
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/parent',
      'https://atomicdata.dev/properties/about',
      'https://atomicdata.dev/properties/replyTo',
    ],
    ['https://atomicdata.dev/classes/NumberFormat']: [
      'https://atomicdata.dev/properties/shortname',
    ],
    ['https://atomicdata.dev/classes/elements/Paragraph']: [
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/parent',
    ],
    ['https://atomicdata.dev/classes/RangeProperty']: [
      'https://atomicdata.dev/properties/min',
      'https://atomicdata.dev/properties/max',
    ],
    ['https://atomicdata.dev/classes/SelectProperty']: [
      'https://atomicdata.dev/properties/allowsOnly',
      'https://atomicdata.dev/properties/max',
    ],
    ['https://atomicdata.dev/classes/Table']: [
      'https://atomicdata.dev/properties/classtype',
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/tableColumnWidths',
      'https://atomicdata.dev/properties/table-views',
      'https://atomicdata.dev/properties/table-default-view',
      'https://atomicdata.dev/properties/table-row-defaults',
    ],
    ['https://atomicdata.dev/classes/View']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/view-kind',
      'https://atomicdata.dev/properties/view-filters',
      'https://atomicdata.dev/properties/view-sort-by',
      'https://atomicdata.dev/properties/view-sort-desc',
      'https://atomicdata.dev/properties/view-columns',
      'https://atomicdata.dev/properties/view-group-by',
      'https://atomicdata.dev/properties/view-end-prop',
      'https://atomicdata.dev/properties/view-timer-exclusive',
      'https://atomicdata.dev/properties/view-split-languages',
      'https://atomicdata.dev/properties/view-derived-columns',
      'https://atomicdata.dev/properties/view-column-order',
      'https://atomicdata.dev/properties/view-aggregates',
      'https://atomicdata.dev/properties/view-row-actions',
      'https://atomicdata.dev/properties/view-quick-add',
      'https://atomicdata.dev/properties/view-dashboard',
      'https://atomicdata.dev/properties/view-group-by-column',
      'https://atomicdata.dev/properties/view-group-granularity',
    ],
    ['https://atomicdata.dev/classes/Dashboard']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/dashboard-blocks',
      'https://atomicdata.dev/properties/dashboard-layout',
    ],
    ['https://atomicdata.dev/classes/Block']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/block-kind',
      'https://atomicdata.dev/properties/block-source',
      'https://atomicdata.dev/properties/block-view',
      'https://atomicdata.dev/properties/block-query',
      'https://atomicdata.dev/properties/block-aggregate',
      'https://atomicdata.dev/properties/block-chart-spec',
      'https://atomicdata.dev/properties/block-quick-add',
      'https://atomicdata.dev/properties/description',
    ],
    ['https://atomicdata.dev/classes/Tag']: [
      'https://atomicdata.dev/properties/shortname',
      'https://atomicdata.dev/properties/color',
      'https://atomicdata.dev/properties/emoji',
    ],
    ['https://atomicdata.dev/ontology/data-browser/class/template']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/ontology/data-browser/property/image',
      'https://atomicdata.dev/ontology/data-browser/property/resources',
    ],
    ['https://atomicdata.dev/classes/DocumentV2']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/documentContent',
    ],
    ['https://atomicdata.dev/classes/PlainText']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/description',
    ],
  },
} as const satisfies OntologyBaseObject;

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace DataBrowser {
  export type Article = typeof dataBrowser.classes.article;
  export type Bookmark = typeof dataBrowser.classes.bookmark;
  export type Chatroom = typeof dataBrowser.classes.chatroom;
  export type ChatLog = typeof dataBrowser.classes.chatLog;
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
  export type FollowEvent = typeof dataBrowser.classes.followEvent;
  export type Meeting = typeof dataBrowser.classes.meeting;
  export type NumberFormat = typeof dataBrowser.classes.numberFormat;
  export type Paragraph = typeof dataBrowser.classes.paragraph;
  export type RangeProperty = typeof dataBrowser.classes.rangeProperty;
  export type SelectProperty = typeof dataBrowser.classes.selectProperty;
  export type Table = typeof dataBrowser.classes.table;
  export type Tag = typeof dataBrowser.classes.tag;
  export type Template = typeof dataBrowser.classes.template;
  export type DocumentV2 = typeof dataBrowser.classes.documentV2;
  export type PlainText = typeof dataBrowser.classes.plainText;
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
    [dataBrowser.classes.chatLog]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/parent';
      recommends: typeof dataBrowser.properties.about;
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
      recommends:
        | typeof dataBrowser.properties.about
        | typeof dataBrowser.properties.replyTo;
    };
    [dataBrowser.classes.followEvent]: {
      requires: BaseProps;
      recommends: 'https://atomicdata.dev/properties/description';
    };
    [dataBrowser.classes.meeting]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends:
        | typeof dataBrowser.properties.documentContent
        | typeof dataBrowser.properties.messages
        | typeof dataBrowser.properties.meetingStartedAt
        | typeof dataBrowser.properties.meetingEndedAt
        | typeof dataBrowser.properties.meetingLeader;
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
      recommends:
        | typeof dataBrowser.properties.tableColumnWidths
        | typeof dataBrowser.properties.tableViews
        | typeof dataBrowser.properties.tableDefaultView
        | typeof dataBrowser.properties.tableRowDefaults;
    };
    [dataBrowser.classes.view]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof dataBrowser.properties.viewKind;
      recommends:
        | typeof dataBrowser.properties.viewFilters
        | typeof dataBrowser.properties.viewSortBy
        | typeof dataBrowser.properties.viewSortDesc
        | typeof dataBrowser.properties.viewColumns
        | typeof dataBrowser.properties.viewGroupBy
        | typeof dataBrowser.properties.viewEndProp
        | typeof dataBrowser.properties.viewTimerExclusive
        | typeof dataBrowser.properties.viewSplitLanguages
        | typeof dataBrowser.properties.viewDerivedColumns
        | typeof dataBrowser.properties.viewColumnOrder
        | typeof dataBrowser.properties.viewAggregates
        | typeof dataBrowser.properties.viewRowActions
        | typeof dataBrowser.properties.viewQuickAdd
        | typeof dataBrowser.properties.viewDashboard
        | typeof dataBrowser.properties.viewGroupByColumn
        | typeof dataBrowser.properties.viewGroupGranularity;
    };
    [dataBrowser.classes.dashboard]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends:
        | typeof dataBrowser.properties.dashboardBlocks
        | typeof dataBrowser.properties.dashboardLayout;
    };
    [dataBrowser.classes.block]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof dataBrowser.properties.blockKind;
      recommends:
        | typeof dataBrowser.properties.blockSource
        | typeof dataBrowser.properties.blockView
        | typeof dataBrowser.properties.blockQuery
        | typeof dataBrowser.properties.blockAggregate
        | typeof dataBrowser.properties.blockChartSpec
        | typeof dataBrowser.properties.blockQuickAdd
        | 'https://atomicdata.dev/properties/description';
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
    [dataBrowser.classes.documentV2]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/name';
      recommends: typeof dataBrowser.properties.documentContent;
    };
    [dataBrowser.classes.plainText]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | 'https://atomicdata.dev/properties/description';
      recommends: never;
    };
  }

  interface PropTypeMapping {
    [dataBrowser.properties.about]: string;
    [dataBrowser.properties.color]: string;
    [dataBrowser.properties.commentsFolder]: string;
    [dataBrowser.properties.trashFolder]: string;
    [dataBrowser.properties.trashedFrom]: string;
    [dataBrowser.properties.coverImage]: string;
    [dataBrowser.properties.coverImageFocus]: number;
    [dataBrowser.properties.followSessionsChatroom]: string;
    [dataBrowser.properties.currentMeetings]: string[];
    [dataBrowser.properties.meetingsFolder]: string;
    [dataBrowser.properties.meetingStartedAt]: number;
    [dataBrowser.properties.meetingEndedAt]: number;
    [dataBrowser.properties.meetingLeader]: string;
    [dataBrowser.properties.currency]: string;
    [dataBrowser.properties.customNodePositioning]: Record<
      string,
      [x: number, y: number]
    >;
    [dataBrowser.properties.dateFormat]: string;
    [dataBrowser.properties.decimalPlaces]: number;
    [dataBrowser.properties.displayStyle]: string;
    [dataBrowser.properties.elements]: string[];
    [dataBrowser.properties.emoji]: string;
    [dataBrowser.properties.icon]: string;
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
    [dataBrowser.properties.publishedAt]: string;
    [dataBrowser.properties.replyTo]: string;
    [dataBrowser.properties.resources]: string[];
    [dataBrowser.properties.subResources]: string[];
    [dataBrowser.properties.tableColumnWidths]: number[];
    [dataBrowser.properties.tableViews]: string[];
    [dataBrowser.properties.tableDefaultView]: string;
    [dataBrowser.properties.tableRowDefaults]: JSONObject;
    [dataBrowser.properties.viewKind]: string;
    [dataBrowser.properties.viewDashboard]: string;
    [dataBrowser.properties.viewFilters]: Array<{
      property?: string;
      value?: string;
      operator?: string;
    }>;
    [dataBrowser.properties.viewSortBy]: string;
    [dataBrowser.properties.viewSortDesc]: boolean;
    [dataBrowser.properties.viewColumns]: string[];
    [dataBrowser.properties.viewGroupBy]: string;
    [dataBrowser.properties.viewEndProp]: string;
    [dataBrowser.properties.viewTimerExclusive]: boolean;
    [dataBrowser.properties.viewSplitLanguages]: string[];
    [dataBrowser.properties.viewDerivedColumns]: Array<{
      id?: string;
      label?: string;
      kind?: string;
      args?: Record<string, string | number>;
      width?: number;
    }>;
    [dataBrowser.properties.viewColumnOrder]: string[];
    [dataBrowser.properties.viewAggregates]: Array<{
      id?: string;
      property?: string;
      function?: string;
    }>;
    [dataBrowser.properties.viewRowActions]: Array<{
      id?: string;
      label?: string;
      kind?: string;
      property?: string;
      value?: string | number;
    }>;
    [dataBrowser.properties.viewQuickAdd]: {
      label?: string;
      field?: string;
      placeholder?: string;
      presets?: { kind?: string; property?: string; value?: string | number }[];
    };
    [dataBrowser.properties.viewGroupByColumn]: string;
    [dataBrowser.properties.viewGroupGranularity]: string;
    [dataBrowser.properties.dashboardBlocks]: string[];
    [dataBrowser.properties.dashboardLayout]: Array<{
      subject?: string;
      w?: number;
      h?: number;
    }>;
    [dataBrowser.properties.blockKind]: string;
    [dataBrowser.properties.blockSource]: string;
    [dataBrowser.properties.blockView]: string;
    [dataBrowser.properties.blockQuery]: Array<{
      property?: string;
      derived?: string;
      operator?: string;
      value?: string;
    }>;
    [dataBrowser.properties.blockAggregate]: {
      function?: string;
      property?: string;
      derived?: string;
    };
    [dataBrowser.properties.blockQuickAdd]: {
      label?: string;
      field?: string;
      placeholder?: string;
      presets?: { kind?: string; property?: string; value?: string | number }[];
    };
    [dataBrowser.properties.blockChartSpec]: {
      mark?: string;
      field?: string;
      granularity?: string;
      encoding?: {
        x?: { field?: string; granularity?: string; timeUnit?: string };
      };
    };
    [dataBrowser.properties.tags]: string[];
    [dataBrowser.properties.tagList]: string[];
    [dataBrowser.properties.url]: string;
    [dataBrowser.properties.documentContent]: never;
  }

  interface PropSubjectToNameMapping {
    [dataBrowser.properties.about]: 'about';
    [dataBrowser.properties.color]: 'color';
    [dataBrowser.properties.commentsFolder]: 'commentsFolder';
    [dataBrowser.properties.trashFolder]: 'trashFolder';
    [dataBrowser.properties.trashedFrom]: 'trashedFrom';
    [dataBrowser.properties.coverImage]: 'coverImage';
    [dataBrowser.properties.coverImageFocus]: 'coverImageFocus';
    [dataBrowser.properties.followSessionsChatroom]: 'followSessionsChatroom';
    [dataBrowser.properties.currentMeetings]: 'currentMeetings';
    [dataBrowser.properties.meetingsFolder]: 'meetingsFolder';
    [dataBrowser.properties.meetingStartedAt]: 'meetingStartedAt';
    [dataBrowser.properties.meetingEndedAt]: 'meetingEndedAt';
    [dataBrowser.properties.meetingLeader]: 'meetingLeader';
    [dataBrowser.properties.currency]: 'currency';
    [dataBrowser.properties.customNodePositioning]: 'customNodePositioning';
    [dataBrowser.properties.dateFormat]: 'dateFormat';
    [dataBrowser.properties.decimalPlaces]: 'decimalPlaces';
    [dataBrowser.properties.displayStyle]: 'displayStyle';
    [dataBrowser.properties.elements]: 'elements';
    [dataBrowser.properties.emoji]: 'emoji';
    [dataBrowser.properties.icon]: 'icon';
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
    [dataBrowser.properties.tableViews]: 'tableViews';
    [dataBrowser.properties.tableDefaultView]: 'tableDefaultView';
    [dataBrowser.properties.tableRowDefaults]: 'tableRowDefaults';
    [dataBrowser.properties.viewKind]: 'viewKind';
    [dataBrowser.properties.viewDashboard]: 'viewDashboard';
    [dataBrowser.properties.viewFilters]: 'viewFilters';
    [dataBrowser.properties.viewSortBy]: 'viewSortBy';
    [dataBrowser.properties.viewSortDesc]: 'viewSortDesc';
    [dataBrowser.properties.viewColumns]: 'viewColumns';
    [dataBrowser.properties.viewGroupBy]: 'viewGroupBy';
    [dataBrowser.properties.viewEndProp]: 'viewEndProp';
    [dataBrowser.properties.viewTimerExclusive]: 'viewTimerExclusive';
    [dataBrowser.properties.viewSplitLanguages]: 'viewSplitLanguages';
    [dataBrowser.properties.viewDerivedColumns]: 'viewDerivedColumns';
    [dataBrowser.properties.viewColumnOrder]: 'viewColumnOrder';
    [dataBrowser.properties.viewAggregates]: 'viewAggregates';
    [dataBrowser.properties.viewRowActions]: 'viewRowActions';
    [dataBrowser.properties.viewQuickAdd]: 'viewQuickAdd';
    [dataBrowser.properties.viewGroupByColumn]: 'viewGroupByColumn';
    [dataBrowser.properties.viewGroupGranularity]: 'viewGroupGranularity';
    [dataBrowser.properties.dashboardBlocks]: 'dashboardBlocks';
    [dataBrowser.properties.dashboardLayout]: 'dashboardLayout';
    [dataBrowser.properties.blockKind]: 'blockKind';
    [dataBrowser.properties.blockSource]: 'blockSource';
    [dataBrowser.properties.blockView]: 'blockView';
    [dataBrowser.properties.blockQuery]: 'blockQuery';
    [dataBrowser.properties.blockAggregate]: 'blockAggregate';
    [dataBrowser.properties.blockChartSpec]: 'blockChartSpec';
    [dataBrowser.properties.blockQuickAdd]: 'blockQuickAdd';
    [dataBrowser.properties.tags]: 'tags';
    [dataBrowser.properties.tagList]: 'tagList';
    [dataBrowser.properties.url]: 'url';
    [dataBrowser.properties.documentContent]: 'documentContent';
  }
}
