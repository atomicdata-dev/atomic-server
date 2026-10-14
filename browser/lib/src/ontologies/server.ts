/* -----------------------------------
 * GENERATED WITH @tomic/cli
 * For more info on how to use ontologies: https://github.com/atomicdata-dev/atomic-server/blob/develop/browser/cli/readme.md
 * -------------------------------- */

import type { OntologyBaseObject, BaseProps, JSONValue } from '../index.js';

export const server = {
  classes: {
    drive: 'https://atomicdata.dev/classes/Drive',
    endpoint: 'https://atomicdata.dev/classes/Endpoint',
    endpointResponse:
      'https://atomicdata.dev/ontology/server/class/endpoint-response',
    error: 'https://atomicdata.dev/classes/Error',
    file: 'https://atomicdata.dev/classes/File',
    invite: 'https://atomicdata.dev/classes/Invite',
    redirect: 'https://atomicdata.dev/classes/Redirect',
    plugin: 'https://atomicdata.dev/classes/Plugin',
    release: 'https://atomicdata.dev/classes/Release',
    installation: 'https://atomicdata.dev/classes/Installation',
    listing: 'https://atomicdata.dev/classes/Listing',
  },
  properties: {
    agent: 'https://atomicdata.dev/properties/invite/agent',
    altText: 'https://atomicdata.dev/ontology/server/property/alt-text',
    attachments: 'https://atomicdata.dev/properties/attachments',
    checksum: 'https://atomicdata.dev/properties/checksum',
    children: 'https://atomicdata.dev/properties/children',
    createdBy: 'https://atomicdata.dev/properties/createdBy',
    defaultOntology:
      'https://atomicdata.dev/ontology/server/property/default-ontology',
    destination: 'https://atomicdata.dev/properties/destination',
    downloadUrl: 'https://atomicdata.dev/properties/downloadURL',
    drives: 'https://atomicdata.dev/properties/drives',
    filename: 'https://atomicdata.dev/properties/filename',
    filesize: 'https://atomicdata.dev/properties/filesize',
    imageHeight: 'https://atomicdata.dev/properties/imageHeight',
    imageWidth: 'https://atomicdata.dev/properties/imageWidth',
    internalId: 'https://atomicdata.dev/properties/internalId',
    mimetype: 'https://atomicdata.dev/properties/mimetype',
    isPost: 'https://atomicdata.dev/properties/endpoint/isPost',
    parameters: 'https://atomicdata.dev/properties/endpoint/parameters',
    property: 'https://atomicdata.dev/properties/search/property',
    publicKey: 'https://atomicdata.dev/properties/invite/publicKey',
    redirectAgent: 'https://atomicdata.dev/properties/invite/redirectAgent',
    responseMessage:
      'https://atomicdata.dev/ontology/server/property/response-message',
    results: 'https://atomicdata.dev/properties/endpoint/results',
    status: 'https://atomicdata.dev/ontology/server/property/status',
    target: 'https://atomicdata.dev/properties/invite/target',
    usagesLeft: 'https://atomicdata.dev/properties/invite/usagesLeft',
    users: 'https://atomicdata.dev/properties/invite/users',
    write: 'https://atomicdata.dev/properties/invite/write',
    config: 'https://atomicdata.dev/properties/config',
    jsonSchema: 'https://atomicdata.dev/properties/jsonSchema',
    namespace: 'https://atomicdata.dev/properties/namespace',
    version: 'https://atomicdata.dev/properties/version',
    pluginAuthor: 'https://atomicdata.dev/properties/pluginAuthor',
    plugins: 'https://atomicdata.dev/properties/plugins',
    pluginFile: 'https://atomicdata.dev/properties/pluginFile',
    pluginAgent: 'https://atomicdata.dev/properties/pluginAgent',
    pluginPermissions: 'https://atomicdata.dev/properties/pluginPermissions',
    searchChunks: 'https://atomicdata.dev/properties/search/chunks',
    llmTxt: 'https://atomicdata.dev/properties/llm-txt',
    signalingUrl: 'https://atomicdata.dev/properties/signaling-url',
    runtime: 'https://atomicdata.dev/properties/runtime',
    world: 'https://atomicdata.dev/properties/world',
    manifest: 'https://atomicdata.dev/properties/manifest',
    source: 'https://atomicdata.dev/properties/source',
    package: 'https://atomicdata.dev/properties/package',
    schemas: 'https://atomicdata.dev/properties/schemas',
    releaseId: 'https://atomicdata.dev/properties/releaseId',
    previousRelease: 'https://atomicdata.dev/properties/previousRelease',
    publisher: 'https://atomicdata.dev/properties/publisher',
    release: 'https://atomicdata.dev/properties/release',
    grants: 'https://atomicdata.dev/properties/grants',
    installationStatus: 'https://atomicdata.dev/properties/installationStatus',
    domains: 'https://atomicdata.dev/properties/domains',
    standards: 'https://atomicdata.dev/properties/standards',
    evidence: 'https://atomicdata.dev/properties/evidence',
    supportTier: 'https://atomicdata.dev/properties/supportTier',
  },
  __classDefs: {
    ['https://atomicdata.dev/classes/Drive']: [
      'https://atomicdata.dev/properties/read',
      'https://atomicdata.dev/properties/children',
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/subresources',
      'https://atomicdata.dev/properties/write',
      'https://atomicdata.dev/ontology/server/property/default-ontology',
      'https://atomicdata.dev/properties/plugins',
      'https://atomicdata.dev/properties/llm-txt',
      'https://atomicdata.dev/properties/signaling-url',
    ],
    ['https://atomicdata.dev/classes/Endpoint']: [
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/endpoint/parameters',
    ],
    ['https://atomicdata.dev/ontology/server/class/endpoint-response']: [
      'https://atomicdata.dev/ontology/server/property/status',
      'https://atomicdata.dev/ontology/server/property/response-message',
    ],
    ['https://atomicdata.dev/classes/Error']: [
      'https://atomicdata.dev/properties/description',
    ],
    ['https://atomicdata.dev/classes/File']: [
      'https://atomicdata.dev/properties/downloadURL',
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/filesize',
      'https://atomicdata.dev/properties/filename',
      'https://atomicdata.dev/properties/checksum',
      'https://atomicdata.dev/properties/mimetype',
      'https://atomicdata.dev/properties/internalId',
      'https://atomicdata.dev/properties/imageWidth',
      'https://atomicdata.dev/properties/imageHeight',
      'https://atomicdata.dev/ontology/server/property/alt-text',
    ],
    ['https://atomicdata.dev/classes/Invite']: [
      'https://atomicdata.dev/properties/invite/target',
      'https://atomicdata.dev/properties/invite/write',
      'https://atomicdata.dev/properties/createdBy',
      'https://atomicdata.dev/properties/invite/users',
      'https://atomicdata.dev/properties/invite/usagesLeft',
    ],
    ['https://atomicdata.dev/classes/Redirect']: [
      'https://atomicdata.dev/properties/destination',
      'https://atomicdata.dev/properties/invite/redirectAgent',
    ],
    ['https://atomicdata.dev/classes/Plugin']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/namespace',
      'https://atomicdata.dev/properties/version',
      'https://atomicdata.dev/properties/config',
      'https://atomicdata.dev/properties/pluginAuthor',
      'https://atomicdata.dev/properties/jsonSchema',
      'https://atomicdata.dev/properties/pluginFile',
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/pluginAgent',
      'https://atomicdata.dev/properties/pluginPermissions',
    ],
    ['https://atomicdata.dev/classes/Release']: [
      'https://atomicdata.dev/properties/runtime',
      'https://atomicdata.dev/properties/manifest',
      'https://atomicdata.dev/properties/releaseId',
      'https://atomicdata.dev/properties/world',
      'https://atomicdata.dev/properties/source',
      'https://atomicdata.dev/properties/package',
      'https://atomicdata.dev/properties/schemas',
      'https://atomicdata.dev/properties/version',
      'https://atomicdata.dev/properties/previousRelease',
      'https://atomicdata.dev/properties/publisher',
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/description',
    ],
    ['https://atomicdata.dev/classes/Installation']: [
      'https://atomicdata.dev/properties/release',
      'https://atomicdata.dev/properties/releaseId',
      'https://atomicdata.dev/properties/installationStatus',
      'https://atomicdata.dev/properties/config',
      'https://atomicdata.dev/properties/grants',
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/namespace',
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/pluginAgent',
      'https://atomicdata.dev/properties/pluginPermissions',
      'https://atomicdata.dev/properties/jsonSchema',
      'https://atomicdata.dev/properties/version',
    ],
    ['https://atomicdata.dev/classes/Listing']: [
      'https://atomicdata.dev/properties/name',
      'https://atomicdata.dev/properties/release',
      'https://atomicdata.dev/properties/emoji',
      'https://atomicdata.dev/properties/description',
      'https://atomicdata.dev/properties/publisher',
      'https://atomicdata.dev/properties/domains',
      'https://atomicdata.dev/properties/standards',
      'https://atomicdata.dev/properties/evidence',
      'https://atomicdata.dev/properties/supportTier',
    ],
  },
} as const satisfies OntologyBaseObject;

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace Server {
  export type Drive = typeof server.classes.drive;
  export type Endpoint = typeof server.classes.endpoint;
  export type EndpointResponse = typeof server.classes.endpointResponse;
  export type Error = typeof server.classes.error;
  export type File = typeof server.classes.file;
  export type Invite = typeof server.classes.invite;
  export type Redirect = typeof server.classes.redirect;
  export type Plugin = typeof server.classes.plugin;
  export type Release = typeof server.classes.release;
  export type Installation = typeof server.classes.installation;
  export type Listing = typeof server.classes.listing;
}

declare module '../index.js' {
  interface Classes {
    [server.classes.drive]: {
      requires: BaseProps;
      recommends:
        | 'https://atomicdata.dev/properties/read'
        | typeof server.properties.children
        | 'https://atomicdata.dev/properties/description'
        | 'https://atomicdata.dev/properties/subresources'
        | 'https://atomicdata.dev/properties/write'
        | typeof server.properties.defaultOntology
        | typeof server.properties.plugins
        | typeof server.properties.llmTxt
        | typeof server.properties.signalingUrl;
    };
    [server.classes.endpoint]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/description'
        | typeof server.properties.parameters;
      recommends: never;
    };
    [server.classes.endpointResponse]: {
      requires:
        | BaseProps
        | typeof server.properties.status
        | typeof server.properties.responseMessage;
      recommends: never;
    };
    [server.classes.error]: {
      requires: BaseProps | 'https://atomicdata.dev/properties/description';
      recommends: never;
    };
    [server.classes.file]: {
      requires: BaseProps | typeof server.properties.downloadUrl;
      recommends:
        | 'https://atomicdata.dev/properties/description'
        | typeof server.properties.filesize
        | typeof server.properties.filename
        | typeof server.properties.checksum
        | typeof server.properties.mimetype
        | typeof server.properties.internalId
        | typeof server.properties.imageWidth
        | typeof server.properties.imageHeight
        | typeof server.properties.altText;
    };
    [server.classes.invite]: {
      requires: BaseProps | typeof server.properties.target;
      recommends:
        | typeof server.properties.write
        | typeof server.properties.createdBy
        | typeof server.properties.users
        | typeof server.properties.usagesLeft;
    };
    [server.classes.redirect]: {
      requires: BaseProps | typeof server.properties.destination;
      recommends: typeof server.properties.redirectAgent;
    };
    [server.classes.plugin]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof server.properties.namespace
        | typeof server.properties.version;
      recommends:
        | typeof server.properties.config
        | typeof server.properties.pluginAuthor
        | typeof server.properties.jsonSchema
        | typeof server.properties.pluginFile
        | 'https://atomicdata.dev/properties/description'
        | typeof server.properties.pluginAgent
        | typeof server.properties.pluginPermissions;
    };
    [server.classes.release]: {
      requires:
        | BaseProps
        | typeof server.properties.runtime
        | typeof server.properties.manifest
        | typeof server.properties.releaseId;
      recommends:
        | typeof server.properties.world
        | typeof server.properties.source
        | typeof server.properties.package
        | typeof server.properties.schemas
        | typeof server.properties.version
        | typeof server.properties.previousRelease
        | typeof server.properties.publisher
        | 'https://atomicdata.dev/properties/name'
        | 'https://atomicdata.dev/properties/description';
    };
    [server.classes.installation]: {
      requires:
        | BaseProps
        | typeof server.properties.release
        | typeof server.properties.releaseId
        | typeof server.properties.installationStatus;
      recommends:
        | typeof server.properties.config
        | typeof server.properties.grants
        | 'https://atomicdata.dev/properties/name'
        | typeof server.properties.namespace
        | 'https://atomicdata.dev/properties/description'
        | typeof server.properties.pluginAgent
        | typeof server.properties.pluginPermissions
        | typeof server.properties.jsonSchema
        | typeof server.properties.version;
    };
    [server.classes.listing]: {
      requires:
        | BaseProps
        | 'https://atomicdata.dev/properties/name'
        | typeof server.properties.release;
      recommends:
        | 'https://atomicdata.dev/properties/emoji'
        | 'https://atomicdata.dev/properties/description'
        | typeof server.properties.publisher
        | typeof server.properties.domains
        | typeof server.properties.standards
        | typeof server.properties.evidence
        | typeof server.properties.supportTier;
    };
  }

  interface PropTypeMapping {
    [server.properties.agent]: string;
    [server.properties.altText]: string;
    [server.properties.attachments]: string[];
    [server.properties.checksum]: string;
    [server.properties.children]: string[];
    [server.properties.createdBy]: string;
    [server.properties.defaultOntology]: string;
    [server.properties.destination]: string;
    [server.properties.downloadUrl]: string;
    [server.properties.drives]: string[];
    [server.properties.filename]: string;
    [server.properties.filesize]: number;
    [server.properties.imageHeight]: number;
    [server.properties.imageWidth]: number;
    [server.properties.internalId]: string;
    [server.properties.mimetype]: string;
    [server.properties.parameters]: string[];
    [server.properties.property]: string;
    [server.properties.publicKey]: string;
    [server.properties.redirectAgent]: string;
    [server.properties.responseMessage]: string;
    [server.properties.results]: string[];
    [server.properties.status]: number;
    [server.properties.target]: string;
    [server.properties.usagesLeft]: number;
    [server.properties.users]: string[];
    [server.properties.write]: boolean;
    [server.properties.config]: JSONValue;
    [server.properties.jsonSchema]: JSONValue;
    [server.properties.namespace]: string;
    [server.properties.version]: string;
    [server.properties.pluginAuthor]: string;
    [server.properties.plugins]: string[];
    [server.properties.pluginFile]: string;
    [server.properties.pluginAgent]: string;
    [server.properties.pluginPermissions]: JSONValue;
    [server.properties.searchChunks]: JSONValue;
    [server.properties.llmTxt]: string;
    [server.properties.signalingUrl]: string;
    [server.properties.runtime]: string;
    [server.properties.world]: string;
    [server.properties.manifest]: JSONValue;
    [server.properties.source]: string;
    [server.properties.package]: string;
    [server.properties.schemas]: JSONValue;
    [server.properties.releaseId]: string;
    [server.properties.previousRelease]: string;
    [server.properties.publisher]: string;
    [server.properties.release]: string;
    [server.properties.grants]: JSONValue;
    [server.properties.installationStatus]: string;
    [server.properties.domains]: JSONValue;
    [server.properties.standards]: string[];
    [server.properties.evidence]: JSONValue;
    [server.properties.supportTier]: string;
  }

  interface PropSubjectToNameMapping {
    [server.properties.agent]: 'agent';
    [server.properties.altText]: 'altText';
    [server.properties.attachments]: 'attachments';
    [server.properties.checksum]: 'checksum';
    [server.properties.children]: 'children';
    [server.properties.createdBy]: 'createdBy';
    [server.properties.defaultOntology]: 'defaultOntology';
    [server.properties.destination]: 'destination';
    [server.properties.downloadUrl]: 'downloadUrl';
    [server.properties.drives]: 'drives';
    [server.properties.filename]: 'filename';
    [server.properties.filesize]: 'filesize';
    [server.properties.imageHeight]: 'imageHeight';
    [server.properties.imageWidth]: 'imageWidth';
    [server.properties.internalId]: 'internalId';
    [server.properties.mimetype]: 'mimetype';
    [server.properties.parameters]: 'parameters';
    [server.properties.property]: 'property';
    [server.properties.publicKey]: 'publicKey';
    [server.properties.redirectAgent]: 'redirectAgent';
    [server.properties.responseMessage]: 'responseMessage';
    [server.properties.results]: 'results';
    [server.properties.status]: 'status';
    [server.properties.target]: 'target';
    [server.properties.usagesLeft]: 'usagesLeft';
    [server.properties.users]: 'users';
    [server.properties.write]: 'write';
    [server.properties.config]: 'config';
    [server.properties.jsonSchema]: 'jsonSchema';
    [server.properties.namespace]: 'namespace';
    [server.properties.version]: 'version';
    [server.properties.pluginAuthor]: 'pluginAuthor';
    [server.properties.plugins]: 'plugins';
    [server.properties.pluginFile]: 'pluginFile';
    [server.properties.pluginAgent]: 'pluginAgent';
    [server.properties.pluginPermissions]: 'pluginPermissions';
    [server.properties.searchChunks]: 'searchChunks';
    [server.properties.llmTxt]: 'llmTxt';
    [server.properties.signalingUrl]: 'signalingUrl';
    [server.properties.runtime]: 'runtime';
    [server.properties.world]: 'world';
    [server.properties.manifest]: 'manifest';
    [server.properties.source]: 'source';
    [server.properties.package]: 'package';
    [server.properties.schemas]: 'schemas';
    [server.properties.releaseId]: 'releaseId';
    [server.properties.previousRelease]: 'previousRelease';
    [server.properties.publisher]: 'publisher';
    [server.properties.release]: 'release';
    [server.properties.grants]: 'grants';
    [server.properties.installationStatus]: 'installationStatus';
    [server.properties.domains]: 'domains';
    [server.properties.standards]: 'standards';
    [server.properties.evidence]: 'evidence';
    [server.properties.supportTier]: 'supportTier';
  }
}
