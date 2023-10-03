
/* -----------------------------------
* GENERATED WITH ATOMIC-GENERATE
* -------------------------------- */

import { BaseProps } from '../index.js'

export const server = {
    classes: {
	error: 'https://atomicdata.dev/classes/Error',
	endpoint: 'https://atomicdata.dev/classes/Endpoint',
	drive: 'https://atomicdata.dev/classes/Drive',
	redirect: 'https://atomicdata.dev/classes/Redirect',
	file: 'https://atomicdata.dev/classes/File',
	invite: 'https://atomicdata.dev/classes/Invite',
   },
    properties: {
	drives: 'https://atomicdata.dev/properties/drives',
	results: 'https://atomicdata.dev/properties/endpoint/results',
	property: 'https://atomicdata.dev/properties/search/property',
	redirectAgent: 'https://atomicdata.dev/properties/invite/redirectAgent',
	agent: 'https://atomicdata.dev/properties/invite/agent',
	publicKey: 'https://atomicdata.dev/properties/invite/publicKey',
	target: 'https://atomicdata.dev/properties/invite/target',
	usagesLeft: 'https://atomicdata.dev/properties/invite/usagesLeft',
	users: 'https://atomicdata.dev/properties/invite/users',
	write: 'https://atomicdata.dev/properties/invite/write',
	filename: 'https://atomicdata.dev/properties/filename',
	filesize: 'https://atomicdata.dev/properties/filesize',
	downloadUrl: 'https://atomicdata.dev/properties/downloadURL',
	mimetype: 'https://atomicdata.dev/properties/mimetype',
	attachments: 'https://atomicdata.dev/properties/attachments',
	createdBy: 'https://atomicdata.dev/properties/createdBy',
	checksum: 'https://atomicdata.dev/properties/checksum',
	internalId: 'https://atomicdata.dev/properties/internalId',
	children: 'https://atomicdata.dev/properties/children',
	parameters: 'https://atomicdata.dev/properties/endpoint/parameters',
	destination: 'https://atomicdata.dev/properties/destination',
   },
  } as const


  // eslint-disable-next-line @typescript-eslint/no-namespace
  export namespace Server {
    export type Error = typeof server.classes.error;
export type Endpoint = typeof server.classes.endpoint;
export type Drive = typeof server.classes.drive;
export type Redirect = typeof server.classes.redirect;
export type File = typeof server.classes.file;
export type Invite = typeof server.classes.invite;
  }


declare module '../index.js' {
  interface Classes {
    [server.classes.error]: {
    requires: BaseProps | 'https://atomicdata.dev/properties/description';
    recommends: never;
  };
[server.classes.endpoint]: {
    requires: BaseProps | 'https://atomicdata.dev/properties/description' | typeof server.properties.parameters;
    recommends: never;
  };
[server.classes.drive]: {
    requires: BaseProps;
    recommends: 'https://atomicdata.dev/properties/read' | typeof server.properties.children | 'https://atomicdata.dev/properties/description' | 'https://atomicdata.dev/properties/subresources' | 'https://atomicdata.dev/properties/write';
  };
[server.classes.redirect]: {
    requires: BaseProps | typeof server.properties.destination;
    recommends: typeof server.properties.redirectAgent;
  };
[server.classes.file]: {
    requires: BaseProps | typeof server.properties.downloadUrl;
    recommends: 'https://atomicdata.dev/properties/description' | typeof server.properties.filesize | typeof server.properties.filename | typeof server.properties.checksum | typeof server.properties.mimetype | typeof server.properties.internalId;
  };
[server.classes.invite]: {
    requires: BaseProps | typeof server.properties.target;
    recommends: typeof server.properties.write | typeof server.properties.createdBy | typeof server.properties.users | typeof server.properties.usagesLeft;
  };
  }

  interface PropTypeMapping {
    [server.properties.drives]: string[]
[server.properties.results]: string[]
[server.properties.property]: string
[server.properties.redirectAgent]: string
[server.properties.agent]: string
[server.properties.publicKey]: string
[server.properties.target]: string
[server.properties.usagesLeft]: number
[server.properties.users]: string[]
[server.properties.write]: boolean
[server.properties.filename]: string
[server.properties.filesize]: number
[server.properties.downloadUrl]: string
[server.properties.mimetype]: string
[server.properties.attachments]: string[]
[server.properties.createdBy]: string
[server.properties.checksum]: string
[server.properties.internalId]: string
[server.properties.children]: string[]
[server.properties.parameters]: string[]
[server.properties.destination]: string
  }

  interface PropSubjectToNameMapping {
    [server.properties.drives]: 'drives',
[server.properties.results]: 'results',
[server.properties.property]: 'property',
[server.properties.redirectAgent]: 'redirectAgent',
[server.properties.agent]: 'agent',
[server.properties.publicKey]: 'publicKey',
[server.properties.target]: 'target',
[server.properties.usagesLeft]: 'usagesLeft',
[server.properties.users]: 'users',
[server.properties.write]: 'write',
[server.properties.filename]: 'filename',
[server.properties.filesize]: 'filesize',
[server.properties.downloadUrl]: 'downloadUrl',
[server.properties.mimetype]: 'mimetype',
[server.properties.attachments]: 'attachments',
[server.properties.createdBy]: 'createdBy',
[server.properties.checksum]: 'checksum',
[server.properties.internalId]: 'internalId',
[server.properties.children]: 'children',
[server.properties.parameters]: 'parameters',
[server.properties.destination]: 'destination',
  }
}
