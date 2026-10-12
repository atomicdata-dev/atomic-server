import { core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import { server } from './ontologies/server.js';

const aliases: Record<string, string> = {
  file: server.classes.file,
  folder: dataBrowser.classes.folder,
  document: dataBrowser.classes.documentV2,
  'document-v2': dataBrowser.classes.documentV2,
  class: core.classes.class,
  property: core.classes.property,
  table: dataBrowser.classes.table,
};

export const standardClassAlias = (name: string): string | undefined =>
  Object.hasOwn(aliases, name.trim().toLowerCase())
    ? aliases[name.trim().toLowerCase()]
    : undefined;
