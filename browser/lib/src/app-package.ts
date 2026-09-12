import stringify from 'fast-json-stable-stringify';
import { Datatype } from './datatypes.js';
import { core } from './ontologies/core.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import { importRecords, type ImportHost } from './import-records.js';
import { validateManifest } from './plugin-manifest.js';
import {
  parseSetupDeclaration,
  type SetupDeclaration,
} from './plugin-setup.js';
import type { PluginRelease } from './plugin-connection.js';
import type { EnsuredSchema, SchemaSpec } from './plugin-schema.js';

/** Distribution data, not an installation. The existing release remains unchanged. */
export interface AppPackage {
  format: 1;
  /** Author-owned revision URI. Reusing it for different content causes an import conflict. */
  id: string;
  name: string;
  description: string;
  emoji?: string;
  release: PluginRelease;
  setup?: SetupDeclaration;
}

/** Package resources are inert: they are neither apps nor executable plugin scripts. */
export function appPackageSchema(): SchemaSpec {
  return {
    properties: [
      {
        shortname: 'app-package-content',
        name: 'Package content',
        description:
          'Portable release and setup declaration. Importing does not activate this code.',
        datatype: Datatype.STRING,
      },
    ],
    classes: [
      {
        shortname: 'app-package',
        name: 'App package',
        description:
          'An app definition available for installation, without credentials or installation state.',
        requires: ['app-package-content'],
      },
    ],
  };
}

/** Parse a JSON file/resource without importing or evaluating its JavaScript. */
export function parseAppPackage(json: string): AppPackage {
  if (
    json.length > 4 * 1024 * 1024 ||
    new TextEncoder().encode(json).length > 4 * 1024 * 1024
  )
    throw new Error('App package exceeds 4 MiB');
  const raw: unknown = JSON.parse(json);

  const object = (value: unknown, keys?: string[]): Record<string, unknown> => {
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Error('Expected an app package object');
    const result = value as Record<string, unknown>;
    if (
      Object.keys(result).some(
        key =>
          ['__proto__', 'constructor', 'prototype'].includes(key) ||
          (keys && !keys.includes(key)),
      )
    )
      throw new Error('Unsupported app package field');

    return result;
  };

  const uri = (value: unknown) => {
    if (typeof value !== 'string' || !value || value.trim() !== value)
      throw new Error('Package references must be absolute resource URIs');
    const url = new URL(value);
    if (
      !['https:', 'http:', 'did:'].includes(url.protocol) ||
      url.username ||
      url.password
    )
      throw new Error('Package references must be absolute resource URIs');
  };

  const entry = object(raw, [
    'format',
    'id',
    'name',
    'description',
    'emoji',
    'release',
    'setup',
  ]);
  if (entry.format !== 1) throw new Error('Unsupported app package format');
  uri(entry.id);
  if (
    typeof entry.name !== 'string' ||
    !entry.name.trim() ||
    typeof entry.description !== 'string' ||
    (entry.emoji !== undefined && typeof entry.emoji !== 'string')
  )
    throw new Error('Invalid app package metadata');
  // These labels are also written as ordinary resource properties, where
  // the shared importer reserves a leading local: for graph references.
  if (
    [entry.name, entry.description, entry.emoji].some(
      value => typeof value === 'string' && value.startsWith('local:'),
    )
  )
    throw new Error(
      'Package labels cannot start with the reserved local: prefix',
    );

  const release = object(entry.release, [
    'source',
    'manifest',
    'runtime',
    'schemas',
  ]);
  if (
    release.runtime !== 'atomic-js/1' ||
    typeof release.source !== 'string' ||
    !release.source.trim()
  )
    throw new Error('App package needs source for atomic-js/1');
  validateManifest(release.manifest);
  for (const subject of Object.values(object(release.schemas))) uri(subject);
  if (entry.setup !== undefined) parseSetupDeclaration(entry.setup);

  // Preserve the exact release payload: normalizing optional manifest fields
  // here would change its server-computed release identity.
  return raw as AppPackage;
}

/** Read back/export the same portable document from an ordinary resource. */
export function readAppPackage(
  values: Record<string, unknown>,
  schema: EnsuredSchema,
): AppPackage {
  const { klass, content } = packageTerms(schema);
  const classes = values[core.properties.isA];
  if (!Array.isArray(classes) || !classes.includes(klass))
    throw new Error('Resource is not an app package');

  const json = values[content];
  if (typeof json !== 'string')
    throw new Error('Package content must be a JSON document');

  return parseAppPackage(json);
}

/** Produce ordinary importer intents for preview/apply. No writes or execution.
 * The host chooses the parent; the package cannot redirect writes or supply rights.
 * A source revision is append-only, with the shared importer's duplicate/conflict handling.
 */
export function prepareAppPackageImport(
  host: ImportHost,
  json: string,
  parent: string,
  schema: EnsuredSchema,
) {
  const pkg = parseAppPackage(json);
  const { klass, content } = packageTerms(schema);
  if (!parent || parent.startsWith('local:'))
    throw new Error('Choose an existing package destination');

  return importRecords(host, [
    {
      localId: 'package',
      sourceId: pkg.id,
      parent,
      isA: [klass],
      mode: 'append',
      values: {
        [core.properties.name]: pkg.name,
        [core.properties.description]: pkg.description,
        ...(pkg.emoji !== undefined
          ? { [dataBrowser.properties.emoji]: pkg.emoji }
          : {}),
        // Opaque JSON text: importer local-reference rewriting must never change
        // source code, schema identities, or literal strings inside the package.
        [content]: stringify(pkg),
      },
    },
  ]);
}

function packageTerms(schema: EnsuredSchema) {
  const klass = schema.classes['app-package'];
  const content = schema.properties['app-package-content'];
  if (!klass || !content)
    throw new Error('Install the app package schema first');

  return { klass, content };
}
