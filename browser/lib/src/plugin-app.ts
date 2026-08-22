import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import { ensureSchema, type SchemaStore } from './plugin-schema.js';
import { pluginSchema } from './plugin-log.js';

/**
 * An app is a parent whose children are its parts.
 *
 * That is the whole design, and it is chosen so that sharing, copying and
 * deletion cost nothing: rights ascend the parent chain, so granting someone
 * the app grants them its ontology, its view and its handlers in one act, and
 * copying the subtree copies the app. None of that is machinery this file has
 * to implement.
 */

export interface CreateAppOptions {
  drive: string;
  name: string;
  /** The module whose `view()` renders the app. */
  source: string;
  description?: string;
}

export interface CreatedApp {
  app: string;
  /** The app's own ontology, where its classes and properties go. */
  ontology: string;
  /** The plugin the app opens to. */
  entrypoint: string;
}

/**
 * Creates an app, its own ontology, and the plugin it opens to.
 *
 * The ontology is the app's, not the drive's. `ensureSchema` writes into the
 * drive's default ontology, so two apps that both invent a `Task` would
 * collide in one namespace — and neither could be copied anywhere else
 * intact, because its schema would live somewhere the copy does not include.
 *
 * An app reuses an existing class by naming its subject, which is how Atomic
 * already works, so nothing here is needed to make apps compose.
 */
export async function createApp(
  store: SchemaStore,
  options: CreateAppOptions,
): Promise<CreatedApp> {
  const schema = await ensureSchema(store, options.drive, pluginSchema());

  const app = await store.newResource({
    parent: options.drive,
    isA: [schema.classes.app],
    propVals: {
      [core.properties.name]: options.name,
      ...(options.description
        ? { [core.properties.description]: options.description }
        : {}),
    },
  });
  await app.save();

  const ontology = await store.newResource({
    parent: app.subject,
    isA: [core.classes.ontology],
    propVals: {
      [core.properties.name]: options.name,
      [core.properties.shortname]: slug(options.name),
      [core.properties.description]: `Classes and properties belonging to ${options.name}.`,
      [core.properties.classes]: [],
      [core.properties.properties]: [],
    },
  });
  await ontology.save();

  const entrypoint = await store.newResource({
    parent: app.subject,
    isA: [schema.classes['plugin-script']],
    propVals: {
      [core.properties.name]: `${options.name} view`,
      [schema.properties['plugin-source']]: options.source,
    },
  });
  await entrypoint.save();

  // Pointed at last, so an app never briefly names a view that is not saved
  // yet — a reader between the two writes would open nothing and be told the
  // app is broken.
  const saved = await store.getResource(app.subject);
  await saved.set(server.properties.defaultOntology, ontology.subject);
  await saved.set(schema.properties.entrypoint, entrypoint.subject);
  await saved.save();

  return {
    app: app.subject,
    ontology: ontology.subject,
    entrypoint: entrypoint.subject,
  };
}

/** A shortname an ontology will accept: lowercase, letters, digits, dashes. */
function slug(name: string): string {
  const cleaned = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

  // Shortnames must start with a letter, and an app called "1Password" is not
  // a reason to refuse to make an app.
  return /^[a-z]/.test(cleaned) ? cleaned : `app-${cleaned || 'unnamed'}`;
}
