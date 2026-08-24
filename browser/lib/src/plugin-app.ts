import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import { dataBrowser } from './ontologies/dataBrowser.js';
import { classes } from './urls.js';
import { issueAccessAgent } from './issue-access-agent.js';
import type { Store } from './store.js';
import {
  ensureSchema,
  type EnsuredSchema,
  type SchemaStore,
} from './plugin-schema.js';
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
  /**
   * One emoji, shown wherever the app is listed.
   *
   * Asked for rather than defaulted: a wall of identical glyphs is how a
   * sidebar of apps stops being scannable, and only the author knows what
   * this one is about.
   */
  emoji?: string;
  /**
   * What the app's rows are called, singular then plural — "Feeding session",
   * "Feeding sessions".
   *
   * Both, because English plurals are not derivable ("person" / "people") and
   * a wrong guess is printed at the top of the user's table forever. Left out,
   * the rows are generically "Item" / "Items", which tells a reader nothing
   * about what the app holds.
   */
  rowName?: { singular: string; plural: string };
}

export interface CreatedApp {
  app: string;
  /** The app's own ontology, where its classes and properties go. */
  ontology: string;
  /** The plugin the app opens to. */
  entrypoint: string;
  /** The table this app's rows live in. */
  data: string;
  /** The class those rows are. */
  rowClass: string;
  /** The app's own agent. Writes it makes are attributable to this DID. */
  agent: string;
  /**
   * That agent's secret, returned once and stored nowhere by this function.
   *
   * A secret in a resource would sync, and the personal drive it lives on can
   * later be shared. Whoever calls this decides where it belongs — for a
   * server-run app that is the host's secret store, never the drive.
   */
  secret: string;
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
      ...(options.emoji
        ? { [dataBrowser.properties.emoji]: options.emoji }
        : {}),
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
      // Not the app's own name. Two sidebar rows reading "Breastfeed Tracker"
      // under a third reading "Breastfeed Tracker" is a puzzle the reader has
      // to solve every time they look at it.
      [core.properties.name]: `${options.name} schema`,
      [core.properties.shortname]: slug(options.name),
      [core.properties.description]:
        `Classes and properties belonging to ${options.name}.`,
      [core.properties.classes]: [],
      [core.properties.properties]: [],
    },
  });
  await ontology.save();

  // The app's rows are a Table, not a folder. Structurally they are the same
  // thing — a table's rows are its children — but a Table carries a row class
  // and display config, so the rows are sortable, filterable, editable and
  // exportable without the app implementing any of it, and someone who wants
  // the data rather than the app can just open it.
  const rows = options.rowName ?? { singular: 'Item', plural: 'Items' };

  const rowClass = await store.newResource({
    parent: ontology.subject,
    isA: [core.classes.class],
    propVals: {
      [core.properties.shortname]: slug(rows.singular),
      [core.properties.name]: rows.singular,
      [core.properties.description]: `A row in ${options.name}.`,
      [core.properties.recommends]: [core.properties.name],
    },
  });
  await rowClass.save();

  // Registered on the ontology, or it is a class the app's own vocabulary
  // does not list — and nothing that reads the ontology would find it.
  const ontologyResource = await store.getResource(ontology.subject);
  await ontologyResource.set(core.properties.classes, [rowClass.subject]);
  await ontologyResource.save();

  const data = await store.newResource({
    parent: app.subject,
    isA: [dataBrowser.classes.table],
    propVals: {
      // Named for what it holds, not for the app. Both appear in the sidebar
      // under the app, and two entries with the same name is a question the
      // reader has to answer every time. "Feeding sessions" also tells someone
      // who never opens the app what is in here — which is the point of the
      // rows being an ordinary table.
      [core.properties.name]: rows.plural,
      [core.properties.classtype]: rowClass.subject,
    },
  });
  await data.save();

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
  await saved.set(schema.properties['app-data'], data.subject);
  // What it can show. Its own rows to begin with — an author who wants it
  // offered on someone else's table adds that class deliberately, rather than
  // every app being offered for every table.
  await saved.set(schema.properties.renders, [rowClass.subject]);
  await saved.save();

  // The app's own identity, and the only thing that decides what it may
  // write. An Agent already is a token: the DID is the principal, `read` and
  // `write` on resources are the scopes, and revoking means taking the DID
  // off those lists. A second permission model beside that one would be
  // enforced only wherever someone remembered to check it — see
  // planning/issued-agents.md.
  //
  // Granted on the app itself, so rights inherit to everything under it.
  // "An app may write its own data" is then something the ordinary rights
  // walk says, not a rule this codebase has to keep restating.
  const key = await issueAccessAgent(store as unknown as Store, {
    name: `${options.name} (app)`,
    description: `The identity ${options.name} writes as.`,
    write: true,
    targets: [app.subject],
    // Not under the app: an app may write its own subtree, so its agent
    // resource kept there would be a public key the app could replace.
    // A folder beside the apps instead — see appIdentitiesFolder.
    parent: await appIdentitiesFolder(store, options.drive, schema),
  });

  return {
    app: app.subject,
    ontology: ontology.subject,
    entrypoint: entrypoint.subject,
    data: data.subject,
    rowClass: rowClass.subject,
    agent: key.subject,
    secret: key.secret,
  };
}

/**
 * The drive's folder of app identities, made on first use.
 *
 * An app's agent cannot live under the app. The app may write its own subtree,
 * so its own agent resource kept there would be a public key it could replace
 * — a key stored in the room it unlocks. But one loose agent per app at the
 * drive root is its own problem: they pile up in the listing, and the answer
 * to "what can write to this drive?" is scattered through it.
 *
 * So: one folder, outside every app's subtree, holding all of them. It is the
 * place to look before revoking something.
 *
 * Found by a pointer on the drive rather than by name, the way the drive
 * already points at its default ontology, so renaming the folder does not
 * silently start a second one.
 */
async function appIdentitiesFolder(
  store: SchemaStore,
  drive: string,
  schema: EnsuredSchema,
): Promise<string> {
  const driveResource = await store.getResource(drive);
  const existing = driveResource.get(schema.properties['app-identities']);

  if (typeof existing === 'string' && existing.length > 0) {
    return existing;
  }

  const folder = await store.newResource({
    parent: drive,
    isA: [dataBrowser.classes.folder],
    propVals: {
      [core.properties.name]: 'App identities',
      [core.properties.description]:
        'The agents apps on this drive write as. Removing one from a resource\u2019s rights revokes that app.',
      [dataBrowser.properties.displayStyle]: classes.displayStyles.list,
    },
  });
  await folder.save();

  await driveResource.set(schema.properties['app-identities'], folder.subject);
  await driveResource.save();

  return folder.subject;
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
