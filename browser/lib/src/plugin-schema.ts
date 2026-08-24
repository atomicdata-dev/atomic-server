import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import type { Datatype } from './datatypes.js';
import type { JSONValue } from './value.js';

/**
 * Creates a plugin's classes and properties as ordinary Atomic resources in the
 * drive's ontology, from a spec written in code.
 *
 * Code-first rather than baked into the core ontology: the shape of a plugin
 * run will keep moving while triggers, preview and cron are built, and churn in
 * the core ontology is paid for by every server. These live in the drive that
 * uses them, and can graduate later once the shape settles.
 */

export interface PropertySpec {
  /** Stable within the spec; also the resource's shortname. */
  shortname: string;
  name: string;
  description: string;
  datatype: Datatype;
  classtype?: string;
}

export interface ClassSpec {
  shortname: string;
  name: string;
  description: string;
  /** Shortnames of properties in the same spec. */
  requires?: string[];
  recommends?: string[];
}

export interface SchemaSpec {
  properties: PropertySpec[];
  classes: ClassSpec[];
}

export interface EnsuredSchema {
  /** Shortname to subject. */
  properties: Record<string, string>;
  classes: Record<string, string>;
}

interface SchemaResource {
  subject: string;
  get(property: string): unknown;
  set(property: string, value: JSONValue): Promise<void>;
  save(): Promise<unknown>;
}

export interface SchemaStore {
  getResource(subject: string): Promise<SchemaResource>;
  newResource(opts: {
    parent: string;
    isA: string[];
    propVals: Record<string, JSONValue>;
  }): Promise<SchemaResource>;
}

/**
 * Makes a spec real in a drive, reusing anything already there.
 *
 * Idempotent by shortname: a second call finds what the first created rather
 * than making a parallel set, which matters because a plugin's first run and
 * its hundredth take the same path.
 *
 * Not safe against two runs racing on a drive that has neither — both would
 * create. Rare enough to leave, loud enough to notice (two classes with one
 * shortname), and the fix belongs with a general schema registry rather than
 * here.
 */
export async function ensureSchema(
  store: SchemaStore,
  drive: string,
  spec: SchemaSpec,
): Promise<EnsuredSchema> {
  const ontologySubject = await findOntology(store, drive);
  const ontology = await store.getResource(ontologySubject);

  const properties = await ensureAll(
    store,
    ontology,
    core.properties.properties,
    spec.properties,
    property => ({
      isA: [core.classes.property],
      propVals: {
        [core.properties.shortname]: property.shortname,
        [core.properties.name]: property.name,
        [core.properties.description]: property.description,
        [core.properties.datatype]: property.datatype,
        ...(property.classtype
          ? { [core.properties.classtype]: property.classtype }
          : {}),
      },
    }),
  );

  const classes = await ensureAll(
    store,
    ontology,
    core.properties.classes,
    spec.classes,
    klass => ({
      isA: [core.classes.class],
      propVals: {
        [core.properties.shortname]: klass.shortname,
        [core.properties.name]: klass.name,
        [core.properties.description]: klass.description,
        [core.properties.requires]: (klass.requires ?? []).map(
          name => properties[name],
        ),
        [core.properties.recommends]: (klass.recommends ?? []).map(
          name => properties[name],
        ),
      },
    }),
  );

  return { properties, classes };
}

/**
 * Looks a spec up without creating anything.
 *
 * Menus and other read paths need to know whether a drive has plugin classes;
 * they must not bring them into existence as a side effect of being rendered.
 * Returns only what is actually there.
 */
export async function findSchema(
  store: SchemaStore,
  drive: string,
  spec: SchemaSpec,
): Promise<Partial<EnsuredSchema>> {
  const driveResource = await store.getResource(drive);
  const ontologySubject = driveResource.get(server.properties.defaultOntology);

  if (typeof ontologySubject !== 'string' || ontologySubject.length === 0) {
    return {};
  }

  const ontology = await store.getResource(ontologySubject);

  const [properties, classes] = await Promise.all([
    pick(
      store,
      asList(ontology.get(core.properties.properties)),
      spec.properties,
    ),
    pick(store, asList(ontology.get(core.properties.classes)), spec.classes),
  ]);

  return { properties, classes };
}

async function pick(
  store: SchemaStore,
  subjects: string[],
  specs: Array<{ shortname: string }>,
): Promise<Record<string, string>> {
  const found = await byShortname(store, subjects);

  return Object.fromEntries(
    specs
      .map(spec => [spec.shortname, found.get(spec.shortname)] as const)
      .filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

/**
 * Brings an existing class or property back in line with the spec.
 *
 * Without this a drive keeps whatever shape the schema had the day it was
 * first used, and a fix to the spec never reaches anyone who already ran the
 * old one — which is the worst case, because their data is the data that
 * already exists.
 *
 * Only `requires` and `recommends` are reconciled. Names and descriptions are
 * left alone: someone may have edited them, and overwriting a person's words
 * on every boot is not a migration.
 */
async function reconcile(
  store: SchemaStore,
  subject: string,
  desired: Record<string, JSONValue>,
): Promise<void> {
  const resource = await store.getResource(subject);
  let changed = false;

  for (const property of [
    core.properties.requires,
    core.properties.recommends,
  ]) {
    const wanted = desired[property];

    if (!Array.isArray(wanted)) continue;

    const current = resource.get(property);
    const same =
      Array.isArray(current) &&
      current.length === wanted.length &&
      wanted.every(value => current.includes(value));

    if (same) continue;

    await resource.set(property, wanted);
    changed = true;
  }

  if (changed) await resource.save();
}

async function ensureAll<T extends { shortname: string }>(
  store: SchemaStore,
  ontology: SchemaResource,
  listProperty: string,
  specs: T[],
  build: (spec: T) => { isA: string[]; propVals: Record<string, JSONValue> },
): Promise<Record<string, string>> {
  const existing = asList(ontology.get(listProperty));
  const found = await byShortname(store, existing);
  const result: Record<string, string> = {};
  const added: string[] = [];

  for (const spec of specs) {
    const hit = found.get(spec.shortname);

    if (hit) {
      result[spec.shortname] = hit;
      await reconcile(store, hit, build(spec).propVals);

      continue;
    }

    const { isA, propVals } = build(spec);
    const created = await store.newResource({
      parent: ontology.subject,
      isA,
      propVals,
    });
    await created.save();

    result[spec.shortname] = created.subject;
    added.push(created.subject);
  }

  if (added.length > 0) {
    await ontology.set(listProperty, [...existing, ...added]);
    await ontology.save();
  }

  return result;
}

async function byShortname(
  store: SchemaStore,
  subjects: string[],
): Promise<Map<string, string>> {
  const entries = await Promise.all(
    subjects.map(async subject => {
      const resource = await store.getResource(subject);
      const shortname = resource.get(core.properties.shortname);

      return [typeof shortname === 'string' ? shortname : '', subject] as const;
    }),
  );

  return new Map(entries.filter(([shortname]) => shortname !== ''));
}

async function findOntology(
  store: SchemaStore,
  drive: string,
): Promise<string> {
  const resource = await store.getResource(drive);
  const ontology = resource.get(server.properties.defaultOntology);

  if (typeof ontology !== 'string' || ontology.length === 0) {
    throw new Error(
      `drive ${drive} has no default ontology, so there is nowhere to put plugin classes`,
    );
  }

  return ontology;
}

function asList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => typeof v === 'string')
    : [];
}
