import { core } from './ontologies/core.js';
import { server } from './ontologies/server.js';
import type { Datatype } from './datatypes.js';
import type { JSONValue } from './value.js';
import { canonicalizeScheme } from './subject.js';
import {
  planOntology,
  readConstraintsValue,
  sortedJson,
  type OntologyInput,
  type OntologyPlan,
} from './ontology-input.js';

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
  /** Reuse this vocabulary term without editing or copying it. */
  subject?: string;
  /** Stable within the spec; also the resource's shortname. */
  shortname: string;
  name: string;
  description: string;
  datatype: Datatype;
  classtype?: string;
}

export interface ClassSpec {
  /** Reuse this class without editing or copying it. */
  subject?: string;
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

export interface SchemaResource {
  subject: string;
  get(property: string): unknown;
  set(property: string, value: JSONValue): Promise<void>;
  save(): Promise<unknown>;
  pushListItem?(property: string, value: JSONValue): void;
}

export interface SchemaStore {
  /** Authoritative lookup must include saved terms not yet linked to the ontology. */
  findByLocalId(
    drive: string,
    parent: string,
    localId: string,
  ): Promise<SchemaResource | undefined>;
  getResource(subject: string): Promise<SchemaResource>;
  newResource(opts: {
    parent: string;
    isA: string[];
    propVals: Record<string, JSONValue>;
    /** Derive the subject from parent, shortname and datatype. */
    contentAddressedProperty?: boolean;
  }): Promise<SchemaResource>;
}

/**
 * Makes a spec real in a drive, reusing anything already there.
 *
 * @deprecated Describe the ontology with {@link ensureOntology}, which also
 * creates the ontology and sets class constraints. This is the same engine
 * pointed at the drive's default ontology.
 *
 * Idempotent by shortname: a second call finds what the first created rather
 * than making a parallel set, which matters because a plugin's first run and
 * its hundredth take the same path.
 *
 * Native localIds recover saved terms even when the ontology-link write was
 * interrupted. Concurrent duplicate creates on one server reuse its winner;
 * ambiguous shortnames are errors, never arbitrary bindings.
 */
export async function ensureSchema(
  store: SchemaStore,
  drive: string,
  spec: SchemaSpec,
): Promise<EnsuredSchema> {
  return ensureTerms(store, drive, await findOntology(store, drive), spec);
}

const DRIVE_PROPERTY = 'https://atomicdata.dev/properties/drive';

export interface EnsureOntologyOptions {
  /** The drive `parent` lives in. Defaults to the parent's own `drive`, or the parent. */
  drive?: string;
}

export interface EnsuredOntology extends EnsuredSchema {
  /** Subject of the Ontology resource. */
  ontology: string;
}

/**
 * Makes an ontology real under `parent`: the Ontology resource, its
 * content-addressed Properties, and its Classes with `requires`, `recommends`
 * and `constraints`. Returns shortname to subject for classes and properties.
 *
 * Idempotent: the Ontology is found again by its shortname under `parent`, a
 * Property by its `atomic:prop:` subject (the same ontology, shortname and
 * datatype always give the same one), a Class by its shortname in the
 * ontology. A second run with the same input writes nothing.
 *
 * What is brought back in line on a class that already exists: `requires`,
 * `recommends` and, when the input has `constraints`, the constraints. Names
 * and descriptions are left alone, as someone may have edited them. Properties
 * are immutable, so an existing one is reused as it is.
 *
 * Throws before writing anything when the input is inconsistent (see
 * {@link planOntology}) or an existing shortname is ambiguous.
 */
export async function ensureOntology(
  store: SchemaStore,
  parent: string,
  input: OntologyInput,
  options: EnsureOntologyOptions = {},
): Promise<EnsuredOntology> {
  const plan = planOntology(input);
  const parentResource = await store.getResource(parent);
  const drive =
    options.drive ??
    (typeof parentResource.get(DRIVE_PROPERTY) === 'string'
      ? (parentResource.get(DRIVE_PROPERTY) as string)
      : parent);

  const ontology = await ensureOntologyResource(store, drive, parent, input);
  const terms = await ensureTerms(store, drive, ontology, {
    properties: plan.properties,
    classes: plan.classes,
  });

  await ensureConstraints(store, plan, terms);

  return { ontology, ...terms };
}

const ontologyLocalId = (shortname: string): string =>
  `schema:ontology:${shortname}`;

async function ensureOntologyResource(
  store: SchemaStore,
  drive: string,
  parent: string,
  input: OntologyInput,
): Promise<string> {
  const localId = ontologyLocalId(input.shortname);
  const existing = await store.findByLocalId(drive, parent, localId);

  if (existing) return existing.subject;

  const name = input.name ?? input.shortname;
  const created = await store.newResource({
    parent,
    isA: [core.classes.ontology],
    propVals: {
      [core.properties.shortname]: input.shortname,
      [core.properties.name]: name,
      [core.properties.description]: input.description ?? name,
      [core.properties.localId]: localId,
    },
  });

  try {
    await created.save();
  } catch (error) {
    const winner = await store.findByLocalId(drive, parent, localId);

    if (!winner) throw error;

    return winner.subject;
  }

  return created.subject;
}

/**
 * Writes `constraints` after the classes exist, as a `class` keyword needs the
 * subject of another class. Skipped when the stored map already says the same.
 */
async function ensureConstraints(
  store: SchemaStore,
  plan: OntologyPlan,
  terms: EnsuredSchema,
): Promise<void> {
  for (const [classShortname, own] of Object.entries(plan.constraints)) {
    if (own === undefined) continue;

    const desired: Record<string, JSONValue> = {};

    for (const [property, keywords] of Object.entries(own)) {
      const subject = canonicalizeScheme(terms.properties[property]);
      const resolved: Record<string, JSONValue> = { ...keywords };
      const target = keywords.class;

      if (typeof target === 'string' && !target.includes(':')) {
        resolved.class = canonicalizeScheme(terms.classes[target]);
      }

      desired[subject] = resolved;
    }

    const klass = await store.getResource(terms.classes[classShortname]);
    const current = readConstraintsValue(
      klass.get(core.properties.constraints),
    );
    const same =
      current === undefined
        ? Object.keys(desired).length === 0
        : sortedJson(current) === sortedJson(desired);

    if (same) continue;

    await klass.set(core.properties.constraints, desired);
    await klass.save();
  }
}

/** Creates or finds the properties and classes of a spec in an ontology. */
async function ensureTerms(
  store: SchemaStore,
  drive: string,
  ontologySubject: string,
  spec: SchemaSpec,
): Promise<EnsuredSchema> {
  const ontology = await store.getResource(ontologySubject);

  const properties = await ensureAll(
    store,
    ontology,
    drive,
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
    drive,
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
  specs: Array<{ shortname: string; subject?: string }>,
): Promise<Record<string, string>> {
  const found = await byShortname(
    store,
    subjects,
    new Set(specs.map(spec => spec.shortname)),
  );

  return Object.fromEntries(
    specs
      .map(
        spec =>
          [spec.shortname, spec.subject ?? found.get(spec.shortname)] as const,
      )
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

/** The native identity a schema term is saved under, so an interrupted
 * ontology-link write can still be recovered by its own id. */
function localIdFor(listProperty: string, shortname: string): string {
  return `schema:${listProperty === core.properties.properties ? 'property' : 'class'}:${shortname}`;
}

async function ensureAll<T extends { shortname: string; subject?: string }>(
  store: SchemaStore,
  ontology: SchemaResource,
  drive: string,
  listProperty: string,
  specs: T[],
  build: (spec: T) => { isA: string[]; propVals: Record<string, JSONValue> },
): Promise<Record<string, string>> {
  const existing = asList(ontology.get(listProperty));
  const found = await byShortname(
    store,
    existing,
    new Set(specs.map(spec => spec.shortname)),
  );

  // Every term is checked before any is written. A shared or recovered term
  // bound to the wrong class or datatype refuses the whole schema, and it must
  // do so before its siblings exist: a refusal that lands after half the terms
  // were created leaves orphans in the drive's ontology that no list points
  // at. The checks are independent reads, so they run together.
  const bindings = await inParallel(specs, spec =>
    bindOne(store, ontology, drive, listProperty, spec, found, build),
  );

  // Then the writes. Each new term is a save of its own and on a drive with no
  // schema every term needs one; in series that was most of the wait between
  // asking for a plugin and seeing its page. They write different resources
  // and none reads another's subject, so the order they land in does not
  // matter.
  const resolved = await inParallel(bindings, binding =>
    writeOne(store, ontology, drive, binding),
  );

  const result: Record<string, string> = {};
  const added: string[] = [];

  // Assembled in spec order, so what lands in the ontology does not depend on
  // which create happened to finish first.
  for (const [index, spec] of specs.entries()) {
    const subject = resolved[index];
    result[spec.shortname] = subject;

    if (!existing.includes(subject) && !added.includes(subject))
      added.push(subject);
  }

  if (added.length > 0) {
    const current = asList(ontology.get(listProperty));
    const missing = [...new Set(added)].filter(
      subject => !current.includes(subject),
    );

    if (ontology.pushListItem) {
      for (const subject of missing)
        ontology.pushListItem(listProperty, subject);
    } else {
      await ontology.set(listProperty, [...current, ...missing]);
    }

    await ontology.save();
  }

  return result;
}

/** What {@link bindOne} decided for a spec, before anything is written. */
type Binding =
  /** A shared term, used as is. */
  | { kind: 'shared'; subject: string }
  /** An existing term of this schema's, brought in line with the spec. */
  | { kind: 'recovered'; subject: string; propVals: Record<string, JSONValue> }
  /** A term that does not exist yet. */
  | {
      kind: 'create';
      /** A Property: created under its content-addressed ID. */
      contentAddressed: boolean;
      localId: string;
      isA: string[];
      propVals: Record<string, JSONValue>;
    };

/**
 * Decides how one spec is bound — shared term, recovered term, or a new one —
 * and checks the binding is compatible. Reads only: a refusal here leaves the
 * drive as it was.
 */
async function bindOne<T extends { shortname: string; subject?: string }>(
  store: SchemaStore,
  ontology: SchemaResource,
  drive: string,
  listProperty: string,
  spec: T,
  /** Resolved once for the whole spec by {@link ensureAll}. */
  found: Map<string, string>,
  build: (spec: T) => { isA: string[]; propVals: Record<string, JSONValue> },
): Promise<Binding> {
  const desired = build(spec);
  const datatype = desired.propVals[core.properties.datatype];

  if (spec.subject) {
    const shared = await store.getResource(spec.subject);
    const classes = asList(shared.get(core.properties.isA));

    if (!desired.isA.every(klass => classes.includes(klass))) {
      throw new Error(`incompatible schema binding: ${spec.subject}`);
    }

    if (datatype && shared.get(core.properties.datatype) !== datatype) {
      throw new Error(`incompatible property datatype: ${spec.subject}`);
    }

    return { kind: 'shared', subject: spec.subject };
  }

  const localId = localIdFor(listProperty, spec.shortname);
  const orphan = found.has(spec.shortname)
    ? undefined
    : await store.findByLocalId(drive, ontology.subject, localId);
  const hit = found.get(spec.shortname) ?? orphan?.subject;

  if (hit) {
    const resource = await store.getResource(hit);

    if (datatype && resource.get(core.properties.datatype) !== datatype)
      throw new Error(
        `incompatible recovered schema datatype: ${spec.shortname}`,
      );

    return { kind: 'recovered', subject: hit, propVals: desired.propVals };
  }

  return {
    kind: 'create',
    // New properties get content-addressed IDs; lookup above still finds the
    // legacy ones by shortname / localId.
    contentAddressed: listProperty === core.properties.properties,
    localId,
    ...desired,
  };
}

/** Carries out a {@link Binding}, returning the term's subject. */
async function writeOne(
  store: SchemaStore,
  ontology: SchemaResource,
  drive: string,
  binding: Binding,
): Promise<string> {
  if (binding.kind === 'shared') return binding.subject;

  if (binding.kind === 'recovered') {
    await reconcile(store, binding.subject, binding.propVals);

    return binding.subject;
  }

  const { localId, isA, propVals, contentAddressed } = binding;
  const created = await store.newResource({
    parent: ontology.subject,
    isA,
    propVals: { ...propVals, [core.properties.localId]: localId },
    ...(contentAddressed ? { contentAddressedProperty: true } : {}),
  });

  try {
    await created.save();
  } catch (error) {
    const recovered = await store.findByLocalId(
      drive,
      ontology.subject,
      localId,
    );

    if (!recovered) throw error;

    return recovered.subject;
  }

  return created.subject;
}

/**
 * Maps with at most `limit` in flight, preserving input order.
 *
 * A schema is a handful of terms, but a drive's own ontology can hold far more
 * than a browser should have in flight at once — and a plugin plan can touch
 * thousands of rows. If `work` rejects, the returned promise rejects with it;
 * work already started is not cancelled.
 */
export async function inParallel<In, Out>(
  items: In[],
  work: (item: In) => Promise<Out>,
  limit = 8,
): Promise<Out[]> {
  const results = new Array<Out>(items.length);
  let next = 0;

  const workers = Array.from(
    { length: Math.min(limit, items.length) },
    async () => {
      while (next < items.length) {
        const index = next++;
        results[index] = await work(items[index]);
      }
    },
  );

  await Promise.all(workers);

  return results;
}

/**
 * Resolves shortnames to subjects among an ontology's existing properties or
 * classes.
 *
 * `interesting` scopes ambiguity checking to the shortnames the caller
 * actually asked about. A drive's ontology accumulates entries from every
 * table and plugin that ever ran on it, so two unrelated columns landing on
 * the same shortname (two different "Status" select columns, say) is real but
 * none of this call's business — it must not fail a lookup for a shortname it
 * was never asked about.
 */
async function byShortname(
  store: SchemaStore,
  subjects: string[],
  interesting: Set<string>,
): Promise<Map<string, string>> {
  const entries = await Promise.all(
    subjects.map(async subject => {
      const resource = await store.getResource(subject);
      const shortname = resource.get(core.properties.shortname);

      return [typeof shortname === 'string' ? shortname : '', subject] as const;
    }),
  );

  const result = new Map<string, string>();

  for (const [shortname, subject] of entries) {
    if (!shortname || !interesting.has(shortname)) continue;
    if (result.has(shortname) && result.get(shortname) !== subject)
      throw new Error(`ambiguous schema shortname: ${shortname}`);
    result.set(shortname, subject);
  }

  return result;
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
