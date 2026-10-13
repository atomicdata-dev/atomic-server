import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  planOntology,
  sortedJson,
  type OntologyInput,
} from './ontology-input.js';
import type { EnsuredOntology } from './plugin-schema.js';
import { propertyId } from './property-identity.js';
import { canonicalizeScheme } from './subject.js';

/** Domain separation for fingerprints, like the one for property IDs. */
export const FINGERPRINT_CONTEXT = 'atomic schema fingerprint v1';

/**
 * The schema lockfile: the ontology subject, the class subjects and the
 * content-addressed property IDs of a schema file, pinned next to it.
 *
 * Property IDs are a pure function of ontology, shortname and datatype, so
 * {@link lockfileFromInput} needs no server. Class subjects are DIDs minted by
 * the server's first commit, so only a push can fill them in.
 *
 * The Rust twin is `lib/src/schema/lockfile.rs`. Both write
 * `lib/tests/fixtures/schema-lockfile.json` byte for byte, so change them
 * together. See `docs/src/schema/json-schema.md`.
 */
export interface Lockfile {
  /** Class shortname to subject. Empty until the ontology has been pushed. */
  classes: Record<string, string>;
  /**
   * `b3-{hex}`, see {@link schemaFingerprint}: a hash of the schema's contract
   * when it was locked. Absent in lockfiles from before it existed.
   */
  fingerprint?: string;
  /** The subject of the Ontology resource. */
  ontology: string;
  /** Property shortname to `atomic:prop:{hex}`. */
  properties: Record<string, string>;
}

/**
 * A hash of the schema's contract: the ontology, the property IDs and per
 * class what it requires, recommends, the classtype of its properties and its
 * constraints. Names and descriptions are cosmetic and stay out, and so does
 * the order of classes and properties. The Rust twin is `fingerprint` in
 * `lib/src/schema/compat.rs`.
 */
export function schemaFingerprint(
  input: OntologyInput,
  ontology: string,
): string {
  const plan = planOntology(input);
  const properties = new Map(
    plan.properties.map(p => [
      p.shortname,
      { id: propertyId(ontology, p.shortname, p.datatype), p },
    ]),
  );
  const id = (shortname: string): string => properties.get(shortname)!.id;
  const ids = (names: string[]): string[] => names.map(id).sort();
  const classes: Record<string, unknown> = {};

  for (const klass of plan.classes) {
    const classtypes: Record<string, string> = {};
    const constraints: Record<string, unknown> = {};

    for (const name of [...klass.requires, ...klass.recommends]) {
      const classtype = properties.get(name)!.p.classtype;

      if (classtype) classtypes[id(name)] = classtype;
    }

    for (const [name, keywords] of Object.entries(
      plan.constraints[klass.shortname] ?? {},
    )) {
      if (Object.keys(keywords).length > 0) constraints[id(name)] = keywords;
    }

    classes[klass.shortname] = {
      classtypes,
      constraints,
      recommends: ids(klass.recommends),
      requires: ids(klass.requires),
    };
  }

  const canonical = sortedJson({
    classes,
    ontology: canonicalizeScheme(ontology),
    properties: [...properties.values()].map(v => v.id).sort(),
  });
  const hash = blake3(utf8ToBytes(canonical), {
    context: utf8ToBytes(FINGERPRINT_CONTEXT),
  });

  return `b3-${bytesToHex(hash)}`;
}

/** Pure: no network. Pass the class subjects once they are known. */
export function lockfileFromInput(
  input: OntologyInput,
  ontology: string,
  classes: Record<string, string> = {},
): Lockfile {
  const properties: Record<string, string> = {};

  for (const property of planOntology(input).properties) {
    properties[property.shortname] = propertyId(
      ontology,
      property.shortname,
      property.datatype,
    );
  }

  return {
    classes: { ...classes },
    fingerprint: schemaFingerprint(input, ontology),
    ontology,
    properties,
  };
}

/**
 * The lockfile of an ontology that `ensureOntology` made or found. Pass the
 * `input` it was made from to pin the fingerprint too.
 */
export function lockfileFromEnsured(
  ensured: EnsuredOntology,
  input?: OntologyInput,
): Lockfile {
  return {
    classes: { ...ensured.classes },
    ...(input
      ? { fingerprint: schemaFingerprint(input, ensured.ontology) }
      : {}),
    ontology: ensured.ontology,
    properties: { ...ensured.properties },
  };
}

const byKey = ([a]: [string, string], [b]: [string, string]): number =>
  a < b ? -1 : a > b ? 1 : 0;

const stringMap = (map: Record<string, string>): string => {
  const entries = Object.entries(map).sort(byKey);

  if (entries.length === 0) return '{}';

  const lines = entries.map(
    ([key, value]) => `    ${JSON.stringify(key)}: ${JSON.stringify(value)}`,
  );

  return `{\n${lines.join(',\n')}\n  }`;
};

/** The canonical text: sorted keys, 2-space indent, trailing newline. */
export function serializeLockfile(lock: Lockfile): string {
  return (
    `{\n  "classes": ${stringMap(lock.classes)},\n` +
    (lock.fingerprint === undefined
      ? ''
      : `  "fingerprint": ${JSON.stringify(lock.fingerprint)},\n`) +
    `  "ontology": ${JSON.stringify(lock.ontology)},\n` +
    `  "properties": ${stringMap(lock.properties)}\n}\n`
  );
}

const isStringMap = (value: unknown): value is Record<string, string> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.values(value).every(v => typeof v === 'string');

export function parseLockfile(text: string): Lockfile {
  let json: unknown;

  try {
    json = JSON.parse(text);
  } catch (error) {
    throw new Error(`Not a valid lockfile: ${(error as Error).message}`);
  }

  const lock = json as Partial<Lockfile> | null;
  const unknownKeys = Object.keys(lock ?? {}).filter(
    key => !['classes', 'fingerprint', 'ontology', 'properties'].includes(key),
  );

  if (
    typeof lock !== 'object' ||
    lock === null ||
    typeof lock.ontology !== 'string' ||
    !isStringMap(lock.properties) ||
    (lock.classes !== undefined && !isStringMap(lock.classes)) ||
    (lock.fingerprint !== undefined && typeof lock.fingerprint !== 'string') ||
    unknownKeys.length > 0
  ) {
    throw new Error(
      'Not a valid lockfile: expected { classes, fingerprint?, ontology, properties }',
    );
  }

  return {
    classes: lock.classes ?? {},
    ...(lock.fingerprint === undefined
      ? {}
      : { fingerprint: lock.fingerprint }),
    ontology: lock.ontology,
    properties: lock.properties,
  };
}

/**
 * What no longer matches between a lockfile and the schema it pins. Empty when
 * it still matches. Every property of the input must be pinned to the ID its
 * current ontology, shortname and datatype give, and nothing else may be
 * pinned. A class the lockfile knows must still be in the input; one it does
 * not know yet is fine, that is what a push adds. When the lockfile has a
 * fingerprint it must match too, unless `fingerprint: false`: a push is how a
 * changed schema gets a new one.
 */
export function checkLockfile(
  lock: Lockfile,
  input: OntologyInput,
  { fingerprint = true }: { fingerprint?: boolean } = {},
): string[] {
  const expected = lockfileFromInput(input, lock.ontology).properties;
  const problems: string[] = [];

  for (const [shortname, id] of Object.entries(expected)) {
    const pinned = lock.properties[shortname];

    if (pinned === undefined) {
      problems.push(
        `property '${shortname}' is in the schema but not in the lockfile (${id})`,
      );
    } else if (pinned !== id) {
      problems.push(
        `property '${shortname}': the lockfile pins ${pinned}, the schema now gives ${id}. ` +
          "A property's identity is its ontology, shortname and datatype, so changing its " +
          'shortname or datatype makes a new property and leaves the old one behind. ' +
          'Change it back, or re-lock to accept the new property',
      );
    }
  }

  for (const shortname of Object.keys(lock.properties)) {
    if (!(shortname in expected)) {
      problems.push(
        `property '${shortname}' is in the lockfile but no longer in the schema`,
      );
    }
  }

  const classNames = input.classes.map(c => c.shortname);

  for (const shortname of Object.keys(lock.classes)) {
    if (!classNames.includes(shortname)) {
      problems.push(
        `class '${shortname}' is in the lockfile but no longer in the schema`,
      );
    }
  }

  if (fingerprint && problems.length === 0 && lock.fingerprint !== undefined) {
    const now = schemaFingerprint(input, lock.ontology);

    if (now !== lock.fingerprint) {
      problems.push(
        `the schema changed since it was locked (fingerprint ${lock.fingerprint}, now ${now}); run \`schema diff\` to see how`,
      );
    }
  }

  return problems;
}

/** Throws with every problem of {@link checkLockfile}, in the words of the Rust CLI. */
export function assertLockfileMatches(
  lock: Lockfile,
  input: OntologyInput,
  options?: { fingerprint?: boolean },
): void {
  const problems = checkLockfile(lock, input, options);

  if (problems.length > 0) {
    throw new Error(
      `The lockfile does not match the schema:\n- ${problems.join('\n- ')}`,
    );
  }
}
