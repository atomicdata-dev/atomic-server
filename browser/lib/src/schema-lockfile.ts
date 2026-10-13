import { planOntology, type OntologyInput } from './ontology-input.js';
import type { EnsuredOntology } from './plugin-schema.js';
import { propertyId } from './property-identity.js';

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
  /** The subject of the Ontology resource. */
  ontology: string;
  /** Property shortname to `atomic:prop:{hex}`. */
  properties: Record<string, string>;
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

  return { classes: { ...classes }, ontology, properties };
}

/** The lockfile of an ontology that `ensureOntology` made or found. */
export function lockfileFromEnsured(ensured: EnsuredOntology): Lockfile {
  return {
    classes: { ...ensured.classes },
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
    key => !['classes', 'ontology', 'properties'].includes(key),
  );

  if (
    typeof lock !== 'object' ||
    lock === null ||
    typeof lock.ontology !== 'string' ||
    !isStringMap(lock.properties) ||
    (lock.classes !== undefined && !isStringMap(lock.classes)) ||
    unknownKeys.length > 0
  ) {
    throw new Error(
      'Not a valid lockfile: expected { classes, ontology, properties }',
    );
  }

  return {
    classes: lock.classes ?? {},
    ontology: lock.ontology,
    properties: lock.properties,
  };
}

/**
 * What no longer matches between a lockfile and the schema it pins. Empty when
 * it still matches. Every property of the input must be pinned to the ID its
 * current ontology, shortname and datatype give, and nothing else may be
 * pinned. A class the lockfile knows must still be in the input; one it does
 * not know yet is fine, that is what a push adds.
 */
export function checkLockfile(lock: Lockfile, input: OntologyInput): string[] {
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

  return problems;
}

/** Throws with every problem of {@link checkLockfile}, in the words of the Rust CLI. */
export function assertLockfileMatches(
  lock: Lockfile,
  input: OntologyInput,
): void {
  const problems = checkLockfile(lock, input);

  if (problems.length > 0) {
    throw new Error(
      `The lockfile does not match the schema:\n- ${problems.join('\n- ')}`,
    );
  }
}
