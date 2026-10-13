import { Client } from './client.js';
import { core, type Core } from './ontologies/core.js';
import type { Resource } from './resource.js';
import type { Store } from './store.js';
import { standardClassAlias } from './standard-class-alias.js';
import { expandSubject } from './subject-refs.js';

/** A class and its properties, in the shape an LLM tool returns. */
export async function toClassObject(subject: string, store: Store) {
  const resource = await store.getResource<Core.Class>(subject);

  if (resource.error || resource.loading) {
    return `Could not read class: ${subject}`;
  }

  return {
    subject,
    shortname: resource.props.shortname,
    description: resource.props.description,
    required: await Promise.all(
      (resource.props.requires ?? []).map(prop =>
        toPropertyObject(prop, store),
      ),
    ),
    recommended: await Promise.all(
      (resource.props.recommends ?? []).map(prop =>
        toPropertyObject(prop, store),
      ),
    ),
  };
}

/** Every class defined somewhere inside `drive`. */
export async function getClassesOnDrive(
  drive: string,
  store: Store,
): Promise<string[]> {
  return store.search('', {
    filters: {
      [core.properties.isA]: core.classes.class,
    },
    parents: [drive],
    include: true,
    limit: 1000,
  });
}

/** The titles of a resource's classes, comma separated. */
export async function getClassNames(
  resource: Resource,
  store: Store,
): Promise<string> {
  const classes = await Promise.all(
    resource.getClasses().map(subject => store.getResource(subject)),
  );

  return classes.map(cls => cls.title).join(', ');
}

/**
 * Resolves a class shortname or title to a class subject: a standard alias
 * (`folder`, `table`, ...) or a class defined on `drive`. Full URLs and short
 * `#refs` pass through (expanded). Throws on unknown or ambiguous names, with
 * a hint the model can recover from.
 */
export async function resolveClass(
  store: Store,
  drive: string,
  nameOrRef: string,
): Promise<string> {
  const nameOrSubject = expandSubject(nameOrRef);

  if (Client.isValidSubject(nameOrSubject)) {
    return nameOrSubject;
  }

  const standard = standardClassAlias(nameOrSubject);

  if (standard) return standard;

  const classSubjects = await getClassesOnDrive(drive, store);
  const wanted = nameOrSubject.toLowerCase();
  const matches: string[] = [];

  for (const subject of classSubjects) {
    const resource = await store.getResource(subject);
    const shortname = resource.get(core.properties.shortname) as
      | string
      | undefined;

    if (
      shortname?.toLowerCase() === wanted ||
      resource.title.toLowerCase() === wanted
    ) {
      matches.push(subject);
    }
  }

  if (matches.length === 1) {
    return matches[0];
  }

  if (matches.length > 1) {
    throw new Error(
      `Ambiguous class "${nameOrSubject}": ${matches.join(', ')}. Use the full class URL.`,
    );
  }

  throw new Error(
    `Unknown class "${nameOrSubject}". Use find_schema to list available classes, or pass a full class URL.`,
  );
}

async function toPropertyObject(subject: string, store: Store) {
  const resource = await store.getResource<Core.Property>(subject);

  if (resource.error || resource.loading) {
    return `Could not read property: ${subject}`;
  }

  return {
    subject,
    shortname: resource.props.shortname,
    datatype: resource.props.datatype,
  };
}
