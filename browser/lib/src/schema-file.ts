import { planOntology, type OntologyInput } from './ontology-input.js';
import { ontologyFromJsonSchema } from './schema-json-schema.js';

/**
 * Reads a schema file the way `atomic-cli schema` and `ad-generate ontology`
 * do. The Rust twin is `parse_plan` in `cli/src/schema.rs`.
 */

/** True for a JSON Schema: it has `$schema` or `$defs`, or is `type: object`. */
export function isJsonSchema(json: unknown): boolean {
  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    return false;
  }

  const obj = json as Record<string, unknown>;

  return '$schema' in obj || '$defs' in obj || obj.type === 'object';
}

/**
 * The text of a JSON Schema or of an `OntologyInput` (`{ shortname, classes }`)
 * as an `OntologyInput`. `shortname` overrides the ontology's shortname.
 * Throws when it is neither, or does not map to an ontology.
 */
export function ontologyFromSchemaFile(
  text: string,
  options: { shortname?: string } = {},
): OntologyInput {
  let json: unknown;

  try {
    json = JSON.parse(text);
  } catch (error) {
    throw new Error(`Not valid JSON: ${(error as Error).message}`);
  }

  if (typeof json !== 'object' || json === null || Array.isArray(json)) {
    throw new Error('A schema file must hold a JSON object');
  }

  if (isJsonSchema(json)) {
    return ontologyFromJsonSchema(json, { shortname: options.shortname });
  }

  const input = json as Partial<OntologyInput>;

  if (typeof input.shortname !== 'string' || !Array.isArray(input.classes)) {
    throw new Error(
      'Neither a JSON Schema ($schema, $defs or type: object) nor an ontology ({ shortname, classes })',
    );
  }

  const result: OntologyInput = {
    ...(input as OntologyInput),
    shortname: options.shortname ?? input.shortname,
  };

  // Fail on an inconsistent ontology now, not halfway through a push.
  planOntology(result);

  return result;
}
