import { AtomicError } from './error.js';
import { server } from './ontologies/server.js';
import { Resource, unknownSubject } from './resource.js';
import { subjectsReferToSameResource } from './subject.js';
import { type JSONObject, type AtomicValue, isJSONObject } from './value.js';
import { decodeB64 } from './base64.js';

/**
 * Parses a JSON-AD object or array into resources. Create a new instance each time you need to parse a json-ad string.
 */
export class JSONADParser {
  /** Resources found nested inside other resources' property values (e.g.
   *  collection `members` served with `include_nested`). Collected during
   *  `parseObject`; the referencing property keeps only the `@id` string. */
  private nestedResources: Resource[] = [];

  public parse(json: unknown, subject: string = unknownSubject): Resource[] {
    this.nestedResources = [];

    if (Array.isArray(json)) {
      // Array responses contain multiple resources (e.g. search with include=true).
      // Each item has its own @id. Parse without enforcing a subject match — the
      // caller (fetchResourceHTTP) will find the right one by subject.
      const mains = json.flatMap(item =>
        typeof item === 'object' && item !== null && !Array.isArray(item)
          ? [this.parseObject(item as JSONObject)]
          : [],
      );

      return [...this.nestedResources, ...mains];
    }

    if (typeof json !== 'object' || json === null) {
      throw new Error('JSON-AD must be an object or array');
    }

    const main = this.parseObject(json as JSONObject, subject);

    // Nested first: `fetchResourceHTTP` falls back to "the last resource is
    // the requested one" when no subject matches exactly.
    return [...this.nestedResources, main];
  }

  private parseObject(json: JSONObject, subject?: string): Resource {
    const resource = new Resource(subject ?? unknownSubject);

    try {
      const hydratedValues: [string, AtomicValue][] = [];

      for (const [key, value] of Object.entries(json)) {
        if (key === '@id') {
          if (typeof value !== 'string') {
            throw new Error('Expected @id to be a string');
          }

          // Only enforce subject match when a specific subject was requested.
          // HTTP aliases of a DID (`https://host/did:ad:…`) are the same
          // resource as `@id: did:ad:…` — the server keeps the DID as
          // identity even when the resource was fetched by URL.
          if (
            subject &&
            subject !== unknownSubject &&
            !subjectsReferToSameResource(subject, value)
          ) {
            throw new Error(
              `Resource has wrong subject in @id. Received subject was ${value}, expected ${resource.subject}.`,
            );
          }

          resource.setSubject(value as string);
          continue;
        }

        // Handle serialized LoroDoc binary values from JSON-AD
        if (
          isJSONObject(value) &&
          value.type === 'lorodoc' &&
          typeof value.data === 'string'
        ) {
          hydratedValues.push([key, decodeB64(value.data)]);
          continue;
        }

        // A nested resource (an object with an `@id`, e.g. collection members
        // served with `include_nested`) is a resource of its own: parse it
        // separately and keep only the reference. Leaving the raw object in
        // the propval hands consumers an object where they expect a subject
        // string (`normalizeSubject` crashes on it). Objects WITHOUT an `@id`
        // are plain JSON-datatype values and pass through untouched.
        if (isJSONObject(value) && typeof value['@id'] === 'string') {
          this.nestedResources.push(this.parseObject(value));
          hydratedValues.push([key, value['@id']]);
          continue;
        }

        if (
          Array.isArray(value) &&
          value.some(v => isJSONObject(v) && typeof v['@id'] === 'string')
        ) {
          hydratedValues.push([
            key,
            value.map(v => {
              if (isJSONObject(v) && typeof v['@id'] === 'string') {
                this.nestedResources.push(this.parseObject(v));

                return v['@id'];
              }

              return v;
            }),
          ]);
          continue;
        }

        hydratedValues.push([key, value]);
      }

      resource.applyHydratedValues(hydratedValues);

      resource.getLoroDoc();

      if (resource.hasClasses(server.classes.error)) {
        resource.error = AtomicError.fromResource(resource);
      }
    } catch (e) {
      e.message = 'Failed parsing JSON ' + e.message;
      resource.setError(e);
      resource.loading = false;

      throw e;
    }

    return resource;
  }
}
