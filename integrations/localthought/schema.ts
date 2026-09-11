// @wc-ignore-file
import { core, Datatype, type SchemaSpec } from "../../browser/lib/src/index.js";
import type { JSONValue } from "../../browser/lib/src/value.js";
export interface Term {
  path: string;
  kind: "class" | "property";
  shortname: string;
  description: string;
  datatype: Datatype;
  requires: string[];
  recommends: string[];
}
export interface FetchedRecord {
  resource: string;
  namespace: string;
  id: string;
  name: string;
  values: Record<string, JSONValue>;
}
export interface FetchedPlatform {
  platform: string;
  ontology: { description: string; terms: Term[] };
  records: FetchedRecord[];
}
export const termKey = (platform: string, term: Pick<Term, "kind" | "shortname">) =>
  `lt-${platform}-${term.kind}-${term.shortname}`;
export function platformSchema(platform: string, terms: Term[]): SchemaSpec {
  const paths = new Map(terms.map((term) => [term.path, termKey(platform, term)]));
  return {
    properties: [
      {
        subject: core.properties.name,
        shortname: "name",
        name: "Name",
        description: "Display name of the imported record.",
        datatype: Datatype.STRING,
      },
      ...terms
        .filter((t) => t.kind === "property")
        .map((t) => ({
          shortname: termKey(platform, t),
          name: t.shortname.replaceAll("-", " "),
          description: t.description,
          datatype: t.datatype,
        })),
    ],
    classes: terms
      .filter((t) => t.kind === "class")
      .map((t) => ({
        shortname: termKey(platform, t),
        name: t.shortname.replaceAll("-", " "),
        description: t.description,
        // API fields can be required yet nullable, or omitted in partial representations.
        // Keep them typed and recommended without forbidding those valid responses.
        requires: [],
        recommends: [
          "name",
          ...[...t.requires, ...t.recommends].map((path) => {
            const key = paths.get(path);
            if (!key) throw new Error(`Unknown ontology property ${path}`);
            return key;
          }),
        ],
      })),
  };
}
