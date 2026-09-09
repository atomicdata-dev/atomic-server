// @wc-ignore-file
import type { JSONValue } from "../../browser/lib/src/value.js";
import { importRecords } from "../../browser/lib/src/import-records.js";
export const manifest = { schemaVersion: 1, operations: [], secrets: [] };
export interface Config {
  platform: string;
  destinations: Record<string, { table: string; rowClass: string }>;
  properties: Record<string, string>;
  records?: {
    resource: string;
    namespace: string;
    id: string;
    name: string;
    values: Record<string, JSONValue>;
  }[];
}
export function run(ctx: {
  config: Config;
  query(p: string, v: string): string[];
  read(s: string): Record<string, unknown>;
}) {
  const c = ctx.config;
  if (!c.destinations || !c.properties || !Array.isArray(c.records))
    throw new Error("Fetch records from the connection before previewing this import");
  const identities = new Set<string>();
  const records = c.records.map((row) => {
    if (!row.id || !row.resource) throw new Error("Provider record is missing a stable identity");
    const target = c.destinations[row.resource];
    if (!target) throw new Error("No typed destination for provider collection");
    const sourceId = JSON.stringify([c.platform, row.resource, row.namespace, row.id]);
    if (identities.has(sourceId)) throw new Error("Provider returned duplicate record identity");
    identities.add(sourceId);
    const values: Record<string, JSONValue> = {
      "https://atomicdata.dev/properties/name": String(row.name),
    };
    for (const [field, value] of Object.entries(row.values)) {
      const property = c.properties[field];
      if (!property) throw new Error(`No ontology property for ${field}`);
      values[property] = value;
    }
    return { sourceId, localId: sourceId, parent: target.table, isA: [target.rowClass], values };
  });
  return importRecords(ctx, records);
}
