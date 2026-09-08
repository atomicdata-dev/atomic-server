// @wc-ignore-file
import {
  importRecords,
  type ImportRecord,
} from '../../browser/lib/src/import-records.js';
import { demoPets } from './data.js';

/** No external provider: no operations, no secrets. */
export const manifest = { schemaVersion: 1, operations: [], secrets: [] };

export interface Config {
  table: string;
  rowClass: string;
  properties: Record<string, string>;
}

interface Host {
  config: Config;
  query(property: string, value: string): string[];
  read(subject: string): Record<string, unknown>;
}

const NAME = 'https://atomicdata.dev/properties/name';

export function run(ctx: Host) {
  const { table, rowClass, properties: p } = ctx.config;

  if (!table || !rowClass || !p)
    throw new Error('Configure the connection before running it');

  const pets = demoPets();
  const records: ImportRecord[] = pets.map(pet => {
    const identity = `pets:demo:${pet.id}`;

    return {
      sourceId: identity,
      localId: `pet-${pet.id}`,
      parent: table,
      isA: [rowClass],
      values: {
        [NAME]: pet.name,
        [p['pet-species']]: pet.species,
        [p['pet-breed']]: pet.breed,
        [p['pet-age']]: pet.age,
        [p['pet-mood']]: pet.mood,
        [p['pet-source-id']]: identity,
      },
    };
  });

  const result = importRecords(ctx, records);

  return {
    intents: result.intents,
    problems: [
      ...result.problems,
      {
        severity: 'warning' as const,
        message: `${pets.length} demo pets reconciled; ${result.summary.unchanged} unchanged. This is static sample data, not a live provider.`,
      },
    ],
  };
}
