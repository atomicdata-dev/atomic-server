import { describe, expect, it } from 'vitest';
import { run } from './plugin';
import { demoPets } from './data';

const p = {
  'pet-species': 'https://example.com/pet-species',
  'pet-breed': 'https://example.com/pet-breed',
  'pet-age': 'https://example.com/pet-age',
  'pet-mood': 'https://example.com/pet-mood',
  'pet-source-id': 'https://example.com/pet-source-id',
};
const config = {
  table: 'https://example.com/table',
  rowClass: 'https://example.com/pet',
  properties: p,
};

describe('pets plugin', () => {
  it('proposes one create intent per demo pet', () => {
    const host = { config, query: () => [] as string[], read: () => ({}) };
    const result = run(host) as {
      intents: Array<{
        op: string;
        parent: string;
        isA: string[];
        set: Record<string, unknown>;
      }>;
      problems: Array<{ severity: string; message: string }>;
    };
    expect(result.intents).toHaveLength(demoPets().length);
    expect(result.intents.every(i => i.op === 'create')).toBe(true);
    expect(result.intents.every(i => i.parent === config.table)).toBe(true);
    expect(result.intents.every(i => i.isA[0] === config.rowClass)).toBe(true);
    const rex = result.intents.find(
      i => i.set['https://atomicdata.dev/properties/name'] === 'Rex',
    );
    expect(rex?.set[p['pet-species']]).toBe('Dog');
    expect(rex?.set[p['pet-source-id']]).toBe('pets:demo:1');
    expect(result.problems.some(pr => pr.severity === 'warning')).toBe(true);
  });

  it('throws without a configured destination', () => {
    const host = {
      config: { table: '', rowClass: '', properties: {} },
      query: () => [] as string[],
      read: () => ({}),
    };
    expect(() => run(host)).toThrow(/Configure the connection/);
  });

  it('is idempotent: reimporting unchanged pets proposes nothing new', () => {
    const written = new Map<string, Record<string, unknown>>();
    let host = {
      config,
      query: () => [] as string[],
      read: (subject: string) => written.get(subject) ?? {},
    };
    const first = run(host) as {
      intents: Array<{
        op: string;
        localId?: string;
        set: Record<string, unknown>;
      }>;
    };
    for (const [index, intent] of first.intents.entries()) {
      written.set(`https://example.com/pet-${index}`, {
        'https://atomicdata.dev/properties/parent': config.table,
        'https://atomicdata.dev/properties/isA': [config.rowClass],
        ...intent.set,
      });
    }
    const bySourceId = new Map(
      [...written.entries()].map(([subject, value]) => [
        value[p['pet-source-id']] as string,
        subject,
      ]),
    );
    host = {
      config,
      query: (property: string, value: string) =>
        property === 'https://atomicdata.dev/properties/localId'
          ? [bySourceId.get(value) ?? ''].filter(Boolean)
          : [],
      read: (subject: string) => written.get(subject) ?? {},
    };
    const second = run(host) as { intents: unknown[] };
    expect(second.intents).toHaveLength(0);
  });
});
