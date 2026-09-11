import { vi } from 'vitest';
import { core, Datatype, type Resource, type Store } from '@tomic/react';

export function formTestFixture() {
  const resources = new Map<string, Resource>();
  const saved: Array<{ subject: string; values: Record<string, unknown> }> = [];

  const make = (
    values: Record<string, unknown>,
    subject = `did:ad:test${resources.size}`,
  ) => {
    const resource = {
      subject,
      props: {},
      get: (key: string) => values[key],
      getSubjects: (key: string) => values[key] ?? [],
      hasClasses: (cls: string) =>
        ((values[core.properties.isA] as string[]) ?? []).includes(cls),
      set: vi.fn(async (key: string, value: unknown) => {
        values[key] = value;
      }),
      push: vi.fn(async (key: string, value: unknown[]) => {
        values[key] = [...((values[key] as unknown[]) ?? []), ...value];
      }),
      destroy: vi.fn(async () => {}),
      save: vi.fn(async () => {
        saved.push({ subject, values: structuredClone(values) });
      }),
    } as unknown as Resource;
    resources.set(subject, resource);

    return resource;
  };

  make({}, 'drive');
  make(
    {
      [core.properties.shortname]: 'name',
      [core.properties.datatype]: Datatype.STRING,
    },
    core.properties.name,
  );
  const store = {
    getResource: async (s: string) => {
      if (!resources.has(s)) throw new Error(`Missing ${s}`);

      return resources.get(s)!;
    },
    newResource: vi.fn(async (opts: Parameters<Store['newResource']>[0]) =>
      make({
        ...opts!.propVals,
        [core.properties.parent]: opts!.parent,
        [core.properties.isA]: Array.isArray(opts!.isA)
          ? opts!.isA
          : [opts!.isA],
      }),
    ),
    notifyResourceManuallyCreated: vi.fn(),
  };

  return {
    make,
    resources,
    saved,
    store: store as unknown as Store,
    opts: {
      driveSubject: 'drive',
      addToOntology: async (r: Resource) => {
        await r.save();
      },
    },
  };
}
