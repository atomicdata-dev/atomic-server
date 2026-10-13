// @wc-ignore-file
import {
  core,
  dataBrowser,
  type Store,
  type Resource,
  type JSONValue,
} from '@tomic/lib';
import { expandSubject, shortenRefsDeep } from '@tomic/react';
import { buildClassContext, resolveKey, coerceValueIn } from '@tomic/react';

export async function updateTableRows(
  store: Store,
  table: string,
  rows: {
    subject: string;
    values: Record<string, string | number | boolean | string[]>;
  }[],
  onResourceEdited?: (resource: Resource) => void,
) {
  const updated: string[] = [];

  try {
    const tableSubject = expandSubject(table);
    const source = await store.getResource(tableSubject);
    if (!source.hasClasses(dataBrowser.classes.table))
      throw new Error('Expected an Atomic table.');
    const prepared = [];
    const seen = new Set<string>();

    // Resolve and check every row before mutating any row.
    for (const patch of rows) {
      const subject = expandSubject(patch.subject);
      if (seen.has(subject)) throw new Error('Each row may occur only once.');
      seen.add(subject);
      const resource = await store.getResource(subject);
      if (resource.get(core.properties.parent) !== tableSubject)
        throw new Error('Row does not belong to the selected table.');
      const agent = store.getAgent();
      if (!agent || !(await resource.canWrite(agent.subject)))
        throw new Error('You cannot edit this row.');
      const context = await buildClassContext(store, resource.getClasses());
      const values = Object.entries(patch.values).map(([key, value]) => {
        const property = resolveKey(context, key);

        return [
          property.subject,
          coerceValueIn(property, value as JSONValue),
        ] as const;
      });
      prepared.push({ resource, values });
    }

    for (const { resource, values } of prepared) {
      const original = resource.clone();
      for (const [property, value] of values)
        await resource.set(property, value);
      await resource.save();
      updated.push(resource.subject);
      onResourceEdited?.(original);
    }

    return shortenRefsDeep({ updated });
  } catch (error) {
    return shortenRefsDeep({
      updated,
      error: String(error),
      note: 'Earlier updated rows remain saved. A failing row may have pending local edits; inspect it before retrying.',
    });
  }
}
