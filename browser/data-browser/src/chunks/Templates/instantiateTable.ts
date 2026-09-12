// @wc-ignore-file
import type { Store } from '@tomic/react';
import { TABLE_TEMPLATES } from '../TablePage/tableTemplates';
import { buildTableFromSpec } from '../TablePage/createTableFromSpec';

/** Both New Table and workspace instantiation resolve the same catalog release. */
export async function instantiateTableTemplate(
  store: Store,
  catalogId: string,
  name: string,
  rowName: string | undefined,
  target: Parameters<typeof buildTableFromSpec>[2],
  examples = false,
) {
  const source = TABLE_TEMPLATES.find(t => t.id === catalogId);
  if (!source?.spec) throw new Error(`Unknown table template: ${catalogId}`);

  return buildTableFromSpec(
    store,
    {
      ...structuredClone(source.spec),
      name,
      rowName: rowName ?? source.rowName,
      rows: examples
        ? [0, 1, 2].map(index => ({
            name: `Example ${source.rowName.toLowerCase()} ${index + 1}`,
            ...Object.fromEntries(
              source
                .spec!.columns.filter(
                  column => column.type === 'select' && column.options?.length,
                )
                .map(column => [
                  column.name,
                  column.options![index % column.options!.length],
                ]),
            ),
          }))
        : [],
    },
    target,
  );
}
