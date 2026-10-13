import {
  Datatype,
  Resource,
  useStore,
  Collection,
  commits,
} from '@tomic/react';
import { useCallback } from 'react';
import { CellPasteData } from '@chunks/TableEditor';
import { resolvePasteValue } from '../dataTypeMaps';
import { withRowDefaults } from '../rowDefaults';
import type { TableColumn } from '../useTableColumns';
import { useSettings } from '../../../helpers/AppSettings';
import {
  HistoryItemBatch,
  createResourceCreatedHistoryItem,
  createValueChangedHistoryItem,
} from './useTableHistory';

export function useHandlePaste(
  table: Resource,
  collection: Collection,
  tableClass: Resource,
  invalidateCollection: () => void,
  addHistoryItemBatchToStack: (historyItemBatch: HistoryItemBatch) => void,
) {
  const store = useStore();
  const { contentLanguage } = useSettings();

  return useCallback(
    async (pasteData: CellPasteData<TableColumn>[]) => {
      const historyItemBatch: HistoryItemBatch = [];

      const resourceMemos = new Map<number, Resource>();
      let shouldInvalidate = false;

      for (const cell of pasteData) {
        // One cell that cannot be written must not abort the rest of the paste.
        try {
          let row = resourceMemos.get(cell.index[0]);

          if (!row) {
            let rowSubject: string | undefined;

            try {
              rowSubject = await collection.getMemberWithIndex(cell.index[0]);
            } catch (e) {
              // ignore
            }

            if (rowSubject) {
              row = await store.getResource(rowSubject);
            } else {
              // Row does not exist yet, create it
              shouldInvalidate = true;

              row = await store.newResource({
                isA: tableClass.subject,
                parent: table.subject,
                propVals: withRowDefaults(table, {
                  [commits.properties.createdAt]: Date.now(),
                }),
              });

              historyItemBatch.push(createResourceCreatedHistoryItem(row));
            }
          }

          const { property, languageTag } = cell.index[1];

          // Nothing to paste into a virtual column (a duration, a row action).
          if (!property) {
            continue;
          }

          historyItemBatch.push(
            createValueChangedHistoryItem(row, property.subject),
          );

          if (property.datatype === Datatype.LOCALIZEDTEXT) {
            // Paste replaces one language and keeps the rest of the map — the
            // split column's language, or the app's content language.
            const existing = row.get(property.subject);
            const map =
              existing &&
              typeof existing === 'object' &&
              !Array.isArray(existing)
                ? (existing as Record<string, string>)
                : {};
            await row.set(property.subject, {
              ...map,
              [languageTag ?? contentLanguage]: cell.data,
            });
          } else {
            const paste = resolvePasteValue(cell.data, property.datatype);

            // `set` throws for undefined: clear an empty cell, leave alone
            // text this column's type cannot read.
            if (paste.action === 'set') {
              await row.set(property.subject, paste.value);
            } else if (paste.action === 'clear') {
              row.remove(property.subject);
            }
          }

          await row.save();
          resourceMemos.set(cell.index[0], row);
        } catch (e) {
          console.warn('[paste] Could not paste into cell', cell.index, e);
        }
      }

      addHistoryItemBatchToStack(historyItemBatch);

      if (shouldInvalidate) {
        invalidateCollection();
      }
    },
    [collection, invalidateCollection, store, contentLanguage],
  );
}
