import {
  Property,
  Resource,
  useStore,
  Collection,
  commits,
} from '@tomic/react';
import { useCallback } from 'react';
import { CellPasteData } from '../../../components/TableEditor';
import { randomSubject } from '../../../helpers/randomString';
import { appendStringToType } from '../dataTypeMaps';
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

  return useCallback(
    async (pasteData: CellPasteData<Property>[]) => {
      const historyItemBatch: HistoryItemBatch = [];

      const resourceMemos = new Map<number, Resource>();
      let shouldInvalidate = false;

      for (const cell of pasteData) {
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
              subject: randomSubject(table.subject, 'row'),
              isA: tableClass.subject,
              parent: table.subject,
              propVals: {
                [commits.properties.createdAt]: Date.now(),
              },
            });

            historyItemBatch.push(createResourceCreatedHistoryItem(row));
          }
        }

        const property = cell.index[1];

        historyItemBatch.push(
          createValueChangedHistoryItem(row, property.subject),
        );

        const value = appendStringToType(
          undefined,
          cell.data,
          property.datatype,
        );

        await row.set(property.subject, value);
        await row.save();
        resourceMemos.set(cell.index[0], row);
      }

      addHistoryItemBatchToStack(historyItemBatch);

      if (shouldInvalidate) {
        invalidateCollection();
      }
    },
    [collection, invalidateCollection, store],
  );
}
