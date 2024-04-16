import { Collection, Property, useStore } from '@tomic/react';
import { useCallback } from 'react';
import { CellIndex } from '../../../components/TableEditor';
import {
  AddItemToHistoryStack,
  HistoryItemBatch,
  createValueChangedHistoryItem,
} from './useTableHistory';
import { transformToPropertiesPerSubject } from './transformPropertiesPerSubject';

export function useHandleClearCells(
  collection: Collection,
  addItemsToHistoryStack: AddItemToHistoryStack,
) {
  const store = useStore();

  return useCallback(
    async (cells: CellIndex<Property>[]) => {
      const resourcePropMap = await transformToPropertiesPerSubject(
        cells,
        collection,
      );

      const historyItemBatch: HistoryItemBatch = [];

      const removePropvals = async ([subject, props]: [string, Property[]]) => {
        const res = await store.getResource(subject);

        await Promise.all(
          props.map(prop => {
            historyItemBatch.push(
              createValueChangedHistoryItem(res, prop.subject),
            );

            return res.set(prop.subject, undefined, false);
          }),
        );

        await res.save();
      };

      await Promise.all(
        Array.from(Object.entries(resourcePropMap)).map(removePropvals),
      );

      addItemsToHistoryStack(historyItemBatch);
    },
    [store, collection],
  );
}
