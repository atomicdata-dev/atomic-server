import { Collection, Property, useStore } from '@tomic/react';
import { useCallback } from 'react';
import { CellIndex, CopyValue } from '../../../components/TableEditor';
import { getValuesFromSubject } from './clipboard';
import { transformToPropertiesPerSubject } from './transformPropertiesPerSubject';

export function useHandleCopyCommand(collection: Collection) {
  const store = useStore();

  return useCallback(
    async (cells: CellIndex<Property>[]): Promise<CopyValue[][]> => {
      const propertiesPerSubject = await transformToPropertiesPerSubject(
        cells,
        collection,
      );

      const unresolvedValues = Array.from(
        Object.entries(propertiesPerSubject),
      ).map(([subject, props]) => getValuesFromSubject(subject, props, store));

      return Promise.all(unresolvedValues);
    },

    [collection, store],
  );
}
