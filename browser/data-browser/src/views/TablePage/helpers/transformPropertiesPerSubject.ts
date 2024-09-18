import { Collection, Property } from '@tomic/react';
import { CellIndex } from '../../../components/TableEditor';

export const transformToPropertiesPerSubject = async (
  cells: CellIndex<Property>[],
  collection: Collection,
): Promise<Record<string, Property[]>> => {
  const result: Record<string, Property[]> = {};

  for (const [rowIndex, property] of cells) {
    const subject = await collection.getMemberWithIndex(rowIndex);

    if (!subject) {
      continue;
    }

    result[subject] = [...(result[subject] ?? []), property];
  }

  return result;
};
