import { Resource } from '@tomic/react';
import type { JSX } from 'react';
import { StringListEditor } from './StringListEditor';
import { useFieldOptions } from './useFieldOptions';

interface MatrixOptionsProps {
  field: Resource;
}

/** A `choice-matrix` is one radio group per row, all sharing the same
 * columns — so both lists are plain strings. */
export function MatrixOptions({ field }: MatrixOptionsProps): JSX.Element {
  const [options, setOptions] = useFieldOptions(field);

  return (
    <>
      <StringListEditor
        label='Rows (statements)'
        value={(options.rows as string[] | undefined) ?? []}
        onChange={list => setOptions({ ...options, rows: list })}
        resetKey={field.subject}
        addLabel='Add row'
        removeLabel='Remove row'
        newItemLabel={index => `Statement ${index}`}
        itemTestId='matrix-row-input'
      />
      <StringListEditor
        label='Columns (answers)'
        value={(options.columns as string[] | undefined) ?? []}
        onChange={list => setOptions({ ...options, columns: list })}
        resetKey={field.subject}
        addLabel='Add column'
        removeLabel='Remove column'
        newItemLabel={index => `Answer ${index}`}
        itemTestId='matrix-column-input'
      />
    </>
  );
}
