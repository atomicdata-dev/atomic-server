import {
  commits,
  JSONValue,
  Property,
  Resource,
  useDebouncedCallback,
  useValue,
} from '@tomic/react';
import { useCallback, useContext, useMemo } from 'react';
import { Cell } from '../../components/TableEditor';
import { CellAlign } from '../../components/TableEditor/Cell';
import {
  CursorMode,
  useTableEditorContext,
} from '../../components/TableEditor/TableEditorContext';
import {
  appendStringToType,
  dataTypeAlignmentMap,
  dataTypeCellMap,
} from './dataTypeMaps';
import { StringCell } from './EditorCells/StringCell';
import { TablePageContext } from './tablePageContext';
import { createValueChangedHistoryItem } from './helpers/useTableHistory';

interface TableCell {
  columnIndex: number;
  rowIndex: number;
  resource: Resource;
  property: Property;
  onEditNextRow?: () => void;
}

function useIsEditing(row: number, column: number) {
  const { cursorMode, selectedColumn, selectedRow } = useTableEditorContext();

  const isEditing =
    cursorMode === CursorMode.Edit &&
    selectedColumn === column &&
    selectedRow === row;

  return isEditing;
}

const valueOpts = {
  commitDebounce: 0,
  commit: false,
  validate: false,
};

export function TableCell({
  columnIndex,
  rowIndex,
  resource,
  property,
  onEditNextRow,
}: TableCell): JSX.Element {
  const { setActiveCell } = useTableEditorContext();
  const { addItemsToHistoryStack } = useContext(TablePageContext);
  const [save, savePending] = useDebouncedCallback(
    async () => {
      await resource.save();
    },
    200,
    [resource],
  );
  const [value, setValue] = useValue(resource, property.subject, valueOpts);

  const [createdAt, setCreatedAt] = useValue(
    resource,
    commits.properties.createdAt,
    { commit: false, commitDebounce: 0 },
  );

  const dataType = property.datatype;
  const isEditing = useIsEditing(rowIndex, columnIndex);

  const Editor = useMemo(
    () => dataTypeCellMap.get(dataType) ?? StringCell,
    [dataType],
  );

  const alignment = dataTypeAlignmentMap.get(dataType) ?? CellAlign.Start;

  const onChange = useCallback(
    async (v: JSONValue) => {
      if (!createdAt) {
        await setCreatedAt(Date.now());
      }

      addItemsToHistoryStack(
        createValueChangedHistoryItem(resource, property.subject),
      );

      await setValue(v);

      save();
    },
    [setValue, setCreatedAt, createdAt, resource, property, save],
  );

  const handleEnterEditModeWithCharacter = useCallback(
    (key: string) => {
      onChange(appendStringToType(undefined, key, dataType));
    },
    [onChange, dataType],
  );

  const handleEditNextRow = useCallback(() => {
    if (!savePending) {
      onEditNextRow?.();
      setTimeout(() => {
        setActiveCell(rowIndex + 1, columnIndex);
      }, 0);
    }
  }, [savePending, setActiveCell, rowIndex, columnIndex]);

  return (
    <Cell
      rowIndex={rowIndex}
      columnIndex={columnIndex}
      align={alignment}
      onEnterEditModeWithCharacter={handleEnterEditModeWithCharacter}
      onEditNextRow={handleEditNextRow}
    >
      {isEditing ? (
        <Editor.Edit
          value={value}
          onChange={onChange}
          property={property.subject}
          resource={resource}
        />
      ) : (
        <>
          <Editor.Display
            value={value}
            onChange={onChange}
            property={property.subject}
          />
        </>
      )}
    </Cell>
  );
}
