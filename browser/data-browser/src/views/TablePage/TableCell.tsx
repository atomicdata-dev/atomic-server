import { JSONValue, Property, Resource, urls, useValue } from '@tomic/react';
import React, {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
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
  invalidateTable?: () => void;
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
  commit: true,
};

export function TableCell({
  columnIndex,
  rowIndex,
  resource,
  property,
  invalidateTable,
}: TableCell): JSX.Element {
  const [markForInvalidate, setMarkForInvalidate] = useState(false);
  const { addItemsToHistoryStack } = useContext(TablePageContext);

  const [value, setValue] = useValue(resource, property.subject, valueOpts);

  const [createdAt, setCreatedAt] = useValue(
    resource,
    urls.properties.commit.createdAt,
    valueOpts,
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
        addItemsToHistoryStack(
          createValueChangedHistoryItem(resource, property.subject),
        );
        await setValue(v);
        await setCreatedAt(Date.now());
        setMarkForInvalidate(true);

        return;
      }

      addItemsToHistoryStack(
        createValueChangedHistoryItem(resource, property.subject),
      );
      await setValue(v);
    },
    [setValue, setCreatedAt, createdAt, value, resource, property],
  );

  const handleEnterEditModeWithCharacter = useCallback(
    (key: string) => {
      onChange(appendStringToType(undefined, key, dataType));
    },
    [onChange, dataType],
  );

  useEffect(() => {
    if (!isEditing && markForInvalidate) {
      setMarkForInvalidate(false);
      invalidateTable?.();
    }
  }, [isEditing, markForInvalidate]);

  return (
    <Cell
      rowIndex={rowIndex}
      columnIndex={columnIndex}
      align={alignment}
      onEnterEditModeWithCharacter={handleEnterEditModeWithCharacter}
    >
      {isEditing ? (
        <Editor.Edit
          value={value}
          onChange={onChange}
          property={property.subject}
          resource={resource}
        />
      ) : (
        <React.Fragment key={`${value}`}>
          <Editor.Display
            value={value}
            onChange={onChange}
            property={property.subject}
          />
        </React.Fragment>
      )}
    </Cell>
  );
}
