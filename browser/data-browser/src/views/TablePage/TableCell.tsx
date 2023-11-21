import {
  JSONValue,
  Property,
  Resource,
  urls,
  useDebouncedCallback,
  useStore,
  useValue,
} from '@tomic/react';
import {
  startTransition,
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
  commit: false,
  validate: false,
};

export function TableCell({
  columnIndex,
  rowIndex,
  resource,
  property,
  invalidateTable,
}: TableCell): JSX.Element {
  const store = useStore();

  const [markForInvalidate, setMarkForInvalidate] = useState(false);
  const { setActiveCell } = useTableEditorContext();
  const { addItemsToHistoryStack } = useContext(TablePageContext);
  const [save, savePending] = useDebouncedCallback(
    async () => {
      await resource.save(store);
    },
    200,
    [resource, store],
  );
  const [value, setValue] = useValue(resource, property.subject, valueOpts);

  const [createdAt, setCreatedAt] = useValue(
    resource,
    urls.properties.commit.createdAt,
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
        setMarkForInvalidate(true);
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
    if (markForInvalidate && !savePending) {
      startTransition(() => {
        setMarkForInvalidate(false);
        invalidateTable?.();
        setTimeout(() => {
          setActiveCell(rowIndex + 1, columnIndex);
        }, 0);
      });
    }
  }, [
    markForInvalidate,
    savePending,
    invalidateTable,
    setActiveCell,
    rowIndex,
    columnIndex,
  ]);

  useEffect(() => {
    if (markForInvalidate && !isEditing && !savePending) {
      startTransition(() => {
        setMarkForInvalidate(false);
        invalidateTable?.();
      });
    }
  }, [isEditing, markForInvalidate, savePending, invalidateTable]);

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
