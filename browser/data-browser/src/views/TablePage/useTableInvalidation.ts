import { Resource, StoreEvents, useStore } from '@tomic/react';
import { useCallback, useEffect, useState } from 'react';
import {
  CursorMode,
  useTableEditorContext,
} from '../../components/TableEditor/TableEditorContext';

export function useTableInvalidation(
  resource: Resource,
  invalidateTable: () => void,
) {
  const store = useStore();
  const { cursorMode } = useTableEditorContext();

  const [markedForInvalidation, setMarkedForInvalidation] = useState(false);

  const onEnter = useCallback(() => {
    if (markedForInvalidation) {
      invalidateTable();
    }
  }, [invalidateTable, markedForInvalidation]);

  useEffect(() => {
    if (markedForInvalidation && cursorMode !== CursorMode.Edit) {
      invalidateTable();
    }
  }, [markedForInvalidation, cursorMode]);

  // The first time a resource is saved, mark it for invalidation
  useEffect(() => {
    return store.on(StoreEvents.ResourceSaved, r => {
      if (!markedForInvalidation && r.subject === resource.subject) {
        setMarkedForInvalidation(true);
      }
    });
  }, [resource, store, markedForInvalidation]);

  return onEnter;
}
