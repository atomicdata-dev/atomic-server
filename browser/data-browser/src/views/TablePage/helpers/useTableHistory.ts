import { JSONValue, Resource, Store, useStore } from '@tomic/react';
import { useCallback, useState } from 'react';

enum HistoryItemType {
  ValueChange,
  ResourceCreated,
  ResourceDeleted,
}

interface ValueChangeItem {
  type: HistoryItemType.ValueChange;
  subject: string;
  property: string;
  previousValue: JSONValue;
}

interface ResourceCreatedItem {
  type: HistoryItemType.ResourceCreated;
  subject: string;
}

interface ResourceDeletedItem {
  type: HistoryItemType.ResourceDeleted;
  subject: string;
  propVals: Map<string, JSONValue>;
}

type HistoryItem = ValueChangeItem | ResourceCreatedItem | ResourceDeletedItem;

export type HistoryItemBatch = HistoryItem[];

export type HistoryStack = Array<HistoryItem | HistoryItemBatch>;

export type AddItemToHistoryStack = (
  item: HistoryItem | HistoryItemBatch,
) => void;

const isValueChangeItem = (
  item: HistoryItem | HistoryItemBatch,
): item is ValueChangeItem =>
  !Array.isArray(item) && item.type === HistoryItemType.ValueChange;

const isResourceCreatedItem = (
  item: HistoryItem | HistoryItemBatch,
): item is ResourceCreatedItem =>
  !Array.isArray(item) && item.type === HistoryItemType.ResourceCreated;

export function createValueChangedHistoryItem(
  resource: Resource,
  property: string,
): ValueChangeItem {
  return {
    type: HistoryItemType.ValueChange,
    subject: resource.getSubject(),
    property,
    previousValue: resource.get(property),
  };
}

export function createResourceCreatedHistoryItem(
  resource: Resource,
): ResourceCreatedItem {
  return {
    type: HistoryItemType.ResourceCreated,
    subject: resource.getSubject(),
  };
}

export function createResourceDeletedHistoryItem(
  resource: Resource,
): ResourceDeletedItem {
  return {
    type: HistoryItemType.ResourceDeleted,
    subject: resource.getSubject(),
    propVals: resource.getPropVals(),
  };
}

async function undoValueChange(item: ValueChangeItem, store: Store) {
  const resource = store.getResourceLoading(item.subject);

  await resource.set(item.property, item.previousValue, store, false);
  await resource.save(store);
}

async function undoResourceCreated(item: ResourceCreatedItem, store: Store) {
  const resource = store.getResourceLoading(item.subject);

  await resource.destroy(store);

  return true;
}

async function undoResourceDeleted(item: ResourceDeletedItem, store: Store) {
  const resource = store.getResourceLoading(item.subject, {
    newResource: true,
  });

  for (const [prop, val] of item.propVals) {
    await resource.set(prop, val, store, false);
  }

  await resource.save(store);

  return true;
}

async function undoItem(item: HistoryItem, store: Store) {
  switch (item.type) {
    case HistoryItemType.ValueChange:
      return undoValueChange(item, store);
    case HistoryItemType.ResourceCreated:
      return undoResourceCreated(item, store);
    case HistoryItemType.ResourceDeleted:
      return undoResourceDeleted(item, store);
  }
}

const shouldMergeItem = (
  item: ValueChangeItem,
  lastItem: HistoryItem | HistoryItemBatch,
) => {
  const matchingValueChangeItem =
    isValueChangeItem(lastItem) &&
    lastItem.subject === item.subject &&
    lastItem.property === item.property;

  const matchingResourceCreatedItem =
    isResourceCreatedItem(lastItem) && lastItem.subject === item.subject;

  return matchingValueChangeItem || matchingResourceCreatedItem;
};

function addSingleItem(item: HistoryItem, stack: HistoryStack) {
  const lastItem = stack[stack.length - 1];

  if (lastItem && isValueChangeItem(item) && shouldMergeItem(item, lastItem)) {
    // If the last item is the same except for value we don't record the new value. This is to prevent recording values every keystroke.
    return stack;
  }

  return [...stack, item];
}

function addBatch(items: HistoryItemBatch, stack: HistoryStack) {
  return [...stack, items];
}

export function useTableHistory(invalidateTable: () => void) {
  const store = useStore();
  const [stack, setStack] = useState<HistoryStack>([]);

  const addItemsToHistoryStack: AddItemToHistoryStack = useCallback(
    (item: HistoryItem | HistoryItemBatch) => {
      setStack(prev => {
        if (Array.isArray(item)) {
          return addBatch(item, prev);
        }

        return addSingleItem(item, prev);
      });
    },
    [],
  );

  const undoLastItem = useCallback(async () => {
    const lastItem = stack[stack.length - 1];
    let shouldInvalidate = false;

    if (!lastItem) {
      return;
    }

    if (Array.isArray(lastItem)) {
      // TODO: Check if the array only consists of value changes and if so use Promise.all

      for (const item of lastItem) {
        const collectionUpdated = await undoItem(item, store);

        if (collectionUpdated) {
          shouldInvalidate = true;
        }
      }
    } else {
      const collectionUpdated = await undoItem(lastItem, store);

      if (collectionUpdated) {
        shouldInvalidate = true;
      }
    }

    setStack(prev => prev.slice(0, prev.length - 1));

    if (shouldInvalidate) {
      invalidateTable();
    }
  }, [stack, store, invalidateTable]);

  return {
    addItemsToHistoryStack,
    undoLastItem,
  };
}
