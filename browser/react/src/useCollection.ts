import { Collection, CollectionBuilder, QueryFilter, Store } from '@tomic/lib';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useServerURL } from './useServerURL.js';
import { useStore } from './hooks.js';

export type UseCollectionResult = {
  collection: Collection;
  invalidateCollection: () => Promise<void>;
  /** Because collection is a class and fetches data after it is created we need a way to track if it changes so we can rerender parts of the UI */
  collectionVersion: number;
};

const buildCollection = (
  store: Store,
  server: string,
  { property, value, sort_by, sort_desc }: QueryFilter,
  pageSize?: number,
) => {
  const builder = new CollectionBuilder(store, server);

  property && builder.setProperty(property);
  value && builder.setValue(value);
  sort_by && builder.setSortBy(sort_by);
  sort_desc !== undefined && builder.setSortDesc(sort_desc);
  pageSize && builder.setPageSize(pageSize);

  return builder.build();
};

/**
 * Creates a collection resource that is rebuild when the query filter changes or `invalidateCollection` is called.
 * @param queryFilter
 * @param pageSize number of items per collection resource, defaults to 30.
 */
export function useCollection(
  queryFilter: QueryFilter,
  pageSize?: number,
): UseCollectionResult {
  const store = useStore();
  const [server] = useServerURL();
  const [collectionVersion, setCollectionVersion] = useState(0);

  const queryFilterMemo = useQueryFilterMemo(queryFilter);

  const [collection, setCollection] = useState(() =>
    buildCollection(store, server, queryFilterMemo, pageSize),
  );

  useEffect(() => {
    collection.waitForReady().then(() => {
      setCollectionVersion(version => version + 1);
    });
  }, []);

  useEffect(() => {
    const newCollection = buildCollection(
      store,
      server,
      queryFilterMemo,
      pageSize,
    );

    newCollection.waitForReady().then(() => {
      setCollection(newCollection);
      setCollectionVersion(version => version + 1);
    });
  }, [queryFilterMemo, pageSize, store, server]);

  const invalidateCollection = useCallback(async () => {
    const clonedCollection = collection.clone();
    await clonedCollection.refresh();
    setCollection(clonedCollection);
    setCollectionVersion(version => version + 1);
  }, [collection, store, server, queryFilter, pageSize]);

  return { collection, invalidateCollection, collectionVersion };
}

function useQueryFilterMemo(queryFilter: QueryFilter) {
  return useMemo(
    () => queryFilter,
    [
      queryFilter.property,
      queryFilter.value,
      queryFilter.sort_by,
      queryFilter.sort_desc,
    ],
  );
}
