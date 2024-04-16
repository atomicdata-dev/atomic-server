import {
  Collection,
  CollectionBuilder,
  proxyCollection,
  QueryFilter,
  Store,
} from '@tomic/lib';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useServerURL } from './useServerURL.js';
import { useStore } from './hooks.js';

export type UseCollectionResult = {
  collection: Collection;
  invalidateCollection: () => Promise<void>;
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
  const [firstRun, setFirstRun] = useState(true);

  const store = useStore();
  const [server] = useServerURL();

  const queryFilterMemo = useQueryFilterMemo(queryFilter);

  const [collection, setCollection] = useState(() =>
    buildCollection(store, server, queryFilterMemo, pageSize),
  );

  useEffect(() => {
    collection.waitForReady().then(() => {
      setCollection(proxyCollection(collection.__internalObject));
    });
  }, []);

  useEffect(() => {
    if (firstRun) {
      setFirstRun(false);

      return;
    }

    const newCollection = buildCollection(
      store,
      server,
      queryFilterMemo,
      pageSize,
    );

    newCollection.waitForReady().then(() => {
      setCollection(proxyCollection(newCollection.__internalObject));
    });
  }, [queryFilterMemo, pageSize, store, server]);

  const invalidateCollection = useCallback(async () => {
    await collection.refresh();
    setCollection(proxyCollection(collection.__internalObject));
  }, [collection, store, server, queryFilter, pageSize]);

  return { collection, invalidateCollection };
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
