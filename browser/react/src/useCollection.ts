import {
  Collection,
  CollectionBuilder,
  proxyCollection,
  QueryFilter,
  Store,
} from '@tomic/lib';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useStore } from './hooks.js';

export type CollectionItemProps = { collection: Collection; index: number };
export type UseCollectionResult = {
  collection: Collection;
  invalidateCollection: () => Promise<void>;
  /**
   * Helper function for rendering a list of all a collections members.
   * @example
   * ```tsx
   * const List = () => {
   *  const { mapAll } = useCollection(queryFilter);
   *
   *  return (
   *    <ul>
   *    {mapAll((props) => (
   *      <li key={props.index}>
   *        <Item {...props}/>
   *      </li>
   *      ))}
   *    </ul>
   *  );
   * }
   *
   * const Item = ({ index, collection }) => {
   *  const member = useMemberFromCollection(collection, index);
   *
   *  return <div>{member.title}</div>;
   * }
   * ```
   */
  mapAll: <T>(func: (props: CollectionItemProps) => T) => T[];
};

export type UseCollectionOptions = {
  /** The max number of members on one page, defaults to 30 */
  pageSize?: number;
  /** URL of the server that should be queried. defaults to the store's serverURL */
  server?: string;
};

const buildCollection = (
  store: Store,
  server: string | undefined,
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
  { pageSize, server }: UseCollectionOptions = {
    pageSize: undefined,
    server: undefined,
  },
): UseCollectionResult {
  const [firstRun, setFirstRun] = useState(true);

  const store = useStore();
  const queryFilterMemo = useQueryFilterMemo(queryFilter);

  const [collection, setCollection] = useState(() =>
    buildCollection(store, server, queryFilterMemo, pageSize),
  );

  const mapAll = useCallback(
    <T>(func: ({ index, collection }: CollectionItemProps) => T): T[] => {
      const list: T[] = [];

      for (let index = 0; index < collection.totalMembers; index++) {
        list.push(func({ index, collection }));
      }

      return list;
    },
    [collection],
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

  return { collection, invalidateCollection, mapAll };
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
