import { Collection } from '@tomic/lib';
import { useEffect, useState } from 'react';

export function useCollectionPage(collection: Collection, page: number) {
  const [items, setItems] = useState<string[]>([]);

  useEffect(() => {
    collection.getMembersOnPage(page).then(setItems);
  }, [collection, page]);

  return items;
}
