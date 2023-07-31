import { urls } from '@tomic/react';

export interface TableSorting {
  prop: string;
  sortDesc: boolean;
}

export const DEFAULT_SORT_PROP = urls.properties.commit.createdAt;
