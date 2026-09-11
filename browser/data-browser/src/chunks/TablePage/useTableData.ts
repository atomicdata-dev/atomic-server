import {
  core,
  type ExpressionFilter,
  PropVal,
  Resource,
  unknownSubject,
  useCollection,
  UseCollectionResult,
  useResource,
  useStore,
  useSubject,
} from '@tomic/react';
import { useTableView, UseTableViewResult } from './useTableView';
import { toAggregation } from './tableAggregates';
import { quantizedNow, splitFilters } from './tableFiltering';

const PAGE_SIZE = 30;

type UseTableDataResult = {
  tableClass: Resource;
  /**
   * The constraints the grid queries with (class + the view's filters). Shared
   * so the totals can be computed over exactly the rows the grid shows.
   */
  queryFilters: PropVal[];
  /** The constraints on computed values, shared with the totals query so the
   *  numbers describe the same rows. */
  queryExpressionFilters: ExpressionFilter[];
} & UseCollectionResult &
  UseTableViewResult;

export function useTableData(
  resource: Resource,
  /** Which view to show, when the caller decides rather than the URL. */
  viewOverride?: string,
): UseTableDataResult {
  const tableView = useTableView(resource, viewOverride);
  const { filters, sorting } = tableView;
  const store = useStore();

  const [classSubject] = useSubject(resource, core.properties.classtype);
  const tableClass = useResource(classSubject);

  // Only constraints with an actual value narrow the query; an in-progress
  // filter (empty value) stays visible as a chip but doesn't blank the table.
  // A constraint on a computed column can't be indexed, so it travels separately
  // and the store evaluates it over the rows the index narrows to.
  const { propVals: userFilters, expressionFilters } = splitFilters(
    filters,
    tableView.viewDerivedColumns,
    quantizedNow(),
  );

  // Constrain rows to instances of the table's classtype. This keeps non-row
  // children — notably the table's own View resources — out of the row list.
  // Don't query at all until the classtype is known: a `parent=` query
  // without `isA` briefly lists views as rows, then filters them out.
  const classReady = !!classSubject && classSubject !== unknownSubject;
  const classFilter: PropVal[] = classReady
    ? [{ property: core.properties.isA, value: classSubject }]
    : [];

  // The view's statistics ride along with the query, so the store computes them
  // over every matching row (filters included, paging excluded) instead of the
  // client adding up the page it happens to have.
  const aggregation = toAggregation(
    tableView.viewAggregates,
    tableView.viewGroupByColumn,
    tableView.viewGroupGranularity,
    tableView.viewDerivedColumns,
  );

  const queryFilter = {
    property: core.properties.parent,
    // `Collection.fetchPage` no-ops when value is undefined. Hold the
    // query until classtype is known so views don't flash as rows.
    value: classReady ? resource.subject : undefined,
    filters: [...classFilter, ...userFilters],
    expression_filters: expressionFilters,
    sort_by: sorting.prop,
    sort_desc: sorting.sortDesc,
    aggregation,
  };

  const { collection, ready, invalidateCollection, mapAll } = useCollection(
    queryFilter,
    {
      pageSize: PAGE_SIZE,
      server: resource.subject.startsWith('http')
        ? new URL(resource.subject).origin
        : store.getServerUrl(),
    },
  );

  return {
    ...tableView,
    tableClass,
    queryFilters: queryFilter.filters,
    queryExpressionFilters: expressionFilters,
    collection,
    ready: classReady && ready,
    invalidateCollection,
    mapAll,
  };
}
