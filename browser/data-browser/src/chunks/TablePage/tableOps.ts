import {
  core,
  dataBrowser,
  getEffectiveConstraint,
  type Datatype,
  type JSONValue,
  type Resource,
  type Store,
} from '@tomic/react';
import { normalizeViewKind, type ViewKind } from './tableViewKinds';
import { parseDerivedColumnSpecs } from './derivedColumns';
import {
  buildViewPropVals,
  createColumnOnClass,
  specRowDefaults,
  type TableColumnSpec,
  type TableViewSpec,
} from './createTableFromSpec';
import { readRowDefaults } from './rowDefaults';

/** What a caller needs to know about one column of a table. */
export interface TableColumnInfo {
  name: string;
  shortname: string;
  subject: string;
  datatype: Datatype;
  /** For select columns: option name → tag subject. */
  tags?: Record<string, string>;
}

/**
 * Everything needed to translate a caller's column *names* into the property
 * subjects a View stores. Built by reading the row class, so it works on any
 * existing table — the assistant never has to know the ontology plumbing.
 */
export interface TableColumnMap {
  columns: TableColumnInfo[];
  /** Lower-cased name AND shortname → subject, plus `name` for the title. */
  byName: Record<string, string>;
  /** Column name → (option name → tag subject), for select columns. */
  tags: Record<string, Record<string, string>>;
}

/** Reads a table's row class into a name → property map. */
export async function readTableColumns(
  store: Store,
  tableClass: Resource,
): Promise<TableColumnMap> {
  const subjects = [
    ...((tableClass.get(core.properties.requires) as string[] | undefined) ??
      []),
    ...((tableClass.get(core.properties.recommends) as string[] | undefined) ??
      []),
  ];

  const columns: TableColumnInfo[] = [];
  const byName: Record<string, string> = {
    name: core.properties.name,
  };
  const tags: Record<string, Record<string, string>> = {};

  for (const subject of subjects) {
    const property = await store.getProperty(subject);
    const resource = await store.getResource(subject);
    const name = resource.title || property.shortname;

    const info: TableColumnInfo = {
      name,
      shortname: property.shortname,
      subject,
      datatype: property.datatype,
    };

    // A select column's options are resources of their own; the caller names
    // them ("Done"), so map those names to their subjects.
    // Options live in the table class's `constraints` (`enum`), with the
    // Property's legacy `allowsOnly` as a fallback.
    const allowsOnly = (
      getEffectiveConstraint(store, [tableClass.subject], subject).enum ?? []
    ).filter((v): v is string => typeof v === 'string');

    if (allowsOnly.length) {
      const options: Record<string, string> = {};

      const lookup: Record<string, string> = {};

      for (const tagSubject of allowsOnly) {
        const tag = await store.getResource(tagSubject);
        const shortname = tag.get(core.properties.shortname) as
          | string
          | undefined;
        // Reported by display name ("Client work"), resolvable by either that or
        // the shortname ("client-work") — the caller may know either.
        const label = tag.title || shortname;

        if (label) {
          options[label] = tagSubject;
          lookup[label.toLowerCase()] = tagSubject;
        }

        if (shortname) {
          lookup[shortname.toLowerCase()] = tagSubject;
        }
      }

      info.tags = options;
      tags[name.toLowerCase()] = lookup;
    }

    columns.push(info);
    byName[name.toLowerCase()] = subject;
    byName[property.shortname.toLowerCase()] = subject;
  }

  return { columns, byName, tags };
}

/** The table's saved views, in order, with the default marked. */
export async function readTableViews(
  store: Store,
  table: Resource,
): Promise<Array<{ resource: Resource; isDefault: boolean }>> {
  const subjects =
    (table.get(dataBrowser.properties.tableViews) as string[] | undefined) ??
    [];
  const defaultView = table.get(dataBrowser.properties.tableDefaultView) as
    | string
    | undefined;

  const views = [];

  for (const subject of subjects) {
    views.push({
      resource: await store.getResource(subject),
      isDefault: subject === defaultView,
    });
  }

  return views;
}

/**
 * Finds a view by name (case-insensitive) or subject. Falls back to the default
 * view when no reference is given, which is what "the view" usually means.
 */
export async function resolveView(
  store: Store,
  table: Resource,
  reference: string | undefined,
): Promise<Resource> {
  const views = await readTableViews(store, table);

  if (views.length === 0) {
    throw new Error(
      'This table has no saved views yet. Open it once, or create the view with create_table.',
    );
  }

  if (!reference) {
    return (views.find(view => view.isDefault) ?? views[0]).resource;
  }

  const match = views.find(
    view =>
      view.resource.subject === reference ||
      view.resource.title.toLowerCase() === reference.toLowerCase(),
  );

  if (!match) {
    throw new Error(
      `Unknown view "${reference}". This table has: ${views
        .map(view => view.resource.title)
        .join(', ')}`,
    );
  }

  return match.resource;
}

/**
 * Updates an existing View in place. Only the fields the caller names are
 * touched — everything else the view already knows keeps working, which is what
 * makes this safe to call repeatedly while building something up.
 */
export async function configureView(
  store: Store,
  opts: {
    table: Resource;
    view: Resource;
    config: Omit<TableViewSpec, 'name' | 'kind'> & {
      name?: string;
      kind?: ViewKind;
      /** Make this the view the table opens with. */
      default?: boolean;
    };
    map: TableColumnMap;
  },
): Promise<void> {
  const { table, view, config, map } = opts;

  const propVals = buildViewPropVals(
    {
      ...config,
      name: config.name ?? view.title,
      kind:
        config.kind ??
        normalizeViewKind(
          view.get(dataBrowser.properties.viewKind) as string | undefined,
        ),
    },
    map.byName,
    map.tags,
    {
      // Only write what was asked for: an absent field must not clear config the
      // view already has.
      partial: true,
      // So a total can name a computed column this call isn't re-declaring.
      existingDerivedColumns: parseDerivedColumnSpecs(
        view.get(dataBrowser.properties.viewDerivedColumns) as
          | JSONValue
          | undefined,
      ).map(spec => spec.label),
    },
  );

  for (const [property, value] of Object.entries(propVals)) {
    await view.set(property, value, false);
  }

  await view.save();

  if (config.default) {
    await table.set(dataBrowser.properties.tableDefaultView, view.subject);
    await table.save();
  }
}

/**
 * Adds columns to an existing table's row class — and appends them to the views
 * that keep an explicit column list, or they are invisible: `view-columns`
 * treats anything it doesn't mention as hidden.
 */
export async function addTableColumns(
  store: Store,
  opts: {
    table: Resource;
    tableClass: Resource;
    columns: TableColumnSpec[];
    /** Views to show the new columns in. Defaults to every view of the table. */
    views?: Resource[];
  },
): Promise<{
  columns: Record<string, string>;
  tags: Record<string, Record<string, string>>;
}> {
  const created: Record<string, string> = {};
  const tags: Record<string, Record<string, string>> = {};

  for (const column of opts.columns) {
    const result = await createColumnOnClass(store, opts.tableClass, column);
    created[column.name] = result.subject;

    if (result.tags) {
      tags[column.name] = result.tags;
    }
  }

  const defaults = specRowDefaults(opts.columns, created, tags);

  if (Object.keys(defaults).length > 0) {
    await opts.table.set(dataBrowser.properties.tableRowDefaults, {
      ...readRowDefaults(opts.table),
      ...defaults,
    });
    await opts.table.save();
  }

  const views =
    opts.views ??
    (await readTableViews(store, opts.table)).map(view => view.resource);

  for (const view of views) {
    const existing =
      (view.get(dataBrowser.properties.viewColumns) as string[] | undefined) ??
      [];

    // An empty list means "show every column of the class", so the new ones are
    // already visible — writing a list now would hide everything else.
    if (existing.length === 0) {
      continue;
    }

    await view.set(
      dataBrowser.properties.viewColumns,
      [...existing, ...Object.values(created)],
      false,
    );
    await view.save();
  }

  return { columns: created, tags };
}

/** A view's stored configuration, in the caller's vocabulary. */
export interface ViewDescription {
  subject: string;
  name: string;
  kind: ViewKind;
  isDefault: boolean;
  sortBy?: string;
  sortDesc?: boolean;
  filters?: JSONValue;
  columns?: string[];
  columnOrder?: JSONValue;
  groupByColumn?: string;
  endColumn?: string;
  timerExclusive?: boolean;
  derivedColumns?: JSONValue;
  aggregates?: JSONValue;
  rowActions?: JSONValue;
  quickAdd?: JSONValue;
  breakdownColumn?: string;
  breakdownGranularity?: string;
}

/**
 * Reads a table's whole configuration back: its class, its columns (with select
 * options) and every view's settings. `get_schema` covers the class but not the
 * views, so without this the only way to change a view is to guess.
 */
export async function describeTable(
  store: Store,
  table: Resource,
): Promise<{
  table: string;
  name: string;
  class: string;
  columns: TableColumnInfo[];
  views: ViewDescription[];
}> {
  const classSubject = table.get(core.properties.classtype) as string;
  const tableClass = await store.getResource(classSubject);
  const map = await readTableColumns(store, tableClass);
  const views = await readTableViews(store, table);

  /** Names a property subject the way the caller would. */
  const columnName = (subject: string | undefined): string | undefined => {
    if (!subject) {
      return undefined;
    }

    return (
      map.columns.find(column => column.subject === subject)?.name ??
      (subject === core.properties.name ? 'name' : subject)
    );
  };

  return {
    table: table.subject,
    name: table.title,
    class: classSubject,
    columns: map.columns,
    views: views.map(({ resource, isDefault }) => {
      const read = (property: string) => resource.get(property);

      const described: ViewDescription = {
        subject: resource.subject,
        name: resource.title,
        kind: normalizeViewKind(
          read(dataBrowser.properties.viewKind) as string | undefined,
        ),
        isDefault,
      };

      const sortBy = columnName(
        read(dataBrowser.properties.viewSortBy) as string | undefined,
      );

      if (sortBy) {
        described.sortBy = sortBy;
        described.sortDesc = !!read(dataBrowser.properties.viewSortDesc);
      }

      const filters = read(dataBrowser.properties.viewFilters);

      if (Array.isArray(filters) && filters.length > 0) {
        described.filters = filters as JSONValue;
      }

      const columns = read(dataBrowser.properties.viewColumns) as
        | string[]
        | undefined;

      if (columns?.length) {
        described.columns = columns
          .map(columnName)
          .filter((name): name is string => name !== undefined);
      }

      const columnOrder = read(dataBrowser.properties.viewColumnOrder);

      if (Array.isArray(columnOrder) && columnOrder.length > 0) {
        described.columnOrder = columnOrder as JSONValue;
      }

      described.groupByColumn = columnName(
        read(dataBrowser.properties.viewGroupBy) as string | undefined,
      );
      described.endColumn = columnName(
        read(dataBrowser.properties.viewEndProp) as string | undefined,
      );

      const exclusive = read(dataBrowser.properties.viewTimerExclusive);

      if (exclusive !== undefined) {
        described.timerExclusive = !!exclusive;
      }

      const derived = read(dataBrowser.properties.viewDerivedColumns);

      if (Array.isArray(derived) && derived.length > 0) {
        described.derivedColumns = derived as JSONValue;
      }

      const rowActions = read(dataBrowser.properties.viewRowActions);

      if (Array.isArray(rowActions) && rowActions.length > 0) {
        described.rowActions = rowActions as JSONValue;
      }

      const quickAdd = read(dataBrowser.properties.viewQuickAdd);

      if (quickAdd !== undefined) {
        described.quickAdd = quickAdd as JSONValue;
      }

      const aggregates = read(dataBrowser.properties.viewAggregates);

      if (Array.isArray(aggregates) && aggregates.length > 0) {
        described.aggregates = aggregates as JSONValue;
        described.breakdownColumn = columnName(
          read(dataBrowser.properties.viewGroupByColumn) as string | undefined,
        );
        described.breakdownGranularity = read(
          dataBrowser.properties.viewGroupGranularity,
        ) as string | undefined;
      }

      return described;
    }),
  };
}
