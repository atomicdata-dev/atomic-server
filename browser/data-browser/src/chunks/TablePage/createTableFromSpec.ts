import {
  ensureSchema,
  resumableInstallation,
  type SchemaSpec,
} from '@tomic/lib';
import {
  Client,
  Datatype,
  JSONValue,
  Resource,
  Server,
  Store,
  commits,
  core,
  dataBrowser,
  perfSpan,
  server,
  urls,
} from '@tomic/react';
import { ViewKind } from './tableViewKinds';
import type { FilterOperator } from './tableFiltering';
import {
  DERIVED_COLUMN_GENERATORS,
  type DerivedColumnKind,
  type DerivedColumnSpec,
} from './derivedColumns';
import { stringToSlug } from '@helpers/stringToSlug';
import type { RowActionKind, RowActionSpec } from './rowActions';
import {
  attachPropertiesToClass,
  createPropertyOnClass,
  createSelectPropertyOnClass,
} from './Kanban/createSelectProperty';

/**
 * The compact, high-level column vocabulary a caller (a template, or the AI
 * assistant) uses to describe a table — one entry per column, no ontology
 * plumbing. Maps onto the same datatypes the New Column dialog offers.
 */
export type TableColumnType =
  | 'text'
  | 'markdown'
  | 'number'
  | 'decimal'
  | 'date'
  | 'datetime'
  | 'checkbox'
  | 'relation'
  | 'file'
  | 'select';

export interface TableColumnSpec {
  /** Resolve a property from the template schema, reusing it within this drive. */
  schemaProperty?: string;
  /** Reuse an existing property without modifying its definition. */
  propertySubject?: string;
  name: string;
  type: TableColumnType;
  /** For `select` columns: the tag options, e.g. ['Todo', 'Doing', 'Done']. */
  options?: string[];
  /**
   * For `relation` columns: the class the link must point at, so the cell's
   * picker searches that class instead of everything. A class subject.
   */
  targetClass?: string;
  description?: string;
}

/**
 * A computed column, described in the same column-name vocabulary as the rest
 * of a spec: its arguments name columns of this table (or are literal numbers),
 * and are resolved to property subjects on creation.
 */
export interface TableDerivedColumnSpec {
  /** The column heading, e.g. 'Duration'. */
  name: string;
  kind: DerivedColumnKind;
  /**
   * The generator's arguments — `difference` takes `from`/`to`, `elapsed`
   * `from`/`until`, `daysSince` `from`, `product` `a`/`b`, `offset`
   * `from`/`days`.
   */
  args: Record<string, string | number>;
}

/**
 * A statistic shown under a view's rows. Computed by the store over every row
 * the view matches, so it costs a number rather than a fetch of every row.
 */
export interface TableAggregateSpec {
  /** One of sum / count / avg / min / max. */
  function: 'sum' | 'count' | 'avg' | 'min' | 'max';
  /** The column to aggregate, by name. Omit for `count` to count rows. */
  column?: string;
  /**
   * A computed column of this view to aggregate instead of a stored one, by its
   * name — a duration, an amount. The store evaluates it per row, so the total
   * still covers every matching row.
   */
  computedColumn?: string;
  /** Which totals row it shows in, from 0. One statistic per column per row. */
  row?: number;
}

export interface TableViewSpec {
  name: string;
  kind: ViewKind;
  /**
   * The column this view arranges rows by: for `kanban` the `select` column
   * whose tags become the board columns, for `calendar` the date column that
   * places rows on days, for `timer` the datetime column holding each entry's
   * start.
   */
  groupByColumn?: string;
  /** For `timer` views: the datetime column holding each entry's end. */
  endColumn?: string;
  /** Columns computed from each row rather than stored on it. */
  derivedColumns?: TableDerivedColumnSpec[];
  /** Statistics shown under the rows (sum, count, average, min, max). */
  aggregates?: TableAggregateSpec[];
  /** Buttons this view puts on each row. */
  rowActions?: TableRowActionSpec[];
  /** A button above the rows that creates one. */
  quickAdd?: TableQuickAddSpec;
  /** A column to break those statistics down by — one subtotal per value. */
  breakdownColumn?: string;
  /** For a date or timestamp breakdown column: the bucket size. */
  breakdownGranularity?: 'day' | 'month' | 'exact';
  /** The column this view sorts by. */
  sortByColumn?: string;
  /** Sort descending (newest / largest first). */
  sortDesc?: boolean;
  /** Constraints on which rows the view shows, combined with AND. */
  filters?: TableFilterSpec[];
  /** The columns this view shows, in order. Omitted columns are hidden. */
  columns?: string[];
  /**
   * The full display order, which can also place columns that aren't
   * properties: a computed column by its name, or `timer` for the timer's
   * Start/Stop button.
   */
  columnOrder?: string[];
  default?: boolean;
}

/**
 * One button on every row, in the caller's column-name vocabulary. `kind` is a
 * closed vocabulary of patches — see `rowActions.ts`.
 */
export interface TableRowActionSpec {
  /**
   * A stable id for this action, used as its column key. Defaults to a slug of
   * the label — worth setting explicitly when the label is symbols ("+1" and
   * "-1" both slug to "1"), and it is how a later `configure_view` addresses
   * this action rather than guessing.
   */
  id?: string;
  /** What the button says. */
  label: string;
  kind: RowActionKind;
  /** The column it writes, by name. */
  column: string;
  /**
   * What to write: the option name for `setValue` on a select column (or the
   * literal for a text/number one), the step for `increment`. Not used by
   * `setNow` or `toggle`.
   */
  value?: string | number;
}

/**
 * The view's create button, in the caller's column-name vocabulary. Its presets
 * reuse the row-action verbs, applied to the row being created.
 */
export interface TableQuickAddSpec {
  /** What the button says, e.g. 'Log a feed'. */
  label: string;
  /**
   * A column to type into before creating, by name — usually 'name'. Omit for a
   * button that just creates.
   */
  field?: string;
  placeholder?: string;
  /** Values the new row starts with. */
  presets?: {
    kind: RowActionKind;
    column: string;
    value?: string | number;
  }[];
}

/** One row constraint, in the caller's column-name vocabulary. */
export interface TableFilterSpec {
  column: string;
  /** Defaults to `eq`. */
  operator?: FilterOperator;
  /** For a `select` column, the option name works. */
  value: string;
}

export interface TableSpec {
  schema?: SchemaSpec;
  name: string;
  /** What a single row is called ("Issue", "Employee"); names the row class.
   *  Falls back to "Row". */
  rowName?: string;
  columns: TableColumnSpec[];
  views?: TableViewSpec[];
  /**
   * Initial rows to insert, each an object of column name → cell value, plus
   * `name` for the row title. `select` cells accept the tag option name (or
   * its subject); a single value is wrapped into the required array.
   */
  rows?: Array<Record<string, JSONValue>>;
}

export interface BuildTableResult {
  tableSubject: string;
  classSubject: string;
  /** Column name → created property subject. */
  columns: Record<string, string>;
  /** For `select` columns: column name → (tag option name → tag subject). */
  tags: Record<string, Record<string, string>>;
  /** Subjects of the rows created from `spec.rows`, in the same order. */
  rowSubjects: string[];
}

const DATATYPE_BY_TYPE: Record<Exclude<TableColumnType, 'select'>, Datatype> = {
  text: Datatype.STRING,
  markdown: Datatype.MARKDOWN,
  number: Datatype.INTEGER,
  decimal: Datatype.FLOAT,
  date: Datatype.DATE,
  datetime: Datatype.TIMESTAMP,
  checkbox: Datatype.BOOLEAN,
  relation: Datatype.ATOMIC_URL,
  file: Datatype.ATOMIC_URL,
};

/** Prefer the drive's default ontology as the parent, else the drive itself. */
export async function resolveOntologyParent(
  store: Store,
  driveSubject: string,
): Promise<string> {
  const drive = await store.getResource<Server.Drive>(driveSubject);
  const ontologyParent = drive.props.defaultOntology;

  return ontologyParent &&
    !ontologyParent.startsWith('internal:') &&
    !ontologyParent.includes('unknown-subject')
    ? ontologyParent
    : driveSubject;
}

/**
 * Creates (but does not save) a table's row class — named after what a single
 * row IS ("Issue", "Employee"), not a generic "row", which reads wrong on
 * every instance. The single class-genesis used by every table-creation flow
 * (templates, the New Table dialog, the AI's create_table tool).
 */
export async function createRowClass(
  store: Store,
  opts: { parent: string; tableName: string; rowName?: string },
): Promise<Resource> {
  const rowName = opts.rowName?.trim() || 'Row';

  return store.newResource({
    parent: opts.parent,
    isA: core.classes.class,
    propVals: {
      [core.properties.shortname]: stringToSlug(rowName),
      [core.properties.name]: rowName,
      [core.properties.description]:
        `Represents a row in the ${opts.tableName} table`,
      [core.properties.recommends]: [core.properties.name],
    },
  });
}

export async function createColumnOnClass(
  store: Store,
  tableClass: Resource,
  column: TableColumnSpec,
  /**
   * Leave the property off the ontology and the row class; the caller attaches
   * every column of the table in one go. See `attachPropertiesToClass`.
   */
  deferAttach = false,
): Promise<{ subject: string; tags?: Record<string, string> }> {
  if (column.propertySubject) {
    const property = await store.getResource(column.propertySubject);
    const expected =
      column.type === 'select'
        ? Datatype.RESOURCEARRAY
        : DATATYPE_BY_TYPE[column.type];

    if (
      !property.hasClasses(core.classes.property) ||
      property.get(core.properties.datatype) !== expected
    ) {
      throw new Error(
        `Shared property ${column.name} has an incompatible datatype`,
      );
    }

    const tags: Record<string, string> = {};

    if (column.type === 'select') {
      if (!property.hasClasses(dataBrowser.classes.selectProperty))
        throw new Error(
          `Shared property ${column.name} is not a select property`,
        );
      const options = property.get(core.properties.allowsOnly) as
        | string[]
        | undefined;

      for (const subject of options ?? []) {
        const tag = await store.getResource(subject);
        tags[String(tag.get(core.properties.name))] = subject;
      }

      for (const option of column.options ?? []) {
        if (!tags[option])
          throw new Error(
            `Shared property ${column.name} has no option ${option}`,
          );
      }
    }

    if (!deferAttach)
      await attachPropertiesToClass(store, tableClass, [property.subject]);

    return {
      subject: property.subject,
      ...(column.type === 'select' ? { tags } : {}),
    };
  }

  if (column.type === 'select') {
    return createSelectPropertyOnClass(store, tableClass, {
      name: column.name,
      tags: (column.options ?? []).map(name => ({ name })),
      deferAttach,
    });
  }

  const subject = await createPropertyOnClass(store, tableClass, {
    deferAttach,
    name: column.name,
    datatype: DATATYPE_BY_TYPE[column.type],
    // A money or measurement column renders with two decimals rather than as a
    // bare float. The same shape the number property form writes, so its own
    // form (currency, percentage, more decimals) opens on it afterwards.
    classes:
      column.type === 'decimal' ? [dataBrowser.classes.formattedNumber] : [],
    propVals:
      column.type === 'decimal'
        ? {
            [dataBrowser.properties.numberFormatting]:
              urls.instances.numberFormats.number,
            [dataBrowser.properties.decimalPlaces]: 2,
          }
        : {},
    classtype:
      column.type === 'file'
        ? server.classes.file
        : // A relation that names its target class gets a picker scoped to that
          // class instead of a search across everything.
          column.type === 'relation'
          ? column.targetClass
          : undefined,
    description: column.description,
  });

  return { subject };
}

/**
 * Translates one row spec (column name → cell value) into propVals keyed by
 * property subject. `name` (any casing) maps to the core name property, select
 * cells map tag option names to their subjects and are wrapped into the
 * ResourceArray the datatype requires.
 */
function rowToPropVals(
  row: Record<string, JSONValue>,
  columns: Record<string, string>,
  tags: Record<string, Record<string, string>>,
): Record<string, JSONValue> {
  const propVals: Record<string, JSONValue> = {};

  for (const [column, value] of Object.entries(row)) {
    if (value === undefined || value === null) {
      continue;
    }

    if (column.toLowerCase() === 'name') {
      propVals[core.properties.name] = value;
      continue;
    }

    const property = columns[column];

    if (!property) {
      throw new Error(
        `Unknown column "${column}". Available columns: name, ${Object.keys(
          columns,
        ).join(', ')}`,
      );
    }

    const tagsByName = tags[column];

    if (tagsByName) {
      const options = Array.isArray(value) ? value : [value];
      propVals[property] = options.map(
        option => tagsByName[String(option)] ?? String(option),
      );
    } else {
      propVals[property] = value;
    }
  }

  propVals[commits.properties.createdAt] = Date.now();

  return propVals;
}

/**
 * Turns the caller's column-name arguments into property subjects. A value that
 * is already a subject passes through, so config copied off an existing view
 * still works; anything else must name a column, or the caller silently gets a
 * column that computes nothing.
 */
/**
 * Turns row actions in the caller's vocabulary into the stored shape: column
 * names become property subjects, and a select column's option name becomes its
 * tag subject. An action naming a column that doesn't exist is an error rather
 * than a silently dead button.
 */
function resolveRowActions(
  actions: TableRowActionSpec[],
  require: (reference: string, context: string) => string,
  tagsByColumn: Record<string, Record<string, string>>,
): RowActionSpec[] {
  const taken = new Set<string>();

  return actions.map(action => {
    const property = require(action.column, `row action "${action.label}"`);

    const base = stringToSlug(action.id ?? action.label) || action.kind;
    let id = base;
    let n = 2;

    while (taken.has(id)) {
      id = `${base}-${n++}`;
    }

    taken.add(id);

    // A select column's options are resources; the caller names them ("Done"),
    // the same way a filter value does.
    const options = tagsByColumn[action.column.toLowerCase()] ?? {};
    const value =
      typeof action.value === 'string'
        ? (options[action.value.toLowerCase()] ?? action.value)
        : action.value;

    return {
      id,
      label: action.label,
      kind: action.kind,
      property,
      ...(value === undefined ? {} : { value }),
    };
  });
}

function resolveDerivedColumns(
  specs: TableDerivedColumnSpec[],
  resolve: (reference: string, role: string) => string,
): DerivedColumnSpec[] {
  return specs.map(spec => {
    const generator = DERIVED_COLUMN_GENERATORS[spec.kind];

    if (!generator) {
      throw new Error(
        `Unknown derived column kind "${spec.kind}". Available kinds: ${Object.keys(
          DERIVED_COLUMN_GENERATORS,
        ).join(', ')}`,
      );
    }

    const args: Record<string, string | number> = {};

    for (const [argument, value] of Object.entries(spec.args)) {
      if (typeof value === 'number') {
        args[argument] = value;
        continue;
      }

      args[argument] = resolve(
        value,
        `the "${argument}" argument of derived column "${spec.name}"`,
      );
    }

    return {
      id: stringToSlug(spec.name),
      label: spec.name,
      kind: spec.kind,
      args,
    };
  });
}

/** Resolves an aggregate's column name to a property subject, or a computed
 *  column's name to its id. */
function resolveAggregates(
  specs: TableAggregateSpec[],
  resolve: (reference: string, role: string) => string,
  /** The names of the computed columns this view declares. */
  derivedNames: string[],
): Array<{
  id: string;
  property?: string;
  derived?: string;
  function: string;
  row?: number;
}> {
  const taken = new Set<string>();
  const derivedIds = new Map(
    derivedNames.map(name => [name.toLowerCase(), stringToSlug(name)]),
  );

  return specs.map(spec => {
    let property: string | undefined;
    let derived: string | undefined;

    if (spec.computedColumn) {
      derived = derivedIds.get(spec.computedColumn.toLowerCase());

      if (!derived) {
        throw new Error(
          `Unknown computed column "${spec.computedColumn}" for the ${spec.function} total. This view's computed columns: ${
            derivedNames.join(', ') || '(none)'
          }`,
        );
      }
    } else if (spec.column) {
      property = resolve(spec.column, `the ${spec.function} total`);
    }

    const base = stringToSlug(
      `${spec.function}-${spec.computedColumn ?? spec.column ?? 'rows'}-${spec.row ?? 0}`,
    );
    let id = base;

    for (let n = 2; taken.has(id); n++) {
      id = `${base}-${n}`;
    }

    taken.add(id);

    return {
      id,
      property,
      ...(derived ? { derived } : {}),
      function: spec.function,
      ...(spec.row ? { row: spec.row } : {}),
    };
  });
}

/**
 * Translates a view spec into the propVals a View resource stores. Shared by
 * table creation and `configure_view`, so a view built by the assistant and one
 * it edits afterwards can never drift apart.
 *
 * With `partial`, only the fields the caller named are returned — editing a
 * view's sort must not silently drop its filters.
 */
export function buildViewPropVals(
  view: TableViewSpec,
  columnSubjectByName: Record<string, string>,
  tagsByColumn: Record<string, Record<string, string>> = {},
  opts: {
    partial?: boolean;
    /**
     * Names of computed columns the view already has. A total can name one
     * without the same call re-declaring the column — which is how the assistant
     * works: add the column, then total it.
     */
    existingDerivedColumns?: string[];
  } = {},
): Record<string, JSONValue> {
  const propVals: Record<string, JSONValue> = {};
  const partial = !!opts.partial;

  /** Resolves a column name (or subject) the caller used. */
  const column = (reference: string | undefined): string | undefined => {
    if (!reference) {
      return undefined;
    }

    if (reference.toLowerCase() === 'name') {
      return core.properties.name;
    }

    return (
      columnSubjectByName[reference] ??
      columnSubjectByName[reference.toLowerCase()] ??
      (Client.isValidSubject(reference) ? reference : undefined)
    );
  };

  const require = (reference: string, role: string): string => {
    const subject = column(reference);

    if (!subject) {
      throw new Error(
        `Unknown column "${reference}" for ${role}. Available columns: name, ${Object.keys(
          columnSubjectByName,
        ).join(', ')}`,
      );
    }

    return subject;
  };

  if (!partial || view.name !== undefined) {
    propVals[core.properties.name] = view.name;
  }

  if (!partial || view.kind !== undefined) {
    propVals[dataBrowser.properties.viewKind] = view.kind;
  }

  const groupBy = column(view.groupByColumn);

  if (groupBy) {
    propVals[dataBrowser.properties.viewGroupBy] = groupBy;
  }

  const end = column(view.endColumn);

  if (end) {
    propVals[dataBrowser.properties.viewEndProp] = end;
  }

  if (view.sortByColumn !== undefined) {
    propVals[
      dataBrowser.properties.viewSortBy
    ] = require(view.sortByColumn, 'the sort');
    propVals[dataBrowser.properties.viewSortDesc] = !!view.sortDesc;
  } else if (view.sortDesc !== undefined) {
    propVals[dataBrowser.properties.viewSortDesc] = view.sortDesc;
  }

  if (view.filters !== undefined) {
    propVals[dataBrowser.properties.viewFilters] = view.filters.map(filter => {
      const subject = require(filter.column, 'a filter');
      // A select column filters by tag subject, but the caller says "Done".
      const tags =
        tagsByColumn[filter.column] ??
        tagsByColumn[filter.column.toLowerCase()] ??
        {};

      return {
        property: subject,
        operator: filter.operator ?? 'eq',
        value:
          tags[filter.value] ??
          tags[filter.value.toLowerCase()] ??
          filter.value,
      };
    }) as unknown as JSONValue;
  }

  if (view.columns !== undefined) {
    propVals[dataBrowser.properties.viewColumns] = view.columns.map(name =>
      require(name, 'the column list'),
    );
  }

  if (view.columnOrder !== undefined) {
    propVals[dataBrowser.properties.viewColumnOrder] = view.columnOrder.map(
      reference => {
        // The order can also place columns that are not properties.
        if (reference.toLowerCase() === 'timer') {
          return 'timer-action';
        }

        const asColumn = column(reference);

        if (asColumn) {
          return asColumn;
        }

        // A computed column, by the name it was created with.
        return `derived:${stringToSlug(reference)}`;
      },
    ) as unknown as JSONValue;
  }

  if (view.derivedColumns !== undefined) {
    // A spec is plain JSON, just a narrower shape than `JSONValue` describes.
    propVals[dataBrowser.properties.viewDerivedColumns] = resolveDerivedColumns(
      view.derivedColumns,
      require,
    ) as unknown as JSONValue;
  }

  if (view.aggregates !== undefined) {
    propVals[dataBrowser.properties.viewAggregates] = resolveAggregates(
      view.aggregates,
      require,
      [
        ...(view.derivedColumns ?? []).map(derived => derived.name),
        ...(opts.existingDerivedColumns ?? []),
      ],
    ) as unknown as JSONValue;
  }

  if (view.rowActions !== undefined) {
    propVals[dataBrowser.properties.viewRowActions] = resolveRowActions(
      view.rowActions,
      require,
      tagsByColumn,
    ) as unknown as JSONValue;
  }

  if (view.quickAdd !== undefined) {
    const { label, field, placeholder, presets } = view.quickAdd;

    propVals[dataBrowser.properties.viewQuickAdd] = {
      label,
      ...(field ? { field: require(field, 'quick-add field') } : {}),
      ...(placeholder ? { placeholder } : {}),
      presets: (presets ?? []).map(preset => {
        const property = require(preset.column, `quick-add preset for "${label}"`);
        const options = tagsByColumn[preset.column.toLowerCase()] ?? {};
        const value =
          typeof preset.value === 'string'
            ? (options[preset.value.toLowerCase()] ?? preset.value)
            : preset.value;

        return {
          kind: preset.kind,
          property,
          ...(value === undefined ? {} : { value }),
        };
      }),
      // A spec is plain JSON, just a narrower shape than `JSONValue` describes.
    } as unknown as JSONValue;
  }

  const breakdown = column(view.breakdownColumn);

  if (breakdown) {
    propVals[dataBrowser.properties.viewGroupByColumn] = breakdown;
    propVals[dataBrowser.properties.viewGroupGranularity] =
      view.breakdownGranularity ?? 'day';
  }

  return propVals;
}

/**
 * Creates one view under `table` and returns it. Linking it into the table's
 * `tableViews` is the caller's job — a table's views are all written to the
 * same two properties, so a table built from a spec links them in a single
 * commit rather than one per view.
 */
async function createViewResource(
  store: Store,
  table: Resource,
  view: TableViewSpec,
  columnSubjectByName: Record<string, string>,
  tagsByColumn: Record<string, Record<string, string>>,
): Promise<Resource> {
  const viewResource = await store.newResource({
    parent: table.subject,
    isA: dataBrowser.classes.view,
    propVals: buildViewPropVals(view, columnSubjectByName, tagsByColumn),
  });
  await viewResource.save();

  return viewResource;
}

/**
 * Builds a complete table — row class, columns, table resource, and any saved
 * views — from one declarative spec. This is the single primitive behind both
 * the in-app table templates and the assistant's `create_table` tool: callers
 * describe *what* they want, not the ~4-resource-per-column commit dance.
 *
 * Does not navigate; returns the created subjects so the caller decides what to
 * do next (open it, link it, keep building).
 */
export async function buildTableFromSpec(
  store: Store,
  spec: TableSpec,
  opts: {
    parent: string;
    driveSubject: string;
    addToOntology: (resource: Resource) => Promise<void>;
    /** Stable app-owned setup key. Repeating the same spec resumes its resources. */
    installationKey?: string;
  },
): Promise<BuildTableResult> {
  if (opts.installationKey)
    store = await resumableInstallation(
      store,
      opts.driveSubject,
      opts.installationKey,
      spec,
    );
  const closeBuild = perfSpan('table.build', { name: spec.name });

  const closeParent = perfSpan('table.resolveOntologyParent');
  const ontologyParent = await resolveOntologyParent(store, opts.driveSubject);
  closeParent();

  const closeClass = perfSpan('table.rowClass');
  const rowClass = await createRowClass(store, {
    parent: ontologyParent,
    tableName: spec.name,
    rowName: spec.rowName,
  });
  await opts.addToOntology(rowClass);
  closeClass();

  const reusable = spec.schema
    ? await ensureSchema(store, opts.driveSubject, spec.schema)
    : undefined;
  const columns: Record<string, string> = {};
  const tags: Record<string, Record<string, string>> = {};

  const columnSubjects: string[] = [];

  for (const column of spec.columns) {
    const closeColumn = perfSpan('table.column', { type: column.type });
    // `true`: hold off registering each column on the ontology and the row
    // class — those are the same two resources for every column, so one
    // attach at the end costs two commits instead of two per column.
    const propertySubject = column.schemaProperty
      ? reusable?.properties[column.schemaProperty]
      : column.propertySubject;
    if (column.schemaProperty && !propertySubject)
      throw new Error(`Unknown schema property ${column.schemaProperty}`);
    const created = await createColumnOnClass(
      store,
      rowClass,
      { ...column, propertySubject },
      true,
    );
    closeColumn();
    columns[column.name] = created.subject;
    columnSubjects.push(created.subject);

    if (created.tags) {
      tags[column.name] = created.tags;
    }
  }

  await attachPropertiesToClass(store, rowClass, columnSubjects);

  const closeTable = perfSpan('table.tableResource');
  const table = await store.newResource({
    parent: opts.parent,
    isA: dataBrowser.classes.table,
    propVals: {
      [core.properties.name]: spec.name,
      [core.properties.classtype]: rowClass.subject,
    },
  });
  await table.save();
  closeTable();

  const viewSubjects: string[] = [];
  let defaultViewSubject: string | undefined;

  for (const view of spec.views ?? []) {
    const closeView = perfSpan('table.view');
    const created = await createViewResource(store, table, view, columns, tags);
    closeView();
    viewSubjects.push(created.subject);

    if (view.default) {
      defaultViewSubject = created.subject;
    }
  }

  if (viewSubjects.length > 0) {
    const closeLink = perfSpan('table.linkViews', { n: viewSubjects.length });
    await table.push(dataBrowser.properties.tableViews, viewSubjects, true);

    if (defaultViewSubject) {
      await table.set(
        dataBrowser.properties.tableDefaultView,
        defaultViewSubject,
      );
    }

    await table.save();
    closeLink();
  }

  const rowSubjects: string[] = [];

  for (const row of spec.rows ?? []) {
    const closeRow = perfSpan('table.row');
    const rowResource = await store.newResource({
      parent: table.subject,
      isA: rowClass.subject,
      propVals: rowToPropVals(row, columns, tags),
    });
    await rowResource.save();
    closeRow();
    rowSubjects.push(rowResource.subject);
  }

  closeBuild();

  return {
    tableSubject: table.subject,
    classSubject: rowClass.subject,
    columns,
    tags,
    rowSubjects,
  };
}
