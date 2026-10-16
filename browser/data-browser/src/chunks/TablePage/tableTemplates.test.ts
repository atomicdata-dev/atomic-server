import { describe, expect, it } from 'vitest';
import { TABLE_TEMPLATES } from './tableTemplates';
import { VIEW_KINDS } from './tableViewKinds';
import { bindFormula, columnSlugs } from './derivedColumns';
import type { TableColumnType, TableViewSpec } from './createTableFromSpec';

/**
 * The templates are pure configuration, which means a typo in one of them is a
 * broken mini-app rather than a compile error: a total on a column that doesn't
 * exist, a kanban grouped by a text column, a computed column whose argument is
 * the wrong datatype. Nothing else checks that, so this does — cheaply, without
 * a store.
 */

/** Column types a total can be summed or averaged over. */
const NUMERIC: TableColumnType[] = ['number', 'decimal'];
/** Column types that place a row in time. */
const INSTANT: TableColumnType[] = ['date', 'datetime'];
/**
 * Column types the store can break totals down by. A text column can't: the
 * query index groups by tag subject, instant bucket or exact value, and free
 * text would make one group per row.
 */
const GROUPABLE: TableColumnType[] = [
  'select',
  'date',
  'datetime',
  'checkbox',
  'relation',
];

const templatesWithSpec = TABLE_TEMPLATES.filter(template => template.spec);

describe('table templates', () => {
  it('has a blank starting point and no other specless template', () => {
    const blank = TABLE_TEMPLATES.find(template => template.id === 'blank');
    expect(blank).toBeDefined();
    expect(blank?.spec).toBeUndefined();

    expect(
      TABLE_TEMPLATES.filter(template => !template.spec).map(t => t.id),
    ).toEqual(['blank']);
  });

  it('has unique ids', () => {
    const ids = TABLE_TEMPLATES.map(template => template.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  describe.each(templatesWithSpec.map(t => [t.id, t] as const))(
    '%s',
    (_id, template) => {
      const spec = template.spec!;
      const typeByColumn = new Map<string, TableColumnType>(
        spec.columns.map(column => [column.name, column.type]),
      );

      /** The type of a column a view refers to. `name` is the row's title. */
      const typeOf = (reference: string): TableColumnType | undefined =>
        reference.toLowerCase() === 'name'
          ? 'text'
          : typeByColumn.get(reference);

      it('names its rows and columns', () => {
        expect(template.rowName).not.toBe('');
        expect(spec.columns.length).toBeGreaterThan(0);
        expect(new Set(typeByColumn.keys()).size).toBe(spec.columns.length);

        for (const column of spec.columns) {
          // `name` is the row title, always present — a second one would shadow it.
          expect(column.name.toLowerCase()).not.toBe('name');

          if (column.type === 'select') {
            expect(column.options?.length ?? 0).toBeGreaterThan(1);
          } else {
            expect(column.options).toBeUndefined();
          }

          // A select default is one of its options, or the table can't be built.
          if (column.type === 'select' && column.default !== undefined) {
            expect(column.options).toContain(column.default);
          }
        }
      });

      it('starts new rows in the first lane of a status board', () => {
        // A task added from the calendar or the grid should land in the board's
        // Todo lane, not in "No status". Boards over a workflow (a Status or
        // Stage column) say where new rows start.
        for (const view of spec.views ?? []) {
          const column = spec.columns.find(c => c.name === view.groupByColumn);

          if (
            view.kind === 'kanban' &&
            column &&
            /^(status|stage|rsvp)$/i.test(column.name)
          ) {
            expect(column.default).toBe(column.options?.[0]);
          }
        }
      });

      it('has exactly one default view, with unique names and known kinds', () => {
        const views = spec.views ?? [];
        expect(views.length).toBeGreaterThan(0);
        expect(new Set(views.map(view => view.name)).size).toBe(views.length);
        expect(views.filter(view => view.default)).toHaveLength(1);

        for (const view of views) {
          expect(VIEW_KINDS).toContain(view.kind);
        }
      });

      describe.each((spec.views ?? []).map(v => [v.name, v] as const))(
        'view %s',
        (_name, view: TableViewSpec) => {
          const derivedNames = (view.derivedColumns ?? []).map(
            derived => derived.name,
          );

          it('arranges its rows by a column that can carry it', () => {
            if (view.kind === 'kanban') {
              // The board's columns are the tags of a select column.
              expect(typeOf(view.groupByColumn ?? '')).toBe('select');
            }

            if (view.kind === 'issues') {
              // Open vs closed is read from a select's tags or a checkbox.
              expect(['select', 'checkbox']).toContain(
                typeOf(view.groupByColumn ?? ''),
              );
            }

            if (view.kind === 'calendar') {
              expect(INSTANT).toContain(typeOf(view.groupByColumn ?? ''));
            }

            if (view.kind === 'timer') {
              expect(typeOf(view.groupByColumn ?? '')).toBe('datetime');
              expect(typeOf(view.endColumn ?? '')).toBe('datetime');
            }
          });

          it('sorts and filters real columns', () => {
            if (view.sortByColumn !== undefined) {
              expect(typeOf(view.sortByColumn)).toBeDefined();
            }

            for (const filter of view.filters ?? []) {
              expect(typeOf(filter.column)).toBeDefined();

              // Value comparisons only mean something for numbers and instants.
              if (filter.operator && filter.operator !== 'eq') {
                expect([...NUMERIC, ...INSTANT]).toContain(
                  typeOf(filter.column),
                );
              }
            }
          });

          it('totals columns of a type the function accepts', () => {
            for (const aggregate of view.aggregates ?? []) {
              // A total over a computed column names it separately, and the
              // column has to be one THIS view declares — the store is sent its
              // expression, not a reference.
              if (aggregate.computedColumn) {
                expect(
                  derivedNames,
                  `${aggregate.computedColumn} is not a computed column of this view`,
                ).toContain(aggregate.computedColumn);
                expect(
                  aggregate.column,
                  'a total names a stored column or a computed one, not both',
                ).toBeUndefined();
                continue;
              }

              if (aggregate.function === 'count' && !aggregate.column) {
                continue;
              }

              const type = typeOf(aggregate.column ?? '');
              expect(type, `${aggregate.column} is not a column`).toBeDefined();

              if (
                aggregate.function === 'sum' ||
                aggregate.function === 'avg'
              ) {
                expect(NUMERIC).toContain(type);
              }

              if (
                aggregate.function === 'min' ||
                aggregate.function === 'max'
              ) {
                expect([...NUMERIC, ...INSTANT]).toContain(type);
              }
            }

            // One statistic per column per totals row, or they overwrite.
            const slots = (view.aggregates ?? []).map(
              aggregate =>
                `${aggregate.row ?? 0}:${aggregate.column ?? ''}:${aggregate.computedColumn ?? ''}`,
            );
            expect(new Set(slots).size).toBe(slots.length);

            // Totals live in the grid's footer, which only the table kind draws.
            if ((view.aggregates ?? []).length > 0) {
              expect(view.kind).toBe('table');
            }
          });

          it('breaks totals down by a groupable column', () => {
            if (view.breakdownColumn === undefined) {
              return;
            }

            const type = typeOf(view.breakdownColumn);
            expect(GROUPABLE).toContain(type);

            // Buckets are a date thing; anything else groups by exact value.
            if (type && INSTANT.includes(type)) {
              expect(['day', 'month']).toContain(view.breakdownGranularity);
            } else {
              expect(view.breakdownGranularity).toBe('exact');
            }
          });

          it('computes its derived columns from columns that hold numbers', () => {
            const slugs = columnSlugs(
              spec.columns.map(column => [column.name, column.name]),
            );

            for (const derived of view.derivedColumns ?? []) {
              const { vars, unknown } = bindFormula(derived.formula, slugs);

              expect(unknown, `${derived.name} reads unknown columns`).toEqual(
                [],
              );

              for (const name of Object.values(vars)) {
                expect(
                  [...NUMERIC, ...INSTANT, 'checkbox'],
                  `${derived.name} reads ${name}`,
                ).toContain(typeOf(name));
              }
            }
          });

          it('points every row action at a column its verb can write', () => {
            for (const action of view.rowActions ?? []) {
              const type = typeOf(action.column);

              expect(
                type,
                `${action.label} writes "${action.column}", which is not a column`,
              ).toBeDefined();

              // The verbs are typed: stamping now needs somewhere to put a
              // date, toggling needs a checkbox, counting needs a number.
              if (action.kind === 'setNow') {
                expect(
                  ['date', 'datetime'],
                  `${action.label} stamps now into a ${type} column`,
                ).toContain(type);
              }

              if (action.kind === 'toggle') {
                expect(type, `${action.label} toggles a ${type} column`).toBe(
                  'checkbox',
                );
              }

              if (action.kind === 'increment') {
                expect(
                  ['number', 'decimal'],
                  `${action.label} increments a ${type} column`,
                ).toContain(type);
                // A step is what makes it an increment rather than a no-op.
                expect(
                  typeof action.value,
                  `${action.label} needs a step`,
                ).toBe('number');
              }

              if (action.kind === 'setValue') {
                expect(
                  action.value,
                  `${action.label} needs a value to write`,
                ).toBeDefined();

                // On a select column the value has to be one of its options,
                // or the button writes a tag that doesn't exist.
                if (type === 'select') {
                  const options =
                    spec.columns.find(c => c.name === action.column)?.options ??
                    [];
                  expect(
                    options,
                    `${action.label} sets "${action.value}", not an option of ${action.column}`,
                  ).toContain(action.value);
                }
              }
            }

            // Two buttons with the same label would produce two columns a
            // person cannot tell apart.
            const labels = (view.rowActions ?? []).map(a => a.label);
            expect(new Set(labels).size).toBe(labels.length);
          });

          it('points its create button at columns that exist', () => {
            const quickAdd = view.quickAdd;

            if (!quickAdd) {
              return;
            }

            expect(quickAdd.label).not.toBe('');

            if (quickAdd.field !== undefined) {
              // What is typed has to land somewhere that holds text.
              expect(
                typeOf(quickAdd.field),
                `${quickAdd.label} types into "${quickAdd.field}", which is not a column`,
              ).toBeDefined();
            }

            for (const preset of quickAdd.presets ?? []) {
              const type = typeOf(preset.column);

              expect(
                type,
                `${quickAdd.label} presets "${preset.column}", which is not a column`,
              ).toBeDefined();

              // Presets are row-action verbs applied to a new row, so the same
              // datatype rules hold.
              if (preset.kind === 'setNow') {
                expect(['date', 'datetime']).toContain(type);
              }

              if (preset.kind === 'toggle') {
                expect(type).toBe('checkbox');
              }

              if (preset.kind === 'increment') {
                expect(['number', 'decimal']).toContain(type);
                expect(typeof preset.value).toBe('number');
              }

              if (preset.kind === 'setValue') {
                expect(preset.value).toBeDefined();
              }
            }
          });

          it('orders columns that exist', () => {
            for (const reference of view.columnOrder ?? []) {
              const known =
                typeOf(reference) !== undefined ||
                derivedNames.includes(reference) ||
                reference.toLowerCase() === 'timer';

              expect(known, `${reference} is not a column`).toBe(true);
            }

            expect(new Set(view.columnOrder ?? []).size).toBe(
              (view.columnOrder ?? []).length,
            );
          });
        },
      );
    },
  );
});

it('task templates reuse the same semantic properties rather than generating copies', () => {
  const issues = TABLE_TEMPLATES.find(t => t.id === 'issue-tracker')!.spec!;
  const tasks = TABLE_TEMPLATES.find(t => t.id === 'project-tasks')!.spec!;

  for (const name of ['Status', 'Assignee', 'Description']) {
    const issue = issues.columns.find(c => c.name === name)!;
    const task = tasks.columns.find(c => c.name === name)!;
    expect(issue.propertySubject).toBeTruthy();
    expect(issue.propertySubject).toEqual(task.propertySubject);
  }
});
