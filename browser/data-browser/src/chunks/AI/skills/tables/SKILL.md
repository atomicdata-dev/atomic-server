# Atomic Data Tables

## Zero-discovery rule

If the table is already attached to this chat (an `<atomic-context>` block
with `Row schema:`, `Row class:` and a row sample), you have EVERYTHING needed
to add or edit rows. Do NOT read the table, its class, its properties, its
tags, or its rows again — go straight to ONE `create_resource` /
`update_table_rows` call (or `edit_atomic_resource` for a single cell) using the refs and shortnames from that block.

## Architecture Overview

A table setup consists of three interconnected parts:

A Table resource: The entry point for the user.
A Class resource: Defines the "schema" or columns of the table. Linked to the table via the table's `classtype` property.
The Properties: Individual fields used by the Class. These represent the columns of the table.

Reading a table with `get_atomic_resource` returns it in compact form; its
`classtype` is the row class. Reading is only needed when the table is NOT
already attached as context.

## Creating Tables

**Start from a template when one fits.** `list_table_templates` shows the
catalogue — expenses, deals, job applications, tasks, groceries, inventory,
plants, workouts, guest lists and more, each with its columns, views, computed
columns and totals already configured. `create_table_from_template` builds one
(`{ template: 'time-tracker', name: 'My hours' }`) and you adapt it afterwards
with `add_table_columns` / `configure_view`, rather than re-deriving its schema
by hand. A template is a starting point, not a straitjacket: the user's own
wording ("track my plants, but per room") is best served by instantiating the
closest one and then changing it.

**Otherwise prefer the `create_table` tool.** It builds the whole table — the row Class,
every column, any saved views (`table`, `kanban`, `calendar` or `timer`) with
their computed columns, AND the initial rows — in a single call. Describe it
declaratively:

```json
{
  "name": "Issues",
  "columns": [
    {
      "name": "Status",
      "type": "select",
      "options": ["Todo", "Doing", "Done"]
    },
    { "name": "Assignee", "type": "relation" }
  ],
  "views": [
    {
      "name": "Board",
      "kind": "kanban",
      "groupByColumn": "Status",
      "default": true
    }
  ],
  "rows": [{ "name": "Set up CI", "Status": "Todo" }]
}
```

A `name` title column is always added automatically — don't include it. Column
`type` is one of `text`, `markdown`, `number`, `decimal`, `date`, `datetime`,
`checkbox`, `relation`, `file`, `select` (`select` needs `options`). Use
`decimal` for money, prices, hours and measurements — `number` is whole numbers
only, so an amount stored in one silently loses its cents.

### Computed columns

A value derived from the row is configuration, not a stored column: put it in a
view's `derivedColumns` instead of asking the user to keep it up to date.

```json
{
  "name": "Timesheet",
  "kind": "table",
  "derivedColumns": [
    {
      "name": "Duration",
      "kind": "elapsed",
      "args": { "from": "Start", "until": "End" }
    },
    { "name": "Fee", "kind": "product", "args": { "a": "Hours", "b": 85 } }
  ]
}
```

The five kinds, with the arguments each takes (a column name, or a literal
number where one makes sense):

- `difference` — `{ from, to }`: a finished duration between two dates.
- `elapsed` — `{ from, until }`: ticks live while `until` is empty, so a row
  with a start and no end reads as still running.
- `daysSince` — `{ from }`: whole days between a date and now.
- `product` — `{ a, b }`: quantity × price, hours × rate.
- `offset` — `{ from, days }`: a next-due date from a last-done date.

### Totals

Ask the server for a total instead of fetching rows to add up yourself. Put them
on a view:

```json
{
  "name": "Expenses",
  "kind": "table",
  "aggregates": [
    { "function": "sum", "column": "Amount" },
    { "function": "count" }
  ],
  "breakdownColumn": "Category"
}
```

- `function` is `sum`, `count`, `avg`, `min` or `max`. `sum`/`avg` need a number
  column, `min`/`max` a number or date column, `count` needs none (it counts
  rows; with a column it counts the rows that have one).
- Computed over EVERY row the view matches — filters included, paging excluded —
  so these are exact on a table of any size.
- `breakdownColumn` gives one subtotal per distinct value (a select, relation,
  checkbox or date column). For a date or datetime column add
  `breakdownGranularity` (`day`, the default, or `month`).
- Totals render in footer rows, under the column each describes. One total per
  column per row: to show a sum and an average of the same column, put the
  second on `"row": 1`.
- A **computed** column can be totalled too — name it with `computedColumn`
  instead of `column`, and the store evaluates it per row:
  `{ "function": "sum", "computedColumn": "Duration" }`. That is how a timesheet
  gets its hours per day (a `sum` of Duration with `breakdownColumn: "Start"`),
  or an inventory its total value (a `sum` of a `product` column). The column has
  to exist on the same view; `configure_view` can name one the view already has.

Only fall back to building a table by hand (multiple `create_resource` calls)
when you need something `create_table` can't express. For that lower-level
recipe read `/creating-tables`.

## Changing an existing table

Before creating a new row class for a table, call `find_schema`: a class for these rows may already exist and should be reused. Three tools, and none of them need ontology knowledge:

- **`describe_table`** — read back the row class, every column (datatype +
  select options) and every view's settings. Do this _before_ changing a view;
  `get_schema` covers the class but not the views.
- **`add_table_columns`** — add columns to the row class. It also appends them to
  the views that keep an explicit column list, which is required: a column
  missing from that list is hidden.
- **`configure_view`** — change a view in place: `kind`, `sortByColumn` /
  `sortDesc`, `filters`, `columns` (which are visible, in order), `columnOrder`
  (the full order, which can also place a computed column or `timer`),
  `derivedColumns`, `aggregates`, `breakdownColumn`, `groupByColumn`,
  `endColumn`, `name`, `default`. **Only the fields you pass are touched**, so
  changing a sort can't drop the filters — call it as often as you like while
  building something up.

Real app-building is iterative: create (or instantiate a template), then add
columns and configure views. Only drop to `create_resource` for structure these
tools can't express, and read `/creating-tables` first if you do.

## Adding and modifying rows

Rows are children of the table, instances of the table's `classtype`. Add
rows with ONE batched `create_resource` call — an array of compact objects:

```json
[
  {
    "@class": "<row class ref>",
    "@parent": "<table ref>",
    "name": "Acme Corp",
    "status": "Lead",
    "value": 50000
  },
  {
    "@class": "<row class ref>",
    "@parent": "<table ref>",
    "name": "TechNova",
    "status": "Qualified"
  }
]
```

- Keys are the row-class shortnames from the schema line; select values are
  tag names. Never call `create_resource` once per row.
- `createdAt` is added automatically when the parent is a table (rows only
  appear in the table once it is set; it drives the default sort order).
- Edit a single cell with `edit_atomic_resource` (shortname + tag name work).
- For several existing rows, use `update_table_rows` once with `table` and
  `rows: [{subject, values: {shortname: value}}]`. File subjects/refs work as
  values for File columns. If a column is missing, call `add_table_columns`
  once before the batch. The result lists completed rows; saves are per row,
  so inspect a failing row and do not repeat already completed edits.

To list rows use `query` with the row class:
`{"class": "<row class ref or shortname>", "where": [...]}` — filters accept
shortnames and tag names (e.g. `{"property": "status", "value": "Done"}`).
Keep in mind that a table might have a huge amount of rows, so it might not
always be preferable to load them all if you're looking for something.

## Gochas
