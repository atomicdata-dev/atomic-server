# Computed columns with formulas

A computed column is a **formula** over the other columns of a row. It stores
nothing, so it is always current, and it can be filtered, sorted-by-eye and
totalled like any column. Use it for durations, days since, amounts, next-due
dates and yes/no flags like "birthday within two weeks" — never ask the user to
keep such a value up to date by hand.

## Where to put one

In a view's `derivedColumns`, with `create_table`, or `configure_view` on an
existing table (the list you pass replaces the view's computed columns):

```json
{
  "name": "Birthdays",
  "kind": "table",
  "derivedColumns": [
    {
      "name": "Days until birthday",
      "formula": "daysUntilAnniversary(birthday)"
    },
    {
      "name": "Birthday soon",
      "formula": "daysUntilAnniversary(birthday) <= 14",
      "valueKind": "boolean"
    }
  ]
}
```

## Naming columns

A formula refers to a column by the **lowercase slug of its name**: letters
`a-z`, digits and `_`, everything else becomes `_`. `Last watered` is
`last_watered`, `Unit price` is `unit_price`, `Meat & fish` is `meat_fish`. Two
columns that slug alike get `_2` on the second. Only columns holding numbers,
dates, datetimes or checkboxes can be read; an unknown name is rejected with the
list of valid ones.

## Syntax

Numbers, `+ - * / %`, comparisons `< <= > >= == !=`, `&&`, `||`, `!`, and
parentheses. Dates and datetimes are read as **milliseconds**; a checkbox is 1
or 0. A comparison or boolean result is 1 (true) or 0 (false).

## Functions

| Function                                               | Meaning                                                             | Example                          |
| ------------------------------------------------------ | ------------------------------------------------------------------- | -------------------------------- |
| `now()`                                                | the current time in ms                                              | `now() - start`                  |
| `coalesce(a, b, ..)`                                   | the first one that has a value                                      | `coalesce(end, now()) - start`   |
| `days(ms)`                                             | whole days in a span, rounded down                                  | `days(now() - last_contact)`     |
| `addDays(ms, n)`                                       | a date moved by n days                                              | `addDays(last_done, interval)`   |
| `daysUntilAnniversary(date)`                           | days until the next time this month and day comes round, 0 if today | `daysUntilAnniversary(birthday)` |
| `min(a, b)`, `max(a, b)`                               | smaller / larger                                                    | `max(0, days(now() - due))`      |
| `if(test, a, b)`                                       | choose by a condition                                               | `if(done, 0, days(now() - due))` |
| `math::floor(x)`, `math::ceil(x)`, `math::round(x)`... | rounding and other math                                             | `math::floor(price * 1.21)`      |

## Recipes

- **Running duration** (a timer entry still running while `end` is empty):
  `coalesce(end, now()) - start`, `valueKind: "duration"`.
- **Finished duration:** `end - start`, `valueKind: "duration"`.
- **Days since** a date: `days(now() - last_contact)`, `valueKind: "days"`
  (shown as `3d ago`).
- **Next due** from a last-done date and an interval in days:
  `addDays(last_done, every_days)`, `valueKind: "date"`.
- **Quantity x price:** `quantity * price` (or `hours * 85` for a fixed rate).
- **"Bijna jarig" / birthday soon:** `daysUntilAnniversary(birthday) <= 14`,
  `valueKind: "boolean"`. For the count itself use
  `daysUntilAnniversary(birthday)`.
- **Overdue flag:** `now() > due`, `valueKind: "boolean"`.

## Numeric gotchas

- Integer literals stay integers: `1 / 2` is `0`. Write `1.0 / 2`.
- Mixing whole and decimal numbers inside a function can fail: write `3.0`, not
  `3`, in `max(x, 3.0)` when x may be a decimal.
- A row missing a column the formula reads has no value: the cell is empty and
  the row is left out of totals and filters. Use `coalesce(col, 0.0)` to count
  it as zero instead.
- Results are numbers, or booleans (true is 1).

## Filters and totals

A computed column can be filtered and totalled. A boolean column keeps its true
rows with the filter "equals 1"; a number column filters with `<`, `>`, `=`
(days and hours, not milliseconds, for a `days` or `duration` column). Total one
by naming it with `computedColumn` in `aggregates`:
`{ "function": "sum", "computedColumn": "Line total" }`. For a boolean column
`sum` is the number of rows where it holds.

## valueKind

Only changes how the number is shown and which totals make sense: `duration`
(ms as `1:05:00`), `days` (`3d ago`), `date`, `boolean` (a check mark),
`number` (the default).
