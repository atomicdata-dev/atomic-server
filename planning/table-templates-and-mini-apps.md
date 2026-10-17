# Table Templates and Mini-Apps

> **Status:** Complete (reconciled 2026-09-15). Steps 3 to 6 shipped 2026-07-31 (derived and computed columns, aggregation with breakdowns, assistant tools, the template catalogue). Derived columns in filters and aggregates shipped too (`tableFiltering.ts` `derivedFilterKey`, `TableTotalsFooter.tsx`). Kept as the as-built record for the template/mini-app model; the template product direction continues in [`unified-templates.md`](./unified-templates.md).

## Status

Steps 3–6 shipped (2026-07-31). Prompted by the Timer view: building it as a
bespoke renderer meant re-implementing the table badly, which raised the
question of what should happen as templates multiply. Steps 3 (derived
columns), 4 (aggregation with breakdowns), 5 (assistant tools) and 6 (the
catalogue) have shipped. What's left is the list of gaps below — chiefly
making derived columns first-class in filters and aggregates.

## The Problem

We have three ways to ship "an app that is mostly a table":

1. **A table template** — a data shape offered in the New Table dialog
   (`tableTemplates.ts`). Today: thirteen, from Blank to Inventory. Pure config: a row
   class, its columns, and some views. No code.
2. **A built-in view kind** — a new renderer in `TablePage`
   (`table` / `kanban` / `calendar` / `timer`). Real code, shipped in the
   data-browser, one `case` per app.
3. **An external app** — a plugin or custom-view iframe, built only on public
   surfaces. This is the route the habits app in [`plugins.md`](./plugins.md)
   argues for,
   explicitly avoiding new `case`s in `ResourcePage.tsx`.

The Timer took route 2, and that was the wrong call. Almost everything it
needed — editable cells, column headings with property menus, add-column,
alignment, responsive layout — already existed in the table and had to be
re-implemented. It still lacks keyboard navigation, column resize, column
sort, drag-reorder, copy/paste, undo, and (worse) virtualisation: it loads
every row via `getAllMembers`, in the one table type guaranteed to grow
without bound.

Route 2 does not scale to N apps. If every mini-app is a view kind, the
data-browser accretes a renderer per app and each one re-litigates the same
table features.

## The Candidate Mini-Apps

A list of plausible templates, and what each needs **beyond a plain table**.

| Mini-app | Beyond a plain table |
| --- | --- |
| Hour tracker / timesheet | start/stop action, live duration, day+week subtotals, rate × hours, invoice export |
| Expenses / receipts | currency amount, month grouping + sum, file attachment, category select |
| Invoices & clients | child line-items, per-invoice total, status, due-date overdue flag |
| CRM / deal pipeline | kanban by stage (have), "days since last contact", relation to Company, activity log |
| Job applications | kanban by stage (have), days-since-applied, follow-up reminder |
| Grocery / shopping list | quick-add bar, done checkbox, group by aisle, "clear completed" bulk action |
| Project tasks | due date (calendar, have), subtask relations, timeline/Gantt |
| Reading list / media log | status select (kanban, have), rating, finished date |
| Workout log | sets/reps, date, personal-record derived from history |
| Plant care / maintenance | last-done date, interval, next-due derived, overdue filter |
| Inventory / collection | quantity, low-stock filter, location, total value |
| Event guest list | RSVP select, +1 counts, headcount total |
| Habit tracker | date heatmap, streaks — genuinely custom; see the habits app in `plugins.md` |
| Bookmarks library | url + preview, tags |

## What Recurs

Reading down the right-hand column, the same handful of capabilities keep
appearing. None of them is specific to one app:

- **Derived columns.** duration (`end − start`), days-since (`now − date`),
  amount (`qty × price`), next-due (`date + interval`), streaks. Wanted by
  timer, CRM, expenses, invoices, plants, workouts.
- **Aggregation.** sum / count / avg, overall and per group. Wanted by timer,
  expenses, invoices, inventory, guest lists. *(Shipped in step 4, as a query
  capability — see below.)*
- **Grouping with subtotals.** by day, category, month, stage. *(Shipped as a
  breakdown under the grid; not as rows inside it.)*
- **Row actions.** start/stop, mark done, log-today, clear-completed. *(Shipped
  2026-07-31 as `view-row-actions`: a closed vocabulary of four patches —
  `setNow`, `setValue`, `toggle`, `increment` — configured per view, offered in
  the Add-column menu and to the assistant. Not yet: the timer's own start/stop,
  which needs a two-property patch and an exclusivity sweep, and the set-level
  "clear completed".)*
- **A quick-add bar.** one field that creates a row with sensible defaults.
  Wanted by timer, grocery, tasks. *(Shipped 2026-07-31 as `view-quick-add`: a
  label, an optional field to type into, and presets that reuse the row-action
  verbs applied to the new row. A button with no field is the one-tap logger —
  "Log set" stamps today and creates. On the Grocery list, Plant care and Workout
  log templates.)*
- **Relations and rollups.** invoice → line items, recipe → ingredients,
  contact → company.

The Timer's "special" features are all instances of these. **Duration is a
derived column. Day totals are grouping + aggregation. Start/stop is a row
action. The "what are you working on?" field is a quick-add bar.** None of
them is a timer concept.

## Direction

Keep view kinds a **small closed set of layouts** — how rows are arranged in
space: `table`, `kanban`, `calendar`, and plausibly `timeline`. A new layout
earns a view kind. A new *app* does not.

Push per-app behaviour into **configurable table capabilities**, stored on the
View like `view-columns` and `view-filters` already are. Then a template is
what it should be: pure data + config, no code. Adding the grocery list would
ship zero renderers.

Anything that genuinely needs a bespoke UI — the habit heatmap — goes to route
3, as an external app.

That gives a ladder with the cheap rungs first:

1. Data shape only → **template**.
2. Data shape + generic table capabilities → **template + view config**.
3. Genuinely novel layout → **view kind** (rare).
4. Genuinely novel UI → **external plugin app**.

## Consequences for the Timer

Rebuild it on `FancyTable`, which is already generic over its column type
(`FancyTable<T>`, `columnToKey`, a pluggable `HeadingComponent<T>`, and the row
renderer passed as children). It does **not** require columns to be Properties —
`TableColumn` is merely what `TableResource` happens to pass. So the timer can
supply the real property columns plus two synthetic ones (live Duration, a
Start/Stop action) and keep every table feature, virtualisation included.

Build those two synthetic columns through a **general** seam — "a column that
isn't a Property, with its own render" — rather than timer-specific branches.
That seam is the precursor to derived columns and row actions above; when they
land as configuration, the timer view kind collapses into a template and the
`case` disappears.

Two thirds of that has happened: the Duration is a derived column (step 3), and
row actions are configuration (2026-07-31) — so an ordinary "stamp the end
column" button is now config rather than code. Its toolbar is now expressible too: `view-quick-add` with a
`setNow` preset on the start column is exactly "name a thing and start timing it".
What still keeps the timer a view kind is the part its start/stop does *beyond*
one patch: starting an entry writes two properties and clears a third, and "one at
a time" sweeps every other running row. A verb that clears a property would cover
the first; the sweep is the set-level action, the last of the six still unbuilt.

Day totals are still open, but for a narrower reason than "grouping isn't built":
aggregation (step 4) reads stored properties, and a duration is derived. See the
end of step 4.

## Letting the Assistant Build These

The strongest argument for config-over-code is the assistant. **An LLM can
write configuration; it cannot ship a renderer.** If a mini-app is a view kind,
the assistant can only ever produce the apps we hard-coded. If a mini-app is a
class plus View config, the assistant can invent the plant-care tracker nobody
on the team thought of.

So the tool surface *is* the app-authoring API. Anything not expressible there
is an app the assistant cannot build.

### Where `create_table` stands today

It is already the right shape — one call builds the row class, its columns, its
views and its initial rows, and the response returns every subject (including
per-tag subjects) so no `get_schema` round-trip is needed afterwards. That
"return everything the caller will need next" property is worth preserving in
anything we add.

The gaps:

- **`views.kind` is `['table', 'kanban']` only.** Calendar has been shippable
  for a while and the assistant still cannot create one; `timer` is missing
  too. Any new view kind must land in this enum in the same change — otherwise
  the feature is invisible to the assistant.
- **View config stops at `groupByColumn` / `endColumn` / `derivedColumns` /
  `aggregates` / `default`.** No sort, no filters, no column visibility. "A table of my hours sorted by newest first" is not
  expressible, though the View resource has stored `view-sort-by` and
  `view-filters` all along.
- **`relation` columns cannot name their target class.** CRM's contact →
  company and invoice → line-items are unbuildable as a result.
- **Creation only, no iteration.** There is no way to add a column to an
  existing table, add or reconfigure a view. Real app-building is iterative
  ("now add a Priority column"), and today that falls back to raw
  `create_resource` plus manual property wiring.
- **Templates are invisible.** With a catalogue of the size above, the
  assistant should be able to start from one and adapt it, rather than
  re-deriving the Issue Tracker's schema from scratch every time.

### Proposed tool changes

1. **Extend `create_table`** — `kind` gains `calendar` and `timer`; each view
   accepts `sortBy` / `sortDesc` / `filters` / `columns`; `relation` columns
   accept a target class.
2. **Add `configure_view`** — update an existing View's config in place
   (kind, sort, filters, columns, group-by, and later derived columns,
   aggregates and row actions). This is the single seam that keeps every future
   capability assistant-reachable.
3. **Add `add_table_columns`** — add properties to an existing row class and
   make them visible in the chosen views, so iteration doesn't require
   schema-level knowledge. (Note the related product bug: a column added to a
   view with an explicit `view-columns` list is invisible unless it's appended
   there — the tool must do the same thing the UI now does.)
4. **Add `list_table_templates` + `create_table_from_template`** — start from a
   catalogue entry, then adapt with the tools above.
5. **Add `describe_table`** — read back a table's full config (class,
   columns, every view's settings), so the assistant can inspect before
   modifying instead of guessing. `get_schema` covers the class but not views.

### The test to hold ourselves to

For each mini-app in the table above: *could the assistant build it, from a
single prompt, using only these tools?* Any "no" is either a missing generic
capability or a missing tool — and it should be answered by adding
configuration, not a renderer.

## Known Gaps

- ~~The timer's day totals~~ and ~~aggregates over a derived column~~: closed by
  step 7 below — the store evaluates a computed column as it aggregates.
- ~~**No filter persists on a table created from a template.**~~ Not a bug. The
  computed-column e2e that reported it was measuring the wrong readiness signal:
  it waited for `pendingDirtyCount === 0`, which is *already* 0 in the window
  between changing a filter and the 600ms debounce queueing the commit, so it
  reloaded before the write existed and read the absence back as a lost filter.
  Re-instrumented 2026-07-31 on the Time tracker template's timer view: the
  persist effect fires, the View resource holds the constraint, and both a stored
  and a computed filter survive a reload. The e2e now waits for the View to
  actually hold the filter before waiting on the sync queue, and asserts the
  reload — the same order `table-views-filters.spec.ts` already documented.
  The lesson generalizes: **`pendingDirtyCount` says nothing about a write that
  has not been queued yet.** Any test of debounced view config has to wait on the
  resource, not the queue.
- ~~**Filters on a computed column: the store can, the UI can't yet.**~~ Shipped
  2026-07-31. `Query` takes
  `expression_filters`, evaluated over the set the index narrows to, with paging
  and `count` computed after them (see step 8). What is missing is the UI and the
  view config: the table's filter machinery is keyed by property subject from end
  to end — the chips, the value input, `view-filters` — so a filter that names a
  computed column needs that key generalized to a target, plus a value input that
  asks for hours rather than milliseconds.
- ~~**`aggregates.spec.ts` is load-sensitive**~~ — fixed by isolating the e2e
  store (2026-07-31). Two earlier sightings blamed the wrong thing, so the
  correction is worth keeping:
  - **The suite talks to the server named in
    `browser/data-browser/.env.development` (`VITE_ATOMIC_SERVER_URL`, currently
    9885), not to 9883.** The suite's own `SERVER_URL` only points the test
    *helpers*. Get this wrong and every test fails on a connection refused that
    names neither port. This is what made the earlier diagnosis attribute the
    failures to the 3.9 GB store at `~/Library/Application Support/atomic-data`,
    which the tests never touch.
  - The store they *did* use was a scratch one that had collected a session's
    worth of manual debugging tables alongside every previous run's drives. On a
    store like that `aggregates.spec.ts` failed at the "add a second totals row"
    click ("element is not stable … detached from the DOM") every time, which
    reads exactly like a code bug and is not one — verified by stashing an entire
    feature branch and re-running to an identical failure set.
  `browser/e2e/scripts/e2e-server.sh` (`pnpm test-server` / `test-server-fresh`)
  now serves the port the app is configured for, from `<repo>/.e2e-store`, and
  warns once that store passes ~150MB. Measured: `aggregates.spec.ts` passes in
  10s on a fresh store and fails outright on a 324MB one — and 324MB is only about
  two full suite runs, so this degrades much faster than "a well-used store"
  suggested. On a clean store the nine table/timer/template/dashboard/row-action
  specs run 33–35 of 36 with two workers; the stragglers pass run alone. So: **reproduce a failure alone before believing it**, and compare
  failure *sets* rather than expecting all-green. If the totals footer's menu is
  worth hardening against its own debounced refresh, that is still open — but it
  is no longer what makes the suite red.
- Aggregation has no per-aggregate filter ("sum of Amount **where** Status =
  Done"); a total follows the view's own filters instead.
- Subtotals render under the grid, not as rows between groups inside it.
- Column widths are a positional array on the table, shared by every view, so
  reordering columns swaps their widths and two views can't size the same column
  differently. Keying widths by column key would fix both.
- ~~**A filtered view keeps a row whose value stopped matching.**~~ Fixed
  2026-07-31. Found building the Inventory template: with a "Quantity at most 3"
  view, restocking a row left it listed there across a reload. The suspicion that
  it was the Loro commit path was wrong — that path is right by construction,
  because it is handed both the old and the new resource. The culprit was
  `Db::add_resource_opts`, which is the *other* write path: given only the new
  resource, it evicted the old values' index entries **against the new resource**.
  `should_update_property` therefore asked whether the new value still matches the
  filter, a restocked row answered no, and the one entry that needed deleting was
  the one deletion was skipped for. It now rebuilds the old resource from the
  stored propvals (as `recursive_remove` already did) and evicts against that.
  The same mistake had a second symptom nobody had noticed: an edit that keeps a
  row in the view but changes its sort value deleted the key the *new* value
  implies rather than the one the entry is filed under, so the row was listed
  **twice** (and `count` disagreed with the rows).
  Why only the browser saw it: the server applies commits, while the browser's
  local database writes whole resources (`putResource` → `add_resource_opts`),
  and a filtered view is answered from that database's cached member list.
  So a scratch test at the `atomic_lib` level passed — it was exercising the
  commit path. Guarded by `lib/tests/query_index_eviction.rs` (leaving a filter,
  entering one, and an unrelated edit that must not evict) plus the Inventory
  e2e, which fails against a wasm build without the fix.
- ~~**A computed cell never refreshes in place.**~~ Fixed 2026-07-31. Editing the
  column a computed column derived from left the derived cell showing whatever it
  computed at mount; only a reload updated it. The note that used to be here
  blamed the draft row, which was wrong — it happened to saved rows too.
  The cause was the React Compiler: `DerivedCell` called
  `generator.compute(resource, args, now)` during render, and the Compiler
  memoizes that on the identities it can see. A `Resource` proxy's identity
  **never changes** — the store mutates resources in place and notifies — so the
  result was computed once and cached forever. Instrumented proof at the time: the
  cell re-rendered, `resource.get(...)` returned the new value in that same
  render, an unmemoized `compute(...)` returned the right answer, and the memoized
  value was still `undefined`.
  Two fixes failed before the third worked, and the failures are the useful part:
  1. `useValue` per argument — the arg count varies by generator, so this meant
     hooks inside `.map()`. A rules-of-hooks violation, and the Compiler broke it.
  2. A version counter added to the `useMemo` dep array. **The Compiler infers a
     memo's dependencies from what the callback reads and ignores the written
     array**, so a cache-busting dep is inert. Worth remembering generally: under
     the Compiler, a dep array is not a lever.
  What worked: the generators are now pure functions of their **resolved argument
  values** (`ArgValues`) rather than of the row, and the cell reads those through a
  *fixed* two top-level `useValue` calls — two because no generator takes more
  than `MAX_DERIVED_ARGS` arguments, which a unit test now enforces so a future
  three-argument generator fails loudly instead of silently losing reactivity in
  its third. The memo's real inputs then change when the data does.
  `TimerActionCell` had the same latent bug and reads through `useValue` now too.
  Guarded by an e2e that edits a factor of Inventory's `Quantity × Unit price` and
  expects the product to follow with no reload — verified to fail without the fix.
  Still open, and a different thing: **a computed cell does not render at all on
  the trailing draft row** you are typing into. The draft is local until it
  materializes, and its cells stay bound to that state, so a value appears only
  once the row is rendered as a saved one.
- No template can seed a default value, so a "date added" column starts empty
  even though `createdAt` is stamped on every row.

## Implementation Plan

Ordered so each step is independently shippable and green. Steps 3, 4 and 5 are
done.

### 3. Derived columns as configuration — done (2026-07-30)

`Duration` used to be hand-built in `useTimerColumns`. Now:

- `chunks/TablePage/derivedColumns.ts` — a `DerivedColumnSpec`
  (`{ id, label, kind, args, width? }`) plus a **fixed** registry of five
  generators, not a formula language: `difference` (`to − from`), `elapsed`
  (`(until ?? now) − from`, the ticking variant), `daysSince`, `product`
  (either factor may be a literal, so a rate needs no column) and `offset`
  (date + days). Each declares its argument names, computes a number and
  formats it. Malformed stored config is dropped, not thrown: hand- or
  assistant-written config must not be able to take a table down.
- `useDerivedColumns.tsx` — turns specs into `TableColumn[]` with `virtual`
  cells, and holds the shared 1s ticker moved out of `useTimerColumns` (only
  `elapsed` reports itself live, so a table of settled durations ticks zero
  times). Keyed on the specs' serialized shape, since the parsed JSON's
  identity churns every render.
- Ontology: `view-derived-columns` (JSON) on the View class, alongside
  `view-filters` — in `lib/defaults/table.json` and
  `browser/lib/src/ontologies/dataBrowser.ts`, and copied by `duplicateView`.
- UI, on the same footing as the tool: **Add column → Computed** opens a dialog
  generated from the registry — the generator's arguments become its fields,
  `accepts` filters the column picker to date or number properties, and
  `allowsLiteral` offers "a fixed number" where one makes sense. A computed
  column's heading carries its own menu (Edit / Remove) since there's no
  property behind it to configure. Anything the assistant can build here, a
  person can build and change too; that constraint is worth keeping for
  aggregation and row actions.
- `create_table` gained per-view `derivedColumns` in the same change, in the
  column-name vocabulary the rest of a spec uses (arguments resolve to property
  subjects on creation), so the capability is assistant-reachable immediately.
- The timer: `Duration` is an `elapsed` spec over `view-group-by` /
  `view-end-prop`, seeded by the Time tracker template. The bespoke duration
  cell is gone; only the start/stop row action stays behind. A timer view that
  configures none of its own (added from the view menu rather than the
  template) falls back to timing its own start/end pair, so nothing regressed
  for views created before this.
- The e2e proof that this is config and not a timer feature: switching the
  template's timer view to `table` keeps the Duration column and drops only the
  Start/Stop one. A second spec drives the human path end to end: add two
  computed columns (one with a typed-in number), rename one, reload, remove it.

Column placement came later, when the timer's own columns needed to lead: order
is now per-view configuration (`view-column-order`, a list of column keys) that
any heading can drag, computed and view-owned columns included.

A rule this established, worth holding to for steps 4 and 5: **a capability
lands with both its tool and its UI.** Config-only would mean the assistant can
build a table its owner cannot then change.

Left for step 4: nothing here aggregates. A derived column is per-row.

### 4. Aggregation and grouping — done (2026-07-30)

Answered as a **query capability**, not a client-side add-up. The store computes
where the data is; only the numbers travel.

- Rust (`lib/src/aggregate.rs`): `Aggregation` on `Query` (sum / count / avg /
  min / max, with an optional `group_by`), outcomes on `QueryResult`. `db.rs`
  runs it as a second, unpaged pass over the same filter and index path as the
  page query — so a total can never summarize a different set than the rows on
  screen. Day and month buckets take a timezone offset from the caller; the
  calendar maths is hand-rolled (`civil_from_days`) because this crate compiles
  to wasm and carries no date dependency.
- Wire: the `aggregation` query param, results on the Collection's new
  `collection/aggregates` (JSON). The browser's local WASM DB runs the same
  code, so an offline table gets the same totals from the same implementation.
- Ontology: `view-aggregates` (JSON `[{ id, property, function }]`),
  `view-group-by-column` and `view-group-granularity` — the group-by column is
  deliberately separate from `view-group-by`, which is what a kanban, calendar
  or timer arranges its rows by. A view can be grouped one way and subtotalled
  another.
- UI: **footer rows inside the grid**, one total per column per row, picked from
  that column's own footer cell (Sum / Average / Min / Max / Count, filtered by
  datatype). More than one row is allowed — a column can show a sum on one line
  and an average on the next — carried as a `row` index on each aggregate. Always in view, scrolls sideways with the columns, and its left
  cell holds the row count plus the breakdown menu. The per-group breakdown
  renders as a panel under the grid, since that is the one part which has no
  column to sit in. `create_table` gained `aggregates` / `breakdownColumn` /
  `breakdownGranularity` in the same change.
- Totals ride their own small query (`useTableAggregates`: one row plus the
  numbers), re-read on save/delete with a debounce. Piggybacking on the row
  collection left them stale after an edit — that collection patches its pages
  surgically instead of re-querying — and refreshing *it* would clear the pages
  under the user's cursor.
- Two honest edges, both surfaced rather than hidden: a `count` counts the rows
  the reader can actually resolve, so it can be lower than `totalMembers`
  (which counts raw index hits, issue #286); and a breakdown past its bucket
  limit says so instead of looking complete.

Subtotal rows *inside* the grid were not built — `FancyTable` assumes a flat row
list, and a summary panel under it turned out to answer the same question
without touching the virtualised editor.

Still open: **the timer's day totals.** Aggregates read stored properties, and a
duration is a derived column — nothing stores it. Closing that needs either a
stored duration or an aggregate that can evaluate a derived column, which is the
same expression-aware seam a formula language would want.

### 5. Assistant tools

- Extend `create_table`: per-view `sortBy` / `sortDesc` / `filters` /
  `columns`, `derivedColumns`, `aggregates`; `relation` columns gain a target
  class.
- `configure_view` — update an existing View in place. This is the single seam
  that keeps every future capability assistant-reachable.
- `add_table_columns` — add properties to an existing row class **and append
  them to the active view's `view-columns`**, or they are invisible (the exact
  bug fixed in the UI on 2026-07-30).
- `describe_table` — read back class + every view's config, so the assistant
  inspects before modifying rather than guessing.
- `list_table_templates` / `create_table_from_template`.
- Acceptance: walk the mini-app table above and build each from a single
  prompt using only these tools. Every failure is a missing capability or a
  missing tool — answered with configuration, not a renderer.

### 6. The catalogue — done (2026-07-31)

The payoff for steps 3–5: the catalogue went from 2 templates to 13, and not one
of them shipped a line of rendering code. Expenses, deals (CRM), job
applications, project tasks, reading list, grocery list, workout log, plant care,
inventory, guest list and bookmarks joined the issue tracker and the time
tracker — every row of the mini-app table above that these capabilities reach.
Each is columns + views, and between them they use every capability: kanban and
calendar layouts, computed columns (`daysSince` for a stale deal, `offset` for a
plant's next watering, `product` for a line total), totals with a month or
category breakdown, two totals rows on one column, per-view column order, and a
filtered second view ("Low stock").

Two things this surfaced:

- **`decimal` columns.** The column vocabulary only had `number`, which is an
  integer — so every money template would have silently dropped its cents.
  `decimal` is a FLOAT carrying the FormattedNumber shape the property form
  writes, so its own form (currency, percentage, more decimals) opens on it
  afterwards. Reachable from `create_table` too.
- **`tableTemplates.test.ts`.** A typo in configuration is not a compile error,
  it is a broken mini-app. The test walks every spec and checks it against the
  capabilities that exist: a total names a real, stored, numeric column; a kanban
  groups by a select; a breakdown column is groupable; a computed column's
  arguments have the datatype the generator accepts; `columnOrder` names things
  that exist. Cheap, and it caught the class of mistake this step is full of.

`table-templates.spec.ts` walks three of them end to end (Expenses' order,
decimals and totals; Plant care's next-due date; Inventory's line value and
filtered view), since "the config arrived wired up" is the only thing a template
can get wrong.

### 7. Computed columns in the store: totals — done (2026-07-31)

A computed column used to live only in the cell: the store knew nothing about it,
so a total couldn't sum one. That is what blocked the timer's day totals, "qty ×
price summed" and inventory's total value — three of the mini-app list's own
requirements.

- `lib/src/expression.rs`: the same five generators, in Rust. An `Expression` is
  the column's own `kind` and argument names, flattened
  (`{kind: 'elapsed', from, until}`), with each argument either a property
  subject or a literal number — so one spec describes the cell and the store.
  A row missing an argument yields no value, which is the same "doesn't
  contribute" a row without a stored value already got: never a zero, which would
  drag an average down.
- `Aggregate` gained `expression` (alternative to `property`) and `id` — two
  totals over computed columns name no property at all, so nothing else told
  their outcomes apart. The outcome echoes the id.
- `Aggregation.now_ms`: the caller's clock, so a running duration totals to the
  same instant the cells are showing, and so a day breakdown can't split one day
  across two buckets mid-pass. The browser quantizes it to the minute, because
  `now` is part of the query's identity — a raw `Date.now()` would re-run the
  query on every render.
- UI, per the rule: a computed column's footer cell now offers the same menu a
  stored column does, and formats the answer the way the column does (a sum of
  durations reads `5:30:00`, not `19800000`) — in the breakdown panel too. A date
  column (a next-due) offers only earliest/latest, since summing dates is
  meaningless. The one cell that still says "nothing to total here" is the timer's
  Start/Stop, which holds an action rather than a value.
- Tool: `aggregates` take `computedColumn` alongside `column`, and
  `configure_view` resolves one the view already has — the assistant adds the
  column in one call and totals it in the next.
- The Time tracker template now ships the day totals it always described: its
  All entries view sums Duration and breaks it down per day.

Filters over computed columns are deliberately not in this step: a total rides
the aggregation pass that already scans the matching set, while a filter decides
*membership*, which today comes from an index keyed by stored values.

## Open Questions

- Do derived columns need a formula language, or is a fixed set of generators
  (difference-of-dates, product-of-columns, days-since) enough to cover the
  table above? The fixed set is far cheaper and covers every row listed.
- Should aggregation live on the View (`view-aggregates`) or be a per-column
  toggle in the column menu?
- Is `timeline` a fourth layout, or a calendar variant?
