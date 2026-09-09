// @wc-ignore-file
/**
 * What the assistant is told about building an app.
 *
 * Kept out of the tools file so it can be read on its own, and because the
 * routing rule it carries is the whole difference between a user getting
 * Atomic's kanban board and getting a hand-written imitation of one.
 */
export const CREATE_APP_DESCRIPTION =
  "Create an app: a custom screen, written in JavaScript, backed by the user's own data.\n\n" +
  'THIS IS THE LAST RESORT. There are three ways to give someone a screen, and you take the FIRST one that fits.\n\n' +
  "  1. A READY-MADE TEMPLATE. Call list_table_templates and actually look. There is already an issue tracker, a CRM pipeline, project tasks, a time tracker, expenses, job applications, a reading list, a grocery list, a workout log, plant care, inventory, a guest list and bookmarks. These are the most complete and most tested answer in the product: the CRM one alone arrives with a kanban pipeline grouped by stage, deal value summed and broken down per stage, and a computed 'days since contact' column. Take one with create_table_from_template, then adapt it with add_table_columns and configure_view. Skipping this rung throws away everything the template already worked out.\n" +
  '  2. A TABLE WITH VIEWS. No template fits, but the thing is still rows. create_table builds the columns and the saved views in one call.\n' +
  '  3. THIS TOOL. Only when neither of the above can express it.\n\n' +
  'Rungs 1 and 2 are CONFIGURATION, and they arrive with drag-and-drop between kanban columns, live sync between people, undo, keyboard navigation, resizable columns and export already working. Anything you write by hand starts with none of that and never catches up.\n\n' +
  'STOP IF YOU ARE ABOUT TO WRITE ANY OF THESE. Every one is a parameter that already exists:\n' +
  "  - cards in columns by status -> configure_view kind:'kanban' with groupByColumn\n" +
  "  - a grid of rows -> kind:'table'. A table can have BOTH, as two views, so the user gets both tabs.\n" +
  "  - anything laid out on dates -> kind:'calendar'. Anything being timed -> kind:'timer'.\n" +
  '  - a search box or a status dropdown -> filters\n' +
  '  - a sort control -> sortByColumn and sortDesc\n' +
  "  - a total, a count, an average, a 'win rate' tile -> aggregates, per group with breakdownColumn\n" +
  "  - an 'add' button -> quickAdd\n" +
  'A sales pipeline, a CRM, a task board, a habit tracker, a reading list, an issue tracker: ALL of these are a table with views, and most of them are a template you can take whole. Building one as an app produces a worse copy of something the user already had, and it will be buggy, because you would be hand-rolling seven features instead of naming them.\n\n' +
  'WRITE AN APP ONLY WHEN THE INTERACTION ITSELF IS THE POINT and no view kind expresses it: a nursing timer with two thumb-sized buttons, a seating chart, a map, a drawing surface, a game, a calculator. The test: if you deleted your custom rendering and showed the same rows in a table, would the user have lost something real? If the honest answer is no, do not build an app.\n\n' +
  'An app made here gets a table of its own for its rows, and never touches an existing one. So if the user already keeps these rows in a table, do NOT build an app around a copy of them — configure a view on the table they have. (A custom view can be added beside their Table tab, but only the user can do that today, from the table\u2019s "Add view" menu.)\n\n' +
  'Use create_plugin instead when the job is importing or changing data on a schedule.\n\n' +
  'You write one JavaScript module that `export async function view({ root, store })`. `root` is a DOM element to render into; build the UI with ordinary DOM calls. There is no React, no bundler and no npm — plain JS only, and no build step, which is why you can write it and it just runs.\n\n' +
  "`store` is the same API as @tomic/lib: `await store.getResource(subject)` (then `.get(propertySubject)`, `.set(prop, value)`, `await .save()`, `await .destroy()`), `await store.newResource({ parent, isA, propVals })`, `await store.query({ property, value })` returning subjects, `await store.getApp()` for this app's own subject, `await store.getData()` for `{ table, rowClass }`, and `store.subscribe(subject, cb)` returning an unsubscribe function.\n\n" +
  "STORE EACH THING AS ITS OWN RESOURCE. The app comes with a table and a row class: `const { table, rowClass } = await store.getData()`. Create a row with `await store.newResource({ parent: table, isA: [rowClass], propVals: { [prop]: value } })` and list them with `await store.query({ property: 'https://atomicdata.dev/properties/parent', value: table })`.\n\n" +
  "DO NOT keep the app's data as JSON in one resource. It is the obvious move if you are used to localStorage, and it throws away everything this platform is for: a blob cannot be sorted, filtered or edited in the table view, cannot be queried or shared per-row, and two people editing at once overwrite each other wholesale instead of merging. One resource per row, always.\n\n" +
  'There is no `children` or `sub-resources` property. Children are found by querying `parent`, as above.\n\n' +
  "GIVE THE ROWS THEIR FIELDS FIRST. A new row class has only `name`. Before writing the view, call add_table_columns with the `data` subject this tool returns, to create the properties the app needs (a CRM's company, value, stage; a tracker's date, done). It returns each property's subject — use those as the keys in propVals. Rows then have real fields, which is what makes them useful in the table as well as in your UI.\n\n" +
  'The app may write ANYTHING UNDER ITSELF without asking, and nothing outside itself. Reading is not restricted.\n\n' +
  'Careful with subscribe: adding a child counts as a change to its parent, so subscribing to the app and writing into it on every notification loops. Guard on what changed, or re-read on user actions instead.\n\n' +
  "Do not invent demo data. An empty app with an obvious way to add the first row is correct; seeded fake contacts are not the user's data and they have to delete them.\n\n" +
  "NAME THINGS THE WAY THE USER WOULD. The app's rows show up in their sidebar as an ordinary table, so `rowNamePlural` is a title they read every day — 'Feeding sessions', not 'Items'. Same for the app's own name and its emoji.\n\n" +
  "THE APP IS RUN BEFORE THIS TOOL RETURNS, and the result comes back as `ran`. If it is anything but 'ok' you are not finished: fix it with update_app and let it be checked again. Never tell the user an app is ready while `ran` says otherwise — they will open it and find what you already knew.";
