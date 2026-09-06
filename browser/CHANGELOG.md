# Changelog

This changelog covers all five packages, as they are (for now) updated as a whole

## UNRELEASED

- Cmd+Up (go to parent) works in tables again: ArrowUp no longer matches
  with Ctrl/Cmd held, and the parent action fetches the resource when a
  stub has not yet materialized `parent`.
- `useCollection` resets `ready` when the query changes, so the table
  grid's `aria-busy` stays true until the new page lands.

- Commits are signed envelopes: `CommitDetail` does not fetch `did:ad:commit:`
  resources; author and dates come from the resource. History no longer
  navigates to a commit DID, and the Sync page log no longer links commit ids.
  Sequential saves no longer set `previousCommit`.
- History shows who signed each version. `Store.getHistoryAttribution(subject)`
  merges the server's `GET /history-attribution` with the local ClientDb
  (`historyAttribution`), and `VersionTitle` labels a version
  `by <agent> Verified` (signature checked), `Unverified` (envelope present,
  signature failed) or `by peer … Unattributed` (no envelope covers it).
  `attributionForVersion`, `mergeHistoryAttributions`, `parseHistoryAttribution`
  and the `HistoryAttribution` / `Attribution` types are exported from `@tomic/lib`.
- [#1232](https://github.com/ontola/atomic-server/issues/1232) Unified
  actions: the ⌘K palette shows a capped Actions section for the current
  resource, hotkeys and the shortcuts overlay/page render from the action
  registry, and simple verbs (`delete`, `favorite`, `share`, `history`)
  derive in-app AI tools.

## [v0.41.0-beta.5] - 2026-09-04

- `@tomic/lib`: `Store.search` uses the durable WASM/OPFS inverted index
  (`ClientDb.search`) for local hits, including `filters`. The MiniSearch
  in-memory index is removed. Online searches merge with hosted `/search`
  (same KV engine). Offline without ClientDb returns no local hits.
  `ClientDbWorker.search` / `NodeClientDb.search` added. Removed
  `escapeTantivyKey` — `filters=` is exact `property:"value"` pairs, no
  query language.
- Fix: [#1358](https://github.com/atomicdata-dev/atomic-server/issues/1358)
  Cloud Vault restore on Safari (and any WebCrypto signer) failed with "no
  wrapper in this envelope accepted that credential". The agent vault proof
  asked the signed-in agent's provider for a signature, which on WebKit is
  WebCrypto with a randomized nonce — a different valid signature every
  call, so the KEK never matched. The proof is now derived once with noble
  (RFC 8032, matching the server) from the raw key at sign-in and persisted
  beside the keypair. When no stored proof exists, a live signature is only
  accepted if signing twice reproduces it.
- Fix: signing in with a passkey or secret on a browser that has no
  control-plane session no longer ends on "Your data is on another device"
  with nothing to do. The connect-device step checks for a session first
  and, when there is none, offers sign-in on the portal (or the device-link
  panel in a webview that cannot hold the cookie).
- Onboarding: the connect-device screen names one way in — restore from the
  backup, sign in to the account that keeps it, or the second-device routes
  — and folds the rest under "…or bring it over from another device".
- Sidebar drive switcher is a two-part control: the drive's emoji or icon
  (home for the private drive) plus its name, both halves bordered like a
  segmented button.
- Quick-create class shortcuts reveal on hover and stay hidden on touch
  (the New page still has them).
- [#1338](https://github.com/atomicdata-dev/atomic-server/issues/1338) Title
  row on touch and narrow screens: the Add icon / Add cover ghost buttons
  next to a page title only render where the viewport can hover and is at
  least 600px wide; elsewhere they appear in the resource context menu.
- Title editor wraps like the heading (a textarea that grows with the text)
  instead of becoming a single-line input that scrolls sideways. Clicking a
  title places the caret under the pointer instead of selecting the whole
  title (a freshly created resource still selects its placeholder). The
  go-to-parent arrow on narrow nav bars is gone.
- The unsaved-changes asterisk is gone. Autosaving editors set the dirty
  flag between every keystroke and its commit, so it blinked on every tap
  and told the user nothing; the sidebar sync item already spins while
  commits are in flight.
- `@tomic/lib` live collaboration speaks binary `EPHEMERAL`. Edits in progress, cursors and drive presence are sent and received as `EPHEMERAL (0x40)` frames (`encodeEphemeral` / `decodeEphemeral`, `EphemeralKind`), raw bytes instead of base64 JSON in the `LORO_SYNC_UPDATE` / `LORO_EPHEMERAL_UPDATE` / `PRESENCE_UPDATE` text frames, which are gone. `WSClient.sendLoroSyncUpdate`, `sendLoroEphemeralUpdate` and `sendPresenceUpdate` now take `(subject, bytes)`; `Store.__handleLoroSyncMessage`, `__handleLoroEphemeralMessage` and `__handlePresenceMessage` take `(subject, bytes)`. The subscribe / unsubscribe frames are still text.
- `@tomic/lib` drive sync speaks binary `SYNC`. The hash-first probe on connect and the reduced reconcile after the RBSR descent are sent as `SYNC (0x30)` with `"probe": true` / `"subjects": [...]` in the JSON tail, and a stale probe is answered with the new `SYNC_RESEND (0x38)` (`decodeSyncResend`, `Tag.SYNC_RESEND`). The text `SYNC_VV` request and text `SYNC_RESEND` answer are gone; the `RBSR_FP` / `RBSR_ITEMS` descent is still text. Servers advertise `sync-probe`; an older server ignores the two keys and runs a full reconcile.
- `@tomic/lib` cleanup. Switching drives now `UNSUB`s the previous drive's fan-out (until now every drive opened in a session kept pushing its commits to the socket). `Store.waitForServerConnected(timeoutMs)` is public and is the one implementation of a wait that existed four times over (`Collection` and two data-browser helpers now use it). Removed: the write-only `serverHasCapability` / `getServerWsCapabilities` cache (the live list is `WSClient.serverCapabilities`), `Store.logIncomingCommit`, the `debugFrame` codec helper and the exported `supportsWebSockets` (all without callers), and a skipped integration test targeting APIs that no longer exist. Liveness constants moved to `liveness.ts`.
- `@tomic/lib` sync protocol follow-ups. The WebSocket client introduces itself with a `HELLO` on open (`CLIENT_CAPABILITIES`, today `commit-ok-slim`), and a server that honours it answers `COMMIT` with a slim `COMMIT_OK` carrying only the commit id; `postCommit` resolves with the commit it signed plus that id, and still accepts the full-JSON ack from older servers. The AUTH proof is bound to the socket: the client signs `{origin}#{nonce}` with the nonce from the server's `CHALLENGE` frame (falling back to the timestamp-only proof after 300 ms on a server that sends none), so a captured proof cannot open a session anywhere else. The outbox drain is pipelined: subjects of one ordering tier (agents, then the drive, then children by depth) are drained up to eight at a time with a barrier between tiers, instead of one round trip per subject (`OutboxDrainContext.tierOf`, `DEFAULT_DRAIN_CONCURRENCY`). A `SYNC_DIFF` no longer pushes raw bytes for a subject the outbox still owns, and the RBSR reconcile no longer offers such subjects; the drain delivers them signed. `ErrorCode.INVALID_SIGNATURE (9)` added. New `websockets.test.ts` exercises the client against a fake socket.
- `@tomic/lib` sync protocol: the WebSocket client now detects a silently dead socket. When the server advertises the `keepalive` capability (in its `AUTH_OK` payload), the client sends a `KEEPALIVE` after 20 s without any inbound frame and closes the socket after 45 s of silence so the reconnect loop takes over; before, a dropped connection stayed "connected" until the next write failed and every push in between was lost. The server's advertised capabilities are exposed as `WSClient.serverCapabilities`. New `WSClient.unsubscribeFromDrive` sends the binary `UNSUB`, which the server now honours. Removed the dead `WSClient.subscribeResource` / `unsubscribeResource` (no callers; the browser is drive-`SUB` only, and the text `UNSUBSCRIBE` frame they sent was never handled). `encodeSync` now writes the length-prefixed hex hash the Rust decoder expects. `ErrorCode.AUTH_FAILED (8)` added. A shared golden-vector test (`protocol_vectors.json`, generated by the Rust codec and mirrored into `browser/lib/src/`) pins the TypeScript and Rust codecs byte-for-byte.

## [v0.41.0-beta.4] - 2026-09-03

- Desktop & mobile apps: the Sync page now offers "Sync with AtomicServer.eu" and Cloud Vault, and "Restore account" works from inside the app. The apps embed their own node, which names no provider, so the store builds now bake in the AtomicServer.eu address. A webview cannot hold the portal's session cookie, so instead of being sent to the portal's sign-in page (a dead end: the magic link opened in another browser), the app links to the account by device code — the same flow the Sync page uses — and the restore check re-runs in place once linked. The welcome-screen button is now labelled "Forgot it? Restore from AtomicServer.eu".
- Fix: signing in with a recovery code on the hosted app (an origin without a node) ended on "/" with "Offline: resource not available locally", and the Sync page said there was no backup. The drive defaulted to the origin, which nothing serves there; boot and sign-in now open the account's key-derived personal drive instead (node-backed origins such as atomicdata.dev keep the origin as their main drive). When the vault has nothing for that drive, the connect-device step says why, and offers the account's most recently backed-up drive if it has another one.
- Fix: a returning account on a device whose key was stored before the derived personal-drive subject was recorded beside it failed with "Cannot work out this account's private drive: its key signs non-deterministically…" as soon as it needed its home (sign-in, creating a drive). The non-extractable key cannot recompute the subject, but the Agent resource carries the pointer, so the Store now reads it from there (local copy, then the server) and caches it for the session.
- Fix: a Commit resource could end up in the sync outbox and stay there for good. Commits are immutable, so the server refused every attempt ("Commits cannot be edited."), the Sync page kept showing "Changes pending", and each reload retried. The Loro subscriber already skipped `did:ad:commit:` subjects but not the older `https://host/commits/<sig>` form; `@tomic/lib` now recognises both (`isCommitSubject`), never queues them, drops any that an older build persisted, and treats "Commits cannot be edited" as a terminal error.
- **Cloud Vault is on for everyone.** On a managed origin, every account's personal drive now gets an encrypted backup without asking: signing in (with a secret, a recovery code or a passkey) enrols the drive and backs it up, the app backs it up again a minute after the last edit and when the tab goes to the background, and an account that was already signed in is enrolled at the next load. A second browser that signs in and finds none of the data restores it from the vault before showing "your data is on another device"; the error page for a drive this device never held offers the same restore. Turning backup off on the Sync page is remembered, so the next sign-in does not switch it back on. Self-hosted installs are unaffected (no control-plane session, nothing to enrol). Every pass still seals the whole drive; incremental export is next.
- Fix: the hosted build no longer treats the origin it is served from as its server when that origin runs no atomic-server. The managed deployment serves the app from a shared static origin; someone on the free tier has no node, and the app kept retrying a WebSocket to that origin (with an error toast on the first screen), polled `/server` for a JSON document that came back as `index.html`, parked every commit in the outbox, and the Sync page counted the origin as "1 other device" and called Cloud Server "a migration, not a backup". The hosted build now asks its origin once at boot (`GET /server`); when the answer is not a node, the Store keeps the URL but opens no socket (`StoreOpts.connect: false`, `@tomic/lib`; the choice sticks to that URL, so the drive defaulting to it through `setDrive` does not open one after all), a new identity and its personal drive are registered local-only from their first save (the same routing the demo uses), and switching Cloud Server on promotes both to the assigned node. Source builds and the desktop shell are unaffected: only the hosted distribution probes.

## [v0.41.0-beta.3] - 2026-09-01

- Fix: opening a v1 document no longer shows a read-only page with an "Update Document" button that throws. Writable v1 documents migrate silently to the Loro-backed editor. Leftover Yjs-era V2 bodies still convert, but `yjs` is loaded only when those bytes are present.
- Fix: opening an adopted HTTP drive no longer moves the home server. A bare origin (`https://host`) is still a server switch; an HTTP subject with a path is a workspace and is fetched cross-origin, so a pre-DID drive on `atomicdata.dev` cannot take the session with it (websocket, DID auth, every later fetch).
- Fix: opening a filled table no longer flashes rows (or sidebar children) in the wrong order. Local queries are unsorted; hydrating each member used to optimistic-add them in arrival order before the client-side sort landed. The sidebar also listed every table row until the resource's class arrived. OPFS cold-load could shuffle array properties the same way by merging a JSON-AD-seeded LoroList with the stored snapshot. Reloading a table after a cell edit no longer leaves the page stuck loading: an OPFS snapshot replace was importing the same bytes twice and could drop `isA`. Table totals now re-query after the edit is queued to OPFS, so a sum follows a cell change without a reload.
- Dev: React Compiler now runs through native `oxc-transform-react` instead of `babel-plugin-react-compiler`. JSX/TS and Fast Refresh share that pass. styled-components `displayName` comes from Oxc's built-in plugin on Vite's oxc pass, so Babel is gone (`babel-plugin-react-compiler`, `babel-plugin-styled-components`, `@rolldown/plugin-babel`). Vite dev no longer pays a Babel tax per module (files that used to take ~100ms now land around ~10ms). Oxlint 1.79's compiler-powered Rules of React (`react/immutability`, `react/purity`, `react/error-boundaries`, …) are on; `set-state-in-effect` / `refs` / `static-components` stay warn until those call sites are cleaned up.
- Fix: clicking a button in the navbar no longer draws a blue outline around the whole bar. The bar used `:has(:focus)`, which matched mouse clicks; keyboard focus still shows on the button itself.

## [v0.41.0-beta.2] - 2026-08-01

### Atomic Browser

- Fix: asking the assistant to point a dashboard block at a different table left its view, its measured column and its chart's buckets pointing at the old one — so the block kept filtering and aggregating against a table it no longer showed, quietly answering nothing rather than visibly breaking. Those three are now cleared when the table changes, unless the same request replaces them. The Configure dialog already did this; the tool did not.
- Fix: asking the assistant to change what a block measures without naming a column — "average it instead of summing" — emptied the block instead. It now keeps the column the block already measures and changes only the function, and says so plainly when there is no column to keep. The same gap in the Configure dialog is closed too: Save is disabled while a sum or average has nothing to measure, rather than saving a block that renders as an em-dash.
- Fix: a dashboard's stored layout is now only what the page actually honours. It held `x`/`y` coordinates alongside each block's size, and nothing ever read them — so a layout the assistant computed, or a position implied by the block menu, was silently ignored while the blocks simply flowed in order. Layout is now size plus order, which is what both the menu and the grid can express; coordinates will come back with drag-and-drop, together with a renderer that honours them. Dashboards created before this keep their sizes.
- Fix: creating a dashboard from the New menu dropped you into the generic resource form, which renders its blocks and layout as raw JSON fields — a create screen asking you to hand-write a layout before any blocks exist to lay out. It now asks for a name and takes you to the dashboard, which is where blocks are added.
- **A dashboard can have the button too.** A new **Button** block puts a create button on a dashboard — press it and the numbers beside it move, on the page you are already looking at, which is what makes a dashboard something you use rather than something you read. It stores exactly what a table's own create button does and is configured through the same form, so there is one thing to learn. (A number updates immediately; a table block embedded beside it shows the new row after a reload.) Note that an embedded table block already carries its view's row-action buttons and its quick-add bar, so those needed no block of their own.
- **One-tap create.** A button above the rows that makes one: type "Milk" and press, or press once and the moment is recorded. Configure it from a view's tab menu — a label, optionally a field to type into, and optionally one value the new row starts with, which reuses the same four verbs the row actions use (so "Log set" can stamp today's date and create in a single press). With no field it is the whole interaction; with one it clears after each press, and Enter works, so a shopping list can be filled at speed. Stored on the View as `view-quick-add`, so two views of a table can offer different buttons, and `create_table` / `configure_view` take `quickAdd`. Shipped on the Grocery list ("Add item"), Plant care ("Add plant") and Workout log ("Log set").
- **Row actions: a button on every row, as configuration rather than code.** The verb a mini-app is mostly made of — "Watered", "Mark done", "+1", "Got it". Four kinds, and deliberately only four: stamp the current time into a date column, write one fixed value, flip a checkbox, or add a fixed amount to a number (use −1 for a "one fewer" button). Add one from **Add column → Action**, edit or remove it from its column heading. A button that records state reads as engaged once it has, so it doubles as the readout, and it goes busy then confirms while the commit is in flight. Every press is an ordinary commit on that row: rights-checked, synced, in history, undoable — and no buttons render at all for someone who cannot write, since an action that is going to be rejected is worse than none. Stored on the View as `view-row-actions`, so two views of a table can offer different buttons. The Plant care template now ships **Watered**, Inventory **+1 / −1**, and the Grocery list **Got it**. `create_table` and `configure_view` take `rowActions`, and `describe_table` reads them back.
- Fix: a computed column now updates as soon as the column it derives from changes. It used to show whatever it computed when it was first drawn — edit the quantity and its "Quantity × Unit price" stayed put until you reloaded the page; press a row action that stamps a date and the "days since" beside it did not move. The React Compiler was caching the computation against a resource identity that never changes, because the store mutates resources in place. Computed columns are now functions of the values they read, and each cell subscribes to exactly those. The timer's Start/Stop button had the same latent problem and is fixed with it. (A computed cell is still blank on the trailing row you are typing into, until that row is saved and redrawn.)
- Fix: the Grocery list template could not be created at all. Its "Meat & fish" aisle option became the shortname `meat--fish`, which the slug rule rejects — `stringToSlug` stripped the `&` only *after* collapsing repeated dashes, leaving the two dashes it had been sitting between. Any name with punctuation between words hit this.
- Fix: a dash could not be typed into a shortname field. The slug rule above is a *final* form — it drops leading and trailing dashes — and the input applied it to every keystroke, so the `-` you were typing was trailing for exactly as long as it took to press the next key: "is-valid" came out as "isvalid". Hyphenated shortnames were untypeable, in the ontology editor and every New Resource form. The field now keeps a single trailing dash while you type and settles it on blur, validating the settled value so no "Invalid Slug" flashes between the words of a name.

- **Dashboards.** A new kind of page that composes blocks over your data: a number, a chart, an embedded table, a note — arranged on a grid. Four block kinds in v1. A **number** is a sum, count, average, min or max computed by the store over *every* row a view matches, so it is exact regardless of paging, and it can measure a computed column (a total duration, quantity × price) as well as a stored one. A **chart** is the same number per bucket, drawn as horizontal bars, bucketed exactly or per day or month. A **table** block embeds the real table — cells stay editable, columns sortable — rather than a snapshot. A **note** is markdown. Blocks are resources of their own, so the same dashboard can be built by hand and by the assistant: `create_dashboard` builds one in a call (resolving column and view names, laying blocks out automatically), `describe_dashboard` reads it back, and `configure_block` changes one field without disturbing the rest — everything the tools can write, the per-block Configure dialog can change. A stat or chart block points at one of the table's *views* and borrows its filters, so "open issues" is the open-issues view plus a count instead of a filter restated in two places. Create one from the New menu.

- Fix: a filtered view kept a row whose value had stopped matching it. Raise a "Quantity at most 3" row to 40 and it stayed in the Low stock view — across a reload, because the local database's index still listed it as a member. Editing a row out of a filtered view now removes it, editing one into a filter still adds it in the right sorted position, and an edit that keeps a row in the view but changes what it sorts by no longer lists it twice.

- [#1236](https://github.com/ontola/atomic-server/issues/1236) [#1238](https://github.com/ontola/atomic-server/issues/1238) **A computed column can be totalled.** Sum a table's Durations, average a days-since, add up quantity × price — and break any of it down per day, month or category. The store evaluates the column as it aggregates, so the number covers every row the view matches rather than the page on screen, and a running timer entry counts its time so far. Totals of a computed column read the way the column does: a sum of durations is `5:30:00`, not `19800000`. This closes the gap that made the Time tracker's day totals impossible, and that template now ships them. `create_table` and `configure_view` take `computedColumn` next to `column`, so the assistant can total one too.
- Fix: when an AI request failed, the chat did nothing at all — no message, no error, just silence, with the only evidence a line in the browser console. An unreachable Ollama, a rejected API key or a model that doesn't exist now says so under the input, naming the provider and quoting its reason, with a Try again button. A turn that dies mid-answer shows its error too: the failure was already recorded on the message, but nothing ever rendered it.
- [#1238](https://github.com/ontola/atomic-server/issues/1238) **Eleven new table templates**, and not one of them ships a renderer: Expenses, Deals (CRM), Job applications, Project tasks, Reading list, Grocery list, Workout log, Plant care, Inventory, Guest list and Bookmarks, next to Issue Tracker and Time tracker. Each arrives configured — kanban and calendar layouts, computed columns (days since you last contacted a deal, when a plant is next due, quantity × price), totals broken down per month or category, its own column order, and a filtered view like Inventory's "Low stock". They are available to the assistant through `list_table_templates` / `create_table_from_template`, which now also reports what each view already computes, so it can start from the closest one and adapt it rather than deriving a schema from scratch. The New Table dialog gives each an icon and scrolls, instead of pushing the name field off the dialog.
- Columns can be `decimal`, not just whole `number`: money, prices, hours and measurements keep their cents. It's a float carrying the FormattedNumber shape the property form writes, so switching one to a currency or a different precision afterwards works as usual. `create_table` takes it too — an amount asked for as `number` would have silently rounded.
- [#1236](https://github.com/ontola/atomic-server/issues/1236) Timer view for tables, alongside table / kanban / calendar. It **is** the table: the same grid, so cells stay editable, columns sortable, resizable and reorderable, keyboard navigation works and long histories stay virtualised. On top of it the timer adds a toolbar — name a thing and hit Start — and two columns: a live-ticking Duration and a Start/Stop button. "One at a time" (on by default) stops the running entry when another starts; turn it off to track several things at once. Its start property lives in the View's `view-group-by` slot, its end in the new `view-end-prop`, and the toggle in `view-timer-exclusive`; a class without timestamp properties gets "Start" and "End" created for it.
- [#1238](https://github.com/ontola/atomic-server/issues/1238) **The assistant can now change a table, not just create one.** Five tools: `describe_table` reads back the row class, every column and every view's settings (sort, filters, visible columns, computed columns, totals); `configure_view` changes a view in place and touches only the fields it's given, so setting a sort can't drop the filters; `add_table_columns` adds columns to an existing class *and* appends them to the views that keep an explicit column list (a column missing from that list is hidden, which is why adding a property alone wasn't enough); and `list_table_templates` / `create_table_from_template` start from the catalogue instead of re-deriving a schema. `create_table` grew to match: per-view `sortByColumn` / `sortDesc` / `filters` / `columns` / `columnOrder`, and `relation` columns can name their target class so the cell picks from that class instead of searching everything. Column names are resolved case-insensitively by name, shortname or subject throughout, and a select filter accepts an option's name. The whole chain is covered end-to-end by an e2e test that scripts the model and lets the tools run for real.
- **Column order is per-view configuration now**, and covers every kind of column. Drag any heading — including a computed column or the timer's Start/Stop — and the order is saved on the View (`view-column-order`, a list of column keys), so two views of the same table can arrange the same columns differently. A column added after the order was saved appears at the end rather than disappearing, and a LocalizedText property split per language still moves as one column. The timer view now leads with its Duration and Start/Stop: timing something is the point of that view, so its controls sit where the eye starts instead of past four columns of data.
- Fix: columns a view adds (a computed column, the timer's Start/Stop) could not be resized, and rendered at the 300px default rather than the width they asked for. Two separate bugs: the table re-imposed their default width on every render, throwing away the resize it had just stored; and the grid's size list, when the column count and the stored widths changed in the same commit, appended defaults over the widths using a stale copy. Their heading also matched the header cell's bold instead of a property heading's regular weight, and the grid's 100px minimum column width made dragging a 70px button column snap wider instead of resizing it — the floor is now 40px. Default widths themselves are unchanged: narrow is right for a duration or a button.
- Fix: switching between views whose column counts differ painted the previous view's column widths for a frame, which churned the grid while it settled. The width list is now ignored when it doesn't match the columns on screen, rather than rendered.
- Fix: a totals cell's menu could stop opening after it had been used once. Its trigger button was built fresh on every render, so React remounted it constantly — and the totals re-render on every store event, so a click landing in that window hit a button that no longer existed. The trigger is now one stable component that reads its contents from context. A computed column's totals cell, which genuinely has nothing to offer (the store aggregates stored values), now says so on hover instead of ignoring the click.
- Totals rows read as a summary rather than more data: their own raised background, a firm line above, and each extra row separated from the one before. The value is bold in the regular text colour with a small grey label — in dark mode the label used the near-black `textLight2`, which made "AVERAGE 14,50" almost invisible.
- **More than one totals row.** Add rows from the totals menu and give a column a different statistic in each, so Amount can show a sum on one line and an average on the next. Stored per aggregate as a `row` index; `configure_view` takes it too. A row you add holds nothing until you fill a cell in it, so an empty one is never persisted.
- **Totals now live in a footer row under the grid**, each under the column it describes — click a column's footer cell and pick Sum / Average / Min / Max / Count, the way a spreadsheet does. The row is always in view (the rows scroll inside their own box) and scrolls sideways with the columns, so a total stays under its column. Its left cell shows how many rows the view matches and carries the "break down by…" menu. This replaces the Σ button in the top-right corner and the free-floating totals strip: a number is much easier to read directly beneath its column than in a labelled list somewhere else.
- Fix: totals didn't update when the data changed — they came from the row collection, which patches its pages surgically on an edit rather than re-querying. They now ride a small query of their own (one row plus the numbers), re-read on save/delete with a short debounce. That also means refreshing them no longer clears the grid's pages under the cursor.
- [#1238](https://github.com/ontola/atomic-server/issues/1238) **Totals under the table**, computed by the server: a sum, count, average, min or max over **every** row a view matches — filters included, paging excluded — plus an optional breakdown giving one subtotal per distinct value of a column (per project, per status, per day, per month). This is a new query capability rather than a client-side add-up: `Query` carries an `aggregation`, the store walks its own index and returns a handful of numbers on the Collection's new `collection/aggregates` property, and because the browser's local database runs the same Rust code, an offline table shows the same totals. Configure it from the Σ button next to the table's filters, or ask `create_table` for `aggregates` / `breakdownColumn`. Day and month buckets use your timezone, not UTC. Stored on the View as `view-aggregates` / `view-group-by-column` / `view-group-granularity`. Note that a `count` counts the rows you can actually read, which can be lower than `totalMembers` (that one counts raw index hits). Aggregating a *derived* column isn't possible yet — those aren't stored.
- [#1238](https://github.com/ontola/atomic-server/issues/1238) **Derived columns**: a table view can show columns computed from each row rather than stored on it — a live duration, a days-since, an amount, a next-due date. They are configuration, not code: the View lists them in the new `view-derived-columns` (JSON), any view kind renders them, and `create_table` can build them, so a mini-app that needs one is a template rather than a renderer. Five fixed generators, deliberately not a formula language: `difference` (to − from), `elapsed` (the ticking variant, stopping once its end is stamped), `daysSince`, `product` (either factor may be a literal, e.g. a rate) and `offset` (a date plus a number of days). The timer's Duration is now one of them — an `elapsed` over the two timestamps the view already knew about, seeded by the Time tracker template — so it renders in a plain table view too, and the timer keeps only its Start/Stop column. Add one from **Add column → Computed**: the dialog is generated from the generator itself, so it only offers columns that fit each argument (date columns for a duration, number columns for a multiplication) and lets you type a fixed number where one makes sense. Its heading carries the menu that edits or removes it again. See `planning/table-templates-and-mini-apps.md`.
- Table columns may now be **virtual** — rendered by the view rather than read off a Property (`TableColumn.virtual`). The grid stack was already generic over its column type, so this cost the editor nothing, and it's the seam that future derived columns and row actions plug into. See `planning/table-templates-and-mini-apps.md`.
- The table's filter and property menus are both plain dropdowns now, instead of one dropdown and one popover full of checkboxes. Each has a header saying what it does, whole rows are the click target rather than a small checkbox, shown properties are marked with a check, and both label properties by their human title. Toggling a property leaves the menu open — `DropdownMenu` items take a new `keepOpen` for menus that toggle state rather than navigate away. Properties a view is structurally built on (a timer's name/start/end, a kanban's or calendar's group-by) are shown locked with a reason instead of offering a toggle that the view would ignore.
- A table's active view is now in the address bar (`?view=`), so a view is linkable, survives a reload, and Back/Forward moves between views instead of leaving the page. It used to be session-only React state.
- Fix: creating a column did nothing in a view that had ever had its columns reordered or toggled. `view-columns` treats any property it doesn't list as hidden, so a newly created one landed on the class and was immediately invisible. New properties are now added to the active view's columns as they're created — same for adding an external property.
- Fix: adding the first filter (or sort) to a table sometimes silently discarded it. Doing so lazily creates the View that stores it, which flips the active view and re-reads its config — racing the write that prompted the creation, and hydrating local state back to empty when it won. The freshly created View is now excluded from that re-read: it exists to hold what's already in local state.
- Fix: typing into a table cell could eat the first character. That keystroke both opens the editor and is written to the resource, but the write is async, so the editor mounted with the pre-keystroke value and the rest of the typing replaced it. The editor is now seeded with the character synchronously, and hands control back to the resource on its next edit.
- [#1236](https://github.com/ontola/atomic-server/issues/1236) A **Time tracker** table template, next to Issue Tracker: Start / End / Project columns with a timer view ready to go. `create_table` can now also build `calendar` and `timer` views (it was limited to table and kanban, so the assistant could never make a calendar), with a new `endColumn` for the timer's end property.
- Fix: an entry started from the timer toolbar was saved but not shown until a reload. The grid holds its member count in a ref, so bumping it renders nothing on its own; the collection is refreshed too now. The failure path also no longer swallows errors silently — it logs and shows a toast.
- Fix: filters did nothing in the kanban and calendar views. The filter dropdown is offered for every view kind, but the row of filter chips was rendered only inside the table branch, so a filter added anywhere else had nowhere to appear and silently never applied.

- Passkey-first account backup. Managed onboarding no longer hands you a second secret to write down: a passkey (WebAuthn PRF) wraps the backup by default, so the common path is a single prompt. The agent secret isn't shown at all when a backup exists, since it stays recoverable from Settings. Only a device-bound passkey (BE flag clear) interrupts to offer a recovery code — the one case where losing the device really does lose the account. PRF is evaluated during credential creation, so enrolling costs one prompt on browsers that support it, falling back to a second assertion where they don't.
- Device lock (Settings → This device): never, on browser close, or after 15 minutes or 1 hour of inactivity. Enforced by withholding the stored keypair at boot rather than via `sessionStorage`, which browsers restore along with tabs — a restart used to come back unlocked.
- Per-agent encrypted local databases. The single per-origin `atomic_data.redb` is split into one OPFS database per agent (a shared plaintext anonymous DB when signed out), each encrypted at rest with XChaCha20-Poly1305. A random 256-bit key per agent is wrapped by HKDF of the agent's private key — the agent key wraps, it never encrypts bulk data. After sign-out or an agent switch a session can no longer read the previous agent's cached private data, without wiping the cache.
- Peer-to-peer video and audio calls in the meeting panel, via Trystero (WebRTC with Nostr signaling). The meeting subject is hashed into the room id and doubles as the signaling password, so only participants can join or read the handshake, and media never touches a server. The call UI ships in a lazy chunk, so the ~24 kB gzipped library is only fetched when someone starts a call. Mentioned in [#1127](https://github.com/atomicdata-dev/atomic-server/issues/1127).
- [#1235](https://github.com/atomicdata-dev/atomic-server/issues/1235) Emoji v1: give any resource an emoji glyph from its context menu or title, shown in the sidebar, search results, cards and inline references.
- Cover images: set an image File as a decorative banner at the top of a resource's page, with an avatar cropper and client-side image resizing. Drag the banner to reposition it and release to save — a wide crop rarely has its subject in the middle — and pick an image you've already uploaded instead of adding a new one.
- The search overlay's "Start AI Chat with ..." now sends your query as the chat's first message. It previously used the query as the chat's title and opened an empty chat, so the thing you asked for was never actually asked.
- Fix: the table grid is sized to the space actually below it rather than a flat `80vh`, which overflowed the viewport and pushed the last rows out of reach once a cover image sat above the table.
- Colorful mode — a new appearance setting that tints the sidebar and navbar with tones of the main color instead of the neutral grey ramp, so no grey sits on a colored surface. Content and text stay neutral for readability. Off, the theme is byte-identical to before. The main-color presets are now also the default tag palette, replacing the neon tag colours.
- Dark mode for the static loading screen, and dark-aware `theme-color` metas so OS and browser chrome match the app.
- The sidebar drive header is unified into a single component.
- Meetings now start from their own page rather than the top bar or the More menu.
- Added an `/app/new-drive` route, for the managed portal's "+ New drive".
- Copy / duplicate a resource. New `copyResource` in `@tomic/lib` carries a resource's content (propvals and classes) into an independent new resource under a chosen parent, without its identity, ACL or history. Unlike `forkResource` the copy has no link back to the source and can't be merged into it; copying a fork yields a plain resource. The name gets a " (copy)" suffix so a duplicate sitting next to its source is tellable apart.
- Fix: only origins that answer `/server` are registered as known servers. The managed deployment serves the SPA from a shared app origin that isn't a node, and listing it offered a "Switch" pointing the store at something that couldn't answer. A non-answer also removes entries that older builds added blindly.
- Fix: Kanban view polish — the column header is merged into one rounded card, plus icons, a header pill, a clearer add-card affordance and an empty-column state.
- Fix: restored the New Meeting quick-create button.
- Fix: genesis and other internal properties are hidden from the resource form and property lists.
- Fix: the slash-menu suggestion handlers are guarded against an unset component.
- Fix: DOM prop leaks, missing list keys, and Enter-to-submit in New Table.
- Fix: editor state updates that ran during the render phase moved into effects.
- Fix: the ClientDb's lock-steal recovery got a realistic settle budget.
- Patched 45 real npm vulnerabilities via scoped pnpm overrides.

## [v0.41.0-beta.1] - 2026-07-22

### Atomic Browser

- [#1069](https://github.com/atomicdata-dev/atomic-server/issues/1069) Content localization / i18n: a new `LocalizedText` property type with a per-language input (`InputLocalizedText`), a table-editor cell with a language switcher and column-language chip, a New Column category + datatype picker, and a read-only view that resolves the visitor's preferred language. `@tomic/cli` codegen maps the datatype to the `LocalizedText` TS type.
- [#1069](https://github.com/atomicdata-dev/atomic-server/issues/1069) The Next.js and SvelteKit site templates (`create-template`) now scaffold two-locale sites out of the box: locale-prefixed routing, a translation-sibling switcher, hreflang tags, group-fallback listings, and a footer language switcher.
- Add `@tomic/edit-mode`: turn any page rendered from Atomic Data into a guest-editable, local-first clone — an "Edit this page" affordance backed by a guest agent and a local-only drive in the visitor's browser. Every edit is a signed CRDT commit; nothing reaches a server.
- Renamed the hosted product from AtomicCloud to AtomicServer.eu.
- Fix: the meeting side panel's title no longer collides with the main page title's view-transition (which silently skipped the transition when both were on screen).
- Fix: the demo's guest identity no longer flashes "Error loading resource" across the UI.
- Fix: the "Sign in to your account" onboarding button no longer sends self-hosted users to a hardcoded dev portal URL.
- Cloud Sync: the Sync page now shows the connected node's per-drive usage (resources + bytes, from the generic `/drive-usage` endpoint), with plan quota for managed nodes, plus a "Manage account & plan" link for managed nodes. The redundant Drive row was removed.
- Cloud Sync identity: when signed in to Cloud Sync with a device agent that differs from the account, the app now converges **silently** — it adopts the device agent (when the account has none) or restores the account's agent — instead of blocking on a "resolve identity mismatch" screen that surfaced agent DIDs.
- Favorites: favorite any resource from its context menu and find it back in a new sidebar **Favorites** panel.
- The per-user index lists — `favorites`, `sharedWithMe` and saved `drives` — are now stored on the user's **private drive** (the per-user home index) instead of on the Agent identity resource. They hold pointers to resources that may live on any drive, resolved per-pointer.
- The **Favorites** and **Shared with me** panels now sit at the bottom of the sidebar (above App settings) rather than scrolling with the active drive's tree.
- Updating any of these lists now surfaces an error toast on failure instead of failing silently.

## [v0.41.0-beta.0] - 2026-06-22

### Atomic Browser

- Search UI is redesigned, now as an overlay, feels like a command bar, shows preview of selected item.
- New navbar design. Always access to important features & hierarchy.
- New onboarding UX for new users & drives.
- Switch to OxLint
- #1178 Sync protocol
- Client persistence & indexing with wasm #1175
- Simplify agent & drive creation in client APIs #1177
- Add `drive` to Store. This used to be a React API, but it's useful in far more contexts.
- #1163 New settings page design with search
- #1160 Switch to Oxlint + Oxfmt
- Comment all the things - chatrooms for every resource #898
- #1198 Kanban view, issue template and Calendar view
- #1229 Presence, see what users are looking at and follow their activity
- [#741](https://github.com/atomicdata-dev/atomic-server/issues/741) New feature: A brand new document editor with realtime collaboration and a fast and efficient editing experience.
- [#741](https://github.com/atomicdata-dev/atomic-server/issues/741) New feature: A brand new document editor with realtime collaboration and a fast and efficient editing experience.
- [#951](https://github.com/atomicdata-dev/atomic-server/issues/951) New feature: Atomic Assistant, AI chat interface with support for custom agents, MCP servers and more. Bring your own OpenRouter key or use Ollama to host your own models.
- [#459](https://github.com/atomicdata-dev/atomic-server/issues/459) New feature: Add tags to your resources to better organize your data. Search for resources with specific tags in the search bar with `tag:[name]`.
- [#1118](https://github.com/atomicdata-dev/atomic-server/issues/1118) New feature: AtomicServer is now also available in German, Spanish and French. Change your language on the settings page.
- [#981](https://github.com/atomicdata-dev/atomic-server/issues/981) Fix bug where the service worker would not update cache with updated code.
- [#989](https://github.com/atomicdata-dev/atomic-server/issues/989) Added an edit button to the resource selector inputs.
- [#992](https://github.com/atomicdata-dev/atomic-server/issues/992) Fix Searchbox overflowing when displaying long names.
- [#999](https://github.com/atomicdata-dev/atomic-server/issues/999) Fix parseMetaTags character escape issue.
- [#1014](https://github.com/atomicdata-dev/atomic-server/issues/1014) Fix date input always showing required error even when filled in.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1005) Showcase standard properties in the resource selector
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Add 'New Property' button to the property list in the ontology editor.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Fix disabled resource selectors still get highlighted on hover.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Add 'open' option to classes and properties in the ontology edit view.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Updated the look of the resource selector and made it more responsive.
- [#1008](https://github.com/atomicdata-dev/atomic-server/issues/1008) Add info dropdowns to different sections of the ontology editor for more information about the section.
- [#1219](https://github.com/atomicdata-dev/atomic-server/issues/1219) Add filters to tables
- [#1219](https://github.com/atomicdata-dev/atomic-server/issues/1219) Persist table views
- Persist table views across sessions and fix table sorting, drag-and-drop, and column-width resizing.
- Add inline AI model selection with optional models, slash commands, latest-used models, improved keyboard input, and clearer checking/blocking states.
- Save AI chats in the user's personal drive and fix chat title generation, sticky scrolling, creator/date refresh, and indexing submission.
- Add a clipboard fallback for insecure local origins so onboarding secrets can still be selected/copied when `navigator.clipboard` is unavailable.
- Improve insecure-context behavior by falling back visibly when Web Locks or OPFS are unavailable.
- Improve offline and local-first UX, including spinner behavior in offline mode and server-only fallback paths.
- Fix resources and collections rendering blank when a snapshot arrives before Loro WASM is ready.
- Fix theme setting persistence, tag queries in the navbar, and long-name search overflow.

### @tomic/lib

- `resource.props` is now writeable: `resource.props.name = 'New Name'`.
- Added `store.preloadResourceTree()` method, see docs for more info.
- Fix generated ontologies not working in a Next.js server context.
- Fix types masquerading as esm module in cjs build.
- `store.search()` now handles multiple values for the same property correctly.
- [#1077](https://github.com/atomicdata-dev/atomic-server/issues/1077) Fix bug where resource.new would not be set back to true when saving fails.
- Added `ResourceEvents.LoadingChange` event on `Resource` to listen for changes to the loading state of the resource.
- Added `resource.stable` property to `Resource` to get a stable reference to the resource, even when it is proxied.
- Added `resource.merge()` method to merge a resource into another resource while preserving local changes on the current resource.
- `store.addResources()` now merges incoming resources with resources already present in the store instead of replacing them.
- SEMI BREAKING CHANGE: When using generated types by cli, @tomic/lib now requires them to be generated by @tomic/cli v0.41.0 or above.
- BREAKING CHANGE: The `StoreEvents.ResourceRemoved` event callback now only receives the subject of the resource instead of the resource itself.
- Add a WASM-backed ClientDb with OPFS persistence and indexing.
- Fix ClientDb offline durability by flushing OPFS writes in the browser worker.
- Release the ClientDb leader lock on destroy, fixing stale Firefox leaders.
- Degrade gracefully when browser persistence APIs are unavailable, including no-OPFS/no-Web-Locks server-only mode.
- Fix local edits persisting across the ClientDb drain.
- Fix `lastCommit` preservation during `Resource.merge()` to avoid accidental genesis saves.
- Preserve cosmetic datatypes and migrate JSON/resource datatype tags through Loro serialization.
- Migrate to URL-safe Base44 for generated identifiers and auth compatibility.

### @tomic/react

- BREAKING CHANGE: `useCanWrite` now only returns a boolean. There is no longer a message returned.
- BREAKING CHANGE: `useCanWrite` does not take an agent as argument any more and only checks the agent set in the store. If you need to explicitly check a different agent, use `await resource.canWrite(agent)`.
- BREAKING CHANGE: `useDebounce` and `useDebouncedCallback` are no longer exported.
- BREAKING CHANGE: @tomic/react now requires React 19.2.0 or above.
- Added `useDebouncedSave` hook.
- Added `VirtualizedCollectionList` component.
- Add a cjs build.

### @tomic/cli

- [#983](https://github.com/atomicdata-dev/atomic-server/issues/983) Give clear error when name collisions are found in an ontology.
- Generates class definitions that enables doing: `resource.props.name = 'New Name'`;
- [#1071](https://github.com/atomicdata-dev/atomic-server/issues/1071) Fix bug where classes and properties with 'name' props would lead to invalid generated typescript code.
- Generated ontologies now base import extensions on the tsconfig.json file. (moduleResolution: bundler will remove the .js extensions in imports)
- Fix generated ontology output for Next.js server contexts.

### @tomic/svelte

- [#700](https://github.com/atomicdata-dev/atomic-server/issues/700) Update to Svelte 5. There are significant changes to the API.
- BREAKING CHANGE: Dropped support for Svelte 4 and below.
- BREAKING CHANGE: `getResource()` now returns a reactive proxy instead of a readable store.
- BREAKING CHANGE: `getResource()` now takes a function returning a subject instead of the subject directly. e.g. `getResource(() => 'https://my-atomicserver.com/my-resource');`.
- BREAKING CHANGE: Removed `getValue()`. It is no longer needed. Instead use `resource.props.name` directly or do `const name = $derived(resource.get(core.properties.name));`.
- BREAKING CHANGE: Removed `initStore()`. You now need to set your store on a context using `createAtomicStoreContext()`.
- BREAKING CHANGE: Removed `loadResourceTree()`. It is now a method on `store`: `store.preloadResourceTree()`.
- Added `createAtomicStoreContext()` and `getStoreFromContext()`.

### @tomic/create-template

- [#700](https://github.com/atomicdata-dev/atomic-server/issues/700) Update SvelteKit-site template to Svelte 5 and the new @tomic/svelte.
- [#966](https://github.com/atomicdata-dev/atomic-server/issues/966) Add NextJS template.
- [#1036](https://github.com/atomicdata-dev/atomic-server/issues/1036) Provide clearer errors when resources couldn't be fetched.
- [#993](https://github.com/atomicdata-dev/atomic-server/issues/993) Fix template not working when the drive subject has a path after the origin.

## [v0.40.0] - 2024-10-07

### Atomic Browser

- [#952](https://github.com/atomicdata-dev/atomic-server/issues/952) Add templates containing pre made ontologies and resources.
- [#970](https://github.com/atomicdata-dev/atomic-server/issues/970) Add "show commit" button in History
- [#968](https://github.com/atomicdata-dev/atomic-server/issues/968) Allow users to pick files by entering a subject into the file picker search bar.
- [#969](https://github.com/atomicdata-dev/atomic-server/issues/969) Fix markdown editor sometimes doesn't update the value after saving.
- [#975](https://github.com/atomicdata-dev/atomic-server/issues/975) Add create button to resource selector without classtype.
- Fix markdown editor closing the edit page when a button is clicked.
- Add an edit button to the default resource view.

### @tomic/lib

- BREAKING CHANGE: removed the `importJsonAdString` function.
- Added `store.importJsonAD()` method.
- Added support for commonJS modules.

### @tomic/cli

- Fix shortnames in externals.ts are not converted to camelCase.
- Filter out duplicate classes and properties in generated types.

### @tomic/create-template

- Added `@tomic/create-template` package to create new templates.

## v0.39.0

### Atomic Browser

- [#855](https://github.com/atomicdata-dev/atomic-server/issues/855) Add a dialog that shows how to fetch and use the current resource in your code.
- [#896](https://github.com/atomicdata-dev/atomic-server/issues/896) Fix an issue where sidebar items require a double tap on iOS.
- Updated look of the default resource form.
- [#896](https://github.com/atomicdata-dev/atomic-server/issues/896) Fix an issue where sidebar items require a double tap on iOS.
- Updated the look & feel of the sidebar a bit.
- [#893](https://github.com/atomicdata-dev/atomic-server/issues/893) Fix tables not showing any rows when viewing from a different server.
- Fix an issue where the resource-array properties would be set to an empty array instead of removing the property when removing all items in the input.
- Fix an issue where dropdown menus sometimes jump from the upper left corner of the screen.
- Added a full page view for tags.
- Redesigned the ontology page.
- Moved the resource context menu to the top of the page.
- [#861](https://github.com/atomicdata-dev/atomic-server/issues/861) Fix long usernames overflowing on the share page.
- [#906](https://github.com/atomicdata-dev/atomic-server/issues/906) Reset changes after clicking the cancel button in a form or navigating away.
- [#914](https://github.com/atomicdata-dev/atomic-server/issues/914) Fix an issue where changing the subject in a new resource form could update the parent of existing resources if their subject matched the new subject.
- [#925](https://github.com/atomicdata-dev/atomic-server/issues/925) Added export to CSV option to tables.
- [#919](https://github.com/atomicdata-dev/atomic-server/issues/919) Automatically sort classes and properties in the ontology editor.
- [#936](https://github.com/atomicdata-dev/atomic-server/issues/936) Updated the address bar to make it clearer it's also search bar.

### @tomic/lib

- Added `LocalChange` event to `Resource`.
- Added `resource.refresh()` method.
- Removed `cross-fetch`, if your environment does not support fetch make sure to add a polyfill or inject one using `store.injectFetch()`.

### @tomic/react

- BREAKING CHANGE: Removed the `useLocalStorage` hook.
- When using any `useValue` type hook, values will now update when local changes are made to the resource from elsewhere in the app.
- [#257](https://github.com/atomicdata-dev/atomic-server/issues/257) Added `<Image />` component that automatically optimizes images for the web.

### @tomic/svelte

- [#257](https://github.com/atomicdata-dev/atomic-server/issues/257) Added `<Image />` component that automatically optimizes images for the web.

## v0.38.0

### Atomic Browser

- [#845](https://github.com/atomicdata-dev/atomic-server/issues/845) Add option to create instances and tables from the ontology view.
- [#845](https://github.com/atomicdata-dev/atomic-server/issues/845) Add default Ontology option to drives.
- [#841](https://github.com/atomicdata-dev/atomic-server/issues/841) Add better inputs for `Timestamp` and `Date` datatypes.
- [#842](https://github.com/atomicdata-dev/atomic-server/issues/842) Add media picker for properties with classtype file.
- [#850](https://github.com/atomicdata-dev/atomic-server/issues/850) Add drag & drop sorting to ResourceArray inputs.
- [#757](https://github.com/atomicdata-dev/atomic-server/issues/757) Add drag & drop sorting to sidebar.
- [#873](https://github.com/atomicdata-dev/atomic-server/issues/873) Add option to allow multiple resources in relation columns (Tables).
- [#825](https://github.com/atomicdata-dev/atomic-server/issues/825) Folder display styles are now saved locally instead of on the resource. The display style property will now act as the default view style.
- [#884](https://github.com/atomicdata-dev/atomic-server/issues/884) Add new markdown editor.

### @tomic/lib

- [#840](https://github.com/atomicdata-dev/atomic-server/issues/840) Added `store.search()`.
- Deprecated `resource.getSubject()` in favor of `resource.subject`.
- Deprecated `store.getResouceAsync()` in favor of `store.getResource()`.
- Deprecated `resource.pushPropval()` in favor of `resource.push()`.
- Deprecated `resource.removePropval()` in favor of `resource.remove()`.
- Added `resource.matchClass()` method.
- Added `resource.setVersion()` method.
- Added `collection.getMembersOnPage()` method.
- Added `collection.totalPages`.
- Fix lib not working in non-secure browser contexts.
- BREAKING CHANGE: Renamed `resource.getCommitsCollection` to `resource.getCommitsCollectionSubject`.
- BREAKING CHANGE: `resource.getChildrenCollection()` now returns a `Promise<Collection>` instead of a subject.
- BREAKING CHANGE: `resource.createSubject()` no longer accepts a class name as an argument and defaults to a fully random subject.
- BREAKING CHANGE: Resource now keeps a reference to store internally, therefore all methods that required you to pass a store have been changed to not require a store.
  These methods are:
  - `resource.canWrite()`
  - `resource.getHistory()`
  - `resource.getRights()`
  - `resource.destroy()`
  - `resource.save()`
  - `resource.set()`
  - `resource.removeClasses()`
  - `resource.addClasses()`

# @tomic/react

- Added `useCollectionPage` hook.
- Fix bug where `useCollection` would fetch the collection twice on mount.
- `useServerURL` no longer stores the server url in localstorage.

### @tomic/cli

- [#837](https://github.com/atomicdata-dev/atomic-server/issues/837) Fix timestamp is mapped to string instead of number.
- [#831](https://github.com/atomicdata-dev/atomic-server/issues/831) Give clear error when trying to generate types from a non ontology resource
- [#830](https://github.com/atomicdata-dev/atomic-server/issues/830) Create output folder if it doesn't exist
- Use type import in generated files.

## v0.37.0

### Atomic Browser

- [#747](https://github.com/atomicdata-dev/atomic-server/issues/747) Show ontology classes on the new resource page.
- [#770](https://github.com/atomicdata-dev/atomic-server/issues/770) Display more info on the search result page.
- [#771](https://github.com/atomicdata-dev/atomic-server/issues/771) Tables: Don't paste in multiple rows when focused on an input
- [#758](https://github.com/atomicdata-dev/atomic-server/issues/758) Fix Relation column forms to close when clicking on the searchbox
- [#780](https://github.com/atomicdata-dev/atomic-server/issues/780) Use tags in ontology editor to create enum properties.
- [#810](https://github.com/atomicdata-dev/atomic-server/issues/810) Add button to resource selectors to navigate to the selected resource.
- [#764](https://github.com/atomicdata-dev/atomic-server/issues/764) Add option to format numbers as currency in tables.
- [#819](https://github.com/atomicdata-dev/atomic-server/issues/819) Fix number input always shows 'required' even when it's optional.
- [#816](https://github.com/atomicdata-dev/atomic-server/issues/816) Fix bug where editing a column in a table would not submit when pressing enter.
- Fix server not rebuilding client when files changed.
- Added persistent scrollbar to table
- Improved table header UX
- Numbers in tables now respect user locale

### @tomic/lib

- [#798](https://github.com/atomicdata-dev/atomic-server/issues/798) Add `store.newResource()` to make creating new resources more easy.
- Always fetch all resources after setting + authenticating new agent with websockets #686
- Add progress callback to `resource.getHistory()` And increased its performance for resources with a large number of commits [#745](https://github.com/atomicdata-dev/atomic-server/issues/745)
- Fix websocket bug on port localhost with port 80

## v0.36.1

### @tomic/svelte

- Add support for types generated by @tomic/cli

### @tomic/react

- Proxy resource objects instead of cloning them for reactivity.

### @tomic/cli

- Fix bug where an externals.ts file was generated for properties that are already available through @tomic/lib.

### @tomic/lib

- `Collection` is now an async iterator
- Added `getAllMembers` method to `Collection`
- Fix `set` call with equal arrays #715
- Fix ontologies export bug #728

## v0.36.0

### Atomic Browser

- Add table editor #639. Add resource instances using table columns, add properties as rows, paste and copy CSV, keyboard support, sorting.
- Add ontology editor #648. Easily create classes, properties and visualize their relationships.
- Show resource usage (incoming links) in data view.
- New resource selector that uses searchbox #677
- Sidebar redesign
- Switch to current drive button #681

### @tomic/lib

- Add support for typed resources through `resource.props`, powered by `@tomic/cli` (see below)
- When saving a resource whose parent has not yet been saved we now add them to a batch that gets saved later when the parent is saved.
- The `scope` option in `SearchOpts` has changed to `parents` and now accepts an array of subjects instead of a single subject.
- BREAKING: Removed `getCommitBuilder()` method from `Resource`
- Added `hasUnsavedChanges()` method to `Resource`
- Fix bugs in state management: proxy resources instead of clone (for react) #682 #675 #657

### @tomic/cli

- **NEW**
- Generate typescript files from ontologies #665

## 0.35.1

### Atomic Browser

- Improve performance collapsed sidebar items.
- Add article view #319
- Add resource history view
- New subjects have nested paths by default

### @tomic/lib

- BREAKING: `buildSearchSubject` now takes a serverURL instead of the store.
- Fix bug where @tomic/lib would not work in a non-browser context.
- Add `resource.getHistory` method that returns a list of previous versions of the resource.
- Add `store.getResourceAncestry` method, which returns the ancestry of a resource, including the resource itself.
- Add `resource.title` property, which returns the name of a resource, or the first property that is can be used to name the resource.
- `store.createSubject` now accepts a `parent` argument, which allows creating nested subjects.

## v0.35.0

### @tomic/browser

- Move static assets around, align build with server and fix PWA #292
- Add `useChildren` hook and `Store.getChildren` method
- Add new file preview UI for images, audio, text and PDF files.
- Add new file preview types to the folder grid view.
- Fix Dialogue form #308
- Refactor search, escape query strings for Tantivy
- Add `import` context menu, allows importing anywhere

### @tomic/react

- Add more options to `useSearch`

### @tomic/lib

- Add `Store.parseMetaTags` to load JSON-AD objects stored in the DOM. Speeds up initial page load by allowing server to set JSON-AD objects in the initial HTML response.
- `store.createSubject` allows creating nested paths
- Add `Store.postToServer` method, add `endpoints`, `importJsonAdString`
- Add `store.preloadClassesAndProperties` and remove `urls.properties.getAll` and `urls.classes.getAll`. This enables using `atomic-data-browser` without relying on `atomicdata.dev` being available.
- Fix Race condition of `store.getResourceAsync` #309
- Add `buildSearchSubject` in `search.ts` which allows you to build full text search queries to send to Atomic-Server.
- Add `importJSONADString` function, allowing you to import resources from external sources.

## v0.35.0-beta.1

### @tomic/react

#### Breaking changes

- Remove `initAgentFromLocalStorage()`.
- No longer save agent to local storage.

### @tomic/lib

- Add the ability to change the `fetch` function used to fetch resources over http.
- `store.addResource` is depricated in favor of `store.addResources`.
- Add `AgentChange` event on store that is fired whenever the stores agent changes.
- `store.fetchResourceFromServer` now returns the requested resource.
- Add `postCommit` method to `store` that respects the injected `fetch` function.

#### Breaking Changes:

- `uploadFiles()` has moved to `store.uploadFiles()`.
- Remove `Agent.fromJSON()`
- `tryValidURL` and `isValidURL` are now static methods on `Client` and have been renamed to `tryValidSubject` and `isValidSubject`.
- Rename `store.fetchResource` to `store.fetchResourceFromServer`.
- Rename `store.handleError` to `store.notifyError`.
- Rename `agent.checkPublicKey` to `agent.verifyPublicKeyWithServer`.
- Remove `store.errorHandler` and replace with new `StoreEvents.Error` event.

## v0.34.10

- Don't use WebSocket in Node context #280

## v0.34.9

- Fix @tomic/lib exports for non-ts contexts #270
- Fix back / forward buttons in desktop build #263
- Fix `isOffline` for node

## v0.34.0

- Add folders with list & grid views, allow drag & drop uploads #228
- Show icons in sidebar
- Add scoped search, funded by NGI NLnet Discovery #245 #254
- Make web app installable #30
- Add cookie based authentication #241
- Get rid of `useWindowSize` #256
- `canWrite` check should succeed for `publicAgent` #252
- Improve error look & text

## v0.32.1

- Lock ed25519 version #230

## v0.32.0

### Breaking changes

- Changed `null` to `undefined` in many places
- `useTitle` returns an `array` with a `setTitle` function, similar to `useState`
- `resource.getError()` is deprecated in favor or `resource.error`

### New

- Add Hierarchy in sidebar #75
- Add DriveSwitcher #209
- Add `new drive` option
- Add `EventManager` to run custom functions when resources are added / edited / etc.
- Add dialog / modal view #24 #181
- Add bookmark import / reader mode #187

### Fixes & improvements

- Stricter non-null checks, improved typings #220
- Switch from `yarn` to `pnpm` #210
- Various improvements to Dropdown forms #194
- Fix crash in circular parent rendering
- Fix race condition #189
- Make all titles editable #199
- Don't subscribe to search endpoint #200
- Refactor e2e tests
- Render floats
- Hide unsortable items in tables
- Fix dropdown resource select input #222

## v0.31.1

- Fix Dropdown input bug
- Fix autogrow textarea bug

## v0.31.0

- Add ChatRooms #153
- Improve UX for creating new Resources, instantly open new ChatRooms and Documents
- Refer to `previousCommit`s in Commits #140
- Disable websockets out of browser context for `@tomic/lib`
- Fix NPM builds for `@tomic/lib` and `@tomic/react` in non-ts environments #155
- tauri back buttons, new tab external links #115
- Fix concurrency issue with commits #91
- Make bugsnag optional #133
- Add `parseCommit` function
- Use `href` attribute in sidebar menu #148
- Use relative links in About page #149
- Show `CommitDetail` that displays audit info (creator, edit date) #145
- Prevent using `localhost` Agents for external Servers
- Implement `push`, for appending new Resources to (existing) Arrays in Commits.
- Replace snowpack with vite #156
- Use yarn v2 and replace lerna #105
- Prevent default actions for keyboard shortcuts
- Improve cross-OS keyboard shortcuts compatibility (cmd & ctrl, option & alt)
- Fix markdown being shown shortly

## v0.30.6 to 9

- Don't use WebSockets if they're not supported #131
- Fix `@noble` build issues

## v0.30.5

- Switch to `dnd-kit` for drag and drop #92
- Improved views for external resources in Documents
- Add upload dropzone to documents
- Replace `react-helmet` with `react-helmet-async`

## v0.30.4

- `@tomic/react` can now be used without `@tomic/lib` - it re-exports the library
- More performant subject updates in new resource form
- Allow `@tomic/lib` to be used in non-browser (Node) context #128
- Add `useMarkdown` function to `@tomic/react`
- Make search result previews smaller
- Fetch full collections when showing CollectionCard
- `useResource` defaults to not accepting incomplete resources
- Add `sign in` button to invite form
- Rename `baseUrl` to `serverUrl`
- Add `useServerSearch` to `@tomic/react`
- Improve UX in Tauri (desktop) mode
  - Regular Links open in your browser, instead of in Atomic

## v0.30.0

- Add File management views. Preview images and videos, download them. #121
- Add `uploadFiles` method to @tomic/lib. #121
- Add upload field to forms #121
- Fix bug resourcearray input #123
- Add WebMonetization support #124

## v0.29.2

- Add Share settings screen where you can see & edit rights / access control #113
- Add Invite form #45
- Convert Classes to typescript interfaces. Show button for this in Class view. #118
- `Create new resource` button on Drive
- Show multiple parents in breadcrumbs
- Refresh collection on opening page
- Don't auto-accept invites
- Improve server switcher design
- Change default port of localhost to 9883 ([issue](https://github.com/atomicdata-dev/atomic-data-rust/issues/229))

## v0.29.1

- Small fix

## v0.29.0

- Add authentication: sign requests, so the server knows who sent it. This allows for better authorization. #108
- Refactor Error type, improve Error page / views
- Automatically retry unauthorized resources (but I want a prettier solution, see #110)
- `useResource` no longer returns an array, but only the resource.
- Improved EndpointPage (show results, useful for Search, for example)

## v0.28.2

- Added server-side full text search #106
- Add a seperate document show page #2, improved performance in Documents
- Improved `canWrite` hook (more stable, faster)
- Improved sidebar performance (less re-renders)

## v0.28.0

- Improve styling tables and sort dropdown
- It's mostly an `atomic-server` version bump :)

## v0.27.2

- Fix setting Agent bug
- Add constructor to Store

## v0.27.1

- Include all Properties and Classes in the initial view, speeding up the app even further. #65

## v0.27.0

- Parse nested, named JSON-AD resources #98
- Refactor resource status - remove `Resource.status`, prefer `.loading` and `.error`
- Add loading and error status to Property class, include in `useProperty`
- Improve loading and error states for various components
- Refactor `store.getResourceLoading`, `store.fetchResource`, `useResource` - add option to `acceptIncomplete`.

## v0.26.2

- Add [Typedoc documentation](https://atomic-docs.netlify.app/) #100
- Fix bug not showing resource form fields
- Fix circular parent handling in `canWrite`
- Update references to changed resources #102
- Use `ws` instead of `wss` for HTTP connections

## v0.26.1

- Fix `wss` websockets
- Update typescript type exports

## v0.26.0

- Added WebSockets for live synchronization with server #80
- Add Commit parsing #80
- Custom fonts
- Prevent re-applying locally defined commits #90
- Fix race condition commits #91
- Added `opts` parameter to react hooks
- Simplify internal Value model (better performance, less bugs) #88

## v0.25.4

- Fix bugs when setting Agent, validate public key before setting
- Add integration / end to end tests #70

## v0.25.0

- Add Document editor ([demo](https://atomicdata.dev/invite/ycj661fdce8)) #2
- Improved performance and less concurrency bugs while quickly saving resources
- Improve styling (soft background on light mode)
- Add baseURL settings page + edit function in top left

## v0.24.2

- Improve resource selector dropdown, show previews, remove dependency #60
- Add toast notifications #63
- Enable `resource.save()` with custom agent
- Add JSON AD array parser
- ~~Add `default_store.json` resource to the browser to make things snappier~~ removed
- Improve type checking for value initialization and serialization types
- Improve view for nested resources

## v0.24.0

- Match version number of [atomic-data-rust](https://github.com/atomicdata-dev/atomic-data-rust)
- Add Version button to menu
- Disable menu buttons that are not usable
- Improve error view in cards
- Only show plus icon in suitable collections

## v0.0.12

### atomic-data-browser

- Fix tests
- Cleaned up Resource form #51
- Handle usages left in Invites #45
- Add social meta tags #44
- Add fetch as JSON / JSON-AD / Turtle and more to data pages
- Fix bug with invites
- Various styling improvements
- Add Atomic Data Logo
- Dark mode syncs with user
- Scroll to top on page change #47
- Improve keyboard shortcuts for edit / data view #52
- Move Agent settings to sidebar item
- Add rights check
- Change routes and settings structure
- Add Disabled state to form fields
- Improved hotkey handling
- Fix edit subject in resource form

### @tomic/react

- Resources will update when properties change (notify listeners on update)
- clean up package.json / dependencies
- Add rights check hook

### @tomic/lib

- Add `getCommitBuilder` and `hasChanges` function to `resource` and `commitBuilder`
- Add rights check to resource

## v0.0.11

- Split packages, switch to monorepo
- Publish `@tomic/lib` and `@tomic/react` libraries to npm
- Add changelog
