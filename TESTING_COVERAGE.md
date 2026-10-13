Chat log entries (2026-10-09, `planning/chat-log.md`): `lib/tests/chat_log.rs` applies signed commits through the real rights path for a `ChatLog` page: an author adds, edits and deletes own entries; a member cannot touch another's entry, claim or forge one, or change page properties; a writer on the chat moderates; page genesis grants no `write` and refuses a self-granted one; entries more than ten minutes ahead of the server clock are rejected. `lib/src/db/test.rs` checks entries reach no propval, index or search row, and `measure_chat_log_entry_bytes` (ignored) prints bytes per message. `browser/lib/src/chat-log.test.ts` covers the TS helpers and that entry changes ride in a saved commit's `loroUpdate`. Step 2 (group chat and comments in the log): `browser/lib/tests/chat-log.integration.test.ts` runs two agents against a real server (an appender adds, edits and removes own entries, is refused on another's, a writer moderates). `helpers/chatLog.test.ts` covers entry ids, the merge and window of old messages and entries, and the page choice; `messageNotification.test.ts` covers entry notifications. Playwright: `chat-log.spec.ts` (entry, edit, reply, copy link, delete, reload, a second member seeing entries and edits live and no edit buttons on another's), `e2e.spec.ts` chatroom, `offline-chatroom.spec.ts`, `chat-mention.spec.ts`, `table-row-comments.spec.ts` (comment and count as entries) and `notifications.spec.ts` (chat, reply and comment toasts for entries, unseen badge). Migration of existing messages (`planning/chat-log.md`, "Existing messages"): `lib/src/db/chat_migration_test.rs` checks grouping by chat and by commented item, the split at 256 with the oldest on the first page, authors and times kept, deterministic keys, replies mapped across pages and left alone for an outside target, follow events keeping their kind, an edited message getting `e`, the old resource and its genesis commit row, snapshot, envelopes and indexes gone, a re-run being a no-op, a run that stopped after the pages and a straggler arriving meanwhile, the slices resuming from the stored state, a member editing own migrated entry and not another's while the chat owner can, a cache of a hosted drive only dropping rows that have their entry, opening a store migrating it, and the bytes per message before and after (`migrating_a_chat_shrinks_the_store`). `client-db.worker.migration.test.ts` covers the worker running the message slices after the index rebuild with progress and the local-only drives; `migratedEntryKey` has one test vector in Rust and TS; `helpers/chatLog.test.ts` covers hiding migrated old messages. Playwright: `chat-log-migration.spec.ts` shows old Message resources, then the same chat once their entries exist (stale copies hidden, one without an entry still listed, order kept); `meetings.spec.ts` covers follow events as entries. Not covered: the browser worker migrating a local-only drive end to end (WASM and OPFS), a real server restart with old messages in an e2e run, and an edited message's genesis commit row (kept). Not covered: concurrent edits of one entry by two members, a chat past one page (256 entries) in the browser, scrolling to a linked entry (not built), and DMs (later step).

AI chat in the log (`planning/chat-log.md`, "Step 3: AI chat"): `lib/src/db/ai_chat_migration_test.rs` checks the order coming from the `messages` list and not `createdAt`, parts (reasoning, text, tool calls with input and output) inlined, authors, the old messages and every part resource gone and `messages` cleared, a re-run being a no-op, a run that stopped before the removal resuming without duplicates, a cache of a hosted drive writing nothing, and the bytes before and after for a 20-message chat with tool calls. `client-db.worker.migration.test.ts` covers the AI step after the message step. `chunks/AI/aiChatLog.test.ts` covers message <-> entry (parts, tool calls, context, errors, summary), a re-save keeping key and time, draft chats not saving, the page rollover at 256, removing one and all-following, entries sorted by `c`, and old messages merged in front and hidden once their entry exists. Playwright: `ai-chat-log-migration.spec.ts` (old chat shows once with and without entries; a new chat stores one page and no message resources) next to `ai.spec.ts`, `ai-chat-discovery.spec.ts`, `ai-sidebar-navigation.spec.ts` and `ai-mobile.spec.ts`. Not covered: the browser worker migrating a local-only AI chat end to end, tool outputs large enough to matter for a page's size, and a chat past 256 messages in the browser.

Date-only values (#1795, 2026-09-25): `browser/data-browser/src/helpers/dates/calendarDate.test.tsx` renders a `date` value through `ValueComp` (row dialog, resource page), the table cell, a min/max aggregate, day and month group headings and the history diff, in Europe/Amsterdam and America/New_York. Each must show the same civil day with no time. The tests set `process.env.TZ` themselves, so they fail on the bug in any CI zone.
Row dialog fields (#1796, 2026-09-25): `browser/data-browser/src/components/PropVal.test.tsx` checks that the row dialog labels a value with its property's name (or a readable shortname when it has none), with the shortname in the tooltip. The label must not be a link, the property opens in a new tab, and the edited checkbox gets its accessible name from the label. Resource pages keep the linked shortname. `browser/e2e/tests/row-dialog.spec.ts` covers the same in a real Grocery list and runs axe (`label`, `link-name`) on the open dialog. It also covers the `ValueFormEdit` key warning through the browser-diagnostics fixture: that warning only shows with the wuchale transform, which vitest does not run.

Server descriptor budget (2026-09-22): `server/src/serve.rs` tests the HTTP
connection budget at small, staging-sized, and effectively unlimited process
descriptor limits. Startup reads the process soft `RLIMIT_NOFILE`, limits Actix
workers and per-worker connections, and reserves descriptors for other services.
This bounds accepted HTTP sockets when they dominate descriptor use; it does
not identify the source of the September 22 staging descriptor spike or bound
Iroh and other non-HTTP sockets. A staging load test and process FD sampling
are still needed before claiming the original incident's cause is fixed.

File uploads during tab handoff (2026-09-22): `browser/lib/src/client-db-handoff.test.ts` closes the leader during hashing and blob storage, verifies recovery when the uploader or a third tab takes over, and covers duplicate announcements, non-repeatable mutations, timeout and teardown. A local Chromium harness also exercised these four handoffs with real Web Locks, BroadcastChannel, WASM and OPFS, verifying the blob survives reload. The exact reported staging profile-picture event could not be retrieved from Sentry on this host; a live-but-unresponsive leader without a handoff still uses the bounded timeout.

Account redirects (2026-09-22): mounted `GettingStartedFlow.test.tsx` and `IdentityReconcileGate.test.tsx` cover hosted local sign-in, settings/passkey continuation, invite/drive priority, missing-data recovery and cancellation of stale identity/hosting checks. See [the route map](browser/data-browser/AUTH_FLOWS.md). Portal session, email-link and dashboard browser checks live in atomic-saas and use HTTP fixtures; real production passkey registration is not covered by these checks.

PR #1585 frontend regressions: Vault backup tests verify a legacy drive ID reads canonical cached metadata and refreshes it after edits. Deep-link and peer-pairing tests retain legacy inputs while checking canonical identity behavior.

PR #1585 upgrade regressions: library tests pin the pre-rename AI Chats singleton and restored alias cache, negotiate nested reduced/full sync identifiers, and export canonical snapshots for legacy requests. Rust tests cover legacy filtered/full version vectors and restarting an interrupted scheme migration after rows moved but before indexes finished. These are library/frame-level checks; a deployed mixed-version browser/Iroh pairing is not exercised.

Collection alias indexing: `sorted_parent_query_deduplicates_legacy_and_canonical_subjects` reproduces an old `did:ad:` query-member key beside its `atomic:` key, then verifies one member, a count of one, canonical output in both sort directions, correct pagination, and stale-key removal on update. It also checks a Table View's class-filtered query without an explicit sort. `basic_parent_query_deduplicates_legacy_and_canonical_subjects` covers the separate property/value and value-only index paths, including both primary index trees and offset pagination. The production drive's duplicate labels were observed on two devices, but their individual resource IDs have not been inspected; these tests prove the alias failure paths rather than the identity of each live row.

New-drive sync: WebSocket unit coverage verifies SUB and SYNC wait for a pending genesis acknowledgement, then resume on ResourceSaved. The Local DB-off rendering E2E exercises this ordering with real server persistence.

Document images: `document-image.spec.ts` uploads a freshly generated PNG through the editor's image picker in a browser-only drive, whose bytes never reach a server, and verifies the image renders from the local blob store before and after a reload instead of showing "Failed to load image". `subject.test.ts` covers mapping a content-addressed `/download/files/<hash>` URL back to its blob. An image in a server-synced drive on a device that has not got the bytes still loads from the server URL; that path is not separately covered.

Cover repositioning: `cover-reposition.spec.ts` uploads a real image and verifies multiple pointer movements update its framing before release (native image dragging previously interrupted the gesture).

Template visibility: `settings-templates.spec.ts` toggles Hide templates through Settings, verifies the loaded New page hides templates across reload, and restores them when unchecked.

AI settings search: browser coverage checks API matches retain provider credentials but hide model, generative, and voice controls; titles matches show only the title toggle within AI.

Model option details: settings browser coverage checks input/output prices per million tokens and the OpenRouter added month inside an option, while preserving selection and dropdown width.

OpenRouter privacy: settings browser coverage filters out models absent from the mocked ZDR endpoint list. The BYOK voice/chat flow asserts provider.zdr is sent on its chat completion; voice audio remains outside this chat-only policy.

Model dropdown geometry: `ai-settings.spec.ts` checks that the open list matches its input width (regression: viewport-wide popover).

Speech settings: browser coverage selects a transcription model, persists the voice toggle across reload, hides the mic when disabled, and verifies the selected model in the personal-key audio request. The managed-credit model remains service-controlled.

AI settings: `ai-settings.spec.ts` exercises navigation from the chat agent menu,
provider controls and default model selection, agent/skill/MCP creation and reload
persistence, and settings search. Provider/MCP APIs are mocked. Agent radios expose
saved selection; voice BYOK regression still passes after the menu refactor.

Voice feedback: unit checks cover audio-level bounds and local-recognition cancellation; the personal-key Chromium flow checks mic scaling with simulated volume and interim word rendering. Real on-device transcription requires browser support and an installed language pack.

Voice with personal OpenRouter key: `ai-voice-byok.spec.ts` verifies the mic remains usable, direct audio requests carry the configured key, and no SaaS voice endpoint is called. Media and model responses are mocked.

Voice chat: `voiceTurn.test.ts` checks PCM WAV serialization and cancellation
without retries. `ai-live.spec.ts` runs the actual chat controls with mocked media
and OpenRouter responses: record, transcribe, hosted AI reply and speech playback,
without a personal API key. SaaS `ai::voice` validates input bounds and model pinning;
shared AI tests cover credit reservations and settlement. Real microphone/provider
quality remains unverified without the SaaS OpenRouter key. The earlier GPT-Live
lifecycle tests remain for its retained, separate backend implementation.

Plugin configuration: hook tests retain a release's validation schema when a save
receipt omits computed metadata, and clear it when the release or installation
changes. The plugin-install E2E checks invalid config after saving valid config.
`browser/lib/src/plugin-install.test.ts` checks that installation and release
updates validate built-in fields without public Property fetches and preserve
JSON tags for grants and config. `embedded-vocabulary-routing.test.ts` covers
host routing for plugin classes, while `plugin.spec.ts` installs a release and
verifies the active plugin in Chromium.

JSON property values: `browser/lib/src/json-value.test.ts` checks that an
object set on a JSON property reads back as an object before the save drains
(validated and unvalidated `set()`), after a commit round trip, and from legacy
docs: untagged objects and string-wrapped (double-encoded) objects. Not covered:
the `InputJSON` editor itself in a component or E2E test.

Editor sync formatting: unit tests cover both enabling and disabling bold before
an incoming property update, so sync receipts cannot reset the next typed text's
formatting. The production-bundle typing E2E exercises the keyboard shortcut.

Sidebar layout: browser checks sample both docked sidebar transitions halfway
through opening/closing and verify that the main content moves with them, with
matching duration/easing. They also cover hover reveal, mobile backdrop dismissal,
and keeping the main content aligned while resizing and after reopening. Tablet
checks verify that opening AI, comments, or meeting chat closes the left sidebar.
Section resizing: hook tests cover touch pointers, drag thresholds, size bounds,
tap preservation, cancellation, secondary pointers and unmount cleanup. Chromium
uses native touch gestures on the AI Chats header to shrink/grow the list, checks
the 44px touch target, saved height after reload, collapse/expand and New Chat.
AI sidebar navigation checks that the AI Chats section is absent on a fresh
drive and appears after a chat is saved, then opens the chat report preview from
its context menu. The tablet composer check simulates a
shorter visual viewport with zero keyboard inset; physical Firefox Android
keyboard behavior still needs device verification.

Creation catalog/context menus: browser checks cover the embedded sidebar filter,
keyboard filtering, removal of plugin/website/app creation actions from menus,
discovery of their blank starters on a fresh drive, and file/upload searches.
Existing app, plugin, and website browser flows create through the catalog,
including a website seeded from its selected parent document.
The resource menu check simulates a shrinking visual viewport and requires the
open menu, including its filter, to remain above the keyboard boundary.

Mobile AI chat navigation: Chromium covers opening the left sidebar above chat,
Back dismissal without leaving the page, the AI settings link, an empty composer
without vertical overflow, and messages without a redundant sender row. History
unit tests cover StrictMode, explicit close, and navigation to another page.
Resource links dismiss mobile chat even for the already-open resource; Chromium
covers current/different targets, retained conversation and desktop staying open.
Link unit tests check dismissal waits for navigation; history tests protect
destinations when navigation inherits the chat marker.

Included AI: managed transport tests cover signed-out status, explicit consent,
backend errors, streaming credit failure and non-streaming title generation without
forwarding a provider key or SDK User-Agent header (Firefox/Zen CORS regression).
Assistant rendering tests retain historical errors and partial replies while
suppressing the duplicate current error when the composer displays it.
Setup component tests cover consent failure/retry and
successful dismissal. atomic-saas owns account isolation, budget concurrency,
month rollover, paid-drive aggregation, origin/auth checks and disconnected-client
accounting tests. These tests do not call the live funded OpenRouter service.

AI setup recovery: component tests reproduce dismissed setup reopening on repeated
requests, prevent login-button mounts from overwriting an in-flight OpenRouter
verifier, verify the clicked link's PKCE challenge and verifier length, and check
visible feedback with navigation cancelled when browser storage is blocked.
Real OpenRouter consent and paid model requests are not exercised by these tests.

Website exports open in a dedicated frozen preview. Browser coverage verifies the
export resource shows original content after source edits and reload, with scripts
disabled and no publication action.

Website publication state: browser coverage verifies unchanged output after publishing
and reload, pending document edits, and pending changes after rollback. Unit tests
compare page bytes and image hashes, including removed files and entry ordering.

Website error recovery: Chromium verifies an unreadable selected image emits the
Store toast and console error, replaces the loading placeholder, disables publication,
and recovers after repairing the selection. Explicit retry is available.

AI sidebar navigation: browser coverage checks the default visible chat list,
its header new-chat action while collapsed, and reopening saved replies without
changing the main URL. Switching chats checkpoints the current message first.
Successful reply persistence clears error descriptions using Resource.remove.

Website media: a real browser test uploads a private PNG, renders it in the draft,
publishes it, and checks decoded image dimensions and a separate HTTP asset as an
anonymous visitor. A browser test optimizes a 6.55 MB JPEG without changing its
source. The object-store adapter test checks blob storage, project isolation and
publication gating; this is not a live S3 bucket test.
Unit tests cover gallery/File-cell image packaging, unselected relationship
exclusion, media limits, reference reload persistence and batch row save failures.

Website publishing UX follow-up (2026-09-15): the Chromium publishing E2E now
uses one-click Publish site / Update site, checks a single primary action and no
manual status refresh control, and verifies a failed hosting request reaches the
standard Store error pipeline (visible toast plus console error). Desktop/mobile
screenshots exercise the preview-first layout. Existing document/export and
Assistant design scenarios retain coverage behind the collapsed export controls.

Self-hosted website publication (2026-09-15): `atomic_lib` website tests cover
bounded packages, unsafe paths, content identity, private upload, activation,
stale revisions, rollback and unpublish. The Actix website HTTP test uses a real
DB and signed requests to check private preview, anonymous refusal, customer
hosts excluding API routes, and drive-root publication authority. The opt-in
`website-publishing.spec.ts` ran on an isolated node with WEBSITE_HOSTING_E2E=1:
Chromium completed private document -> release -> upload/review -> publish,
an independent signed-out browser read, draft isolation, republish, rollback
and unpublish (1 passed, 7.7s). No model API or cloud service is mocked into this
publication path. `hostingClient.test.ts` checks trusted-origin signing, no key
in the payload and conflict refusal without retry. SaaS deployment, production
TLS/DNS, load testing and full-suite/CI validation remain outside these checks.

Website composition and snapshot views: the focused website/FrameBridge set has
16 passing tests, including invalid layout references and a host that refuses
non-snapshot operations and foreign frames. `website.spec.ts` exercises a two-page
Assistant-authored document/table site, real FrameBridge search, no-results state,
navigation, source inline edits and frozen release persistence (2 passed, 19.2s).
`website-export.spec.ts` takes WEBSITE_EXPORT_URL pointing at the actual extracted
archive; navigation, search and mobile width pass with non-site requests blocked
and Atomic stopped (1 passed, 807ms). It skips without that explicit fixture.
The model is scripted. Third-party plugin loading, production build and public
SaaS activation are not covered. Runtime assets regenerate via build/dev/start.

Inline website editing (2026-09-13): `websiteInlineEditing.test.ts` adds four
passing boundary tests (12 website unit tests total): current selection, source
rights/private ancestry, text type, changed source value and pending-save failure.
The website Assistant E2E now uses the real shared `@tomic/edit-mode` controls,
checks original-record writes, field clearing, reload and frozen release output.
The model is scripted; rich-text inline editing and arbitrary plugin HTML are
outside this coverage. Source stale-value detection is optimistic client-side.

Website prototype (2026-09-12): `chunks/Website/renderWebsite.test.ts` has eight
focused passing tests for rich-text escaping, rejected media/active links,
path/CSS validation, portable HTML, grid output, deterministic hashes, inherited
private permissions and pending-save refusal. `e2e/tests/website.spec.ts` has two
passing Chromium cases (1 worker, 16.6s): document-to-website preview, release
review/download, independent drafts and reload; actual Assistant tools with a
scripted model, existing table binding, design updates and omitted private data.
This is private authoring/static export coverage, not public SaaS publication or
live-model quality. See `planning/assistant-websites.md` for limits.

App runner production regression (2026-09-12): `plugins.spec.ts` exercises
release publishing, manual preview/apply, missing-target refusal and manifest
credential discovery against the embedded production frontend.
The runner must use Vite's worker bundling: copying only its entry with `?url`
left shared library imports missing in production. The publish-button assertion
also catches an obsolete English catalog entry rendering an empty label.

Save acknowledgement: `browser/lib/src/save-acknowledgement.test.ts` reproduces
an online genesis POST failure reported as persisted. It verifies pending/backoff
saves return offline and a later acknowledged retry preserves the subject.

Installation prerequisites: `browser/lib/src/plugin-installation.test.ts` checks
local-only rejection without a server call, missing server resources, network
failure and successful server visibility. The provider setup browser flows
(`app-setup.spec.ts`) moved to atomic-plugins with the providers.

# Testing coverage map

Plugin discovery: `PluginRuns/pluginCatalog.test.tsx` covers parsing the remote
plugin catalog, which entries unlock "Show experimental plugins" (entries
that need API plugins don't), and a remounted hook rendering the cached catalog
on its first render without fetching again; `helpers/integrationVisibility.test.ts` covers the
stored preferences. `integration-visibility.spec.ts` checks no "Show API
plugins" toggle is offered.

The data-browser no longer connects or syncs LocalThought platforms: that code
was removed, and plugins will run in their own iframe and make proxy calls
through the host (#1624). Nothing in this repo tests a LocalThought connection.

Finding another table (#1807): `TablePage/ColumnFilterDropdown.test.tsx`
(jsdom) checks the table's column-filter menu names its input "Find a column…"
and, when nothing matches, offers "Search the drive for …", which opens the
search overlay with the query on Enter. `components/overlayState.test.ts`
checks the pre-filled search query is dropped on close and on a plain open.
The labelled header search button is not covered beyond `test-utils.ts`
still finding it by its `Search (` title.

Issues view: `TablePage/Issues/issueStatus.test.ts` covers reading open/closed
status tags and booleans, picking close/reopen targets, and title/`#number`
filtering; `browser/e2e/tests/issues-view.spec.ts` covers the Issues view for
tracker tables.

Table cell readability (#1808): `helpers/dates/dateInput.test.ts` covers
reading typed dates (unpadded, year-first, locale order in en-GB/en-US/de/nl,
eight bare digits) and rejecting impossible or two-digit-year dates.
`EditorCells/DateCell.test.tsx` (jsdom) checks the date cell stores once, on
Enter or when it closes, never per keystroke. `EditorCells/TruncatedText.test.tsx`
checks the tooltip and the selected-cell panel for cut-off text; jsdom has no
layout, so widths are stubbed and the panel's `:focus` rule is checked by
selector, not by rendering. `tables.spec.ts` "create and fill" and
`table-templates.spec.ts` "Plant care" still type dates as `ddmmyyyy`.

Typed app setup: `browser/lib/src/plugin-setup.test.ts` covers shared input validation,
partial model drafts, forbidden arguments and size limits. It also validates resource JSON
setup declarations: detached round-trips, supported constraints, malformed schemas,
choice hints and rejection of unknown keywords before form/model use. `AppSetup/setup.test.ts`
checks that credential values are redacted from reported host errors and that no setup
actions are registered.
The provider setup E2E (`app-setup.spec.ts`) moved to atomic-plugins. Live
authentication, installation recovery and arbitrary authored setup execution
are not covered here.

`integrations/localthought/settings.test.ts` verifies that reconnects cannot reuse
legacy installation identities, while repeated imports on one connection remain
stable. The LocalThought Vitest config has an explicit root so all six suites
also execute when invoked from outside the repository (including `/`).

LocalThought browser migration: `integrations/localthought/browser.test.ts`
covers secret-free selected-platform redirects, S256 PKCE, one-time redemption,
actor/drive/platform ownership, cancellation, expiry, rotation before dispatch,
pagination, uncertain-response refusal and cross-origin pagination refusal.
`browser-smoke.mjs` exercised the complete mock consent/import/review/OPFS/reload
journey through the WASM engine, which was removed in #1618; it fails until
the proxy calls move into the plugin iframe. Local installation/schema lookup tests reject missing or
incomplete local databases rather than inferring permission to create duplicates.
The proxy redirect work has 60 passing Rust tests including PostgreSQL-backed
consent/replay, optional credential grants, callback binding and redemption expiry.
CORS was verified with the earlier live browser flow; the new secret-free flow
still requires matching proxy/frontend deployments and live verification.

The standalone browser-only Devonian demo (`chunks/DevonianDemo/`, the
`/app/devonian-demo` route, and `browser/e2e/tests/devonian-issue-sync.spec.mts`)
and the `integrations/github-issues/devonian` bridge were removed along with
the `devonian` dependency; their coverage no longer applies. GitHub issue
sync tests moved to atomic-plugins with the provider.

What is tested, at which layer, and — the part that matters — **what is not**.

This exists because the protocol is far better tested than the glue around it,
and that imbalance is invisible from a passing CI run. Every production bug in
device sync so far has been in a layer this document lists as uncovered.

**Keep it current.** When you add a test, add the row. When you find a blind
spot, write it down even if you are not fixing it today — an admitted gap is
worth more than a forgotten one. When you fix a bug, ask which row would have
caught it, and if the answer is "none", that is the row to add.

---

## WASM database opening

`browser/lib/src/client-db-open.test.ts` covers `ClientDb.open()` success,
wrong-key cache recovery, and propagation of blocked/corrupt-storage errors.
The save-state and crash-durability browser tests exercise the generated WASM
factory through the real worker and OPFS; the async constructor is no longer used.

## E2E isolation and performance harness (#1461)

`search.test.ts` verifies search-cache invalidation only evicts memory entries,
without deleting persisted resources or adding pending database writes.

`bootstrap.test.ts` verifies website language properties are ready from bundled
definitions without fetching atomicdata.dev. The discussion badge test uses the
shared reconnecting reload helper before asserting device-local unseen state.

A live Dagger service probe confirmed identical definitions share a process,
while a per-instance runtime environment variable starts a distinct process.
Shards now vary runtime identity while sharing binary builds. This probe does
not establish full Dagger E2E acceptance or a supported worker count.

`loro-selection.test.ts` checks cursor preservation across a remote metadata
update followed by keystrokes before and after queued timers. The scoped
loro-prosemirror 0.4.3 patch restores document and selection atomically.

`loro-typing-history.test.ts` exercises ordinary typing and fallback formatting
with real ProseMirror transactions and Loro documents. Its synthetic imported
history reproduces redundant inclusive-mark operations without private document
data. Assertions cover materialization counts, formatting-history growth, text
container identity, UTF-16 edits and persisted marks.
`loro-typing-collaboration.test.ts` covers undo/redo followed by typing, concurrent
text/format convergence without import echoes, duplicate paragraph mappings and
multi-step composition fallback. `editor-typing.spec.ts` runs against the built
GUI, checks that real keystrokes avoid `toDelta`, and verifies text after reload;
it records frame timings without a machine-dependent timing threshold.

`documentUndoSession.test.ts` covers document undo/redo across editor bindings,
authentication-session isolation, system/remote changes and callback ownership.
`browser/e2e/tests/document-undo.spec.ts` checks undo and redo through the
Data View round trip, including persisted content after reload.

`store-search-server.test.ts` checks that authoritative server lookups after
imports do not wait on local indexing or WebSocket readiness.

`cargo test -p atomic-server --test build_assets` exercises content/settings
cache separation, corrupted Brotli recovery and concurrent atomic publication.
`cargo test -p atomic-server --test build_plugin_runtime --features wasm-plugins`
builds a tiny release workspace using the production runtime build script. It
checks that nested Cargo completes while the parent holds its release lock and
that the server embeds a real WASI component, including with a custom target dir.
The context-menu E2E flow catches title blur stealing focus from the menu;
Enter retains its explicit handoff into page content.

`node --experimental-strip-types --test browser/e2e/scripts/*.node.mjs`
checks process-group ownership with concurrent real HTTP servers, ephemeral
ports, unrelated-service preservation, startup failure and worker disconnect
cleanup. Additional Node checks cover hardware budgets and checkout locking.
These run through the E2E package test script in recursive JS tests.
Playwright provides accounting, reports and step timings. Custom build caches,
host sampling and matrix-acceptance scripts were removed to simplify maintenance.
`node --experimental-strip-types --test scripts/e2e-budget.test.mjs` validates
CI overrides without mutating the profile or coverage selection.
`pnpm --dir .dagger test` also exercises the actual Dagger module against a
recording SDK double: lint must not construct a WASM build, CI validates and
forwards budget arguments, and E2E applies them to shard and clone settings.
These checks run before Dagger in CI and reproduce the incomplete merge in
`2ccff0976`; they do not substitute for container or browser execution.
The existing full-snapshot duplicate-import test also covers parent-only resources
through initial sync, replay and later offline edits.
`parent_only_existing_resource_cannot_be_pushed_through_another_drive` verifies
that resolving their stored parent does not permit a cross-drive overwrite.
`initClientDb.handoff.test.ts` checks the deferred anonymous startup and identity
handoff guard.
The ontology E2E test gates an earlier instance save's completion while the next
form is open, catching stale cleanup that empties the new form.
The existing browser diagnostic/failure-state tests cover bounded retained
attachments; the renderer load probe adds only timing metadata.

`session-fixtures.ts` is an opt-in closed-profile clone experiment, currently
used by drive-scoped dashboard and table/view specs with
`ATOMIC_E2E_CLONE_SESSION=1`. Every test gets
separate browser files, device ID and project drive; each worker reuses its seed
agent. Cold identity/storage/account tests keep the fresh fixture. Full-suite
acceptance with this setup remains pending. Playwright 1.63 uses a documented,
version-specific Chromium preload compatibility flag; browser cross-world
service-worker isolation is outside this validation (see the E2E README).

`template.spec.ts` exercises each actual generated Next/Svelte site independently,
using the fresh drive from `before()` instead of provisioning a second drive.
Both can run in parallel. All timing/coverage claims require actual suite runs:
five unfiltered Chromium passes per high-worker setting, skips reviewed, are
still pending. See `planning/e2e-concurrency.md` for live measurement status.

## New-resource catalog

`creationCatalog.test.ts` covers catalog completeness, multiword search and the
assistant request's parent context. `new-resource-catalog.spec.ts` covers template
search, autofocus, outlined arrow-key selection, Enter activation, clearing and
search-only layout, table creation inside a folder, mobile layout and retaining the assistant
request from either input before a model is connected, plus nested website template creation.
Actual model generation is not exercised by these tests.

Local validation (2026-09-11): all 840 data-browser unit tests and all five
new-resource Chromium E2Es pass, including nested website import. E2Es used
the existing local backend and WASM assets, not a fresh Rust build.

New Table's "Use existing class" picker (`SearchBoxWindow.test.tsx`, vitest):
an external class the store already fetched is found by a partial shortname,
name or description, marked with its origin and not listed twice next to the
server's results, and a pasted URL is still selected directly. The server search
is mocked. There is no E2E. A class the store has not fetched (after a reload,
say) is only reachable by its URL.

## Pre-commit lint gate

`node --test scripts/pre-commit.test.mjs` exercises real Git commits with Oxlint
in a temporary repository using real pnpm 11.10.0 (via Corepack):
initial commits, staged errors hidden by unstaged
fixes, clean staged files with unstaged errors, filenames with spaces,
documentation-only commits, missing dependencies, and preservation of the index
and working tree. Noninteractive recursive lint runs with symlinked dependencies
and incompatible pnpm metadata reproduce issue #1437; the fixture checks that
installed metadata and a dependency sentinel remain untouched. Corepack must
have this pnpm version cached or be able to download it. A stub Cargo command
verifies Clippy dispatch, staged input, and failure propagation; this fixture does not compile the Rust workspace.

## Browser WebRTC transport (issue #1396)

`browser/lib/src/webrtc-transport.test.ts` covers frame fragmentation/order,
backpressure and cancellation, bounded queues, caller buffer ownership, malformed
input and close behavior. `browser/e2e/scripts/verify-webrtc.mjs` establishes real
WebRTC channels between isolated browser contexts in Chromium and Firefox and
checks bidirectional 1 MiB transfers and disconnects without an AtomicServer.
The harness is loaded through Playwright routing; ICE and data transfer are real.
`lib/src/sync/browser_peer.rs` tests authentication, replay, drive isolation,
unauthorized snapshot writes, forged commits and outgoing permission revocation.
`browser/e2e/scripts/verify-peer-sync.mjs` uses distinct agents, real signaling,
WebRTC and OPFS with HTTP data access disabled: initial sync, concurrent edits,
presence, attachments, offline reconciliation, reload and signed deletion.
`browser-peer-sync.test.ts` covers parallel negotiation, isolated retries,
departure, membership checks and the per-browser connection bound. It also
checks shutdown during a signaling handshake: the socket closes after opening
without joining a room or scheduling a reconnect.
`verify-peer-mesh.mjs` uses eight distinct Chromium agents: full mesh, ninth-member
rejection, concurrent creations, group presence, attachment replication, creator
departure, offline reconciliation and signed deletion. Rust regressions cover
late snapshots and delayed pulls after deletion (unknown pulls still fail), and concurrent blob replies across independent edges.
`browserPeerSync.test.ts` checks that another member can mint an invitation for
the existing room without restarting its connection.
`verify-peer-ui.mjs` checks invitation creation and disconnect in the Sync page.
These scripts require built WASM and `ATOMIC_PEER_SIGNALING_URL` pointing to the
SaaS signaling handler; neither starts an AtomicServer data process. The UI script requires
a running app at its configured test URL. They are not wired into CI yet.
Still uncovered: two physical devices, forced TURN, full Firefox drive sync,
public deployment, and interactive rich-text editor/cursor acceptance.

## How to read this

Plugin catalog: the e2e suite runs against a static mock of the atomic-plugins
catalog (`testdata/atomic-plugins-mock`: `catalog.json` plus the test plugins'
`plugin.js` bundles in the published layout), which Playwright starts as a
`webServer` unless `PLUGIN_CATALOG_URL` names another catalog. So
`integration-visibility.spec.ts` asserts against fixed entries rather than
whatever is published upstream. Provider plugins, their fixture tests and their
certification live in atomic-plugins; this repo tests only discovery and
install.

Integration UX: `plugins.spec.ts` covers release publish and draft creation,
propose/apply (nothing written until approval), a blocked run on a missing
target, and two credential cases: a plugin asks only for the credentials it
declares, and an undeclared secret still has somewhere to go. The trigger HTTP
response regression `response_filters_round_trip_into_updates` ensures GET
filter values can be sent back to POST. Provider connection flows (GitHub,
the mock-proxy Pets flow) moved to atomic-plugins.
Run it against a production build to catch missing translation catalog entries:
Vite dev extracts them automatically and can hide blank production labels.

Coverage is split by *layer*, because the same flow can be well covered in one
and absent in another:

| Layer | Meaning |
|---|---|
| **protocol** | `atomic_lib` sync engine — the bytes on the wire |
| **glue** | the code wrapping the protocol: HTTP handlers, the Flutter bridge, browser helpers |
| **flow** | what a user actually does, end to end, through a UI |

A flow is only genuinely safe when all three are covered.

### Playwright light vs full

Only the browser suite has light/full modes. Lint, Rust, vitest, JS
integration, and Flutter run on every Main CI job. Automatic CI on PR events
and feature-branch pushes is paused while runner capacity is limited.

| Trigger | Playwright |
|---|---|
| PR event or feature-branch push | No automatic repository CI |
| `develop` push | **full**, required (staging) |
| `v*` tag | **full**, required (release) |
| Manual `workflow_dispatch` on a temporary branch combining PR heads | **full** |

Tag a new journey `@smoke` (`smoke` from `browser/e2e/tests/test-utils.ts`)
only if a failure means the first-hour demo is dead. Extra operators,
templates, and offline variants stay in the full suite. Policy:
[`planning/e2e-light-heavy.md`](./planning/e2e-light-heavy.md).

---

## Where the suites live

`browser/lib/src/store.test.ts` covers async reads waiting through intermediate
loading notifications before exposing a resource to callers such as table columns.

| Suite | Command | CI job |
|---|---|---|
| `atomic_lib` unit + integration | `cargo nextest run -p atomic_lib --features db-redb,iroh,ws` | `rustTest` |
| Server integration | `cargo test -p atomic-server --test it <module>` | `rustTest` |
| Browser unit (vitest) | `cd browser && pnpm run -r test` | `jsTest` |
| Browser integration (vitest + real server) | `cd browser/lib && pnpm run test:integration` | `jsTestIntegration` |
| Browser e2e light (`@smoke`) | `cd browser && pnpm run test-e2e:light` | Local diagnostic |
| Browser e2e full | `cd browser && pnpm run test-e2e` | `endToEnd` on dispatched batches, `develop`, and `v*` tags |
| Flutter Dart | `cd flutter && flutter test` | `flutterTest` |
| Flutter Rust bridge | `cargo test --manifest-path flutter/rust/Cargo.toml` | `flutterTest` |

CI runs `cargo nextest run --workspace --exclude atomic-server-tauri
--no-default-features --features light`. Feature unification pulls in
`db-redb` + `iroh`, so feature-gated sync tests do run there.

Two things worth knowing about the runners:

- **`flutter/rust` is excluded from the workspace** (root `Cargo.toml`), so
  `--workspace` never compiles it. It is covered only by the explicit
  `--manifest-path` step in `flutterTest`.
- **`.config/nextest.toml` sets `retries = 2`.** A flaky test passes CI
  silently. Check for `FLAKY` in nextest output, not just the summary line.

---

## Sync and pairing

### Protocol — well covered

| Flow | Where |
|---|---|
| Two Iroh nodes reconcile (bulk + live) | `lib/src/sync/iroh_e2e.rs` (13 tests, real QUIC) |
| Stroke appended after sync propagates | `lib/src/sync/iroh_e2e.rs` |
| A peer only receives what its agent may read | `iroh_e2e.rs`, `peer.rs` |
| A peer cannot forge a third agent's resource | `iroh_e2e.rs` |
| Relayed write accepted only for a drive we own and dialled | `peer.rs` |
| Iroh accept side refuses any frame before `AUTH` (ERROR + closed stream), binds `AUTH.requestedSubject` to the handshake drive | `peer.rs` (`accept_gate_tests`, raw QUIC stream) |
| Rejected `SYNC_PUSH` answers `ERROR SYNC_REJECTED`, never `SYNC_OK` | `peer.rs` (`accept_gate_tests`), `server/tests/it/ws_auth_gate.rs` |
| WS: writes and identity-bearing subscriptions need `AUTH`; anonymous `SUB` on a public drive still works; unreadable subscriptions answer `ERROR UNAUTHORIZED_READ` | `server/tests/it/ws_auth_gate.rs` |
| Rejected cross-drive sync entry leaves no snapshot; later valid import cannot inherit rejected properties | `engine.rs` (`rejected_sync_entry_does_not_persist_snapshot`) |
| Legacy `set`/`push`/`remove` commit rejection is on the parsed commit's properties: a signed commit carrying `set` is refused under hub and peer policy, a value quoting the deprecated URLs applies, a commit *on* the `set` Property reaches the ownership gate | `lib/src/sync/tests.rs` (`ingest_commit_rejects_legacy_field_commits`, `ingest_commit_accepts_values_that_mention_legacy_fields`) |
| A fresh server store gets the core models without `--initialize` (`Db` open seeds them) | `server/src/tests.rs` (`fresh_store_gets_core_models_without_initialize`) |
| Missing-drive bootstrap (OQ5): `Public` never creates a drive, Owner mode enrolls only the owner, open node admits an authenticated first-sync | `lib/src/sync/engine.rs` (`bootstrap_and_sub_tests`), `peer.rs` (`live_write_admission_tests`) |
| Engine-owned `SUB`/`UNSUB`: granted `SUB` is a session command, unreadable `SUB` answers `ERROR UNAUTHORIZED_READ` | `lib/src/sync/engine.rs` (`bootstrap_and_sub_tests`) |
| Signed `SYNC_DIFF.removeCommits`: envelope applies regardless of connection agent, tampered envelope does not delete, envelope only handed to drive readers, replay after re-creation refused | `lib/src/sync/peer.rs` (`initiator_trust_tests`), `engine.rs` (`bootstrap_and_sub_tests`), `tombstones.rs`, `protocol.rs` |
| `SyncSession` over an in-process `AtomicTransport` holds `AUTH` across frames | `lib/src/sync/session.rs` |
| Signed envelopes per resource: `latest`/`all` retention, time order, not indexed, verified attribution per Loro token, tampered envelope unverified, two writers, destroy fold | `lib/src/envelopes.rs` |
| `GET /history-attribution` names the verified signer and is read-gated | `server/tests/it/history_attribution.rs` |
| Attribution parse / version lookup / server+local merge | `browser/lib/src/history-attribution.test.ts` |
| Engine-level two-store sync, private drives, blobs, live push | `lib/src/sync/tests.rs` |
| Drive hashing; a filtered `SYNC` (`subjects`) diffs like the full one | `lib/src/sync/tests.rs` |
| Remote update merge, drive-spoof rejection, tombstones | `lib/src/sync/ws_apply.rs`, `tombstones.rs` |
| `DbEvent::Destroyed` for a removed resource and its cascade-deleted children arrives only after the removal is applied (the store no longer holds them when a listener hears), each subject announced exactly once | `lib/src/db/test.rs` (`destroyed_events_follow_the_applied_removal`) |
| Pairing envelope encode/decode | `browser/lib/src/pairing.test.ts` |

### Cross-process — covered since 2026-07

Both matter because `iroh_transport` holds the router and node identity in
**process globals**; anything sharing a process shares one node.

| Flow | Where |
|---|---|
| Drive reconciles across a real OS process boundary | `lib/tests/cross_process_sync.rs` |
| Iroh NodeID survives an unclean kill (`abort()`, no flush) | `lib/tests/identity_durability.rs` |
| Paired peer + its relay/direct addresses survive a kill | `lib/tests/identity_durability.rs` |
| Two whole servers pair via `POST /iroh-sync` and reconcile | `server/tests/it/iroh_pairing.rs` |
| `/iroh-sync` refuses malformed node ids with a UI-showable error | `server/tests/it/iroh_pairing.rs` |

### Glue

| Flow | Where | Note |
|---|---|---|
| Browser records a peer and calls `/iroh-sync` | `data-browser/src/helpers/pairing.test.ts` | stubbed fetch |
| Known-peer store: labels, dedupe, corrupt data, quota | `data-browser/src/helpers/knownPeers.test.ts` | |
| `forgetServerPeer` signs the exact `?node=` URL, and fails soft | `data-browser/src/helpers/managedServer.test.ts` | mocked `signRequest` |
| Opening a foreign HTTP drive does not move `serverUrl` | `browser/lib/src/store.set-drive.test.ts` | bare origin still switches the server; path-bearing HTTP is a drive |
| Canvas editing session merges a peer's stroke | `flutter/rust/src/api/simple/tests.rs` | |
| Whole-list rewrite (erase/undo) keeps a peer's stroke | `flutter/rust/src/api/simple/tests.rs` | |
| Bridge `start_peer` → `add_known_peer` → `peer_sync` pushes a drawing to a real remote process | `flutter/rust/src/api/simple/peer_tests.rs` | receiving side writes the receipt |
| Bridge known-peer bookkeeping (add / rename / dedupe / forget) | `flutter/rust/src/api/simple/peer_tests.rs` | |
| Bridge `peer_sync` to an unreachable node errors rather than hanging | `flutter/rust/src/api/simple/peer_tests.rs` | |
| **`POST /iroh-sync` request shape, both sides** | `testdata/pairing-request.json` + `pairing.test.ts` + `iroh_pairing.rs` | shared fixture binds them |
| Dart pairing-code parser, peer-sync result formatting | `flutter/test/atomic/` | pure parsers |
| Rotation does not treat a metrics-change pop as "back to gallery" | `flutter/test/canvas/rotation_pop_test.dart` | |
| `AtomicNode`: `mutate` on one node, `apply_commit(IngestPolicy::Peer)` on another, query + `DbEvent` reflect it | `lib/src/runtime/node.rs` | in-process, no transport; `LocalCache` skips signature check, `Peer` does not |

## Local full-text search

| Flow | Layer | Where |
|---|---|---|
| Exact title, prefix typeahead, 1-edit typo (`avacado`→`avocado`) | protocol | `lib/src/search/tests.rs` |
| Title ranks above description; parent/drive scope; Loro body text | protocol | `lib/src/search/tests.rs` |
| Update replaces old title; delete drops postings; commits skipped | protocol | `lib/src/search/tests.rs` |
| Tokenizer + prefix-Levenshtein | protocol | `lib/src/search/tokenize.rs`, `fuzzy.rs` |
| Query latency vs N (1k / 10k / 50k) | protocol | `lib/benches/search_bench.rs` (`--features db-redb`) |
| `Store.search` offline hits `ClientDb.search` | JS | `browser/lib/src/store.test.ts` |
| Search-result excerpts: document preference, exact/prefix before fuzzy, Unicode source offsets, token boundaries, bounded context including long matches | JS | `browser/data-browser/src/helpers/searchResultHint.test.ts` |

Not covered: table `contains`; Playwright search overlay on the KV path and assertion for the search-result excerpt; Flutter bridge `search`. Hosted `/search` is `atomic_lib::search` (Tantivy and MiniSearch are gone). Offline E2E polls `ClientDb.search`. Filters (`isA`, tags) are covered by `lib/src/search/tests.rs` and `server/tests/it/file_search_repro.rs`.

### Flow — the thin layer

| Flow | Where |
|---|---|
| Pairing code renders, is a routable envelope, carries no secret | `browser/e2e/tests/sync-devices.spec.ts` |
| Pasting a code: form gated to the app, malformed refused without dialling, node's refusal shown, success reports what synced, peer remembered | `browser/e2e/tests/pairing-dialog.spec.ts` |
| Paired-device cards render, expose a way to forget, and hide undialable entries | `browser/e2e/tests/pairing-dialog.spec.ts` |
| Copy pairing code | `sync-devices.spec.ts` |
| Add-a-device form validation | `sync-devices.spec.ts` |
| Sync page status renders | `browser/e2e/tests/sync.spec.ts` |
| Offline edits persist and sync on reconnect | `sync.spec.ts` |
| Second device cold-loads a drive from the server | `second-device-load.spec.ts` |
| Property reads stay pending through loading-placeholder notifications until hydration completes | `browser/lib/src/store.test.ts` |
| Cold-load local hydration: all `useResource` misses of one tick share one worker round trip, a duplicate subject is asked once, a miss during a flush lands in the next batch, a failed bulk read is a per-subject miss, batches chunk at 200 | `browser/lib/src/store.read-policy.test.ts` |

---

## Blind spots

### Plugin execution lifecycle (2026-09-05)

On `feat/plugin-model`, the JS plugin suite and Rust server plugin suite cover
caller-scoped get/query, verified drive binding, source pinning after edits,
review/source matching, no replay of pending/interrupted schedules, preservation
of query proposals, empty/partial checkpoint decisions, schema reuse and shared
TS/Rust manifest validation. `lib/src/db/plugin_schedule.rs` also decodes an old
MessagePack schedule containing an old approval. See
[plugin-model-review](planning/plugin-model-review.md) for limits and progress.

Remaining gaps:

- App/connection capability scope in addition to account authorization.
- Complete immutable release/installation lifecycle and permission upgrades.
- Remote write receipts, provider idempotency and uncertain-result recovery.
- Crash recovery of partially applied creates; current policy pauses for review.
- Durable event queue/backfill while a trigger's proposal waits for review.
- Egress streaming-cap and DNS pinning tests against a controlled HTTP provider.
- Connector convergence under normalization, concurrent edits and lost responses.

Ordered by how much they would hurt.

### 1. No cross-runtime peer test above the bridge

Canvas's *sync* is now covered against a real remote process
(`peer_tests.rs`), which is Canvas ↔ Desktop at the code level — both sides run
the same `atomic_lib` peer, and there is only one Iroh implementation, so the
wire protocol between any two surfaces is the same well-tested code.

What is still untested is everything **above** the bridge: the Dart call sites,
Flutter's lifecycle, the Tauri wrapper, and the browser driving a real node.
Android-specific behaviour (backgrounding, process death, 16 KB pages) has no
automated coverage at all and is still hand-verified on devices.

### 2. `peer_announce` and discovery from the bridge

`peer_announce` and `peer_discover_sync` remain untested — they depend on pkarr
relay reachability, which the bridge tests deliberately short-circuit by
handing addresses over directly. `pkarr_discovery_and_iroh_sync` covers
discovery in `atomic_lib`, but not through the bridge.

### 3. Remaining one-sided contracts

`POST /iroh-sync` is now bound by a shared fixture
(`testdata/pairing-request.json`): the browser test asserts it *sends* that
body, the server test asserts it *accepts* it, and renaming a field fails both.

`/forget-peer` is covered on both sides now — `iroh_pairing.rs` for the handler
(unsigned refused, full pair → listed → forget → gone lifecycle) and
`managedServer.test.ts` for the client (signs the exact `?node=` URL). They are
not *bound* by a shared fixture the way `/iroh-sync` is, so a rename would still
pass both; the query-parameter name is asserted literally in each.

Unbound: the `nodeId` property on `/server` as consumed by the browser — the
replacement for `/iroh-node-id`.

### 4. Tauri-gated UI

`ConnectToDeviceForm` (paste a code) and the pairing dialog are now covered —
`isRunningInTauri()` only checks for `window.__TAURI_INTERNALS__`, so
`page.addInitScript` reaching it is enough, and nothing on that path calls
`invoke`. See `pairing-dialog.spec.ts`.

Paired-peer cards are covered too, by seeding `atomic-peers` in an init script.

Still uncovered: `PairingLinkHandler`'s deep-link entry (the system camera
launching the app) and `IdentityReconcileGate`. Anything that genuinely calls
`invoke` needs a real desktop harness, not a faked global.

**Known wart, not a test gap:** `PairingLinkHandler` drops input that does not
start with `atomic://` or `did:ad:node:`, so pasting something that is not a
URI reports *nothing at all* — no dialog, no error. Only malformed input that
is URI-shaped reaches the flow and gets a message.

### 5. QR camera path

`scanPairingCode.ts` and the camera flow: untested at every layer.

### 6. Ephemeral / presence over Iroh

No producer or consumer exists (`EPHEMERAL` 0x40 is WS-only), so there is
nothing to test yet. Listed so it is not mistaken for covered.

### 7. Flutter integration_test is effectively dead

One 13-line smoke test, never run in CI — the pipeline has no emulator.

### 8. Known residual races

None outstanding. The concurrent-writer bug that lived here — a local edit
racing a peer update lost ~⅓ of all operations, because both paths
read-modify-write the same Loro snapshot and end in a replace — was fixed
2026-07-20 with a per-subject lock (`lib/src/subject_lock.rs`). Regression test:
`lib/tests/concurrent_commit_and_peer_apply.rs`, which lost 53–56 of 80
operations before the fix and now keeps all of them, with a sequential control
that isolates concurrency as the cause.

No known flaky tests. The one that was
(`rbsr_reduced_matches_full_sync_vv`) turned out to be a genuine RBSR bug, not
test noise — see below. (RBSR itself was removed in 2026-09.)

---

## Things that are *not* what they look like

Recorded because each one cost real debugging time.

- **`push_stroke` + `save_locally` cannot lose a peer's op.** The commit is
  imported into a freshly-read store doc and Loro import never removes ops. The
  damage from a stale editing session comes from *reads* — index-based deletes
  and whole-list rewrites — not from the append. A test written the obvious way
  passes with and without the fix.
- **A test child process must not drop its `Db`.** redb's `Database::drop`
  closes cleanly and makes pending `Durability::None` commits durable, so a
  durability test that lets the store drop is testing a graceful shutdown.
  `std::mem::forget` it before `abort()`.
- **Servers in one process share an Iroh node.** They all advertise the same
  node id regardless of whose store holds the data. Multi-server Iroh tests
  must use subprocesses, and the test process itself must run no server.
- **`--exact` filters need the module path** in the single-binary `it` suite
  (`iroh_pairing::child_runs_a_second_server`, not the bare name).
- **A leaked child server silently corrupts later runs.** Own it with a `Drop`
  guard so a panicking assertion still kills it.
- **The bridge's tests share one drive.** `DB` is a `OnceLock` and every test
  works in the same drive, so "find a canvas with strokes" matches a
  neighbour's drawing. Assert on a specific subject, and never change the
  active drive from a test.
- **Known peers are stored under a normalised node id**, not the
  `did:ad:node:` form the UI passes in. Look them up with
  `normalize_node_id`, or the lookup silently finds nothing.
- **A lock keyed only by subject couples unrelated stores.** `populate()` seeds
  well-known subjects that are byte-identical in every store, so a global
  registry makes two independent `Db` instances — including two tests sharing a
  process — wait on each other for no reason. `SubjectLocks` therefore lives on
  the `Db`, and every clone of a store shares one registry.
- **Measure a suspected regression on a quiet machine.** A test that looked
  newly flaky right after a four-minute stress run was passing 20/20 once the
  machine was idle. Compare against a stashed baseline under the same
  conditions before concluding you caused something.
- **A flaky test can be a real bug wearing a costume.**
  `rbsr_reduced_matches_full_sync_vv` failed ~1 run in 3. It was not noise:
  `reconcile_range` anchored its first child range at the first *local* key
  instead of the range's own `lo`, leaving `[lo, first_local)` covered by no
  child at all. A subject the remote had and we lacked, sorting below
  everything we held, was dropped from the diff and would never have synced.
  It looked intermittent only because the test's subjects are content-derived
  DIDs, so whether one landed in the dead zone varied per run — and
  `retries = 2` meant CI almost never showed it.

  The TypeScript port (`browser/lib/src/rbsr.ts`) had the **same** off-by-one,
  and it *is* live: `websockets.ts` uses it to compute the `subjects` filter a
  browser client sends the server, so an affected resource was never pulled.
  Both were fixed 2026-07-20, each with two deterministic regression tests.

  (RBSR was removed in 2026-09; the lesson stands.)

  **Treat a flake as an unread bug report until proven otherwise** — and when
  an algorithm is ported, check the port for the same defect.

- **An empty local-DB collection page used to drop its aggregates.** Count=0
  is a real statistic (and sum=null is too). Leaving `collection.aggregates`
  unset made dashboard/table totals render an em-dash forever, because the
  follow-up `ResourceUpdated` never came — the rows were already in the JS
  store. Guard: `collection-empty-trust.test.ts`, plus the dashboard e2e
  that waits for `946.5` / `4` rather than the placeholder.

- **Opening a filled table (and the sidebar) flashed as if order changed.**
  Two independent paints: (1) WASM `parent=` queries are unsorted;
  hydrating each member notifies `ResourceUpdated`, and `useCollection`
  optimistic-added them in arrival order before client-side sort wrote
  the page. Guard: `collection-page-assemble.test.ts`. (2) The sidebar
  fetched children while `isA` was still empty, so every table row
  appeared in the tree until the class arrived and hid them. The
  ResourceSideBar now treats unknown class as hide-children. OPFS
  cold-load could also shuffle array props (`requires`/`recommends`) by
  seeding a new LoroList from JSON-AD then merging the snapshot;
  `importLoroUpdate(snapshot, true)` replaces instead. Guard:
  `resource.test.ts` ("importing a snapshot over a cache-seeded doc").

### Algorithms mirrored in two languages

`lib/src/genesis.rs` ↔ `browser/lib/src/genesis.ts` share a personal-drive
derivation (`personal_drive_subject` / `personalDriveSubject`). The cross-lang
vector (`personal_drive_cross_lang_vector`) pins the nonce, signature, and DID.

## Unified actions

| Flow | Layer | Where |
|---|---|---|
| ⌘K action section: prefix/keyword match, cap, `available`/`disabled`, no mid-word / resource-name hits | glue | `browser/data-browser/src/actions/matchActions.test.ts` |
| Shortcuts overlay / `/app/shortcuts` list equals `appActions` + `resourceActions` that carry a shortcut | glue | `browser/data-browser/src/actions/catalog.test.ts` |
| `asTool` verbs derive AI tools; `execute` calls `run` and respects `available` | glue | `browser/data-browser/src/actions/deriveTools.test.ts` |
| ⌘K shows a matching action and runs it; a resource-name query shows none | flow | `browser/e2e/tests/command-palette-actions.spec.ts` |
| `?` overlay lists registry shortcuts; `\` toggles the sidebar | flow | `browser/e2e/tests/shortcuts.spec.ts` |
| ⌘M searchable menu + ⌘↑ parent from the registry | flow | `browser/e2e/tests/resource-context-menu.spec.ts` |
| Parent action stays available on a non-drive stub and fetches parent at run | glue | `browser/data-browser/src/actions/resourceActions.parent.test.ts` |

Not covered: derived AI tools invoked through a real model; MCP protocol projection (no Atomic MCP server yet); collapsing specialized `destroy()` call sites (table rows, views, tags) onto the resource delete action.
## View transitions

| Flow | Layer | Where |
|---|---|---|
| Hashed `view-transition-name` plus `view-transition-class` per tag | glue | `browser/data-browser/src/helpers/viewTransition.test.ts` |
| `startViewTransition` throw / hung `finished` / rejected `ready` still navigates and skips the overlay | glue | `browser/data-browser/src/helpers/viewTransition.test.ts` |
| Navigation skips `startViewTransition` unless the user opts in, and uses it once they do | glue | `browser/data-browser/src/hooks/useNavigateWithTransition.test.tsx` |

Not covered: visual morph of a grid card into the resource page in Firefox (needs a headed Firefox run; Playwright's firefox project is locks-only and automation bypasses view transitions unless `forceViewTransitions` is set). Android Chrome is not covered at all, which is why transitions are off by default ([#1563](https://github.com/ontola/atomic-server/issues/1563)): re-enabling by default needs a per-browser check first.

## Documents

| Flow | Layer | Where |
|---|---|---|
| V1 element list + paragraph markdown (+ resource embed) → TipTap JSON; leftover Yjs `XmlFragment` walker; `{ type: 'ydoc' }` detection without loading `yjs` | glue | `browser/data-browser/src/views/Document/documentMigrationUtils.test.ts` |
| Opening a writable v1 document migrates it silently into the Loro editor (no "Update Document" button) | flow | `browser/e2e/tests/documents.spec.ts` |
| Uploaded text-file conversion: supported MIME/extensions, literal text and line breaks, Markdown parsing, permission/download failure, and class replacement | glue | `browser/data-browser/src/views/File/convertFileToDocument.test.ts` |

No automated end-to-end coverage: uploaded-file conversion through the full UI and a server-backed save/reload (manually verified in Chromium). Also not covered: leftover Yjs-era DocumentV2 bodies end-to-end (needs a stored `{ type: 'ydoc' }` fixture); read-only v1 documents stay on the element list and have no e2e.

## Commits as envelopes

| Flow | Layer | Where |
|---|---|---|
| `LoroDoc` values are not KV-index keys | protocol | `lib/src/values.rs::loro_doc_is_not_indexed` |
| Content commits are not stored; genesis/ACL/destroy are | protocol | `lib/src/db/test.rs::content_commits_are_not_stored` |
| Signed destroy removes the resource, keeps its envelope and tombstones the subject in one apply | protocol | `lib/src/db/test.rs::destroy_commit_removes_resource_and_keeps_envelope_atomically` |
| Sequential saves do not chain `previousCommit`; commit DIDs are not store resources | glue | `browser/lib/src/commit.test.ts` |

## Personal drive identity

| Flow | Where |
|---|---|
| Same agent key → same personal-drive DID | `lib/src/genesis.rs`, `browser/lib/src/genesis.test.ts` |
| Cross-language personal-drive vector | `genesis.rs` + `genesis.test.ts` |
| Repeat genesis for that DID merges Loro state | `lib/src/commit.rs::repeat_personal_drive_genesis_merges` |
| Repeat genesis without a cert is still rejected | `lib/src/commit.rs::repeat_genesis_without_cert_is_still_rejected` |
| `createDrive({ personal: true })` uses the derived DID | `browser/lib/src/store.private-drive.test.ts` |
| Two stores with the same key mint the same subject | `store.private-drive.test.ts` |
| Extra drives are listed on the derived personal drive | `store.private-drive.test.ts` |
| Extra drive created offline drains on reconnect (genesis must not set a rewind baseline) | `browser/lib/src/offline-create-drain.test.ts` |
| Idempotent offline saves clear only after a complete local snapshot matches the synced baseline | `browser/lib/src/offline-create-drain.test.ts`, `browser/e2e/tests/offline-create-then-online.spec.ts` |
| Lists from a previous random-DID home are unioned onto the derived drive | `store.private-drive.test.ts` |
| `Agent.privateDriveSubject` matches the genesis helper | `agent.test.ts` |
| `Db::setup` / `ensure_personal_drive` use the derived DID and are idempotent | `lib/src/db.rs::personal_drive_tests` |
| Extra `Db::create_drive` is listed on the personal drive | `lib/src/db.rs::personal_drive_tests` |

Not covered: Flutter `create_drive` still mints a random DID (the Rust
`ensure_personal_drive` helper exists for `setup()`). E2E sign-in on a second
machine with the old machine offline.

Cloud Vault display metadata: `vaultAutoBackup.test.ts` verifies name/emoji enrollment and refresh after edits; SaaS `enrollment_display_metadata_refreshes_and_survives_legacy_clients` verifies persistence and account ownership.

## Cloud Server setup

- October 6 local audit: `atomic_lib`'s
  `sync_probe_bootstraps_an_admitted_missing_drive_only` covers first-upload
  hash probes, dense/sparse negotiation, unlisted and over-quota refusal,
  anonymous access and existing private roots. Probes create no resource.
- `cloudSync.test.ts` verifies that a standalone local agent profile is not
  promoted as an unenrolled drive. `local-only-drive.test.ts` verifies that
  copy verification waits for a readable root before requesting inventory.
  WebSocket rejection tests retain complete atomic, DID and HTTP drive IDs.
- `managedServer.test.ts` keeps public metadata requests free of cookies
  that belong to a different server on the same localhost hostname.
- The paired `drive-switcher-hosting.spec.ts` verifies that reopening the
  menu bypasses the brief metadata cache and reflects updated receipts.
- `data-browser/src/helpers/managed/cloudSync.setup.test.ts`: missing placement,
  source-server replication and refusal, assigned-server connection ordering,
  and failed connection without local-drive promotion.
- `data-browser/src/helpers/managed/reconcile.test.ts`: pending/empty placements
  do not switch the app away from its source.
- Paired `atomic-saas/portal/e2e/server-setup.spec.ts`: setup checks the selected
  drive's subscription before opening hosting in the app; it never creates a
  content-free enrollment in the portal.
- Paired `atomic-saas/portal/e2e/drive-billing-ux.spec.ts`: billing has no fake
  account-wide free plan, named drives survive selection/reload/Back, and a
  paid drive's price and quota do not leak into an unsubscribed drive.
- `data-browser/src/helpers/driveBillingUrl.test.ts`: Sync links preserve the
  exact drive and portal, or open the picker when no drive is selected.
- Paired `atomic-saas/portal/e2e/server-hosting-live.spec.ts`: opt-in real sign-in,
  grant, signed enrollment, setup UI, source replication and destination HTTP
  read. Requires two isolated nodes and dev magic links (`ATOMIC_HOSTING_LIVE=1`).
  Verified with plain and managed destinations. `ATOMIC_HOSTING_MANAGED=1`
  additionally checks Active usage receipts and the switcher state. Production
  deployment and Desktop/Tauri replication are not runtime-tested.
- October 6: the live hosting spec also exercises a drive registered as
  local-only, a standalone local agent profile, and a fresh browser signing in
  with the same agent secret and reloading the hosted drive. Both variants
  passed with strict console checks on two isolated current nodes. The local
  variant originates from `/app/dev-drive`; browser-only onboarding was
  additionally exercised manually. Paired portal regressions cover invitation
  quotas, retrying a refused admin revocation and editing an enrollment whose
  owner is an account ID. Production billing and deployment remain untested.

- Hosting consent: `cloudSync.setup.test.ts` refuses transfer/enrollment without
  an explicit agreement; paired SaaS HTTP tests enforce and record version 1.
- `driveHostingState.test.ts` covers Local/Remote, empty placement, combined
  Server/Vault, disabled, paused and unknown states. Paired SaaS
  `drive-switcher-hosting.spec.ts` checks menu rendering and refresh/error
  behavior against mocked receipts in the running browser app.

- Billing return: `enrollment.test.ts` checks the typed 402 response; paired
  SaaS `server-billing-live.spec.ts` follows a free account through mock checkout,
  back to the selected drive, then explicit consent, replication and an
  authenticated read from the real managed node. Plan purchase alone creates
  no enrollment. Real Stripe-hosted test-card checkout remains a deployment check.

## Host-to-Drive routing and hosted vanity subdomains

`Tree::DriveMapping` is what makes one server answer for many hostnames. It
backs `/bind-drive` for self-hosters and hosted vanity subdomains for
`atomic-saas`, whose control plane reconciles it through
`Db::sync_drive_mappings`.

- `db::drive_mapping_tests`: the reconcile a managed node runs on every policy
  poll — add, repoint, remove; idempotent on an unchanged list; scoped so a
  binding it did not install (including the `localhost` / `127.0.0.1` entries
  from `setup_test_env`, and anything bound by hand through `/bind-drive`) is
  never removed; keys normalized so a mixed-case `Host` still resolves; empty
  hosts and empty drives skipped.
- `db::resolver_tests::a_bound_host_whose_drive_is_missing_does_not_serve_the_store_root`:
  the multi-tenant leak. A host bound to a Drive this node does not hold (not
  synced yet, or migrated away) must 404 rather than fall through to the store
  root, which would answer one tenant's hostname with another namespace's
  content. This is the property that lets the control plane authorize a
  certificate on reservation instead of only after a node confirms.
- `context::tests::a_served_domain_suffix_accepts_tenants_without_a_base_domain`:
  `--served-domain-suffix` makes the request origin follow the hostname the
  visitor used, without turning on `--base-domain` and with it the store's
  subject normalization.
- Paired `atomic-saas` coverage (registry, plan gating, `/caddy-ask`, the
  heartbeat report) is listed in that repo's
  `planning/TEST_COVERAGE_AND_CI.md`.

**Not covered:** no test drives a real HTTP request against a vanity host
end to end — the reconcile and the resolver are tested separately, and joining
them needs the representative two-service environment. The multi-node gateway
routing that a second node would require does not exist yet.

## Error reporting and feedback

- `browser/data-browser/src/helpers/feedback.test.ts`: unavailable reporting, failed delivery, blank input and successful submission.
- `browser/data-browser/src/helpers/sentry.test.ts`: runtime disable override, environment and build attribution.
- `browser/e2e/tests/feedback.spec.ts`: sidebar form, unavailable-reporting guidance, failed Sentry transport, retained input and successful retry; uses a fake Sentry project with intercepted transport.
- `browser/data-browser/src/chunks/AI/formatAIChatReport.test.ts`: reviewable AI chat text, error inclusion, attachment-data exclusion, and long-chat truncation. `ai-sidebar-navigation.spec.ts` checks the menu, preview, and explicit send through a fake Sentry feedback transport; a real Sentry receipt still needs production verification.
- Real Sentry evidence and remaining production gates: `planning/sentry-feedback-readiness.md`.

### E2E browser diagnostic gate

Every spec imports the automatic fixture in `browser/e2e/tests/fixtures.ts`.
Unexpected console warnings/errors and uncaught exceptions fail; extra contexts
and tabs are included. `browser-diagnostics.spec.ts` verifies capture, exact
expectations and rejection behavior. See `planning/e2e-diagnostic-hygiene.md`
for current failures. This does not assert Rust process logs or Sentry delivery.

### Diagnostic root-cause follow-up (2026-09-07)

Strict probes cover feedback, sign-in, account changes, recovery and chat. Store
unit regressions cover loading personal-drive placeholders, database handoff,
render-time snapshot notification, and attachment creation before a form is saved.
WebSocket tests reject stale version-vector/reduced-sync responses after identity
or drive changes. Managed tests cover cancellation, eligibility, and confirmed
object collisions without a premature backup cursor advance. Concurrent local key
creation and sign-in use a persistence regression test.

See `planning/e2e-diagnostic-hygiene.md` and the SaaS
`planning/E2E_DIAGNOSTICS.md` for current acceptance totals and open release gates.

Additional regressions cover computed-filter membership invalidation, first-genesis
fork bodies, cancelled outbox writes, GET error classification, missing-base delta
recovery, and the known server-only browser capability fallback. Rust commit tests
count document-body changes in the causality guard while retaining rejection of
property writes that lose completely; expression tests exercise browser operator
aliases. The editor Link lifecycle test preserves telephone links across multiple
mounts without resetting or re-registering the global parser.

`lib/src/sync/protocol.rs` classifies a causality refusal as a conflict, and
`server/src/errors.rs` checks its HTTP 409 response. `browser/lib/src/local-outbox.test.ts`
classifies both the structured code and the older server message as blocking,
not terminal; the outbox's existing tests cover bounded retries and keeping
blocked edits pending. `lib/src/sync/outbox.rs` checks the same verdict for
native clients.

### Save durability and identity lifecycle regressions

- `save-acknowledgement.test.ts` exercises `Resource.save()` through the real
  outbox with a stubbed commit transport: server refusals (including terminal
  drops), backoff, blocked entries and cancellation cannot report persistence.
  It also covers offline transport failures, successful retries, unrelated
  subjects and edits arriving during an acknowledged save (#1388).
- `destroy-via-outbox.test.ts` exercises `Resource.destroy()` through the same
  outbox: an online delete POSTs one destroy commit and removes the resource; a
  delete while disconnected queues the pre-signed envelope, survives a simulated
  reload (fresh `LocalOutbox` hydrating the same agent namespace) and is POSTed
  exactly once on reconnect; create + delete while offline POSTs neither
  envelope; a never-saved `newResource` is dropped without a POST; a server
  refusal rejects `destroy()` and keeps the entry queued; a transport failure
  resolves as queued and flips the store offline; "already gone" server answers
  (`already applied here`, `predates the resource's genesis`, `does not exist
  yet`) count as acknowledged; a pending destroy blocks resurrection through
  `applyIncoming` / `hydrateResourceFromJsonAd` and is excluded from
  `computeDriveSyncState`. Not covered: a real server round trip for the
  reconnect drain (no `*.integration.test.ts` or Playwright variant yet).
- The outbox is stored in the client DB (`Tree::Outbox`).
  `local-outbox-database.test.ts` covers the storage layer against a fake
  database: the one-time import of a localStorage queue (durable before the key
  is removed, kept when the import fails), reads after a reload, which writes
  are durable, the not-hydrated window, edits made while rows load, a rebind
  during an attach, and the localStorage fallback. `outbox-client-db.test.ts`
  runs offline edit, create and delete through `Store` + `Resource` with a
  reload (a second `Store` on the same database) and the reconnect drain.
  `tests/outbox-client-db.integration.test.ts` repeats those against the real
  WASM database in Node, plus per-agent isolation. `client-db-durable-put.test.ts`
  checks the worker writes the row with the snapshot under one flush. Not
  covered: the OPFS worker and leader handoff in a real browser (Playwright).
- `issue-access-agent.test.ts` ("an issued agent queued while offline"): an
  app agent queued together with the folder it lives in (the drive-app install
  after a socket drop, ontola/atomic-plugins#171) drains after that folder, not
  in the agents-first tier, against a stub server that refuses a child whose
  parent it has not seen. The real server's rule is `check_append` /
  `check_agent_self_creation` in `lib/src/hierarchy.rs`.
- `server/tests/it/ws_fragmented.rs`: a `COMMIT` sent as a first frame plus
  continuation frames is joined and applied. Chromium sends any message over
  ~128 KB this way; the handler used to drop the socket (`1006`).

- `scripts/owned-process.node.mjs` exercises the template runner process lifecycle,
  including independent ephemeral ports and descendant cleanup. The superseded
  template-process helper and its standalone Playwright regression were removed.
- `cancelled-lifecycle.test.ts` covers cold-fetch cancellation, optional tree
  preload cancellation, pending worker destruction, and persistence rejection
  without misreporting cancellation as a storage fault. Real storage failures
  still reject and log errors.
- `loroSelection.test.ts` drives real ProseMirror transactions and Loro imports
  to verify that resource metadata arriving between keystrokes cannot reorder
  text. It guards the synchronous-selection patch to `loro-prosemirror` 0.4.3.

- `collection-page-assemble.test.ts` holds a local query in flight while a
  member is deleted, then releases the stale result. It checks membership,
  counts, skipped hydration, optimistic additions, and subsequent readmission.
- The `delete resource` smoke E2E requires a known sidebar link to disappear
  before reload; a success toast no longer substitutes for this assertion.
  Local Chromium verification passed using the existing Rust/WASM builds.
  One run timed out at the separate child-cascade store-removal barrier;
  a subsequent run passed, so cascade timing remains an intermittent gap.

- `client-db.worker.test.ts` requires vault cursor commits to flush before the
  worker acknowledges backup completion, and propagates flush failures. The
  SaaS `vault-refresh.spec.ts` checks stored objects and bytes across reloads.
- `db::compaction::tests::startup_compaction_shrinks_a_bloated_store_and_keeps_every_resource`
  (`cargo test -p atomic_lib --features db-redb --lib`) churns a real redb
  file through `Db::init_redb_file_with_policy` — overwrites that double in
  size plus throwaway resources deleted mid-file, so the buddy allocator
  cannot reuse the holes — and reopens it: the policy compacts, the file
  gives back most of the measured free space, every kept resource reads its
  last value, the record survives the next open, and a disabled policy leaves
  the file byte-for-byte alone. Overwrites *alone* leave only ~20% dead
  (freed blocks coalesce and get reused), which is why the test deletes.
  `server::config::tests` cover the `--auto-compact*` flags. Not covered:
  compaction of a store another process holds open (the open itself fails
  first, as before), and the cost of `DatabaseStats` on a multi-GB file.
- `synthetic_agent_reads_have_stable_history_without_persisting` checks that
  fallback agent lookups neither invent creation timestamps nor generate new
  CRDT history or persist a resource merely by reading it.
- `client-db.test.ts` verifies that cold worker initialization does not steal
  its own Web Lock or emit a false ghost-leader warning. It also covers safe
  follower calls and unacknowledged writes during lock handoff, plus a failed
  replacement worker. `client-db-locks.spec.ts` exercises the pending-call
  handoff with real tabs in Chromium and Firefox.
- `store.private-drive.test.ts` verifies that linking a private drive on a
  nodeless origin preserves the local profile without fetching it from the SPA.


- Client-library tests gate both the snapshot write and worker flush: an existing
  resource's save cannot resolve before either durability barrier completes.
- WebSocket tests deliver an old connection's close event after its replacement
  opens and verify the Store stays connected.
- HTTP and Loro-loader tests distinguish document-unload cancellation from an
  active-page failure; real failures remain visible.
- `initClientDb.handoff.test.ts` switches identities twice during the old worker's
  flush and verifies the obsolete intermediate database is never attached.
- Dashboard reload, offline tables, reconnect, search/deletion and generated
  Next.js/SvelteKit sites cover the corresponding browser flows.

The node-type toolbar lifecycle is covered by `NodeSelectMenu.test.tsx` (destroyed
editors do not expose state/commands) and `oxc-react-compiler.test.ts` (production
compilation does not hoist command getters into render). `sentry.test.ts` covers
packaged WebView initialization without server-injected Sentry configuration.

`react-compiler-cli.test.ts` covers the file-targeted compiler command: emitted
memoization, a bailout in a partially optimized file, explicit opt-outs, relative
paths, and continued checking after an unreadable file with a failing exit code.
It also verifies compact line/column diagnostics and optional verbose output.
`react-compiler-hook.test.mjs` covers UTF-8 source locations, advisory hook JSON,
per-session content caching, source changes, staged/untracked/deleted files,
excluded files, subdirectory invocation, ignored non-PostToolUse events and
advisory output when the hook cannot run. It feeds an Edit event to the script
through a symlinked path, verifying compact advisory JSON and silence on a
repeated check. The hook is opt-in personal config, so no agent config is tested.

Automatic Vault scheduling (`vaultAutoBackup.test.ts`) covers sustained-edit
maximum delay, queued edits across drive switches, late account availability,
connectivity recovery, enrollment rediscovery after reload, account expiry during
encryption and in-flight requests, and distinguishing
Tauri embedded nodes from remote servers. Native background execution after OS
suspension remains outside this scheduler's guarantees.

## Collaboration profile onboarding

The `e2e.spec.ts` authorization/invite and chatroom journeys now complete the
full-name step for inviter and new invitee, retain the secret-backup step, and
verify subsequent shared access. The chatroom journey also checks the named
personal drive. Browser warnings/errors fail these tests, including localization
render warnings. The authorization journey also covers cropped avatar upload, metadata and image
download from the recipient account, and existing-agent acceptance. SaaS
email-to-drive acceptance still needs dedicated flow coverage.
`ollama-feedback.spec.ts` checks sidebar feedback hover, local Ollama discovery
only after expanding AI settings, one-click URL acceptance and persistence after
reload. Its default run stubs the model-list endpoint; `TEST_REAL_OLLAMA=1` ran
successfully against local Ollama on 2026-09-08. The shared setup-panel component
is not separately covered by this probe. The existing Vite-only Wuchale/React
key warning when expanding AI settings is explicitly expected; other console
errors remain failures.

`username-live.spec.ts` changes the owner's display name through user settings
while a different agent reads an existing chat message. It asserts the author
updates without a reload and verifies a second change after the reader reloads.
`websockets.test.ts` checks targeted profile SUB frames, subscription replay,
multiple-reader cleanup through both Store unsubscribe APIs, and retaining
ordinary document drive-wide fan-out. Profiles no longer depend on being inside
the reader's active drive to receive live updates.


### Per-drive Cloud Server display

`driveSyncStatus.test.ts` rejects another drive's sync timestamp and scopes
asynchronous hosting/usage results to the selected drive and server. It covers
unenrolled/local drives and shared drives confirmed directly by their node.
`sync-devices.spec.ts` renders a managed connection with zero data for the selected
drive, injects another drive's completed sync, and verifies that Cloud Server
stays off with its setup action visible.

- Managed Vault display metadata: `vaultAutoBackup.test.ts` now covers a drive
  present only in local storage, as well as rename/emoji refresh. Manual enable
  and automatic backup share `driveDisplayMetadata`; only name and emoji are sent.
- FOSS account lookup: `helpers/managed/session.test.ts` verifies that an installation with no managed API does not probe the hosted account endpoint.
- FOSS logout: `helpers/managed/session.test.ts` verifies that an installation
  with no configured control plane makes no SaaS logout request (the CI smoke
  test exposed a 405 at `/api/logout`).

## Desktop workspace discovery (2026-09-08)

`sync::discover::tests::inspection_checks_access_without_importing_or_pairing`
uses real Iroh endpoints with node-bound AUTH: an authorized identity sees a peer name without importing
the drive or pairing; a stranger is rejected. The local Tauri debug build connected
to staging's advertised Iroh node and received a no-readable-data response for its
test identity. Live drive and node PKARR signatures were verified separately.
This does not yet prove restoration of the user's private staging workspace.

## Recovery-code passkey enrollment

`browser/data-browser/src/helpers/managed/recovery-enrollment.test.ts` verifies code-only reveal without WebAuthn, preservation of ciphertext and existing wrappers when adding a passkey, unlocking with either passkey, and no writes on wrong-code, account-mismatch or cancelled registration. Tests use WebCrypto, Argon2id and a simulated authenticator; physical mobile PRF support remains a device acceptance check.

## Plugin UI sandbox and private assets

- `browser/e2e/tests/plugin.spec.ts`: private plugin assets load through signed parent requests; custom rendering and RPC still work.
- The bootstrap test opens the shell directly and verifies its server-enforced opaque origin, independently of iframe attributes.
- `signout-signin-data.spec.ts` uses fresh persistent profiles on macOS WebKit because ephemeral contexts reject OPFS; these remain browser tests, not native Tauri acceptance.

- `browser/lib/src/store.test.ts`: receiving an older resource preserves the merged value in both JSON and the persisted Loro snapshot; dashboard configuration reload exercises the real OPFS path.

## Plugin release and recovery additions

| Flow | Layer | Where |
|---|---|---|
| Immutable package identity, corruption refusal, explicit public catalog | protocol | `lib/src/db/plugin_release.rs` |
| Local replay reuses created identities; uncertain receipt blocks duplication | glue | `server/src/plugins/apply.rs` |
| Duplicate external delivery and lost response after provider write | glue | `server/src/plugins/external.rs` |
| Independent edits, conflicting edits, tombstones, partial pages, acknowledged baseline | glue | `browser/lib/src/plugin-reconcile.test.ts` |
| Signed publication/write SDK refuses anonymous calls and never blindly retries | glue | `browser/lib/src/plugin-connection.test.ts` |
| Publish, discover, create independent draft | flow | `browser/e2e/tests/plugins.spec.ts` |

Not covered: real provider conformance, durable trigger edge backfill and upgrades.
Catalog badges remain unverified. Recovery and baseline coverage is listed below.

Plugin recovery follow-up (2026-09-06): `plugins/external.rs` tests confirmed-applied
recovery after a lost provider response, audit retention, evidence validation,
connection isolation and refusing receipt replacement. `plugins/connection_state.rs`
tests stale checkpoints, divergent projections, whole-page atomicity, identity
collisions, empty pages and tombstones. `plugin-connection.test.ts` covers recovery
SDK serialization and refusing automatic retry of a stale checkpoint. These are
host-contract tests; provider verification and a recovery UI remain uncovered.

## GitHub issues ↔ kanban pilot

`server/src/plugins/sync_session_tests.rs` runs the shipped provider bundle in
QuickJS/WASM against real Atomic persistence and a simulated GitHub host. It covers
imports, creations, independent/competing edits, kanban transitions, unrelated
labels, stale previews, uncertain-write refusal, approval identities and an
imported issue triggering a linked chatroom Message through the ordinary trigger
engine. `connection_state` tests cover idempotent checkpoint recovery.

The provider's own suites (`adapter.test.ts`, `automation.test.ts`, the live
tests) moved to atomic-plugins with `integrations/github-issues`.

Live GitHub conformance, durable event replay, concurrent-edit atomicity,
background sync and scale/performance are not covered. Dagger's Rust test feature
selection now includes the sandbox; the updated container gate has not been run.


### Background sync and independent JS automations (2026-09-06)

- `plugins/triggers.rs`: transactional event backlog while no listener runs or a
  review is pending, preserving a waiting event when auto-execution is enabled,
  and subprocess termination/reopen before notification delivery.
- `plugins/sync_worker.rs`: completed-review grant requirement, pinned background
  execution, no repeat on a quiet tick, and hard restart midway through a saved
  session without a browser or duplicate Atomic create.
- `plugins/sync_session_tests.rs`: hard termination after provider acceptance,
  uncertain-result refusal, verified-receipt recovery without resending, and
  discovery markers excluding initial backfill/local-origin issues.

Still not certified: live GitHub failure recovery, multi-provider remote-action workflows, guided
Atomic uncertain-write recovery, query-outbox performance/retention at scale and
the Dagger container gate. Queue storage prevents loss; it does not imply
cross-system exactly-once execution or automatic reconciliation of uncertain writes.

### Live connector query snapshots

Moved to atomic-plugins with `integrations/github-issues` (its live tests
and fixture suites). `uuid_paths_are_single_canonical_segments` still
covers constrained UUID authorization and path-escape rejection here.

### Named integration actions

- Rust `plugins::actions::tests`: actual GitHub JS/WASM preparation, strict inputs,
  actor checks, explicit automation reference/release pin, stable call IDs, stale
  and expired approval, successful and uncertain-write retry protection (fake provider).
- `browser/lib/src/integration-actions.test.ts` and `plugin-manifest.test.ts`:
  MCP adapter/shared signed API contract and bounded action schema validation.
- GitHub install Playwright flow: named action form and sandbox-backed preparation;
  approval transport stubbed so no live GitHub issue is created.
- `plugins::actions::tests`: persisted history, cancellation, fresh recovery evidence,
  source/actor/configuration-pinned grants, app-scoped access, revocation, manual
  preview refusing automatic writes, and the fresh-call rate limit.
- Trigger and scheduler `integration_approval_resumes_*` tests: saved waits,
  same-input replay, receipt reuse, one Atomic effect after approval (fake provider).
- `browser/data-browser/scripts/integration-mcp.test.mjs`: real SDK stdio handshake,
  signed loopback requests, no approval tool and refusal of remote plaintext origins.
- Extended GitHub browser flow: cancellation, granting/revoking action permissions,
  recovery inspection followed by explicit confirmation (provider responses stubbed).
- Open: live provider recovery, production load, history archival,
  remote HTTP/OAuth MCP deployment and provider-specific automatic matching.

History pagination regression: `plugins::actions::tests::history_pages_migrate_ties_and_isolate_actors_under_load`
seeds 2,001 action records, migrates legacy rows, traverses tied timestamps,
inserts during traversal, rejects invalid cursors/page limits and excludes another
actor's records. It also verifies that expired history does not enter the pending
approval list. Browser `plugins.spec.ts` checks Load more and recovery together;
`integration-actions.test.ts` checks signed pagination requests. Production load
and worst-case automation-retention load remain untested.

Manual action retention: `compaction_preserves_ids_and_skips_provider_and_automation_records`
covers non-mutating preview, payload reduction, idempotent application, refusal of
archived IDs and approvals, and preservation of recent/manual provider attempts
and automation-originated records. The JS signed API test verifies preview defaults;
`plugins.spec.ts` checks that preview sends no cleanup mutation and the archive
button explicitly applies it (synthetic cleanup response). Physical database
shrinkage and compaction of consumed automation receipts are not covered.

Completed manual retention:
`completed_manual_retention_preserves_journal_tombstones_and_recent_recovery`
verifies explicit opt-in, 30-day settlement age, preservation of unknown-age/failed/
automation receipts, removal of duplicate recovery payloads, per-action counts,
idempotent cleanup, and refusal of direct executor retries against archived IDs.
The cleanup browser regression checks the real signed preview endpoint on a fresh
connection, then the opt-in request and explicit application using a synthetic batch.
Production retention/load measurements remain open; this test does not establish a safe deletion policy for automation receipts.

Completed automation acknowledgement: scheduler and trigger tests named
`finished_*_acknowledges_without_replaying_or_reading_old_waits` first execute a
successful run, then restore an interrupted schedule/queued event with unusable
integration waits. Fresh worker passes acknowledge the terminal run, preserve its
completion marker and create no second effect. These simulate the persisted crash
window; they do not kill a process at that exact instruction. Concurrent consumer/cleanup lock-race stress testing remains open.

Automation receipt ownership:
`automation_retention_waits_for_every_consumer_and_preserves_untracked_calls`
checks multiple consumers, completion age, a new active consumer preventing
cleanup, finished-run refusal, old-client opt-out and permanently protected
untracked access. Runtime test
`only_host_triggered_runs_own_receipts_and_js_cannot_change_the_identity`
checks public trigger spoofing and mutation of the trusted trigger ID in JS.
The cleanup UI passes explicit automation opt-in through the signed endpoint.
Worst-case consumer-count load and abandoned-consumer reconciliation remain open.

Consumer abandonment: `abandoning_a_consumer_is_audited_busy_safe_and_preserves_uncertainty`
checks busy-worker refusal, unrelated IDs, wrong actor, required reason, immutable
audit, refusal of future plan/receipt use, a fresh retention period, no approval
when all consumers were abandoned, and preservation of uncertain provider status.
Scheduler/trigger `abandoned_*_is_acknowledged_without_applying_its_saved_plan`
tests cover terminal acknowledgement without writes. The browser uses synthetic
consumer responses to check inspection, required reason and one explicit abandon
request; the JS client test checks the signed request fields. Deleted-automation
reconciliation and per-run (rather than per-worker) concurrency remain open.

Runtime feature coverage: `cargo check -p atomic-server` and
`cargo check -p atomic-server --no-default-features --features light` validate
both default runtime-on and runtime-off binaries. The `wasm-plugins` feature
controls the nested WASM build, runtime modules and runtime HTTP registrations.

`discoverIntegrations.test.ts` checks assistant capability search, exclusion of
nonconnection drafts, partial failures and drives without a plugin schema.
It does not validate model tool selection or live provider credential health.

Assistant event previews: `previewTrigger.test.ts` checks event identity, payload,
clock validation and manual fallback. The existing Rust runtime authority test
was rerun successfully. New in-chat proposal controls use host refetch and existing
approve/cancel endpoints; browser interaction and live-model behavior are not yet covered.

Task schema/template pilot: `tableTemplates.test.ts` checks shared references
across Issue Tracker and Project Tasks. `task-schema.test.ts` checks the embedded
vocabulary against exported identities/options. `client-proxy.test.ts` checks
identity-preserving local schema resolution and rejects an unrelated proxy
identity. GitHub setup into an existing Project Tasks table moved to
atomic-plugins with the provider.
# GitHub token setup shortcut

The connection form now links to GitHub's fine-grained token template with
Issues write access and the owner from a valid owner/repository input. Catalog
extraction was checked; live GitHub token generation has not been tested.

New automation and integration shortcuts open a fresh assistant chat with resource
context, requesting user intent before draft creation. Browser acceptance of
these entry points and assistant-led creation remains open.

## Shared import identity and source baselines

`browser/lib/src/import-records.test.ts` covers native localId persistence,
immediate-parent identity scope, ambiguous duplicates, local/source conflicts,
append-only source changes, existing links, interrupted batch replanning and
legacy adoption. `plugin-apply.test.ts` also verifies distinct approval markers
without modifying the reviewed proposal.

`lib::import_identity::tests` covers these real-Db scenarios: concurrent signed identity
claims have one winner (the same ID in another destination succeeds), and stale
baselines/duplicate approvals cannot overwrite newer source values or local edits.
The existing `did_import_resolves_forward_local_id_references` regression confirms
JSON-AD nested references and reimport retain their subtree namespace.

MT940 and Clockify provider tests and certification moved to atomic-plugins;
the dated verification notes below mentioning them are history.

Remaining: offline-peer identity collision repair and whole-batch atomicity.
Process-abort recovery, lost-receipt recovery and browser conflict review
are covered by the follow-up checks below.

### Import follow-up acceptance

- Shared mapper/verdict/apply/Clockify Store suite: 54 tests pass. The Store test
  now injects a lost receipt after durable creation, then replans and applies only
  the missing two records. This is failure injection, not an OS-process kill.
- Core identity suite: three real-Db tests, including reviewed local-value
  preservation and stale-resolution rejection.
- Installer/Clockify update helpers: three tests for recovery after a lost receipt,
  failed-query refusal, JSON-only settings extraction and replacement generation.
- Browser: MT940 and both Clockify flows pass. The linked Clockify flow now also
  exercises both conflict choices, clean repreview, and a reviewed installed-code
  update that restores the bundled source without changing its settings.
- All four provider certifications pass (50 offline fixtures; four live cases
  skipped intentionally). GitHub and Notion real-runtime tests additionally assert
  persisted provider-qualified native localIds while retaining two-way behavior.
- `lib/tests/import_durability.rs` aborts a child process after an acknowledged
  DID import, reopens redb and verifies identity lookup plus continued nested writes.
  Removing the commit flush reproduces loss; restoring it passes.
- Schema unit tests recover unattached saved terms. The resumable-installation
  helper reuses saved logical steps while preserving repeated identical rows.
  `installation-recovery.spec.ts` injects a lost table-class receipt and checks
  that retries reuse the class, table and view.
- Duplicate-review fixture covers record links and blocked Apply; it does not
  simulate replication between independent nodes.
- Still unfinished: cross-node collision repair, universal adoption of resumable
  setup, and live account upgrades.

### Recovery verification (2026-09-07)

Five Chromium flows pass against rebuilt native/WASM code: interrupted table
installation, duplicate-source review, MT940 import/reimport, Clockify setup
errors and Clockify linked import/conflict/upgrade. Both changed providers pass
full offline certification. Frontend typecheck and client declaration build pass.
The three core identity tests pass, with the stale-baseline regression repeated
15 times to exercise concurrent Loro ordering. These checks make no live provider
writes and do not demonstrate offline collision repair.

### Offline duplicate preservation

`import_identity::tests::offline_duplicates_remain_visible_after_sync_in_both_orders`
creates the same source identity independently in two databases. Bulk SYNC_PUSH
and live UPDATE each preserve both DID resources and their distinct names in
both arrival orders and on replay. Lookup reports ambiguity and a third authored
import is rejected. This exercises the real persistence/index path, but not
network transport, OS-process isolation or reviewed alias/reference repair.

### Reviewed primary-record decisions (2026-09-07)

- Native identity regression now saves a signed decision, rejects a stale member
  snapshot, keeps both original values, survives replay, and reopens review on a
  new offline edit. Both bulk/live arrival orders remain covered.
- `import-resolution.test.ts` covers ordering, primary updates, retained-copy
  changes, missing/unseen members and competing decisions followed by re-review.
  The mapper test verifies subsequent proposals target only the reviewed primary.
- Connection-state test verifies alias provenance, preserved baseline, incremented
  revision, idempotent reads and rejection of the earlier checkpoint revision.
- `drain-datatype-tags.test.ts` reproduces and fixes newly added JSON values becoming
  strings on incremental saves. It also drives the public `newResource → set → save`
  flow through the real outbox drain and replays the posted `loroUpdate`s: the signed
  incremental commit carries `json`/`resourceArray` tags for properties first set
  after genesis, and the tag write runs after the user's ops are sealed, so the edit
  keeps its own commit origin and stays on the undo stack. The full client suite has
  564 passing tests.
- Five Chromium flows pass against rebuilt native/WASM code. Duplicate review uses
  real authenticated SYNC_PUSH plus a signed primary decision and fresh lookup;
  the other flows cover setup recovery, MT940 and Clockify. It does not yet test
  field consolidation, graph-wide relinking or independent OS-process resolution.
- Frontend typecheck and client declaration build pass. Clockify and MT940 offline
  certifications pass; no live provider writes were made by these tests.

### Reviewed field consolidation

`import-resolution.test.ts` covers explicit choices, absent fields, protected
fields and unknown members. The native offline-duplicate regression now rejects
an unfulfilled choice and persists the reviewed field value while preserving
the retained record, through both replica ingress paths and arrival orders.
`import-reference-review.test.ts` covers typed links, preserved array order and
multiplicity, skipped history/text/JSON, lost acknowledgements, stale records and
idempotent retry after partial completion. The native signed-commit test verifies
that a stale link update cannot overwrite a newer value, while normal edits can
retain the review receipt. Five native identity tests pass.

The Chromium duplicate-review flow now also selects a value from the other copy,
saves it to the primary, discovers a typed incoming link, applies it and verifies
that refreshing finds no remaining supported links. Broader graph-wide discovery,
all-or-nothing multi-record transactions and actual network partitions remain
outside this coverage.

The extended link-review browser flow also edits a second record after preview:
its link stays unchanged, the other record is confirmed, and reopening the primary
page resumes discovery without duplicating completed writes. Five focused browser
flows passed across the final runs (setup recovery, duplicate review, MT940 and
Clockify), with 567 client tests, native checks and offline certifications passing.

### Searchable creation catalog (2026-09-08)

`new-resource-catalog.spec.ts` verifies searchable table and website templates in
folders, selection passed to table setup, server-confirmed nesting for table and
website imports (both parent URL parameters), and the minimal assistant prompt
on a 390px viewport. It checks that the request remains editable when a model
needs connecting; it does not send a live model request. The blank-table setup
regression also passes. `creationCatalog.test.ts` covers catalog completeness,
multiword search and the assistant parent context. Frontend typecheck passes.

## Workspace and connection navigation (2026-09-08)

`browser/e2e/tests/integration-workspace.spec.ts` installs a GitHub connection
without provider credentials and verifies the native kanban workspace opens,
connection settings keep source and secrets behind their tabs, automation creation is available,
and a changed opening-view setting survives reload. Uses the existing table view
renderer and table-default-view property. Typecheck passes. No live provider sync
or standalone custom AppFrame behavior is exercised by this test.

The integration workspace browser check also visits all management tabs and
verifies Edit with AI opens the assistant with an editing request. Screenshots
were inspected for tab spacing. This verifies handoff, not live model edits.

The integration workspace test holds the preview HTTP response to verify the
spinner, busy label and disabled button, then returns a provider error and checks
that the error is visible and preview can be retried. No live provider request is
made for this failure-path check.

## Collaboration profile onboarding

The `e2e.spec.ts` authorization/invite and chatroom journeys now complete the
full-name step for inviter and new invitee, retain the secret-backup step, and
verify subsequent shared access. The chatroom journey also checks the named
personal drive. Browser warnings/errors fail these tests, including localization
render warnings. The authorization journey also covers cropped avatar upload, metadata and image
download from the recipient account, and existing-agent acceptance. SaaS
`portal/e2e/invite-signup.spec.ts` covers a real invitation through email signup,
recovery-code backup, automatic acceptance, and workspace reload. It also restores
the existing identity in a second browser before accepting the invitation again.
The test injects the standalone node's managed/portal metadata and declines
automatic workspace-vault enrollment (no S3 service). Invitation, email login,
encrypted identity recovery, and workspace operations use real local services.
The invite journey also rejects transient duplicate acceptance buttons, opens the
avatar file picker from the person button, and checks Feedback in the secret
backup dialog. `onboarding-storage.spec.ts` injects a failed ClientDb initialization
and verifies that signup controls stay hidden while recovery advice and Feedback
remain available. `onboardingStorage.test.ts` covers initialization readiness,
failure, missing attachment, and timeout. Actual private-window storage policies
across browsers remain outside the injected-failure test.
`ollama-feedback.spec.ts` checks sidebar feedback hover, local Ollama discovery
only after expanding AI settings, one-click URL acceptance and persistence after
reload. Its default run stubs the model-list endpoint; `TEST_REAL_OLLAMA=1` ran
successfully against local Ollama on 2026-09-08. The shared setup-panel component
is not separately covered by this probe. The existing Vite-only Wuchale/React
key warning when expanding AI settings is explicitly expected; other console
errors remain failures.

`username-live.spec.ts` changes the owner's display name through user settings
while a different agent reads an existing chat message. It asserts the author
updates without a reload and verifies a second change after the reader reloads.
`websockets.test.ts` checks targeted profile SUB frames, subscription replay,
multiple-reader cleanup through both Store unsubscribe APIs, and retaining
ordinary document drive-wide fan-out. Profiles no longer depend on being inside
the reader's active drive to receive live updates.


### Per-drive Cloud Server display

`driveSyncStatus.test.ts` rejects another drive's sync timestamp and scopes
asynchronous hosting/usage results to the selected drive and server. It covers
unenrolled/local drives, unknown enrollment, and the requirement for both enrollment and remote data before claiming hosted service. Node synchronization remains a separate status.
`sync-devices.spec.ts` renders a managed connection with data but no enrollment,
injects another drive's completed sync, and verifies that Cloud Server does not
claim hosting. It checks unknown recovery wording, account refresh on window focus,
and missing translation markers. `saved-drives.spec.ts` checks that a portal Open
link selects the requested drive, consumes the drive parameter, and preserves
current-drive behavior for ordinary resource links.

- Managed Vault display metadata: `vaultAutoBackup.test.ts` now covers a drive
  present only in local storage, as well as rename/emoji refresh. Manual enable
  and automatic backup share `driveDisplayMetadata`; only name and emoji are sent.
- Standalone account probes: `helpers/managed/session.test.ts` verifies that
  no `/api/me` request is made without a configured control plane.
  `helpers/managed/api.test.ts` covers localhost/127.0.0.1 without implicit SaaS
  routing, explicit local API configuration, and discovered/build portal routing.
- FOSS logout: `helpers/managed/session.test.ts` verifies that an installation
  with no configured control plane makes no SaaS logout request (the CI smoke
  test exposed a 405 at `/api/logout`).

## Desktop workspace discovery (2026-09-08)

`sync::discover::tests::inspection_checks_access_without_importing_or_pairing`
uses real Iroh endpoints with node-bound AUTH: an authorized identity sees a peer name without importing
the drive or pairing; a stranger is rejected. The local Tauri debug build connected
to staging's advertised Iroh node and received a no-readable-data response for its
test identity. Live drive and node PKARR signatures were verified separately.
This does not yet prove restoration of the user's private staging workspace.

## Recovery-code passkey enrollment

`browser/data-browser/src/helpers/managed/recovery-enrollment.test.ts` verifies code-only reveal without WebAuthn, preservation of ciphertext and existing wrappers when adding a passkey, unlocking with either passkey, and no writes on wrong-code, account-mismatch or cancelled registration. Tests use WebCrypto, Argon2id and a simulated authenticator; physical mobile PRF support remains a device acceptance check.

## Plugin UI sandbox and private assets

- `browser/e2e/tests/plugin.spec.ts`: private plugin assets load through signed parent requests; custom rendering and RPC still work. The compiled PluginPage flow checks client metadata updates without replacing its mounted resource, active draft preservation, valid/invalid config, Save completion and offline save/reconnect persistence.
- The bootstrap test opens the shell directly and verifies its server-enforced opaque origin, independently of iframe attributes.
- `signout-signin-data.spec.ts` uses fresh persistent profiles on macOS WebKit because ephemeral contexts reject OPFS; these remain browser tests, not native Tauri acceptance.

- `browser/lib/src/store.test.ts`: receiving an older resource preserves the merged value in both JSON and the persisted Loro snapshot; dashboard configuration reload exercises the real OPFS path.

Drive changes and reauthentication on an already-open WebSocket: `browser/lib/src/websockets.test.ts` verifies a fresh SYNC is sent without reconnecting, including local-only drive exclusion. This covers the Sync page remaining at Connecting after sign-in or drive switching; live staging acceptance remains separate.

### Pending fork banner

`PendingForks.test.tsx` rejects ordinary resources, proposals for another subject,
and loading candidates even if a query page lists them. `forks.spec.ts` checks
ordinary resources after reload and real proposals on their original resource.
The reported Safari query contamination is not reproduced locally: WebKit test
setup currently fails opening OPFS before it can create its dev drive.

### Managed admission retries and content-addressed image downloads

- `local-outbox.test.ts`: enrollment/quota refusals stop after bounded retries,
  retain dirty edits, and can be re-armed by a new edit; legacy messages and
  structured `SYNC_REJECTED` classification are covered.
- `store-commit-fallback.test.ts`: a WebSocket enrollment refusal is not
  duplicated over HTTP; a transport failure still falls back.
- `local-outbox.test.ts` ("classification is code-first") and
  `save-acknowledgement.test.ts` ("terminal drops are classified by error
  code"): a recognized `AtomicError.code` (`GENESIS_COLLISION`,
  `IMMUTABLE_COMMIT`, ...) decides terminal/benign/blocking regardless of
  message wording, including one parsed off an HTTP `/commit` JSON-AD error
  body's `errorCode`; a code-less legacy message still classifies; another
  recognized code wins over a legacy phrase in the message. Rust:
  `protocol::classify_commit_error_matches_known_patterns` covers
  `IMMUTABLE_COMMIT`.
- Server `errors::admission_error_tests`: enrollment/quota refusals carry a
  blocking code and HTTP 403 rather than an internal-error response.
- Server `tests::content_addressed_image_download`: raw, WebP and AVIF downloads
  work for a blob with no File resource at its hash URL; missing hashes return
  404, and attachment/nosniff headers are retained for renditions.

Staging triage verified that the two reported hashes still returned HTTP 200
without resize parameters. Deployment acceptance must recheck their resized
URLs and confirm the rejected-write rate falls after clients update.

Automatic browser discovery: `browser/data-browser/src/helpers/browserPeerSync.test.ts` verifies deterministic per-drive rooms, automatic startup for locally snapshotted drives, duplicate prevention, and skipping unknown snapshots. `ATOMIC_PEER_AUTOMATIC=1` with `verify-peer-mesh.mjs` verifies eight browsers rediscover trusted local drives without saved invitations, then sync creations, presence, attachments, reconnects and deletion. Full app UI acceptance remains separate.

The WebSocket unit suite also covers a socket closing while an asynchronous version-vector probe is computed: no SYNC is sent on the closed connection. General UI tests stub public discovery with an empty room; the separate peer mesh acceptance script still exercises real signaling and authenticated sync.

## Account drive catalog

`helpers/managed/driveCatalog.test.ts` covers union/deduplication, removal precedence,
offline retry/cache isolation, and stale results after logout or account switching.
`e2e/tests/drive-catalog.spec.ts` renders an account-only drive without a local
saved pointer, publishes the local drive, and applies a removal after reconnect
(real app/node, mocked account API). Existing saved-drive tests remain separate.
SaaS handler tests cover authenticated additive registration, account isolation,
service-backed discovery and removal versus stale upload. Catalog entries confer
no access to resource content. A live cross-app deployment acceptance is separate.

## Unified account passkey

`helpers/managed/accountPasskey.test.ts` checks account-credential reuse, server-challenge registration, PRF-output exclusion from API payloads, cancellation and standalone fallback. `recovery-enrollment.test.ts` covers additive migration, old recovery-code preservation, failed upgrades, unsupported login credentials and duplicate-credential PRF-salt selection. These use simulated authenticators and real WebCrypto/Argon2id.

Paired SaaS `portal/e2e/recovery-passkey.spec.ts` uses Chromium virtual PRF authenticators with the real control plane to verify app enrollment followed by portal login using one credential, reuse of a portal-created credential, and account-settings migration without replacing ciphertext or old wrappers. Physical Safari/iCloud, Android/password-manager and native-shell behavior remain device acceptance checks.

## September 10 SaaS and browser invite regressions

- `browser/lib/src/browser-peer-invite.test.ts`: signed invitation validation, expiry, target and issuer checks, recipient proof, and additive permission grants.
- `browser/e2e/tests/browser-invite.spec.ts`: distinct signed-in identities create an invitation through the sharing UI and join a local drive using real WebRTC with an in-process signaling relay. Runs against production assets without Vite source imports or a SaaS dependency, and verifies received content and write rights. `store.test.ts` prevents explicit server refreshes from poisoning local-only drives with server errors.
- `browser/e2e/scripts/verify-peer-sync.mjs` with `ATOMIC_PEER_INVITE=1`: invitation bootstrap and real WebRTC reconciliation with HTTP data access disabled.
- `browser/e2e/tests/recovery-option.spec.ts`: recovery availability in the managed welcome flow.
- Existing-drive migration to browser-only storage and fresh-account email onboarding through a peer invitation remain unverified.

- `browser/data-browser/src/helpers/passkeySupport.test.ts` checks secure-context and credential API availability. `browser/e2e/tests/passkey-unavailable.spec.ts` removes WebAuthn from the browser and verifies that account settings explain the limitation, hide passkey setup, and preserve recovery-code access. Native credential-provider failures with the API present remain outside this check.


## Managed sync presentation and local transition

`syncPresentation.test.ts` covers Vault-aware summaries and hiding unrelated
saved managed nodes. `enrollmentApi.test.ts` distinguishes unknown hosting from a
successful empty enrollment list. `client-db.test.ts` covers nested WASM Map
normalization, and `local-drive-copy.test.ts` rejects incomplete history and
missing/corrupt attachments.

`managed-sync-presentation.spec.ts` uses a real local node and OPFS with mocked
account/enrollment/Vault responses. It reproduces both reported connection states,
checks refusal when local history cannot be read, confirms the extra Sync-page
button is absent, switches to browser-only sync with the server-card toggle,
and verifies an edit plus attachment survive reload without HTTP/WS data writes.
It turns server sync back on and checks that the local edit is sent.
It also exercises the compiled Vault session error path (no React hook in an
error constructor). Actual staging billing/admission and multi-device migration
remain separate acceptance checks.

Table loading feedback: `browser/data-browser/src/chunks/TableEditor/TableEditor.test.tsx`
checks that a busy grid with only an entry row renders a visible spinner/status,
and that settled empty and populated grids remove it. This is a component render
check; real refresh/query timing remains a browser acceptance check.

## WebSocket disconnect cancellation

`websockets.test.ts` covers closing during authentication and range reconciliation, and index-status subscription cancellation. `file-upload-offline.spec.ts`, `offline-chatroom.spec.ts` and `offline-create-then-online.spec.ts` verify disconnect, local writes, reload and reconnect without unexpected browser diagnostics.

`browser/data-browser/src/hooks/useFile.test.tsx` checks that the first preview
render waits for a local blob lookup instead of issuing a premature server
request, while files without a local database use the server immediately.
The offline upload E2E also asserts that the preview issues no image download
requests, even if a server request would have succeeded.

## Profile edit hydration

`store.test.ts` loads an offline profile with nontrivial persisted Loro history, edits it and merges into the original document, verifying the rename survives. `username-live.spec.ts` edits immediately through the enabled profile field and verifies existing remote chat authors update before and after reload. Profile controls stay disabled while the resource is loading. Managed-account E2Es explicitly configure the hosted runtime and API responses; the mocked same-origin dashboard test blocks the app service worker navigation fallback.

`store.test.ts` also verifies that a buffered property snapshot materializes before `getProperty` reads its datatype. Computed-column resize, reorder and filter E2Es exercise this during table creation and reload.

`store.test.ts` keeps property readers pending when a delta lacks base history; `sync-import.test.ts` checks the loading-to-error transition if recovery fails. `plugin.spec.ts` verifies installation completes without accessing an unmounted upload input.

## Resource lifecycle and reproducible local E2E

- `browser/lib/src/resource.test.ts`: explicit buffered/loading/recovering/ready/error
  states, including readable cached values while recovery is in flight.
- `browser/lib/src/store.test.ts`: local hydration publishes the original causal
  snapshot in one ingress; immutable status snapshots retain the live mutation handle.
- `browser/lib/src/websockets.test.ts`: close cancels pending authentication signing;
  a reconnect to the same account cannot revive an old sync computation.
- Production `e2e.spec.ts`, `browser-invite.spec.ts`, and `username-live.spec.ts`
  exercise compiled profile and invitation readiness without a compiler opt-out.
- `deployment-fixtures.ts` composes the console-diagnostics fixture for standalone,
  managed, and managed-with-dev-drive modes. Expected mocked 401 responses and the
  intentional service-worker block are declared only in the tests causing them.
- `pnpm test-e2e:local` builds JS, WASM and the native backend from the checkout,
  serves the embedded app and API from one `atomic.localhost` origin with fresh data
  on a free port, and preserves its report/build logs. `--preview` opts into Vite.
  Failure traces are retained. Real Cloud Vault integration requires an explicitly
  supplied `ATOMIC_VAULT_PORTAL_URL`; the runner never discovers unrelated portals.

## Boolean reads and managed development origins

- `reactBoolean.test.ts` runs actual hook renders and mount effects, checking that
  missing Boolean values remain absent while loading and after loading. Reads must
  not create Loro writes that can race incoming snapshots.
- `managed/api.test.ts` accepts loopback `*.localhost` portal URLs while rejecting
  lookalike public hosts. Recovery and managed-sync E2Es exercise that CI origin.
- Device-status route interception uses the Node-reachable service URL, since
  Chromium host-resolver rules do not configure Node DNS.

- `e2e.spec.ts` opens two real local drives by URL; switching does not depend
  on public `atomicdata.dev` hosting or its `/server` discovery endpoint.

- `collection-attach.test.ts` delays database attachment after a collection starts:
  an expected worker must get the query before the server fallback. Apps without
  an expected local database retain the immediate server path.
- `resource-context-menu.spec.ts` delivers a late resource-creation notification
  while typing in a menu. Automatic title editing must preserve overlay focus;
  the folder-creation E2E continues to verify normal title autofocus.

- `store.test.ts` verifies that applying a received Loro snapshot does not start
  another fetch of that subject. Pending offline edits retain their hydration path.
- The tag-search E2E creates two tags sequentially and verifies both drive-list
  entries and search filters. Tag callbacks append to the live resource, so a
  delayed callback cannot replace the list with an older render's array.
- `searchAndOpen` treats overlay closure as click completion when retrying a
  detached result row, avoiding false failures after successful navigation.

## CI quality and failure evidence

- `failure-state.spec.ts` checks bounded failure metadata and omission of resource
  values and signed payloads, including real WebSocket metadata retained after page close.
- `collector-lifecycle.spec.ts` checks idempotent start/disposal, detached context/page/socket
  listeners, stable captured evidence, exact expectations and the 30-frame metadata cap.
- CI lint uses installed sources without JS/WASM builds; feature-branch pushes cancel
  superseded runs while develop and tags retain completed validation for deployment.

- `scheduled-save.test.ts` covers coalescing, idempotent cancellation, flushing,
  concurrent in-flight work and failures. `store.test.ts` covers immutable save
  snapshots, identity renaming, offline queueing and direct-save notifications.

- `data-save-state.spec.ts` reproduces a compiled inspector missing an unsaved-edit
  warning, then verifies the subscribed warning clears after saving/reconnecting.

Failure attachments include up to 30 recent WebSocket frame metadata records per
page, never payload contents. A real local WebSocket exercises this collection.

- `save-status-coordinator.test.ts` exercises narrow injected dependencies without a
  Store: overlapping owners, idempotent observer disposal, resource renaming, cached
  immutable snapshots, current outbox/connection state and failure accounting.

## S3 hosted file storage

`server/src/blob_storage.rs` tests node replacement with no local blob copies,
verified/resumable migration, storage failures with no fallback, peer BLOB frames,
and invalid configuration. Its ignored S3 round-trip runs against a scratch
bucket; SaaS representative CI supplies MinIO. `server/src/tests.rs` checks
remote multipart upload/download and image renditions, asserting Tree::Blobs
stays empty. Standalone local storage still runs through the original tests.

Not covered here: live Hetzner rollout, arbitrary large-file memory limits,
blob garbage collection, or encrypted Vault attachment recovery.

`shared_files_count_once_per_drive_independently_of_other_owners` proves that
one physical object shared by two owners counts once in each drive, repeated
references within one drive do not inflate usage, and report ordering,
co-location and removal of another owner's references do not change attribution.

The durable snapshot worker regression (`client-db-durable-put.test.ts`) checks
that JSON and Loro writes finish before the flush acknowledgement, flush errors
reject, failed flushes retry, and successful writes avoid a redundant flush.
`store.test.ts` holds that acknowledgement pending to verify an online save
cannot resolve early and needs no second RPC during identity handoff.

`useAvailableHeight.test.ts` checks that observer-driven grid sizing defers and
coalesces DOM writes outside ResizeObserver delivery, and cancels pending work
on unmount. Table filtering E2E retains strict browser diagnostics.

## CI server hostname mapping

`browser/e2e/scripts/server-dns.node.mjs` starts a real HTTP server and a Node
child with the CI DNS preload. It verifies callback-based fetch and promise-based
DNS lookup reach the service while preserving the public HTTP Host, and that
unrelated hosts remain unchanged. The template and plugin integration E2E tests
use the public server URL for generated configuration and signed requests.

## Unified templates and create-drive setup

`chunks/Templates/model.test.ts` tests version-pinned composition, duplicate keys,
missing dependencies and dependency cycles. `aiProposal.test.ts` tests catalog-only
AI references, size limits and removal of undeclared authority/executable fields.
`drive-template-onboarding.spec.ts` exercises a mobile local-only preview, edits it,
then adopts a fresh workspace without the demo edit or sample rows; it also checks
blank creation and that the mobile feedback footer cannot cover its action.
Existing `table-templates.spec.ts` exercises the same table adapter.
Not covered: a live AI provider, durable interrupted-install resume, portable graph
import/export, shared schema IDs, initial identity signup, physical mobile browsers.

- Demo speaker attribution: `browser/data-browser/src/chunks/Demo/messageSpeaker.test.ts` covers local persona display and rejection outside the demo, without overriding verified creator metadata.

Template adoption: `keepTemplateDemo.test.ts` covers retaining graph identity, saved-drive registration, failed-save retry preservation, and expired-preview rejection. `drive-template-onboarding.spec.ts` covers the keep-edits and fresh-template UI choices.

Onboarding dialog feedback: the authorization/invite and chatroom cases in
`e2e.spec.ts` verify Continue remains clickable while feedback is offered.
`onboarding-storage.spec.ts` checks feedback availability;
`drive-template-onboarding.spec.ts` checks mobile creation and dismissal.
## Paged table hydration count (2026-09-08)

`collection-page-assemble.test.ts` reproduces 90 rows becoming 150 when deferred
hydration notifications re-add rows outside page zero. Covers full-query membership
and reconciling optimistic additions already represented in that query. The other
collection sorting, drive-scope and empty-result regressions are run alongside it.
Verified in the user's Zen integration table: total is 90, final rows render, and
the phantom loading rows are gone. No source issue records were edited.

Workspace separation coverage: `plugin-workspace.test.ts` checks explicit and
legacy destinations, malformed configuration, authorization failure propagation,
and exclusion of automations (including empty connection lists). The workspace
browser spec removes the new relationship to exercise old GitHub installs, opens
native kanban then connection settings, preserves the opening view, checks sync
preview errors, and starts assistant chat without a connection. It also creates
an on-demand script through the authoring helper and finds it from its workspace.
`plugins.spec.ts` covers reuse of an existing task template with its views intact.
These checks do not prove live AI generation, provider sync, multi-repository row
ownership, disconnect revocation, or consolidation of the other UI runtimes.
`store.test.ts` reproduces and fixes an HTTP fetch returning undefined when its
response has a canonical subject different from the requested query URL.

## Shared iframe bridge (2026-09-08)

`FrameBridge.test.ts` covers both wire envelopes, wrong-frame requests and ready
messages, theme updates, subscription deduplication, initial load versus document
replacement, and teardown dropping late replies/subscriptions. `pluginRPC.test.ts`
exercises the actual legacy adapter: permitted edits, denied outside writes,
protection of plugin resources, notification grant revocation, host navigation,
and permission responses arriving after unmount. Existing `hostStore.test.ts`
keeps the generated app identity/subtree write checks exercised.

The generated-app and packaged-plugin browser suites exercise the shared bridge
through their real entry points. Packaged installation uses the bundled fixture
and real server; its unrelated SaaS `/api/me` probe is explicitly stubbed to the
supported 204 no-account response.

`viewPolicy.test.ts` covers host-selected scopes, inherited public/agent grants,
deep packaged ancestry, bounded app writes, cycles and unavailable ancestors.
`viewSession.test.ts` checks canonical resource/error replies. The actual packaged
and generated SDK clients share conformance tests in
`browser/plugin/src/viewProtocol.test.ts`, including ignoring foreign-window replies.
The generated client also accepts a reply after the host's 30-second recovery
window, clears its deadline on completion, and rejects a host that stays silent.
The packaged adapter additionally tests canonical requests, caller-supplied policy
spoofing, subscription acknowledgements and unsupported operations.

App frame `store.getMany(subjects)` (#1737): `hostStore.test.ts` checks it
answers in order through the same store read as `get` (same state after a
local change), reports an unreadable subject in its place without failing the
rest, and refuses more than 100 subjects or a non-array before reading any.
`viewProtocol.test.ts` checks the generated client makes one request for the
batch, hands back resources like `getResource`'s, asks nothing for an empty
list and refuses 101 without asking.

App frame theme (#1738): `views/PluginView/useCreateThemeVars.test.ts` checks
the frame stylesheet carries `--t-color-success` and `color-scheme` from the
built theme's `darkMode`. `FrameBridge.test.ts` checks the theme message
carries `colorScheme` and keeps it across a ready message and a reload.
`viewProtocol.test.ts` checks `store.getTheme()` reads the scheme from the
applied stylesheet before any message, then from messages (only the parent's,
only `light`/`dark`), and `onThemeChange` fires once per change until stopped.

`apps.spec.ts` runs the first write scenario with both the served SDK and this
checkout's v1 JS asset. The latter explicitly intercepts only `format=client`;
resource creation and signing still use the real local backend. This verifies the
new asset without claiming a rebuilt Rust binary. Backend signing identities and
per-profile operation capabilities remain distinct; this is not certification of
a common installation authority model.


## Installation identity lifecycle (2026-09-08)

`plugins::installation::tests` resolves existing nested subjects, legacy and active
identities, rejects a forged drive even when a key exists there, and checks revoke /
reconnect without reparenting records. `store_host::installation_tests` reproduces
and prevents fallback to the server signer after a selected key is removed.
`scheduler::tests::a_revoked_installation_cannot_resume_a_granted_schedule` verifies
that an armed run records a revocation error without creating its proposed row.
Existing app endpoint tests cover real signed writes, caller rights and outside
scope denial; provider fixtures cover existing release/receipt/sync behavior.

`db::app_agent` tests cover legacy MessagePack decoding, idempotent revocation,
erased key material, explicit reconnect and a subprocess that exits without
running destructors. Reopening the database must still show a revoked identity.
These checks do not migrate packaged UI signing or certify live provider delivery.


## Activation and upgrades (2026-09-08)

`release_binding::tests` covers release/configuration comparison, absent/removed
bindings and unchanged parent links. `sync_session_tests` rejects stale unapproved
previews without provider writes and exercises compatible upgrades/rollback with
an actual connection binding while retaining original receipts. The background
worker regression proves a due job stops with a stored error when activation
settings change, rather than writing with an older grant. Existing subprocess
recovery tests continue to exercise already-approved work across process exit.


## Packaged consent isolation and delete authorship (2026-09-09)

`grantIdentity.test.ts` checks separation by server, drive, actor and installation,
including unambiguous tuple encoding. The packaged-plugin browser flow verifies
picker consent is persisted under the new identity, and installation, writes and
reload still work. View remounting prevents the key-changing local-storage hook
from retaining a previous account's state; pending permission/picker promises are
cancelled on teardown. Old plugin-name grants are deliberately not migrated.

`store_host::destroy_identity_tests` checks the signer of the persisted destroy
commit. It failed with the server signer before `Resource::destroy_as` was used;
installation deletion must use the same selected identity as create/update.
LocalThought: the browser and fixture tests cover selected-platform consent,
PKCE redemption, one-time handoff consumption, rotating proxy credentials,
duplicate-page rejection, typed paginated previews, and Calendar UTC date-range
validation. The new redirect flow uses a synthetic fixture identity. These
automated checks do not certify live LocalThought login, consent, redemption or
provider writes; matching deployment evidence is tracked separately in PR and
release verification.

Google Calendar one-way projection and its E2E (`google-calendar-import.spec.mts`)
were removed with the Calendar lens; there is no Calendar import coverage here.

## Google Calendar recurrence

- `browser/lib/src/calendar-recurrence.test.ts`: daily/weekly/monthly rule sets,
  COUNT/UNTIL, DST gaps and offset changes, exclusions/additions, moved/cancelled
  instances, cross-calendar identities, provider-expanded deduplication and
  date-only recurring spans. No real provider calls.
- `browser/data-browser/src/chunks/TablePage/Calendar/calendarOccurrences.test.ts`:
  imported/native property names, civil-day placement across offset boundaries,
  recurring all-day spans clipped to the visible grid, and moved instances
  (#1804): "moved from" on the new day, a placeholder on the original day with
  the same original-instance key (also when the new day is off the grid), and
  no mark for a same-day time change or a cancellation.

The bundled Google Calendar (Devonian) lens and its end-to-end coverage
(`browser/e2e/tests/google-calendar-import.spec.ts`, which drove the retired
`devonian-google-calendar` card) were removed along with the `devonian`
dependency. LocalThought imports (including Google Calendar) are currently
broken (see the gap under Plugin discovery), so there is no e2e coverage of a
recurring-series import.

The actionable fidelity audit is `docs/imports/google-calendar-gap-report.md`.
Live Google equivalence for historical/exotic recurrence rules remains outside
these fixtures; unsupported full-series rules are rejected before import.

Calendar view UI: `browser/e2e/tests/calendar.spec.ts` covers adding an item
on a day, grid alignment at desktop and phone width, and a crowded day (#1798):
"+N more" counts what doesn't fit, and the day list (from "+N more", the day
number by keyboard, or a click on the day's empty space) shows every event and
opens each row on top of it. How many chips fit is measured, so it needs a
real browser; jsdom can't cover it.

All-day ranges: `browser/lib/src/calendar-date.test.ts` covers civil-date
validation, exclusive single/multi-day ends, leap days, DST dates and year
boundaries; run under UTC, America/Los_Angeles and Pacific/Kiritimati.

## Metadata-driven platform extraction (2026-09-10, removed)

History: this section documented the Rust tests of the vendored Syncables
crate and its WASM bridge. Both were removed in #1618, together with the
browser-side OpenAPI-driven import they backed.

`integrations/localthought/browser.test.ts` covers consumer-owned request budgets,
Retry-After handling with rotating credentials, deadline rejection, and separate
catalog selections with explicit caller precedence.

GitHub and Clockify implementations, fixture suites and
certification live in atomic-plugins.

`integrations/localthought/settings.test.ts` covers runtime proxy selection,
deployment-default fallback, URL validation without losing the previous setting,
origin-separated connection keys and migration of legacy connections only for
the matching proxy and owner.



Portable app definitions: `browser/lib/src/app-package.test.ts` loads a standalone
JSON fixture through the shared importer, planner and apply engine with in-memory
storage. It verifies nested placement, native localId, repeat import, conflicting
revision reuse, opaque source/setup text, and refusal of installation fields or
unsupported declarations. This is library coverage: marketplace UI, real-server
package persistence, schema/template graph import and sandbox activation remain
unverified/unimplemented by this slice.

### Assistant context failure recovery

`useCurrentSubject.test.ts` covers `/app` and nested app routes remaining UI
routes rather than becoming backend resource subjects.
`processAtomicResources.test.ts` verifies an unavailable attachment does not
discard a readable product attachment or abort context preparation.
`store.test.ts` covers a failed WebSocket GET settling concurrent readers and
subsequent reads of its error placeholder. Existing gap-recovery and ingress
tests cover missing-history and snapshot recovery; these are not proof that
every resource in a user's live session has recovered.
`sync-delta-local-base.test.ts` covers a sync delta for a resource the local
query hydrated from JSON-AD (no Loro history): it is replayed on the local
database's snapshot without a server round trip, and the rebuilt doc is not
written back over that history (#1905).
`useDriveApps.localBase.test.tsx` covers the "+ Add view" case of it: an app's
edit arriving that way while the menu is open (#1846). Editing a resource that
is still without its history (it is saved from the rebuilt doc) is not covered.

`toolHistory.test.ts` checks interrupted tool calls remain explicitly unknown
in outgoing model history, completed calls retain results, and persisted tool
errors and falsy outputs survive round trips. Recovery does not replay tools
or mutate the user's stored chat. Live provider recovery is not covered by
the scripted website E2E.

### Streamed Assistant message persistence

The AI chat partial-response E2E holds the model stream open, emits two text
updates, checks that a single Assistant message reached the backend through an
independent authenticated HTTP read, and reopens it after refresh.
`persistSidebarMessage.test.ts` requires the current message to persist even
when React does not run the state updater immediately. Streaming checkpoints
run once per second and serialize updates to the same message and parts;
refresh before the first completed checkpoint can still lose the newest text.

The AI rate-limit E2E emits received reasoning followed by a provider 429. It
checks the reasoning remains visible and that reopening the chat restores both
the reasoning and the provider error. Error replies do not launch follow-up
question generation or automatic compaction.

`prepareDriveSharing.test.ts` covers verified local transition before peer invitation, rejection on failed verification, preservation of an enrolled drive connection, and isolation from another drive enrollment. `local-drive-copy.test.ts` covers missing history, incomplete inventory, and missing or corrupt attachments. Full sharing UI acceptance remains pending.
## Signed-out local drive opened from the portal

`browser/data-browser/src/helpers/isDriveSignInError.test.ts` covers a local-only missing-resource error with no app agent, including origins with a configured node. It also covers signed-out DID resources absent from the current node: their copy may be in the account vault, so they offer unlock. Signed-in users, ordinary HTTP 404s, and unrelated transport failures retain their error handling.

Paired SaaS `portal/e2e/passkey-open-drive.spec.ts` covers account/profile creation, passkey enrollment, recovery-code acknowledgement, completed app sign-out, portal passkey sign-in, and the Open link reaching the app unlock screen. It then unlocks and verifies the original drive title. Chromium virtual PRF state is tied to the original CDP target, so the unlock portion runs there after verifying the real popup handoff. Unlocking within the popup itself remains a physical-browser acceptance check.
## Ontology codegen (`@tomic/cli`) and DID fetch

| Flow | Where |
|---|---|
| HTTP path `https://host/did:ad:…` / `https://host/atomic:…` and `/resource?subject=` extract the same identifier | `browser/lib/src/subject.test.ts` |
| JSON-AD parse accepts `@id: did:ad:…` when the request used the HTTP path alias | `browser/lib/src/parse.test.ts` |
| `Client.fetchResourceHTTP` resolves identifiers via `/resource?subject=` and does not touch `window` in Node | `browser/lib/src/client.fetch.test.ts` |
| Store fetch by HTTP path alias returns the resource stored under the DID | `browser/lib/src/store.test.ts` |
| Writes collapse `did:ad:` / `atomic:` aliases; parent queries match either spelling; destroy-replay sees a legacy commit id | `lib/src/db/test.rs` `canonical_scheme_store_boundary` |
| Opening a store rewrites leftover `did:ad:` resource keys and reference values to `atomic:` | `lib/src/db/test.rs` `canonical_scheme_open_rewrites_legacy_keys` |
| Wire subjects follow `canonical-scheme` (empty caps emit `did:ad:`) | `browser/lib/src/subject.test.ts` `emitSubjectForCaps` |

Not covered: `ad-generate ontologies` end-to-end against a live server (no CLI test runner).

`helpers/managed/vaultAutoBackup.test.ts` verifies successful vault restoration preserves known node absence as local-only routing, while transport failures and failed restores do not disable node sync. Paired SaaS second-browser coverage verifies the original profile and vault-only canary after restore, with bounded pre-restore refusal diagnostics.

Paired SaaS `portal/e2e/identity-reconcile.spec.ts` exercises dev-drive creation while a managed account is active: reconciliation waits until the temporary identity has a drive, and creation must not enroll it in the account.

Session restore routing: `helpers/managed/reconcile.test.ts` covers connecting the
exact hosted drive before availability checks, clearing local-only routing,
skipping Pending/Disabled placements and other drives, and ignoring discovery
that completes after its deadline. Staging phone restore latency and end-to-end
WebSocket query delivery remain unverified.

Cloud Vault download concurrency: `helpers/managed/vault.test.ts` holds network
responses open to verify concurrent downloads are bounded at four and that
reverse completion preserves listing order at import. Existing progress and
failure checks also pass. Actual staging phone restore latency remains unmeasured.

## Right-panel lifecycle

`components/RightPanel/panelState.test.ts` covers session-local initial state, exclusive panels, cleared meeting selection, account/drive scoping, stale callbacks, and missing/unauthorized versus temporarily unavailable targets.

`e2e/tests/right-panel-lifecycle.spec.ts` asserts visible panel state with legacy localStorage values for meeting/comments/AI, SPA navigation away from commentable resources, deletion of an explicitly opened meeting, and switching drives and back without resurrecting the panel. Existing `meetings.spec.ts` agenda/start/end coverage verifies that minutes and explicitly opened meeting chat still work. AI chat E2E (`ai.spec.ts`, `table-tools.spec.ts`) opens the assistant with the navbar button rather than `atomic.rightPanel.active`, because that key is no longer restored.

## Replication completion and CI tool installation

`lib/src/sync/replicate.rs` has five scripted WebSocket peer tests covering
resource-only completion without the idle timeout, acknowledgement of every
chunk, unrelated-drive acknowledgements, an independently mismatching hash,
trailing blob requests and asynchronous storage errors, and the fallback for
peers without keepalive support. They exercise the real Rust WebSocket client
and snapshot/chunk encoding with an isolated in-memory source; the peer scripts
simulate replies and do not validate authentication or remote import policy.
The real-server `server/tests/it/replicate.rs` tests retain destination-data,
repeat-push, boot-reconcile and export-authorization assertions.

The pinned wasm-pack installer was executed in Dagger's `rust:bookworm` image
on Linux x86_64, including a cached install followed by changed downstream
source input and execution of the retained binary. Its aarch64 archive digest
is pinned to the upstream release; native aarch64 execution is not covered by
that check. Full CI wall-time savings require a completed hosted run.
## Query index consistency (2026-09-18)

`db::test::is_a_encodings_all_match_the_class_constraint` (formerly
`#[ignore]`d as an open bug) writes four rows whose `isA` names one class in
four encodings and asserts a drive-scoped, sorted, class-filtered query lists
all of them and that `Db::check_query_index` finds index and store in
agreement. `replicated_rows_reach_a_watched_scoped_sorted_query` watches that
query shape with 5 rows and then replicates 17 more through
`persist_replicated_resource` (the sync import path, propvals materialized
from a Loro doc), asserting the sorted, unsorted and differently scoped shapes
all answer 22. `first_build_cross_checks_the_unscanned_constraint` removes one
row's `isA` entry from `PropValSub` and asserts the first build still files
the row through the `parent` constraint.
`check_query_index_names_missing_and_stale_members` corrupts a member index in
both directions and asserts the report names each subject.
`did_rows_stamped_into_another_drive_stay_out_of_a_watched_query` covers the
audit's C17 on both the build and the commit path, including the unstamped
row that is deliberately not excluded. Not covered: the runtime `warn!` text
itself, and a UI-level comparison of a client's local answer with the
server's (see `planning/silent-failures.md`).

## External cache access and authentication origins (#170)

Paired SaaS `portal/e2e/recovery-passkey.spec.ts` uses Chromium virtual PRF authenticators with the real control plane to verify app enrollment followed by portal login using one credential, reuse of a portal-created credential, and account-settings migration without replacing ciphertext or old wrappers. Physical Safari/iCloud, Android/password-manager and native-shell behavior remain device acceptance checks.

## September 10 SaaS and browser invite regressions

- `browser/lib/src/browser-peer-invite.test.ts`: signed invitation validation, expiry, target and issuer checks, recipient proof, and additive permission grants.
- `browser/e2e/tests/browser-invite.spec.ts`: distinct signed-in identities join a local drive through the app without the server invite endpoint.
- `browser/e2e/scripts/verify-peer-sync.mjs` with `ATOMIC_PEER_INVITE=1`: invitation bootstrap and real WebRTC reconciliation with HTTP data access disabled.
- `browser/e2e/tests/recovery-option.spec.ts`: recovery availability in the managed welcome flow.
- Existing-drive migration to browser-only storage and fresh-account email onboarding through a peer invitation remain unverified.

- `browser/data-browser/src/helpers/passkeySupport.test.ts` checks secure-context and credential API availability. `browser/e2e/tests/passkey-unavailable.spec.ts` removes WebAuthn from the browser and verifies that account settings explain the limitation, hide passkey setup, and preserve recovery-code access. Native credential-provider failures with the API present remain outside this check.


## Managed sync presentation and local transition

`syncPresentation.test.ts` covers Vault-aware summaries and hiding unrelated
saved managed nodes. `enrollmentApi.test.ts` distinguishes unknown hosting from a
successful empty enrollment list. `client-db.test.ts` covers nested WASM Map
normalization, and `local-drive-copy.test.ts` rejects incomplete history and
missing/corrupt attachments.

`managed-sync-presentation.spec.ts` uses a real local node and OPFS with mocked
account/enrollment/Vault responses. It reproduces both reported connection states,
checks refusal when local history cannot be read, confirms the extra Sync-page
button is absent, switches to browser-only sync with the server-card toggle,
and verifies an edit plus attachment survive reload without HTTP/WS data writes.
It turns server sync back on and checks that the local edit is sent.
It also exercises the compiled Vault session error path (no React hook in an
error constructor). Actual staging billing/admission and multi-device migration
remain separate acceptance checks.

Standalone Rust library tests enable Tokio’s multithread runtime through a dev
dependency. `db::app_agent::store_tests::revocation_survives_process_exit_without_destructors`
exercises runtime construction in both the parent and its abruptly exiting child
with `cargo test -p atomic_lib --features db-redb --lib`, without workspace feature
unification or an extra Tokio feature on the command line.

Integration discovery preferences: `integrationVisibility.test.ts` covers absent
or malformed values and all four independent boolean combinations.
`integration-visibility.spec.ts` covers default-hidden discovery, settings links,
Atomic persistence across reloads, independent toggles, visible existing connections
and no community catalog fetch while disabled. Existing plugin browser tests explicitly opt in
through Settings. Cross-device preference sync uses normal private-drive sync;
a dedicated multi-device preference test is not yet present.

## Local Thought browser refresh

- `integrations/localthought/browser.test.ts`: one provider request for validation,
  no pagination/retry or import, credential rotation, and denied/throttled/failed
  access checks.
- No app-side coverage: the data-browser's LocalThought sync was removed; it
  returns as plugins running in their own iframe.
Portable app definitions: `browser/lib/src/app-package.test.ts` loads a standalone
JSON fixture through the shared importer, planner and apply engine with in-memory
storage. It verifies nested placement, native localId, repeat import, conflicting
revision reuse, opaque source/setup text, and refusal of installation fields or
unsupported declarations. This is library coverage: marketplace UI, real-server
package persistence, schema/template graph import and sandbox activation remain
unverified/unimplemented by this slice.

`prepareDriveSharing.test.ts` covers verified local transition before peer invitation, rejection on failed verification, preservation of an enrolled drive connection, and isolation from another drive enrollment. `local-drive-copy.test.ts` covers missing history, incomplete inventory, and missing or corrupt attachments. Full sharing UI acceptance remains pending.
## Signed-out local drive opened from the portal

`browser/data-browser/src/helpers/isDriveSignInError.test.ts` covers a local-only missing-resource error with no app agent, including origins with a configured node. It also covers signed-out DID resources absent from the current node: their copy may be in the account vault, so they offer unlock. Signed-in users, ordinary HTTP 404s, and unrelated transport failures retain their error handling.

Paired SaaS `portal/e2e/passkey-open-drive.spec.ts` covers account/profile creation, passkey enrollment, recovery-code acknowledgement, completed app sign-out, portal passkey sign-in, and the Open link reaching the app unlock screen. It then unlocks and verifies the original drive title. Chromium virtual PRF state is tied to the original CDP target, so the unlock portion runs there after verifying the real popup handoff. Unlocking within the popup itself remains a physical-browser acceptance check.
## Ontology codegen (`@tomic/cli`) and DID fetch

| Flow | Where |
|---|---|
| HTTP path `https://host/did:ad:…` / `https://host/atomic:…` and `/resource?subject=` extract the same identifier | `browser/lib/src/subject.test.ts` |
| JSON-AD parse accepts `@id: did:ad:…` when the request used the HTTP path alias | `browser/lib/src/parse.test.ts` |
| `Client.fetchResourceHTTP` resolves identifiers via `/resource?subject=` and does not touch `window` in Node | `browser/lib/src/client.fetch.test.ts` |
| Store fetch by HTTP path alias returns the resource stored under the DID | `browser/lib/src/store.test.ts` |
| Writes collapse `did:ad:` / `atomic:` aliases; parent queries match either spelling; destroy-replay sees a legacy commit id | `lib/src/db/test.rs` `canonical_scheme_store_boundary` |
| Opening a store rewrites leftover `did:ad:` resource keys and reference values to `atomic:` | `lib/src/db/test.rs` `canonical_scheme_open_rewrites_legacy_keys` |
| Wire subjects follow `canonical-scheme` (empty caps emit `did:ad:`) | `browser/lib/src/subject.test.ts` `emitSubjectForCaps` |

Not covered: `ad-generate ontologies` end-to-end against a live server (no CLI test runner).

`helpers/managed/vaultAutoBackup.test.ts` verifies successful vault restoration preserves known node absence as local-only routing, while transport failures and failed restores do not disable node sync. Paired SaaS second-browser coverage verifies the original profile and vault-only canary after restore, with bounded pre-restore refusal diagnostics.

Paired SaaS `portal/e2e/identity-reconcile.spec.ts` exercises dev-drive creation while a managed account is active: reconciliation waits until the temporary identity has a drive, and creation must not enroll it in the account.

Session restore routing: `helpers/managed/reconcile.test.ts` covers connecting the
exact hosted drive before availability checks, clearing local-only routing,
skipping Pending/Disabled placements and other drives, and ignoring discovery
that completes after its deadline. Staging phone restore latency and end-to-end
WebSocket query delivery remain unverified.

Cloud Vault download concurrency: `helpers/managed/vault.test.ts` holds network
responses open to verify concurrent downloads are bounded at four and that
reverse completion preserves listing order at import. Existing progress and
failure checks also pass. Actual staging phone restore latency remains unmeasured.

## Right-panel lifecycle

`components/RightPanel/panelState.test.ts` covers session-local initial state, exclusive panels, cleared meeting selection, account/drive scoping, stale callbacks, and missing/unauthorized versus temporarily unavailable targets. It also covers the comments panel's target: aiming it at another resource switches threads instead of toggling, the NavBar button (no target) returns to the page's own thread rather than closing a row's, the target is dropped when another panel takes over, and `closePanelState` closes the panel whatever it is aimed at — which a targetless toggle cannot express.

`e2e/tests/table-row-comments.spec.ts` covers commenting on a table row from the gutter bubble: the panel opens headed by the row's title, the count is live and belongs to that row alone, another row's bubble switches threads, the same row's closes the panel, the comment survives a reload, and the trailing entry row (no resource yet) offers no bubble. What is NOT covered: reaching the bubble by keyboard — it shares the row-gutter's mouse-only reachability with the existing expand button, since the grid owns Tab for cell navigation.

`e2e/tests/right-panel-lifecycle.spec.ts` asserts visible panel state with legacy localStorage values for meeting/comments/AI, SPA navigation away from commentable resources, deletion of an explicitly opened meeting, and switching drives and back without resurrecting the panel. Existing `meetings.spec.ts` agenda/start/end coverage verifies that minutes and explicitly opened meeting chat still work. AI chat E2E (`ai.spec.ts`, `table-tools.spec.ts`) opens the assistant with the navbar button rather than `atomic.rightPanel.active`, because that key is no longer restored.

## Replication completion and CI tool installation

`lib/src/sync/replicate.rs` has five scripted WebSocket peer tests covering
resource-only completion without the idle timeout, acknowledgement of every
chunk, unrelated-drive acknowledgements, an independently mismatching hash,
trailing blob requests and asynchronous storage errors, and the fallback for
peers without keepalive support. They exercise the real Rust WebSocket client
and snapshot/chunk encoding with an isolated in-memory source; the peer scripts
simulate replies and do not validate authentication or remote import policy.
The real-server `server/tests/it/replicate.rs` tests retain destination-data,
repeat-push, boot-reconcile and export-authorization assertions.

The pinned wasm-pack installer was executed in Dagger's `rust:bookworm` image
on Linux x86_64, including a cached install followed by changed downstream
source input and execution of the retained binary. Its aarch64 archive digest
is pinned to the upstream release; native aarch64 execution is not covered by
that check. Full CI wall-time savings require a completed hosted run.
## External cache access and authentication origins (#170)

`db::test::cached_external_resources_keep_read_permissions` checks that a cached
external resource remains private in public collection queries (nested and
subject-only) and direct reads, while the authorized agent can still read it.
`client::helpers` origin tests reject lookalike hosts, userinfo-host confusion,
changed ports/schemes, malformed URLs and non-HTTP URLs; normalized same-origin
and localhost requests remain eligible for DID-agent authentication.

## Drive root file drops

`views/Drive/DrivePage.test.tsx` renders the drive page with its real dropzone
and upload hook, then delivers multiple files through the drop callback. It
verifies the upload targets the displayed drive even when the current drive
setting differs. Native drag events, overlay geometry and the refreshed child
list are not covered by this component test.

---

## Collection query authorization

| Flow | Where |
|---|---|
| Destroyed children don't inflate `parent=` `totalMembers` | `lib/src/db/test.rs` `destroy_clears_parent_index_count` |
| In-page auth-denied members: `count` equals `subjects.len()` | `unauthorized_query_count_matches_subjects` |
| Public child after a private streak still fills the page | `unauthorized_query_skips_denials_to_fill_the_page` (20 private, then one public) |
| Auth-denied listing does not full-decode ancestors; each member is still shallow-fetched | `unauthorized_collection_query_bounds_fetch_counts` (call counts, not wall clock) |

Not covered: wall-clock on a large real store (the 21.7KB-parent form from
`planning/slow-collection-queries.md`); per-GET rights walks on the invite-code
panel (memo is per-query, not per-request).

---

## Commit delivery and the Loro save cursor

The client exports each commit as a delta starting at its save cursor
(`_loroVersionAtLastSave`). If the cursor ever sits past ops the server never
received, every later delta is un-importable server-side — and Loro parks such
ops as *pending* (VV unchanged, empty diff), which without a guard is
indistinguishable from an idempotent replay. This lost a real user's
`form-pages` write in 2026-08.

| Flow | Where |
|---|---|
| Server rejects a delta whose deps it never received (pending import), and accepts the full-range re-send | `lib/src/commit.rs::commit_with_pending_loro_deps_is_rejected` |
| Idempotent replay of an already-applied commit is still accepted | `lib/src/commit.rs::idempotent_commit_replay_is_accepted` |
| Drain reacts to the pending-deps rejection by clearing the cursor and re-sending a self-contained snapshot | `browser/lib/src/store.test.ts` ("recovers from a server pending-deps rejection…") |
| `clone()` / `merge(replaceLoroDocs)` carries the cursor VALUE, not the current doc version | `browser/lib/src/resource.test.ts` ("clone preserves the save cursor value…") |
| Imports/echoes don't advance the cursor past unsigned local edits | `browser/lib/src/resource.test.ts` ("importLoroUpdate does not advance…") |

Not covered: the OPFS-suppression window (edits live only in memory between
`markDirty` and a successful drain — an app kill in that window still loses
them, `store.ts` `addResource`'s `!hasPendingCommits` gate); WS `COMMIT_OK`
acks carrying no server-side apply confirmation beyond the echoed commit.

---

## Forms

AI `create_form` resource graphs (standalone pages, typed properties and choice tags; existing-table schema preservation; invalid mappings rejected before writes) are covered by `browser/data-browser/src/chunks/FormBuilder/createFormFromSpec.test.ts`. `formOps.test.ts` covers inspection, partial JSON patches, page/field additions, ordering and deletion, choice Tag identity preservation, shared-schema protection, membership checks, and conditional-order validation. `formFieldSettings.test.ts` covers explicit option schemas in both creation/editing, persisted type-specific settings, numeric bounds enforced by renderer validation, clearing bounds, invalid patches rejected before writes, and shared-column selection limits. Model tool selection and live AI-to-published-form submission are not covered by these unit tests.

| Flow | Where |
|---|---|
| Existing table → form checklist → unused-column menu → label rename preserves Property → publish → anonymous submit → original table row | `browser/e2e/tests/forms-from-tables.spec.ts` |
| Column datatype/cardinality → compatible input types; unsupported types excluded; mapping creates only presentation and respects required columns | `browser/data-browser/src/chunks/FormBuilder/tableColumns.test.ts` |
| Removing a form destroys pages, questions and conditions while keeping columns and Tags | `browser/data-browser/src/chunks/FormBuilder/deleteForm.test.ts` |
| Pre-existing required column and named SelectProperty Tags validate without a form-owned schema | `server/src/forms.rs::existing_table_columns_validate_without_form_owned_schema` |
| Number presentation preserves integer storage and rejects fractions | `server/src/forms.rs::number_presentation_preserves_integer_columns` + `browser/form-renderer/src/validation.test.ts` |
| FormCondition evaluator (visibility + hidden-field validation skip) | Shared fixtures `testdata/form-conditions.json` loaded by `server/src/forms.rs::condition_fixtures_match_ts` **and** `browser/form-renderer/src/conditions.test.ts`. A fix to one is a fix to the other. |
| Definition serializer inlines FormCondition resources as `{field, operator, value}` | `server/src/forms.rs::definition_inlines_field_conditions` |
| Form ontology populate (incl. FormCondition) | `lib/src/store.rs::populate_forms_ontology` |
| Publish → anonymous submit of a branching follow-up | `browser/e2e/tests/forms-submission.spec.ts` ("branching hides a follow-up unless its condition matches") |
| Extended question types: validation + coercion per type (phone/url shape, currency bounds, dropdown membership, likert/rating range, matrix rows/columns + completeness, table columns/types/row bounds, address subfields), and all-empty composites reading as unanswered | `server/src/forms.rs` (`phone_field_accepts_common_shapes_and_rejects_junk` … `all_empty_composites_count_as_unanswered`) |
| Extended types route onto the existing summary shapes (choice counts / histogram / answer sample) | `server/src/forms.rs::extended_types_reuse_the_existing_summary_shapes` |
| `picture-choice` option images: subjects rewritten into `/form/{id}/image?file=`, and that route refuses files the form doesn't reference | `server/src/forms.rs::rewrite_option_images_only_touches_option_image_subjects` + `server/src/tests.rs::form_submission_flow` (step 3d) |
| Choice options resolve from the mapped SelectProperty's `allowsOnly` Tags into inline `{value,label,color,emoji,image}` objects, in order, with unset keys omitted | `server/src/forms.rs::resolves_choice_options_from_the_mapped_propertys_tags` |
| Option membership fails closed: a question with no options allows nothing, and a *label* is not an answer (answers are option subjects) | `server/src/forms.rs::choice_options_are_empty_when_the_property_allows_nothing` + `browser/form-renderer/src/validation.test.ts` ("choice option membership") |
| Non-choice questions keep their options bag untouched by option resolution | `server/src/forms.rs::non_choice_fields_keep_their_options_bag` |
| A question can borrow another column's Tags (`optionsSource.property`) — the source's list wins over the question's own | `server/src/forms.rs::choice_options_can_mirror_another_columns_tags` |
| A question can offer a table's *rows* (`optionsSource.table`) — answers are row subjects, a row *label* is not an answer | `server/src/forms.rs::choice_options_can_be_the_rows_of_a_table` |
| An `optionsSource` pointing at a deleted Property/Table fails closed (empty list) rather than falling back to the question's own tags | `server/src/forms.rs::an_unresolvable_options_source_allows_nothing` |
| A row whose label column is empty is left out of the options instead of falling back to its `name` | `server/src/forms.rs::rows_the_label_column_is_empty_for_are_not_offered` |
| A freshly added choice question has *no* options (no placeholder Tag resources) | `browser/e2e/tests/forms.spec.ts` ("create a form, add every field type…", step 4) |
| Every choice type stores a `resourceArray` of option subjects, single-pick included | `server/src/forms.rs::dropdowns_enforce_option_membership` |
| Multi-pick selection bounds (`minSelected`/`maxSelected`): too few / too many rejected, membership checked first, an empty answer still reads as unanswered, unusable bounds ignored | `server/src/forms.rs::multi_picks_enforce_selection_bounds` + `browser/form-renderer/src/validation.test.ts` ("multi-select selection bounds") |
| A maximum set in the builder reaches the rendered form: the hint line, options disabled at the cap, re-enabled on untick | `browser/e2e/tests/forms.spec.ts` ("a multi-select respects the maximum set in the builder") |
| Renaming an option in the builder rewrites the label in place (options are Tags, not copied strings) | `browser/e2e/tests/forms.spec.ts` ("create a form, add every field type…", step 4) |
| Builder can add every question type and they survive a reload | `browser/e2e/tests/forms.spec.ts` ("create a form, add every field type…") |
| `phone` accepts both the renderer's E.164 output and loosely formatted national numbers, and rejects a half-typed one | `browser/form-renderer/src/validation.test.ts` + `server/src/forms.rs::phone_field_accepts_common_shapes_and_rejects_junk` |
| `country` stores an ISO 3166-1 code: the list is complete and named, names localize, and a country *name* is rejected | `browser/form-renderer/src/validation.test.ts` + `server/src/forms.rs::country_field_takes_an_iso_code_and_rejects_a_name` |
| `country` summaries count picked codes by popularity (no configured option list to zero-fill) | `server/src/forms.rs::country_counts_rank_by_popularity_then_code` |
| Builder → publish → anonymous submit → row, for one type per value shape (dropdown/rating/address) | `browser/e2e/tests/forms-submission.spec.ts` ("extended field types round-trip from builder to submission") |
| Page transitions: off until the builder's Animate-page-transitions switch is on, then the page leaves in the right direction and the arriving page fades in one element at a time — a choice question's options included, each taking the slot after its own question — and `prefers-reduced-motion` still skips both | `browser/e2e/tests/forms.spec.ts` ("page transitions animate once switched on") + `browser/form-renderer/src/pageTransition.test.ts` |
| Every element in the cascade gets its own delay, in order, and a long page compresses the step rather than capping it (a cap made later options arrive with the question below them) | `browser/e2e/tests/forms.spec.ts` ("page transitions animate once switched on", computed-delay checks) + `pageTransition.test.ts::enterEnvelopeMs` |
| The animation opt-in survives the definition round-trip (unset = no animation, `true` = animated) | `server/src/forms.rs::definition_can_enable_page_animations` + `definition_includes_styling` |
| Drafts: what gets stored (answered values only, with each answer's field type), and what is dropped on load — another version, an expired draft, a deleted or retyped question, a page index the form no longer reaches. Storage that is absent or refuses (private mode, quota, partitioned iframe) leaves the form working | `browser/form-renderer/src/draft.test.ts` |
| Drafts end to end: returning to a half-filled form opens the resume dialog over the seeded answers, Continue keeps them, Reset wipes them on screen *and* on disk, and submitting clears the draft so the next visitor on that browser gets a blank form | `browser/e2e/tests/forms-submission.spec.ts` ("an unfinished form is restored from the visitor's own device") |
| The drafts opt-out survives the definition round-trip (unset = drafts on and the key absent from the wire format, `false` = off) | `server/src/forms.rs::definition_can_disable_drafts` |
| Scheduling: `form-published-at` stays the master switch (a schedule alone never publishes), half-open window edges, either bound alone, an inverted window never opening, and the UTC rendering of a bound | `server/src/forms.rs` (`unpublished_form_is_never_available` … `schedule_moment_renders_in_utc`) |
| Scheduling end to end: a close-at in the past and an open-at in the future each 410 the definition, the HTML page (still embeddable) and submit; clearing both bounds reopens the form, for a real anonymous visitor too | `server/src/tests.rs::form_submission_flow` (step 7b) + `browser/e2e/tests/forms-submission.spec.ts` ("a scheduled window opens and closes a published form") |
| A GET of a Form serves the *persisted* Loro snapshot: the class extender's `form-submission-summary` is in the JSON-AD but never as a Loro op the store does not have (the op that parked every later commit from a builder tab that had hydrated over HTTP) | `server/src/tests.rs::form_submission_flow` (step 2b) + `lib/src/class_extender.rs::extended_get_serves_the_persisted_snapshot` |
| Visitor-facing form routes forbid HTTP caching (`Cache-Control: no-store` on the definition, 200 and 410 alike) — a cached 410 is what made the builder's publish look like it never reached the server | `server/src/tests.rs::form_submission_flow` (steps 1 and 2) |
| Custom CSS is sanitized and minified on the way out: `@import` stripped (it would fetch a third-party sheet into every visitor's browser), `@font-face` kept, empty / unparseable / over-50 KB dropped whole, and brace breakouts re-serialized balanced so they cannot escape the renderer's `@layer`/`@scope` wrapper | `server/src/forms.rs` (`sanitize_custom_css_minifies_and_keeps_rules` … `sanitize_custom_css_reserializes_brace_breakouts`) |
| Sanitized custom CSS reaches `styling.customCss` in the definition, and the key is absent from the wire format when unset | `server/src/forms.rs::definition_carries_sanitized_custom_css` + `definition_omits_custom_css_when_unset` |
| The renderer wraps custom CSS in `@layer atomic-form-custom` + `@scope (.atomic-form-shell)` verbatim, and injects nothing at all when there is none | `browser/form-renderer/src/customCss.test.ts` |
| The builder's CSS editor catches what would silently lose an owner's work: unbalanced braces (ignoring braces inside comments and strings) and CSS past the server's byte cap | `browser/data-browser/src/chunks/CodeEditor/cssLint.test.ts` |
| Custom CSS end to end: written in the builder, published, and applied for an anonymous visitor on the real `/form/:id` route — including the layering claim itself, since a bare `h1` (0-0-1) overrides the renderer's `.atomic-form-title` (0-1-0), which only a later cascade layer can do; plus `:scope` re-theming through `--atomic-form-*`, `@import` gone from the served definition, and a `body` rule matching nothing (`@scope` held) | `browser/e2e/tests/forms-submission.spec.ts` ("a published form carries the owner's custom CSS") |

Previously listed here as "Not covered (scheduling, blocked by a sync bug)":
the reopen half of the scheduling e2e. Two things were going on, neither of
them the sync race it was filed as. The commit that got parked ("Commit's
Loro update depends on ops the server does not have") depended on a Loro op
the server had written into the response of an HTTP GET but never persisted
— the Form class extender used `set` for the summary, and the doc was
re-exported as the served `loroUpdate` (fixed in `get_resource_extended`, and
the extender now shapes the response without touching the doc). The client's
recovery for a parked commit (drop the save cursor, re-send a full snapshot)
did work, so the server converged; what kept the test — and a console
`fetch` — reporting the old state was Chromium replaying a cached `410` for
the definition URL. The e2e probe now fetches with `cache: 'no-store'` and the
server sends `Cache-Control: no-store` on those routes.

Not covered (custom CSS): only one browser. `@scope` sets the floor at Chrome
118 / Safari 17.4 / Firefox 128 and the suite is chromium-only, so a visitor
below that floor silently gets the base styling and no test would notice. The
e2e above deliberately asserts the *layer* rather than just "some CSS applied"
— an identical `h1` rule placed in `atomic-form-base` loses to
`.atomic-form-title`, and in `atomic-form-custom` wins, so that assertion fails
if the layering regresses rather than passing on a coincidence.

Not covered (extended types): the client-side mirror of the new validators in
`browser/form-renderer/src/validation.ts` is only unit-tested for `phone` (the
one rule that deliberately diverges — it is stricter than the server for E.164
values); every other type is tested on the Rust side only, and the two are
hand-mirrored, so they can drift (the
same known gap as `buildFormDefinition.ts` vs `build_form_definition`, and as
`chunks/FormBuilder/formSchedule.ts` vs `form_availability_at` — the builder's
schedule status line is hand-mirrored from the server rule and has no test of
its own, though the server side it mirrors is fully covered); the
option-image *picker* in `PictureChoiceOptions.tsx` (uploading or picking a file
for an option) is only exercised manually; `choice-matrix` / `table-input` /
`picture-choice` are rendered and validated but never submitted end-to-end in
e2e.

Not covered (options as resources): that a form's choice column is usable *as a
table column* — picking its tags in `SelectCell`, grouping a kanban by it — is
untested, even though making that work is the reason the mapped Property is a
real SelectProperty. `max` enforcement in `SelectCell` (how single-pick is
expressed) has no test either. Deleting an option that submissions already
reference folds those answers into the summary's "Other" bucket; that path is
reasoned about but not pinned by a test.

Not covered (options from another table): the whole builder side is manual —
`LinkOptionsDialog` (picking a table + column), the "linked to X" panel and
unlinking, and everything `applyOptionsSource` does to the mapped Property
(mirroring `allowsOnly`, switching to a relation column for row-sourced
questions, destroying the question's own orphaned Tags). The client mirror
`rowOptions`/`tagOptions` in `buildFormDefinition.ts` has no test either — the
same hand-mirroring drift as the rest of that file. `OPTIONS_ROW_LIMIT`
truncation (a table with more than 1,000 rows silently offering only the first
1,000, and rejecting a pick past the cap) is untested, and the preview
deliberately applies no cap at all.

Class constraints in tables, kanban and the ontology editor
(`planning/class-constraints-and-forms.md`, step 2): `getEffectiveConstraint` /
`setClassConstraint` are unit-tested in `browser/lib/src/effective-constraint.test.ts`
(merge across classes, per-keyword fallback to `allowsOnly` / `classtype` /
`min` / `max`, edit semantics). `createSelectProperty.test.ts` pins that a new
select column's options and single pick land in the row class's `constraints`
(not on the Property), that a reused property gets Tags of its own, and the
`constraintsOn: 'property'` mode the form builder still uses. `ontology.spec.ts`
drives linked class, options and instance restrictions through the class card;
`tables.spec.ts` creates and fills a select column. Not covered: editing an
existing select column's options in `EditPropertyDialog` (class save, legacy
dual-write), the number / text range and relation class going from the dialog
to the class map, `useTableColumns` re-reading columns when the class map
changes, `TagPropertyCard`'s class usage rows, and forms bound to a table column
whose options now live only in the class map (see the forms entry below).

Class constraints in forms (`planning/class-constraints-and-forms.md`, step 3):
`formFieldSettings.test.ts` and `formConstraints.test.ts` pin the limit
keywords, that old names read and are rewritten on edit, that a question can only
tighten its column's constraint (rejected before any write), and the
`describe_form` JSON Schema (class narrowed by the question, `enum` of Tags).
`createFormFromSpec.test.ts` / `formOps.test.ts` pin that a new choice question's
options and single pick land in the data class's constraints and that choice
edits write the class, not the Property. `server/src/forms.rs` tests cover
options from the class `enum` over legacy `allowsOnly`, legacy key renaming,
narrowing, exclusive bounds, `pattern` and row counts in `validate_submission`;
`class_constraints.rs` covers `effective_constraint` / `tighten`. The renderer
checks the same keywords in `validation.test.ts`. `forms.spec.ts` reads option
labels from the class map. Not covered: linking options to another table in the
builder writes the class (no unit test; the e2e links a table), the Rust and TS
narrowing are separate implementations without a shared fixture, a `pattern`
the Rust regex and the JS `RegExp` read differently, and legacy forms whose
Property keeps `allowsOnly` after a row link (the class `enum` is removed but the
Property fallback still lists the old tags in the builder).

Not covered (drafts): the debounce/flush wiring in `useFormDraft` — the
`pagehide` and `visibilitychange` flushes in particular — is only exercised
through the e2e (which waits for the debounced write rather than forcing a
flush); a tab closed mid-keystroke is reasoned about, not pinned. The
`saveDrafts` opt-out is tested at the definition layer but never toggled in
the builder UI, and multi-page draft resume (the stored `pageIndex`) is unit
tested only. The resume dialog is exercised through its buttons; dismissing it
with Escape (which maps to Continue) is not.

Not covered: builder UI for adding/removing conditions (the e2e walks it once as setup, not as its own assertion); page-level (not field-level) branching in e2e (unit fixtures cover it); add/delete-page write ordering in `PageTabBar` (both now `await` the form's `form-pages` save — add before selecting, delete before destroying — but no test pins that ordering).

---

## Files and image previews

| Flow | Where |
|---|---|
| Upload → blob stored → content-addressed download round-trip | `server/src/tests.rs::upload_download_test` |
| `/download/files/{hash}` answers with the File's real mimetype, not `application/octet-stream` | `server/src/tests.rs::upload_download_test` |
| An uploaded SVG actually decodes in the preview (local `blob:` URL **and** the server `downloadURL`) | `browser/e2e/tests/filePicker.spec.ts` ("uploaded SVG renders in the preview") |
| File picker lists files, filters by name, previews text | `browser/e2e/tests/filePicker.spec.ts` |
| Upload while offline, then reconnect | `browser/e2e/tests/file-upload-offline.spec.ts`, `browser/lib/tests/upload-offline-reconnect.integration.test.ts` |

Both halves of the SVG row guard the same class of bug and neither implies the
other: a `blob:` URL takes its Content-Type from the `Blob`'s `type`, the
network URL from the response header, and an `<img>` renders SVG only when that
type is exactly `image/svg+xml` (raster formats it will sniff; SVG it never
will). `user_blob_response` also sets `nosniff`, so an `application/octet-stream`
answer breaks *every* image type on the network path, not just SVG.

Not covered: that the network `downloadURL` path is what actually renders once
the local bytes are evicted — the e2e asserts the header directly rather than
clearing the ClientDb and re-rendering. No test pins the `?w=`/`?f=` rendition
route's refusal to process SVG (`is_image_bytes` rejects it); the app avoids
that route for SVG, but nothing enforces that it keeps doing so.
## Private-drive sign-in availability regressions (2026-09-22)

Required outcome: a valid agent secret can open a writable private drive at
its deterministic DID even when no prior content can be recovered. Creating
that root must not be presented as successful recovery of previous content.

`browser/e2e/tests/sign-in-without-data.spec.ts` now requires:

- A fresh account with no recoverable data opens the exact derived home,
  reads it as a Drive, creates a document, and retains its title after reload
  (`@smoke`). This subsumes the old "not another workspace" assertion.
- An unavailable legacy home does not prevent that same writable-home outcome.
- A persisted identity with no home can initialize it on a direct link. The
  fixture seeds only the supported IndexedDB fallback identity record, so it
  does not depend on sign-in first creating the drive.
- An unrelated missing drive stays unreadable; Sync does not claim it is
  cached/offline-ready or known to exist on another device.

The old recovery-roadblock expectation and localStorage-DID-only "place to
write" assertions were removed. The label-only "sync page shows correct
status" test was removed; `sync-devices.spec.ts` retains device rendering,
provider isolation and pairing coverage.

`helpers/syncPresentation.test.ts` rejects an inferred remote copy in the
missing-drive summary. `helpers/driveData.test.ts` covers read failures and
refresh after a cached miss, alongside local/server refresh dispatch. These
boolean-helper tests do not establish why a read failed or where copies exist.
`private-drive-idempotence.test.ts` requires exactly one own-drive list entry
(previously zero passed); the duplicate same-subject test was removed because
`store.private-drive.test.ts` already checks repeated creation and identity.

The browser now recovers first, then initializes only the signed-in identity’s
derived home with an optional device/backup nudge. `openPrivateHome.test.ts`
covers existing/recovered data preservation, foreign subjects, concurrent
requests, recovery failure and identity switches. Mounted onboarding tests
cover the nonblocking own-home path and the foreign-workspace recovery gate.
Existing genesis, migration, sign-out/content preservation and successful
Vault restoration tests remain. The E2E fixture installs the commit watcher
so document persistence is checked for both HTTP and WebSocket saves.

Still missing: late failed reads invalidating a newly initialized home;
reconciliation preserving both old content and new fallback work; integrated
sign-in variants for empty Vault, failed restore, read timeout, offline nodes
and blocked local storage. Vault helper tests cover several return values,
but do not prove sign-in's next action. The real Vault E2E skips without its
control plane. Same-subject library tests are not persistence evidence, and
a second browser using the same populated server is not an unavailable-data
scenario.

Validation for this coverage change: 14 library tests passed; 14 presentation/
availability tests passed and the new missing-drive-summary assertion failed
on the unsupported "device that has it" claim. All four Chromium regressions
failed against the current app: both sign-in cases stayed at recovery, the
persisted-session home remained unreadable, and Sync displayed both false
claims. Document creation/reload assertions are downstream of these failures
and are not yet validated by this run. The smoke listing includes the new
no-data sign-in acceptance test. Focused lint/format checks passed. App and
E2E typechecks report errors in unchanged files (including RTE CommandsExtension,
AI, plugin, right-panel and website tests), not the edited coverage files.

## Mac app account handoff

`helpers/onboardingStorage.test.ts` covers the browser OPFS readiness check and
the Tauri embedded-node `/server` and WebSocket readiness checks.
`helpers/managed/reconcile.test.ts` protects an unreadable local identity from
being treated as disposable. Managed API and device-link tests cover bearer
requests without cookies from a native WebView. `lib/src/native-offline-writes.test.ts`
checks that native saves fail visibly when the embedded node is disconnected,
rather than reporting an OPFS-only offline save. The browser
`native-account-restore.spec.ts` covers the fresh native sign-in and recovery
entry, and `vault-backup-restore.spec.ts` checks Vault restore against a real
S3-compatible store when the acceptance services are available.

The packaged Mac app was launched and its embedded `/server` returned
`internal:/server`. Its welcome, sign-in, and account creation entry screens
were visually checked with their production styling; the native WebView had
previously held entry animations at opacity zero while unfocused. A full
account-first and Mac-first transfer
with a fresh macOS test user, Vault canary, relaunch, and cross-device edit is
still a manual acceptance check. See `desktop/ACCOUNT_ACCEPTANCE.md` for the
isolated service setup and exact journeys. Browser E2E and an ad-hoc signed
package do not establish production passkey, Developer ID, or update behavior.

## Rust build alignment

`scripts/test_rust_alignment.py` tests matching pairs, compiler/workflow pin drift,
development profile drift, transitive Loro versions, missing shared crates, extra
cryptography prereleases, and allowed unrelated dependency differences. Run
`python3 -m unittest discover -s scripts -p test_rust_alignment.py -v`.
The Rust build policy workflow runs these checks; downstream CI checks both
repositories and rejects dependency lockfile drift before builds.

## Mobile AI chat (#1591)

`browser/e2e/tests/ai-mobile.spec.ts` checks full-width phone layout and message bodies, long titles keeping the header menu on-screen, the chat resource menu targeting the saved conversation and opening its full-page view, a composer that fits above a simulated keyboard inset, options and token visibility, closing the panel, desktop composer bounds, and model selection with focus returning to the editor. A long-response regression reproduces the final sentence being clipped after keyboard resize, verifies bottom-following and the small gap above the composer, and preserves reading position when scrolled up. AI responses are mocked; a physical mobile keyboard is not exercised.

AI credit display: `helpers/managed/ai.test.ts` verifies usage notification when the SDK cancels a hosted stream; `components/AI/useHostedAI.test.tsx` verifies the immediate refresh and one delayed settlement refresh without ongoing polling. `HostedAICredits.test.tsx` covers fractional monthly and purchased balances and offers the purchase link only in a hosted distribution when SaaS reports checkout available. `ai-mobile.spec.ts` verifies the balance stays hidden until AI Chat options opens, refreshes from the account API, and does not offer checkout in a FOSS build. These use mocked account/provider responses and do not verify live billing or the chat error purchase action.

Recovery read fan-out: `recovery-fetch.test.ts` verifies concurrent reads share
one in-flight request per API/account, settled responses are not cached, failures
can be retried, and signed-out callers make no request. The SaaS legacy recovery
upgrade journey passes with the production per-account request limit.

## AI chat folder identity and discovery

`agent.test.ts` covers independent devices deriving the same valid folder certificate, separation by drive/account, and refusal to derive an identity using a nondeterministic signer. `agentStorage.test.ts` checks stable folder IDs survive non-extractable key storage and subsequent keypair updates. `standardLocations.test.ts` covers concurrent calls across stores, reuse without resetting folder metadata, legacy sessions, and refusal to initialize over transport failures or known deletion.

`ai-chat-discovery.spec.ts` checks that the visible sidebar includes chats from duplicate folders and the drive root before and after reload, excludes other drives and non-chat resources, and that two separately signed-in browser contexts create chats using the same folder ID. AI responses are mocked. Physical Safari and an offline two-device reconnect are not covered.

Unreadable workspace summaries: `syncPresentation.test.ts` rejects copy that assumes another device has the data or that local data is protected; the summary reports an unreadable workspace without asserting where its data resides.

## Compact presence and retry pressure (2026-09-22)

`NavBarButton.test.tsx` reproduces the compact navbar hiding span-based presence
triggers and verifies only action labels disappear. `presence-follow.spec.ts`
uses two tabs sharing one stored test identity, checks the avatar at 320px,
opens Follow and verifies subsequent navigation. The updated Chromium test
passed against the local app; cross-network staging presence was not certified.
`sidebar-layout.spec.ts` checks the resource menu stays inside 390px and 320px
viewports, action labels collapse, and the menu opens on tap.

`recovery-fetch.test.ts` verifies 429 cooldowns (Retry-After seconds and a
60-second fallback), retry after expiry, in-flight sharing and fresh successful
reads. `browser-peer-sync.test.ts` verifies increasing per-peer retry delays and
that repeated discovery notifications cannot bypass them. These mitigate retry
pressure; they do not prove the cause of the reported staging slowdown.

The sign-in/profile/sign-out smoke test also requires explicit sign-out to
clear the local identity and land on the welcome screen without an account
settings continuation, both immediately and after reload. The settings guard
must not override an intentional sign-out or device lock.


## Legacy HTTP compatibility

| Behavior | Tests | Scope |
| --- | --- | --- |
| Foreign HTTP parent/drive collections query their own origin despite an empty or partial local cache and disconnected home server | `browser/lib/src/legacy-http-collection.test.ts` | HTTP subjects preserved; unrelated default personal-drive scope omitted; explicit server respected; DID queries remain local-first |
| Pre-DID queries retry without unsupported parameters and filter locally | `browser/lib/src/legacy-http-collection.test.ts` | Preserves drive ancestry and AND filters, sorts before pagination, keeps undated rows; a loaded parent Drive overrides stale default scope |
| Migrated agents authenticate legacy HTTP reads at their original origin | `browser/lib/src/client-legacy-auth.test.ts` | Original HTTP identity, padded standard-base64 key/signature, real Ed25519 verification; other hosts, schemes, ports and lookalikes never receive the legacy identity |
| Public legacy HTTP drive and its children load from a nodeless home | `browser/lib/src/legacy-http-live-check.test.ts` | Opt-in `ATOMIC_LEGACY_LIVE=1`; live atomicdata.dev read verified 2026-09-23. Does not cover private legacy auth or browser sidebar rendering |

## Agent secrets from app.atomic.place (#1649)

`browser/lib/src/agent-secret-1649.test.ts` passes a synthetic secret in the
deployed app's base64 JSON format with an `atomic:agent:` subject through the
same `Agent.fromSecret` parser used by the local welcome form. It verifies
the identity and public key. Browser sign-in and data recovery are separate
flows.

## Hidden-tab liveness and presence after reconnect (#1800)

`browser/lib/src/liveness.test.ts` replays the WS liveness timer at a hidden
tab's once-a-minute cadence and checks that a socket whose probes are answered
is never closed, while a dead one still closes one tick after its probe times
out. It does not drive a real browser's throttling.
`server/tests/it/drive_presence.rs`
(`presence_sent_right_after_subscribe_is_delivered`) sends a presence update
right behind `PRESENCE_SUBSCRIBE`, as every reconnect does, and checks it
reaches the other subscriber without a retry, and that an update held for a
refused subscribe is dropped.

## Onboarding audit regressions

- `websockets.test.ts`: missing and unauthorized drives cannot SUB or automatically
  reconcile via a legacy DID when the read error is cached under its canonical ID.
- `helpers/readableDrive.test.ts`: explicit portal selection waits for a readable
  resource and discards results after navigation or identity changes.
- `helpers/managed/vaultAutoBackup.test.ts`: a confirmed missing canonical drive
  stays local-only after recovery through its legacy alias; transport failures
  do not change routing.
- `helpers/managed/readCache.test.ts`: short metadata read sharing, expiry,
  independent response bodies, provider/token isolation, mutation invalidation,
  cancellation/cache-control bypass, and retryable error/anonymous responses.
- `oxc-react-compiler.test.ts`: the full app must avoid internal compiler invariants,
  including identity creation and the connect-device polling loop.
- The paired SaaS `portal/e2e/onboarding.spec.ts` closes the original context,
  downloads the vault into a fresh browser, verifies the saved document and
  profile, requires a clean console, and budgets metadata reads after reload.

## Flutter account package (draft)

`packages/atomic_flutter/test/account_test.dart` covers device approval, provider
origin binding, redirect refusal, account/backup mismatch, authenticated discovery,
AES-GCM envelope compatibility with an independently generated Node fixture,
tamper rejection, and closing during a pending request. Atomic Audio additionally
checks isolated native identity installation and actual bidirectional iroh/Loro
with BLAKE3 files introduced after pairing. Production account approval, Vault
transport and recovery on a physical device are not covered by these tests.

## Lenses (`docs/src/schema/lenses.md`)

Both implementations run the cases in `lib/tests/fixtures/lenses.json`
(rename, wrap and head, enum map, string to integer with an unparseable value,
both properties present, no chaining): `lens::tests::shared_fixture` (JSON and
propvals paths) in `lib/src/lens.rs`, and `browser/lib/src/lens.test.ts`. Lens
ID vectors are asserted on both sides. Store level: `db::test::lenses` covers
derived values on read and in the value index (backfill when the Lens arrives,
an edit of the old property, a real value winning, index rebuild from stored Lens
resources), the `parent` authority check, ID mismatch and identity
immutability; `lens.test.ts` covers `ensureLens`, activation, and
re-materializing a loaded resource when a Lens arrives.

Not covered: lens application on the Iroh and WebSocket sync import paths (they
share `persist_replicated_*`, which is covered through `build_projection_tx`
only by reasoning, not a test), a browser reload with lenses loaded through
`loadLenses`, and the data-browser flows that mint a lens (datatype change,
form question shortname) end to end.

## Optional account sign-in after local identity unlock

`helpers/managed/agentSession.test.ts` checks that a local identity can unlock
without an account, avoids a redundant account read after that result, and
retains linked-account sign-in. Paired SaaS HTTP tests verify the optional
lookup returns a normal signed-out result only after a valid signature; explicit
unlinked sign-in remains 404 and tampered signatures remain 401.
`signout-signin-data.spec.ts` verifies content and the same encrypted database
key survive sign-out/sign-in with strict browser console checks enabled.

Paired SaaS `hosted-recovery-live.spec.ts` opts into isolated nodes and mock
billing. It onboards a fresh account, uploads its browser-only drive to a
managed node, reads a saved child directly over HTTP, queues an edit with WS
disconnected, reconnects, then signs in on a fresh browser and verifies the
edited child after reload. It does not certify real billing or a full network
partition.
