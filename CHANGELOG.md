# Changelog

List of changes for this repo, including `atomic-cli`, `atomic-server` and `atomic-lib`.
By far most changes relate to `atomic-server`, so if not specified, assume the changes are relevant only for the server.
**Changes to JS assets (including the front-end and JS libraries) are not shown here**, but in [`/browser/CHANGELOG`](/browser/CHANGELOG.md).
See [STATUS.md](server/STATUS.md) to learn more about which features will remain stable.

## [UNRELEASED]

- Remove `process-management` feature #324 #334

## [v0.37.0] - 2024-02-01

- Refactor `atomic_lib::Resource` propval methods (e.g. `set_propval` => `set`), make them chainable. #822
- Make `set_propval` and `set_propval_shortname` chainable #785
- Deterministic serialization JSON AD #794
- Use `musl` + `alpine` builds for docker images, way smaller images #620
- Support multi-platform docker builds #731
- Remove deprecated ENV vars #732
- Fix no Agent as drive
- Add `clear` option to error component (resets all front-end state)
- Add `Agent::from_secret` #785
- Don't use default agent when fetching with Db #787
- Fix HTTPS / TLS setup #768

## [v0.36.1] - 2023-12-06

- Fix locally searching for atomicdata.dev resources in external servers #706
- Use Earthly for CI: building, testing, pushing Docker images #576
- Host @tomic NPM docs [on Netlify](https://atomic-lib.netlify.app/) #707
- Deprecate Tauri Desktop build #718
- Merge Docs repository into this one #719

## [v0.36.0] - 2023-11-02

- **Requires `--rebuild-index`**
- Switch to monorepo. Include `atomic-data-browser` in this repo #216
- Add Tables (edit, keyboard support, sorting, more) #638
- The `parent` query param in `/search` has changed to `parents` and accepts an array of Subjects #677
- Improve query performance, less index storage #678

## [v0.34.3] - 2023-06-27

- Remove `tpf` queries from `atomic-cli` #610
- Fix `pageSize` property in Collections not using persistence
- Add Table Ontology #25
- Fix Post endpoints not including search params in returned `@id` field.
- Rebuilding indexes done on separate thread, only once #616 #615
- Don't require building index for populate commands
- Refactor `for_agent` arguments to use the new `ForAgent` enum #623
- Add support for Bearer token authentication, find in `/app/token` #632
- Add a `query` endpoint that allows performing collection queries via an endpoint instead of repurposing the collections collection.
- `resource.destroy` now recursively destroys its children.
- Update JS assets, add History view

## [v0.34.2] - 2023-03-04

- **Requires `--rebuild-index`**
- Improve full-text search, use JSON fields #335
- Rename `setup-env` to `generate-dotenv` and build it from clap #599
- Remove `remove_previous_search` and `asset_url` options
- Parse multiple auth cookies #525
- Fix `--script` flag
- Add `Storelike::post_resource`, which allows plugins to parse HTTP POST requests #592
- Move Server-Timing header to crate `simple-server-timing-header`
- Add `POST` + `body` support for Endpoints #592
- Refactor `Endpoint` handlers, uses a Context now #592
- Re-build store + invite when adjusting server url #607
- Use local atomic-server for properties and classes, improves atomic-server #604

## [v0.34.1] - 2023-02-11

- Improve query performance, refactor indexes. The `.tpf` API is deprecated in favor of the more powerful `.query`. #529
- Replace `acme_lib` with `instant-acme`, drop OpenSSL dependency, add DNS verification for TLS option with `--https-dns` #192
- Improved error handling for HTTPS initialization #530
- Add `--force` to `atomic-server import` #536
- Fix index issue happening when deleting a single property in a sorted collection #545
- Update JS assets & playwright
- Fix initial indexing bug #560
- Fix errors on succesful export / import #565
- Fix envs for store path, change `ATOMIC_STORE_DIR` to `ATOMIC_DATA_DIR` #567
- Refactor static file asset hosting #578
- Meta tags server side #577
- Include JSON-AD in initial response, speed up first render #511
- Remove feature to index external RDF files and search them #579
- Add staging environment #588
- Add systemd instructions to readme #271

## [v0.34.0] - 2022-10-31

- Add parent parameter to search endpoint which scopes a search to only the descendants of the given resource. #226
- Bookmark endpoint now also retrieves `og:image` and `og:description` #510
- Give server agent rights to edit all resources, fix issue with accepting invites in private drives #521
- Add cookie based authentication #512
- `Store::all_resources` returns `Iterator` instead of `Vec` #522 #487
- Change authentication order #525
- Fix cookie subject check #525

## [v0.33.1] - 2022-09-25

- Change how the sidebar resources are created
- Update JS assets

## [v0.33.0] - 2022-09-03

- Use WebSockets for fetching resources and authentication. Faster than HTTP! #485
- Added JSON-AD Importer
- Add HTML Bookmarks features
- Update Atomic-Data-Browser
- Improve CLI errors for Atomic-Server #465
- Fix default config directory, set it again to `~/.config/atomic`. This accidentally was `~` since v0.32.0.
- Fix flaky query test #468
- Don't subscribe to external resources #470
- Improve frequency search indexing #473
- Add HTML importer / bookmarks endpoint #432
- Allow new `Drive` resources without a parent
- Refactor end-to-end tests

## [v0.32.2] - 2022-06-20

- Upgrade to stable tauri #451
- Improve performance of invites #450
- Update JS bundle:
  - Fix Dropdown input bug
  - Fix autogrow textarea bug

## [v0.32.1] - 2022-06-15

- Fix issue when creating invite for chatroom #413
- Add OpenTelemetry suport #416
- Fix `remove` Commit command #417 (thanks @rasendubi!)
- Make tests less flaky by removing the `Store` in `Agent:to_resource` #430
- Update JS bundle

## [v0.32.0] - 2022-05-22

- **Warning**: Various default directories have moved (see #331). Most notably the `data` directory. The location depends on your OS. Run `show-config` to see where it will be stored now. If you have data in `~/.config/atomic/db`, move it to this new directory. Also, the search index will have to be rebuilt. Start with `--rebuild-index`.
- Updated various dependencies, and made `cargo.toml` less restrictive.
- Handle `previousCommit`. This means that Commits should contain a reference to the latest Commit.
- Remove `async-std` calls from `upload.rs`
- Added `reset` and `show-config` commands to `atomic-server`.
- Added `data-dir` flag
- Replaced `awc` with `ureq` #374
- Get rid of `.unwrap` calls in `commit_monitor` #345
- Make process management optional #324 #334
- Auto-update desktop distributions using Tauri #158
- Internal migration logic for inter-version compatibility of the database. Makes upgrading trivial. #102
- Use commits in populate and init
- Fix bug when opening the same invite twice with the same agent
- Update atomic-data-browser, deal with new commits, add chatrooms
- Add `Store::set_handle_commit`. Changes how Commits are internally processed. Now, users of `atomic_lib` can pass a custom handler function. This can be used to listen to events. #380 #253
- Added ChatRoom functionality. #373
- Add `push` option to Commits, which allows for efficient manipulation of ResourceArrays. Remove `Resource::append_subjects` method in favor of `push_propvals` #289.
- Add `append` right, only allows creating children #381.
- Fix logic for updating indexes. Sometimes atoms were ignored. #392 #395

## [v0.31.1] - 2022-03-29

- Host the data-browser assets / JS bundles from `atomic-server`'s binary #185
- Allow reading Commits #307
- Upgrade `actix`, `clap` and `tauri` dependencies #301
- No `Mutex` for `Appstate` in server #303
- Removed system tray from `atomic-server`, since I only want to maintain the Tauri version
- Rename `src-tauri` to `desktop` and make the tauri code part of the cargo workspace
- In Queries, respect a `limit` of `None` and `include_external` #317
- Run end-to-end tests from `atomic-data-browser` in `atomic-server` CI #204
- Use `nextest` for testing #338
- Improve and monitor test coverage #337
- Fix commit indexing #345

## [v0.31.0] - 2022-01-25

- Huge performance increase for queries! Added sortable index, big refactor #114
- Added `store.query()` function with better query options, such as `starts_at` and `limit`. Under the hood, this powers `Collection`s,
- `Resource.save` returns a `CommitResponse`.
- Refactor `Commit.apply_opts`, structure options.
- Remove the potentially confusing `commit.apply` method.
- `store.tpf` now takes a `Value` instead of `String`.
- Improved sorting logic. Still has some problems.

## [v0.30.4] - 2022-01-15

Run with `--rebuild-index` the first time, if you use an existing database.
Note that due to an issue in actix, I'm unable to publish the `atomic-server` crate at this moment.
You can still build from source by cloning the repo.

- Improve performance for applying commits and updating index (from ca. 50ms to <1ms), refactor value index #282
- More tracing / logging insights
- More search results for authorized resources #279
- Fix panic on unwrapping multipart upload
- Improve tauri dev UX

## [v0.30.3] - 2021-12-31

- Fix HTTPS initialization
- Add `--server-url` option
- Improved logs (better fitting level options, less verbose by default)
- rename `base_url` to `server_url`

## [v0.30.2] - 2021-12-30

- Update to actix v4, get Tauri to work again #246

## [v0.30.1] - 2021-12-28

- Replace `log` with `tracing` for structured logging and add tracing to `atomic-lib`, enables better (performance) diagnostics #261
- Add `--log-level` option #261
- Add `--trace-chrome` option #261
- Correct 404 status code
- Server-Timings header #256
- Added various endpoints as resources #259
- Show version, author and description in cli tool
- Fix indented welcome message in generated Drive

## [v0.30.0] - 2021-12-22

- Add file uploading and downloading #72
- Reverted to earlier Actix build, which unfortunately also means you have to wait longer for the Tauri desktop version of Atomic-Server #246
- Stricter authorization checks for Invites #182
- Add expires at check to Invites #182
- Add github CI action for Tauri Builds #221
- Add `append_subjects` method to Resource, helps dealing with arrays
- Running `--initialize` is non-destructive - rights to the Drive are only added, not removed.
- Stricter collection authorization #247
- Improved `check_rights` API #247
- Make Agents public by default, required for authentication process #247

## [v0.29.2] - 2021-12-10

- Desktop build (using Tauri) with system tray, icon, installers, menu items. #215
- Upgraded Actix to latest (needed for Tauri due to usage of Tokio runtime) #215
- Allow Agents to write and edit themselves #220
- Less collections for first-time users #224
- Sort collections by subject by default
- Set default port to 9883 instead of 80 #229

## [v0.29.0]

- Add authentication to restrict read access. Works by signing requests with Private Keys. #13
- Refactor internal error model, Use correct HTTP status codes #11
- Add `public-mode` to server, to keep performance maximum if you don't want authentication.

## [v0.28.2]

- Full-text search endpoint, powered by Tantify #40
- Add RDF-Search usecase (enables re-use of this server as search service for Solid pods)
- Add `enum` support using the `allows-only` Property. #206

## [v0.28.1]

- Fix docker env issue #202
- Fix docker image by switching `heim` with `sysinfo` #203
- Fix path ENV variables
- Fix logging while terminating existing process

## [v0.28.0]

- **IMPORANT**: before upgrading to this version, export your database using your previous version: `atomic-server export`. The database could become corrupted when running the new version.
- Refactor internal `Value` model and add Nested Resource parsing #195
- Added tests, improved some documentation
- Fix indexing commits #194
- Add more control over adding resources with `Store.add_resource_opts()`

## [v0.27.2]

- Make HTTPS optional #192
- Fix parsing .env file

## [v0.27.1]

- Fix bootstrapping issue #193

## [v0.27.0]

- **IMPORANT**: before upgrading to this version, export your database using your previous version: `atomic-server export`. The database could become corrupted when running the new version.
- Include Resources in Collection responses, improving performance dramatically for collections #62
- Introduce `incomplete` resources
- Update `get_resource_extended`, allow specify whether to calculate nested resources.
- Sort `children` in hierarchies.
- Sort `export` output - first export Properties, fixing #163
- Add `only-internal` to `export` CLI command in `atomic-server`.

## [v0.26.3]

- Many `atomic-server` CLI improvements. Add options as flags, without needing environment variables. #154

## [v0.26.2]

- Add `setup-env` command to `atomic-server` for creating a `.env` file #154 #187
- Remove analytics in server
- Make `asset-url` and `script` in HTML template customizable. #189

## [v0.26.1]

- Improved error message for hierarchy authorization check #178
- Fix Property `recommends` #177
- Refuse commits with query parameters in their subjects #179
- Add `resource.destroy()` method, which uses commits
- Improve killing existing processes - wait until other process has stopped #167
- Make `atomic-cli` smaller (don't use `db` feature from `atomic-lib`)

## [v0.26.0]

- Added WebSockets support for live synchronization / real-time updates with the front-end #171
- Update index after `destroy`ing a resource #173

## [v0.25.7]

- Improve process ID functionality #167
- Improve invite URL

## [v0.25.6]

- Fix domain .env #169
- Fix HTTPS port bug

## [v0.25.5]

- Check and terminate running instances of `atomic-server` when running instance #167

## [v0.25.4]

- Add flags for `reindex` and `init`
- Improve CI for automated tests & builds #165

## [v0.25.3]

- Improve ease of initial setup with initial invite on `/setup` #159 and welcoming descriptions for first Drive and Invite.

## [v0.25.2]

- Fixes caching bugs for collections introduced by #14
- Fix external resources in Collections #161

## [v0.25.1]

- Add Value indexing, which speeds up TPF queries / collections tremendously #14
- Add models for Document editor
- Improve commit authorization checks - allow new resources with existing parents

## [v0.24.2]

- Fix `/path` endpoint return values #143
- Add ASCI logo in terminal on boot
- Fix getting resources from server's `/commit` path #144
- Fix cache-control header issue when opening a closed tab #137
- Add collection properties `name`, `sortBy` and `sortDesc` #145
- Extract `apply_changes` from `apply_commit`, make versioning safer and more reliable #146
- Remove AD3 remnants, clean up code #148
- TPF endpoint supports JSON-AD #150
- Custom serializations in `atomic-cli tpf`

## [v0.24.1]

- Add write rights to Agent itself on accepting Invite
- Fix RDF serialization for dynamic resources #141
- Update and check Usages for Invites #134
- Make names for agents optional
- Move shortname property always to first one

## [v0.24.0]

- [Hierarchy](https://docs.atomicdata.dev/hierarchy.html) with breadcrumbs and easy to use navigation #134
- Authorization using Hierarchy, which means you can add write & read permissions anywhere in a hierarchy.
- Invites to invite new and existing users to read / edit a bunch of resources. Test it [here](https://atomicdata.dev/invites/1).

## [v0.23.5]

- Build using esbuild instead of webpack #31
- Some documentation improvements
- Remove `createdAt` from Agent model required fields
- Fix `n-triples` content type negotiation

## [v0.23.4]

- Fix deadlock in `cli new` command #124
- Added boolean, timestamp and unsupported fallback to `cli new` command #30
- Fix CLI input `server` - no subcommand required for running

## [v0.23.3]

- Added import / export to server and lib #121
- Added basic cli functionality with Clap to server #125
- Added multi-resource JSON-AD array parsing #123
- Use JSON-LD as default store #79

## [v0.23.2]

- Removed all HTML rendering from `atomic-server` (since we're using `atomic-data-browser`).
- Changed how config paths are calculated and shared.
- Remove the need for having the `./static` folder #118 when running `atomic-server`, moved to config dir.
- Add `open config` to tray icon
- Updated `atomic-cli` path, no longer requires quotes

## [v0.23.0]

- Added versioning #42
- Added endpoints #110 #73
- Moved `/path` logic to `atomic-lib` as endpoint #110
- `get_extended_resource` is now DB only #110
- Correct response codes (404) #105
- Improved .html page (+PWA support and Matomo tracking)
- Upgraded various dependencies

## [v0.22.4]

- Reject commits if they are editing a non-owned resource #106
- Correct response codes (404) #105

## [v0.22.3]

- Use atomic-data-browser js frontent by default #103

## [v0.22.2]

Warning: existing databases will _not_ work with this version.

- Fix deleting items #101
- Add a datatype for floats #93.

## [v0.22.1]

- Switch to JSON-AD parsing & serialization for Commits #100

## [v0.22.0]

Warning: existing Agents and Commits will no longer work. Be sure to create new ones.

- Change Commit serialization to [match atomic-data-browser](https://github.com/atomicdata-dev/atomic-data-browser/issues/3) implementation #98.

## [v0.21.1]

- Permissive CORS #92

## [v0.21.0]

- Add JSON-AD serialization #79, use it in Commits
- Servers are aware of their own URL #51
- Improved CLI edit feature, more flexible (create new resources if none exist, fix newlines)
- Add `resource.save_locally()`

## [v0.20.4]

- Fix array length bug in paths
- Add docker link to homepage
- Add system tray icon #75
- Removed `ResourceString`
- Improved WASM compliance #76
- Add ARM Docker compatibility #80
- Remove dead dependency #82
- CLI commit commands shortname fix #83
- rename `set_propval_by_shortname` to `set_propval_shortname`

## [v0.20.3]

- Added persistence to server docker image #70
- Improved default Agent setup for server

## [v0.20.1]

- Improved error handling in cli
- Added tests for cli #67
- Fixed generated addresses `localhost/collection` vs `localhostcollection`
- Added dockerfile for server #69

## [v0.20.0]

- Huge refactor of internals. Got rid of all string representations for Atoms, so store should only contain valid data. All Resources have all required props, and data is of the correct datatype.
- `Resource.save()` can be called! Easy way to store changes, both locally and externally.
- Added collection sorting #63

## [v0.19.0]

- Added table view for `atomic-server` #53
- Changed many methods from the `Resource` API to fix some ownership / trait object issues #45. `Resource` no longer has an internal reference to `Store`, so it needs an explicit store in most methods.

## [v0.18.0]

- Atomic-cli 0.18.0 allows for instantiating new Resources, whilst creating commits! It also re-introduces the TPF query.

## [v0.17.1]

- Atomic-server 0.17.1 now automatically renews HTTPS certificates on boot, if needed.

## [v0.17.0]

- `atomic-cli` can now edit data securely on an `atomic-server` #41 #13
- Root agent is automatically generated #38
- Convenient Collections (such as a list of all Commits, Classes, Agents, etc.) are generated for every store on `populate()`. #43
- Fixed some props for Collections and Commits

## [v0.15.0]

- Add dynamic collections with pagination #36 #17
- Refactor Db to use native values, for allowing nested resources #16
- Atomic Commits using deterministic serialization and cryptographic signatures #26 #24 #27 #31
- Recognize filetypes in URL #33

## [v0.13.0]

- Save reference to Store inside Resource #19
- No more &muts #18 #15

## [v0.12.1]

- Adds HTTPS auto certificate support
