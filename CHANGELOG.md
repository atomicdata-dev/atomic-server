# Changelog

List of changes for this repo, including `atomic-cli`,
`atomic-server` and `atomic-lib`.

## v0.25.1

- Add Value indexing, which speeds up TPF queries / collections tremendously #14
- Add models for Document editor
- Improve commit authorization checks - allow new resources with existing parents

## v0.24.2

- Fix `/path` endpoint return values #143
- Add ASCI logo in terminal on boot
- Fix getting resources from server's `/commit` path #144
- Fix cache-control header issue when opening a closed tab #137
- Add collection properties `name`, `sortBy` and `sortDesc` #145
- Extract `apply_changes` from `apply_commit`, make versioning safer and more reliable #146
- Remove AD3 remnants, clean up code #148
- TPF endpoint supports JSON-AD #150
- Custom serializations in `atomic-cli tpf`

## v0.24.1

- Add write rights to Agent itself on accepting Invite
- Fix RDF serialization for dynamic resources #141
- Update and check Usages for Invites #134
- Make names for agents optional
- Move shortname property always to first one

## v0.24.0

- [Hierarchy](https://docs.atomicdata.dev/hierarchy.html) with breadcrumbs and easy to use navigation #134
- Authorization using Hierarchy, which means you can add write & read permissions anywhere in a hierarchy.
- Invites to invite new and existing users to read / edit a bunch of resources. Test it [here](https://atomicdata.dev/invites/1).

## v0.23.5

- Build using esbuild instead of webpack #31
- Some documentation improvements
- Remove `createdAt` from Agent model required fields
- Fix `n-triples` content type negotiation

## v0.23.4

- Fix deadlock in `cli new` command #124
- Added boolean, timestamp and unsupported fallback to `cli new` command #30
- Fix CLI input `server` - no subcommand required for running

## v0.23.3

- Added import / export to server and lib  #121
- Added basic cli functionality with Clap to server #125
- Added multi-resource JSON-AD array parsing #123
- Use JSON-LD as default store #79

## v0.23.2

- Removed all HTML rendering from `atomic-server` (since we're using `atomic-data-browser`).
- Changed how config paths are calculated and shared.
- Remove the need for having the `./static` folder #118 when running `atomic-server`, moved to config dir.
- Add `open config` to tray icon
- Updated `atomic-cli` path, no longer requires quotes

## v0.23.0

- Added versioning #42
- Added endpoints #110 #73
- Moved `/path` logic to `atomic-lib` as endpoint #110
- `get_extended_resource` is now DB only #110
- Correct response codes (404) #105
- Improved .html page (+PWA support and Matomo tracking)
- Upgraded various dependencies

## v0.22.4

- Reject commits if they are editing a non-owned resource #106
- Correct response codes (404) #105

## v0.22.3

- Use atomic-data-browser js frontent by default #103

## v0.22.2

Warning: existing databases will _not_ work with this version.

- Fix deleting items #101
- Add a datatype for floats #93.

## v0.22.1

- Switch to JSON-AD parsing & serialization for Commits #100

## v0.22.0

Warning: existing Agents and Commits will no longer work. Be sure to create new ones.

- Change Commit serialization to [match atomic-data-browser](https://github.com/joepio/atomic-data-browser/issues/3) implementation #98.

## v0.21.1

- Permissive CORS #92

## v0.21.0

- Add JSON-AD serialization #79, use it in Commits
- Servers are aware of their own URL #51
- Improved CLI edit feature, more flexible (create new resources if none exist, fix newlines)
- Add `resource.save_locally()`

## v0.20.4

- Fix array length bug in paths
- Add docker link to homepage
- Add system tray icon #75
- Removed `ResourceString`
- Improved WASM compliance #76
- Add ARM Docker compatibility #80
- Remove dead dependency #82
- CLI commit commands shortname fix #83
- rename `set_propval_by_shortname` to `set_propval_shortname`

## v0.20.3

- Added persistence to server docker image #70
- Improved default Agent setup for server

## v0.20.1

- Improved error handling in cli
- Added tests for cli #67
- Fixed generated addresses `localhost/collection` vs `localhostcollection`
- Added dockerfile for server #69

## v0.20.0

- Huge refactor of internals. Got rid of all string representations for Atoms, so store should only contain valid data. All Resources have all required props, and data is of the correct datatype.
- `Resource.save()` can be called! Easy way to store changes, both locally and externally.
- Added collection sorting #63

## v0.19.0

- Added table view for `atomic-server` #53
- Changed many methods from the `Resource` API to fix some ownership / trait object issues #45. `Resource` no longer has an internal reference to `Store`, so it needs an explicit store in most methods.

## v0.18.0

- Atomic-cli 0.18.0 allows for instantiating new Resources, whilst creating commits! It also re-introduces the TPF query.

## v0.17.1

- Atomic-server 0.17.1 now automatically renews HTTPS certificates on boot, if needed.

## v0.17.0

- `atomic-cli` can now edit data securely on an `atomic-server` #41 #13
- Root agent is automatically generated #38
- Convenient Collections (such as a list of all Commits, Classes, Agents, etc.) are generated for every store on `populate()`. #43
- Fixed some props for Collections and Commits

## v0.15.0

- Add dynamic collections with pagination #36 #17
- Refactor Db to use native values, for allowing nested resources #16
- Atomic Commits using deterministic serialization and cryptographic signatures #26 #24 #27 #31
- Recognize filetypes in URL #33

## v0.13.0

- Save reference to Store inside Resource #19
- No more &muts #18 #15

## v0.12.1

- Adds HTTPS auto certificate support
