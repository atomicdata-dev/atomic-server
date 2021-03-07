# Changelog

List of changes for this repo, including `atomic-cli`,
`atomic-server` and `atomic-lib`.

## v0.23.0

- Added versioning #
- Correct response codes (404) #105

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
