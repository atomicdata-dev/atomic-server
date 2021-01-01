# Changelog

List of changes for this repo.
Mostly concerns `atomic-lib`.

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

- Add dynamic collections with pagination #36  #17
- Refactor Db to use native values, for allowing nested resources #16
- Atomic Commits using deterministic serialization and cryptographic signatures #26 #24  #27 #31
- Recognize filetypes in URL #33

## v0.13.0

- Save reference to Store inside Resource #19
- No more &muts #18 #15

## v0.12.1

- Adds HTTPS auto certificate support
