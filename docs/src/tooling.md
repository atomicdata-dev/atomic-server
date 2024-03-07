{{#title Software and libraries for Atomic Data}}
# Software and libraries for Atomic Data

Libraries and clients (all MIT licenced) that work great with [atomic-server](atomic-server.md):

- Typescript / javascript library: [@tomic/lib](js.md)
- React library: [@tomic/react](usecases/react.md)
- Type CLI (npm): [@tomic/cli](js-cli.md) for generating TS types from ontologies
- Svelte library: [@tomic/svelte](svelte.md)
- Client CLI (rust): [atomic-cli](rust-cli.md) for fetching & editing data
- Rust library: [atomic-lib](rust-lib.md) powers `atomic-server` and `atomic-cli`, and can be used in other Rust projects ([docs.rs](https://docs.rs/atomic_lib/0.37.0/atomic_lib/))
- [Raycast Extension](https://www.raycast.com/atomicdata-dev/atomic-data-browser): full-text search

## Want to add to this list? Some ideas for tooling

This document contains a set of ideas that would help achieve that success.
Open a PR and [edit this file](https://github.com/atomicdata-dev/atomic-server/edit/develop/docs/src/tooling.md) to add your project!

### Atomic Companion

A mobile app for granting permissions to your data and signing things. See [github issue](https://github.com/ontola/atomic-data-docs/issues/45).

- Show a notification when you try to log in somewhere with your agent
- Notifications for mentions and other social items
- Check uptime of your server

### Atomizer (data importer and conversion kit)

- Import data from some data source (CSV / SQL / JSON / RDF), fill in the gaps (mapping / IRI creation / datatypes) an create new Atoms
- Perhaps a CLI, library, GUI or a combination of all of these

### Atomic Preview

- A simple (JS) widget that can be embedded anywhere, which converts an Atomic Graph into an HTML view.
- Would be useful for documentation, and as a default view for Atomic Data.
- Use `@tomic/react` and `@tomic/lib` to get started

### Atomic-Dart + Flutter

Library + front-end app for browsing / manipulating Atomic Data on mobile devices.
