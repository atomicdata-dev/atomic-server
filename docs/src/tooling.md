{{#title Software and libraries for Atomic Data}}
# Software and libraries for Atomic Data

Although Atomic Data is a specification, it also has reference implementations:

Open source (MIT licenced) software for Atomic Data:

- **Server + Database**: [atomic-server](https://github.com/atomicdata-dev/atomic-server)
- **CLI**: [atomic-cli](https://github.com/atomicdata-dev/atomic-server)

Libraries (MIT licenced) to build apps with:

- Typescript / javascript library: [@tomic/lib](js.md)
- React library: [@tomic/react](usecases/react.md)
- Svelte library: [@tomic/svelte](svelte.md)
- Rust library: [atomic-lib (crates.io)](https://crates.io/crates/atomic-lib)

## Applications

### `atomic-server`

Server for hosting Atomic Data. Uses `atomic-lib`, `@tomic/lib` and `@tomic/react`.


- Responds to requests for created Atomic Resources, makes atomic data available at their URL.
- Embedded database
- Authorization, authentication, versioning, collections, pagination
- Browser-friendly HTML presentation, JSON serialization, RDF serialization.
- View & edit atomic data, using dynamic forms
- Collections with pagination and sorting
- Client-side full-text search

One liner: `$ docker run -p 80:80 -v atomic-storage:/atomic-storage joepmeneer/atomic-server`

[demo](https://atomicdata.dev/)

[repository + issue tracker](https://github.com/atomicdata-dev/atomic-data-browser).

### `atomic-cli`

A tool for generating / querying Atomic Data from the command line. Install with `cargo install atomic-cli`.

```
atomic 0.20.0
Joep Meindertsma <joep@ontola.io>
Create, share, fetch and model linked atomic data!

USAGE:
    atomic-cli [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    destroy    Permanently removes a Resource. Uses Commits.
    edit       Edit a single Atom from a Resource using your text editor. Uses Commits.
    get        Traverses a Path and prints the resulting Resource or Value.
    help       Prints this message or the help of the given subcommand(s)
    list       List all bookmarks
    new        Create a Resource
    remove     Remove a single Atom from a Resource. Uses Commits.
    set        Update an Atom's value. Uses Commits.
    tpf        Finds Atoms using Triple Pattern Fragments.

Visit https://github.com/atomicdata-dev/atomic-data-browser for more info
```

[repository + issue tracker](https://github.com/atomicdata-dev/atomic-data-browser).


### Raycast extension: Full-text search from your desktop

[Install here](https://www.raycast.com/atomicdata-dev/atomic-data-browser).

## Libraries

### `@tomic/lib` and `@tomic/react`

Javascript / typescript libraries, especially useful for creating front-end apps.

Fork the [atomic-data-react-template](https://codesandbox.io/s/atomic-data-react-template-4y9qu?file=/src/MyResource.tsx) on codesandbox to get started directly!

### `atomic-lib` (Rust)

Library that powers `atomic-server` and `atomic-cli`. Features:

- An in-memory store
- Parsing (JSON-AD) / Serialization (JSON-AD, JSON-LD, TTL, N-Triples)
- Commit validation and processing
- Constructing Collections
- Path traversal
- Basic validation

[repository + issue tracker](https://github.com/atomicdata-dev/atomic-server).

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
