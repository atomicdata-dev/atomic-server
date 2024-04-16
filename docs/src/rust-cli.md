{{#title atomic-cli: Rust Client CLI for Atomic Data}}
# atomic-cli: Rust Client CLI for Atomic Data

An open source terminal tool for generating / querying Atomic Data from the command line.
Install with `cargo install atomic-cli`.

```
atomic-cli --help
Create, share, fetch and model Atomic Data!

Usage: atomic-cli [COMMAND]

Commands:
  new      Create a Resource
  get      Get a Resource or Value by using Atomic Paths.
  tpf      Finds Atoms using Triple Pattern Fragments.
  set      Update a single Atom. Creates both the Resource if they don't exist. Overwrites existing.
  remove   Remove a single Atom from a Resource.
  edit     Edit a single Atom from a Resource using your text editor.
  destroy  Permanently removes a Resource.
  list     List all bookmarks
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

Visit https://atomicdata.dev for more info
```

[Repository](https://github.com/atomicdata-dev/atomic-server/tree/develop/cli)
