# Atomic

_Disclaimer: this project primarily serves as a project for me to learn Rust, and to check whether
the [Atomic Data spec](https://docs.atomicdata.dev) I'm working on actually makes some sense._

_Status: buggy, pre-alpha_

Create, share, fetch and model linked [Atomic Data](https://docs.atomicdata.dev)!
This project consists of a [CLI](#atomic-cli), a [server](#atomic-server) and a [library](#atomic-lib) for Rust.

## Install

### Using binaries

You can find the binaries on the [Releases page](https://github.com/joepio/atomic/releases/tag/v0.3.1).
Currently only builds for debian / ubuntu.

### From source

Install [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) to build from source.

```sh
git clone git@github.com:joepio/atomic-cli.git
cd atomic-cli
# Install atomic and atomic-server to path
cargo install --path ./
```

## Quick start

```sh
# Add a mapping, and store the Atomic Class locally
$ atomic map person https://example.com/person

# Create a profile for yourself
$ atomic new person
# By default, atomic creates IFPS resources for your created data, which are publicly stored
Created at: ipfs:Qwhp2fh3o8hfo8w7fhwo77w38ohw3o78fhw3ho78w3o837ho8fwh8o7fh37ho
# Add a mapping for your newly created resource, so you can use that shortname instead of the long IPFS url.
bookmark (optional): shortname

# Instead of link to an Atomic Server where you can upload your stuff
# If you don't, your data exists locally and gets published to IPFS
$ atomic setup
# install ontologies and add their shortnames to bookmarks
$ atomic install https://atomicdata.dev/ontologies/meetings
# when no URL is given, use the Ontola repo's ontologies
$ atomic install meetings
```

## Binaries

This repo contains two executables (the `atomic` CLI and the `atomic-server` application).

### `atomic` (CLI)

A command-line application to create, read and interact with Atomic Data.
Should work with Atomic-Server (which is not yet the case).

```
atomic 0.1.3
Joep Meindertsma <joep@ontola.io>
Create, share, fetch and model linked atomic data!

USAGE:
    atomic [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    get     Traverses a Path and prints the resulting Resource or Value. Examples:
            atomic get "class description"
            atomic get "https://example.com"
            Visit https://docs.atomicdata.dev/core/paths.html for more info about paths.
    help    Prints this message or the help of the given subcommand(s)
    list    List all bookmarks
    new     Create a Resource

Visit https://github.com/joepio/atomic-cli for more info
```

#### Progress

- [x] Stores & reads stuff from and to .ad3 user files on disk
- [x] A `new` command for instantiating [Atomic Classes](https://docs.atomicdata.dev/schema/classes.html)
- [x] A `list` command for showing local bookmarks (mappings)
- [x] A `get` command for finding resources and parts of data using Atomic Paths with...
  - [x] AD3 Serialization
  - [x] Basic JSON Serialization
  - [ ] Actually good JSON Serialization
  - [ ] RDF (Turtle / N-Triples / RDF/XML) Serialization
- [ ] Works with `atomic-server` (stores there, uses domain etc.)
- [ ] Fetch data from the interwebs with `get` commands
- [ ] A `map` command for creating a bookmark and storing a copy
- [ ] An `edit` command for manipulating existing resources

#### Config

Atomic creates a `~/.config/atomic` folder, which contains a `mapping.amp` and a

#### Mapping

The Mapping refers to your user specific set of shortname-URL combinations.
This Mapping lives as a simple text file in `./user_mappping.amp`.

```
person=https://atomicdata.dev/classes/Person
```

### `atomic-server`

A lightweight HTTP server that shares created Atomic data on the web.

For setting up the server:

```sh
# Create a new .env using the template
cp default.env .env
# Run the server. It loads the .ad3 store that you point towards
atomic-server
# Visit http://localhost:8080/test
```

- [x] Respond to GET request for individual resources
- [ ] Content-type negotiation
- [ ] HTML serialization
- [ ] TPF endpoint
- [ ] HTTPS
- [ ] Write / Mutations support
- [ ] Collections / dynamic resources

## `atomic-lib`

A rust library for handling Atomic Data.
The `atomic` CLI and `atomic-server` applications both use this `atomic-lib` library.
This library should do the following:

- [x] Serialization to [AtomicTriples (.ad3)](https://docs.atomicdata.dev/core/serialization.html)
- [x] Read / write / resolve mappings
- [x] Resolve Atomic Paths
- [ ] [Validate]() Atomic Graphs

## Development

```sh
# You can pass arguments to binaries using cargo run like this
$ cargo run --bin atomic -- get class
```
