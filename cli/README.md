# `atomic` (CLI)

[![crates.io](https://meritbadge.herokuapp.com/atomic-cli)](https://crates.io/crates/atomic-cli)
[![Discord chat][discord-badge]][discord-url]
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

_Status: pre-alpha_

A command-line application to create, read and interact with Atomic Data.

```
atomic 0.12.1
Joep Meindertsma <joep@ontola.io>
Create, share, fetch and model linked atomic data!

USAGE:
    atomic-cli [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    delta       Update the store using an single Delta
    get         Traverses a Path and prints the resulting Resource or Value.
    help        Prints this message or the help of the given subcommand(s)
    list        List all bookmarks
    new         Create a Resource
    populate    Adds the default Atoms to the store
    tpf         Finds Atoms using Triple Pattern Fragments
    validate    Validates the store
```

## Installation

Install [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) to build from source.

Install using crates.io:

```sh
cargo install atomic-cli
```

Or build from this repo:

```sh
git clone git@github.com:joepio/atomic.git
cd atomic/cli
# Install atomic to path
cargo install --path ./
```

## Usage

```sh
# Learn how to use it
atomic --help
# Try some commands
atomic get class
atomic get "class description"
atomic new class
```

## Progress

- [x] Stores & reads stuff from and to .ad3 user files on disk
- [x] A `new` command for instantiating [Atomic Classes](https://docs.atomicdata.dev/schema/classes.html)
- [x] A `list` command for showing local bookmarks (mappings)
- [x] A `get` command for finding resources and parts of data using Atomic Paths with...
  - [x] AD3 Serialization
  - [x] Basic JSON Serialization
  - [x] RDF (Turtle / N-Triples / RDF/XML) Serialization
- [x] Fetch data from the interwebs with `get` commands
- [ ] Works with [`atomic-server`](../server) (fetches from there, stores there, uses domain etc.) [#6](https://github.com/joepio/atomic/issues/6)
- [x] A `delta` command for manipulating existing resources
- [ ] Tests for the cli
- [ ] A `map` command for creating a bookmark and storing a copy

## Config

Atomic creates a `~/.config/atomic` folder, which contains a `mapping.amp` and a `store.ad3`.

## Mapping

The Mapping refers to your user specific set of shortname-URL combinations.
This Mapping lives as a simple text file in `./user_mappping.amp`.

```
person=https://atomicdata.dev/classes/Person
```

## What this should be able to do

This serves as a UX story that guides the development of this CLI.

```sh
# Add a mapping, and store the Atomic Class locally
# NOT YET SUPPORTED
$ atomic map person https://example.com/person

# Create a profile for yourself
$ atomic new person
# By default, atomic creates IFPS resources for your created data, which are publicly stored
# NOT YET SUPPORTED
Created at: ipfs:Qwhp2fh3o8hfo8w7fhwo77w38ohw3o78fhw3ho78w3o837ho8fwh8o7fh37ho
# Add a mapping for your newly created resource, so you can use that shortname instead of the long IPFS url.
bookmark (optional): shortname

# Instead of link to an Atomic Server where you can upload your stuff
# If you don't, your data exists locally and gets published to IPFS
# NOT YET SUPPORTED
$ atomic setup
# install ontologies and add their shortnames to bookmarks
$ atomic install https://atomicdata.dev/ontologies/meetings
# when no URL is given, use the Ontola repo's ontologies
$ atomic install meetings
```

[discord-badge]: https://img.shields.io/discord/723588174747533393.svg?logo=discord
[discord-url]: https://discord.gg/a72Rv2P
