# `atomic` (CLI)

_Status: pre-alpha_

A command-line application to create, read and interact with Atomic Data.

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
  - [ ] RDF (Turtle / N-Triples / RDF/XML) Serialization
- [ ] Fetch data from the interwebs with `get` commands
- [ ] Works with [`atomic-server`](../server) (fetches from there, stores there, uses domain etc.)
- [ ] A `map` command for creating a bookmark and storing a copy
- [ ] An `edit` command for manipulating existing resources

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
