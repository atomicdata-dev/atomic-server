# `atomic-cli`

[![crates.io](https://img.shields.io/crates/v/atomic-cli)](https://crates.io/crates/atomic-cli)
[![Discord chat](https://img.shields.io/discord/723588174747533393.svg?logo=discord)](https://discord.gg/a72Rv2P)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![github](https://img.shields.io/github/stars/atomicdata-dev/atomic-data-rust?style=social)](https://github.com/joepio/aget_basetomic)

_Status: Beta. [Breaking changes](../CHANGELOG.md) are expected until 1.0._

**A command-line application to create, read and interact with Atomic Data.**

Designed and tested to work with [atomic-server](https://crates.io/crates/atomic-server/).

```
atomic-cli 0.23.2
Joep Meindertsma <joep@ontola.io>
Create, share, fetch and model Atomic Data!

USAGE:
    atomic-cli [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    destroy    Permanently removes a Resource.
    edit       Edit a single Atom from a Resource using your text editor.
    get        Get a Resource or Value by using Atomic Paths.
    help       Prints this message or the help of the given subcommand(s)
    list       List all bookmarks
    new        Create a Resource
    remove     Remove a single Atom from a Resource.
    set        Update a single Atom. Creates both the Resource if they don't exist. Overwrites existing.

Visit https://atomicdata.dev for more info
```

## Installation

You can install `atomic-cli: in multiple ways:

### Using [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)

```sh
cargo install atomic-cli
```

### Build from source

```sh
git clone git@github.com:atomicdata-dev/atomic-data-rust.git
cd atomic/cli
# Install atomic to path
cargo install --path ./
```

## Usage

Run `atomic-cli command --help` for mor information about specific commands.

The write commands (`set`, `remove`, `edit`, `destroy`) require some authentication config, which needs to match with the target [atomic-server](https://crates.io/crates/atomic-server).
It will read the `~/.config/atomic/config.toml` file, and create one using some prompts if it is not yet present.

## Features

- A `list` command for showing local bookmarks (mappings)
- A `get` command for finding resources and parts of data using Atomic Paths with various serialization options (JSON, JSON-AD, JSON-LD, Turtle, N-Triples, Pretty). Also supports [path traversal](https://docs.atomicdata.dev/core/paths.html).
- `set`, `remove`, `destroy` and `edit` commands that send commits.
- A `new` command for instantiating [Atomic Classes](https://docs.atomicdata.dev/schema/classes.html)

## Config

Atomic creates a `~/.config/atomic` folder, which contains a `mapping.amp` and a `db`.
This folder is also used by `atomic-server`.

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
