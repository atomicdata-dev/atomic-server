# Atomic CLI

_Disclaimer: this project primarily serves as a project for me to learn Rust, and to check whether
the [Atomic Data spec](https://docs.atomicdata.dev) I'm working on actually makes some sense._

_Status: buggy, pre-alpha_

Create, share, fetch and model linked [Atomic Data](https://docs.atomicdata.dev)!

```sh
# Add a mapping, and store the Atomic Class locally
atomic map person https://example.com/person
# Create a new instance with that Class
atomic new person
name (required): John McLovin
age: 31
Created at: ipfs:Qwhp2fh3o8hfo8w7fhwo77w38ohw3o78fhw3ho78w3o837ho8fwh8o7fh37ho
# link to an Atomic Server where you can upload your stuff
# If you don't, your data exists locally and gets published to IPFS
atomic setup
# install ontologies and add their shortnames to bookmarks
atomic install https://atomicdata.dev/ontologies/meetings
# when no URL is given, use the Ontola repo's ontologies
atomic install meetings
```

## Install

Install [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) to build from source.

```sh
git clone git@github.com:joepio/atomic-cli.git
cd atomic-cli
cargo install --path ./
```

## Quick start

After installing `atomic`, create yourself a class:

```sh
atomic new class
```

Let's create the Person class.
Or get creative, of course.

```sh
shortname: person
description: a real human being
recommends: name description birthdate
```

## Config

Atomic creates a `~/.config/atomic` folder, which contains a `mapping.amp` and a

## Mapping

The Mapping refers to your user specific set of shortname-URL combinations.
This Mapping lives as a simple text file in `./user_mappping.amp`.

```
person=https://atomicdata.dev/classes/Person
```
