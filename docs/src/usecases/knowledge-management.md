# Atomic Data for (semantic) knowledge graph management

Knowledge **management** is about making valuable knowledge easily findable, so everybody in an organization can be as effective as possible.
Knowledge **graphs** are information structures that help organizations to organize their knowledge using a graph model.
Graphs are especially useful for structuring knowledge, as they allow having links between resources which makes relationships understandable and makes data browsable.

Atomic Data is a Graph structure, and [Atomic-Server](https://crates.io/crates/atomic-server/) is an open source Graph database / knowledge management system.

## Knowledge management systems

How do organizations store and share knowledge?
Some rely completely on their brains and social networks: if you want to know how the copier works, ask Sara.
But most use digital documents - more often than not in the cloud.
If your knowledge is digital and online available, people can retrieve it from anywhere at great speed.
Being able to search and browse through information is essential to making it effortless to retrieve.

But good knowledge management systems are not just static: they have lives of their own.
Knowledge changes over time.
People add documents, make changes, move things.

## Why use Atomic-Server as a knowledge management system

### The entire web as one knowledge graph

Atomic Data uses URLs to identify resources.
This means that it

### Type-safe, decentralized data structures

Contrary to many other types of graph systems, Atomic Data ensures type-safety by having a built-in schema language ([Atomic Schema](../schema/intro.md)).
This means that it is very easy to share and re-use data models, which helps you standardize the classes and properties that you use.

## Non-goals of Atomic-Server

- Deep, specific query requirements
- Time-series data / data visualization

## Alternatives

- **LinkedDataHub** by Atomgraph (unrelated, don't mind the name similarities): knowledge graph management tool that also supports RDF. Open source.
- **
