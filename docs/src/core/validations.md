# Atomic Graph Validations

An Graph is a set of Atoms.
Since Atomic Data is designed to facilitate decentralized data storage, Graphs will often lack information or contain invalid data.
In this section, we define some of these concepts.

- A **Valid Graph** contains no mismatches between Datatypes from Properties and their usage in Atoms
- A **Closed Graph** contains no unfetched outgoing links
- A **Verified Graph** contains only Atoms from verified Authors
- A **Schema Complete Graph** contains all used linked Properties
- A **Frozen Graph** contains content-addressing identifiers (e.g. IPFS), all the way down

These concepts are important when creating an implementation of a Store.

## Valid Graphs

We refer to a Graph as Valid, if the following constraints are met:

- **The Datatypes are correctly used**. The Graph does not contain Atoms where the Datatype of the Value does not match the Datatype of the Property of the Atom.
- **The links work**. All URLs used in the Graph (Subject, Property, Value) resolve correctly to the required Datatype.
- **The Class Restrictions are met**. If a Class sets required properties, these must be present in Resources that are instances of that Class.

Making sure Graphs are Valid is of great importance to anyone creating, sharing or using Atomic Data.
Services should specify whether they check the validity of graphs.

## Closed Graphs

A Graph is Closed, when the Resources of all URLs are present in the Graph.
In other words, if you were to fetch and download every single URL in a Graph, you would not have any more Atoms than before.
There are no more unfetched outgoing links.

Closed Graphs are _rarely_ required in Atomic Data; it's often perfectly fine to have outgoing links that do not have been fetched.

## Verified Graphs

When you are given some Atomic Graph by someone, you initially don't know for sure whether the Atoms themselves are actually created by the one controlling the subject URL.
Someone may have tempered with the data, or fabricated it.

The process of Verification can be done in two ways:

1. **Request the subjects, and check if the atoms match**.
1. **Verify the signatures of the Resources or Commits**

When one of these steps is taken, we say that the Graph is Verified.

## Schema Complete Graphs

When a Graph has a set of Atoms, it might not possess all the information that is required to determine the datatype of each Atom.
When that is the case, we say the Graph is _Schema Complete_.

Having a Schema Complete Graph is essential for determining what the Datatype is of a Value.
Most implementations of Atomic Data will need Schema Completeness to create fitting views, or apply functional business logic.

Imagine some application (perhaps an app running inside a web-browser) that has only the following data:

```ndjson
["https://example.com/john","https://example.com/birthDate","1991-01-20"]
```

Now, by looking at this single Atom, we might assume that the Value is an ISO date,
but this type information is not known yet to the application.
This type information should be specified in the `example:birthDate` Property.
It is the responsibility of the application to make sure it possess the required Schema data.

We say a Graph is _Schema Complete_ when it contains _at least_ all the Property Classes that are used in the Property fields.

So let's add the missing Property: `https://example.com/birthDate`

```ndjson
["https://example.com/john","https://example.com/birthDate","1991-01-20"]
["https://example.com/birthDate","https://atomicdata.dev/datatypes/Datatype","https://atomicdata.dev/datatypes/dateTime"]
```

Now, since we've introduced yet another Property, we need to include that one as well:

```ndjson
["https://example.com/john","https://example.com/birthDate","1991-01-20"]
["https://example.com/birthDate","https://atomicdata.dev/datatypes/Datatype","https://atomicdata.dev/datatypes/dateTime"]
["https://atomicdata.dev/datatypes/Datatype","https://atomicdata.dev/datatypes/Datatype","https://atomicdata.dev/datatypes/atomicURI"]
```

Since all valid Atomic Data requires Property fields to resolve to Atomic Properties Classes, which are required to have an associated DataType...
We can safely say that the last atom in the example above (the one describing `https://atomicdata.dev/datatypes/Datatype`) will have to be pre
sent in all Schema Complete Atomic Graphs.

## Frozen Graphs

A Frozen Graph consists only of resources with content-addressing identifiers as Subjects.
A [content-addressable](https://flyingzumwalt.gitbooks.io/decentralized-web-primer/avenues-for-access/lessons/power-of-content-addressing.html) URL (such as an IPFS URL) refers to specific immutable content, that is absolutely certain not to change over time.
Due to its static nature, we call it _Frozen_.
As long as a graph contains links to HTTP Resources, it is not Frozen, since responses from that HTTP address might change over time.

Freezing a Graph, therefore, entails converting all resources to IFPS (or another content-addressable schema) Resources, and using only IPFS URLs.

Freezing a Graph has performance benefits for clients, since clients can easily verify if they already have (part of) the Graph locally, simply by comparing the URLs or Resources.
It also helps to make sure the content can be shared peer to peer

Note that **Graphs with cyclical relations cannot be frozen**, since every iteration that you'd try to freeze will change its references and therefore also its contents, and therefore also its content hash.
