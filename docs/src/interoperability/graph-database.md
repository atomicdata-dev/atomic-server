{{#title How does Atomic Data relate to Graph Databases?}}
# Atomic Data and Graph Databases

Atomic Data is fundamentally a _graph data model_.
We can think of Atomic Resources as _nodes_, and links to other resources through _properties_ as _edges_.

In the first section, we'll take a look at Atomic-Server as a Graph Database.
After that, we'll explore how Atomic Data relates to some graph technologies.

## Atomic-Server as a database

- **Built-in REST**. Everything is done over HTTP, there's no new query language or serialization to learn. It's all JSON.
- **All resources have HTTP URLs**. This means that every single thing is identified by where it can be be found. Makes it easy to share data, if you want to!
- **Sharable and re-usable data models**. Atomic Schema helps you share and re-use data models by simply pointing to URLs.
- **Authorization built-in**. Managing rights in a hierarchy (similar to how tools like Google Drive or filesystems work) enable you to have a high degree of control over read / write rights.
- **Built-in easy to use GUI**. Managing content on Atomic-Server can be done by anyone, as its GUI is extremely easy to use and has a ton of features.
- **Dynamic indexing**. Indexes are created by performing Queries, resulting in great performance - without needing to manually configure indexing.
- **Synchronization over WebSockets**. All changes (called [Commits](../commits/intro.md)) can be synchronized over WebSockets, allowing you to build realtime collaborative tools.
- **Event-sourced**. All changes are stored and reversible, giving you a full versioned history.
- **Open source**. All code is MIT-licensed.

## Comparing Atomic Data to Neo4j

Neo4j is a popular graph database that supports multiple query languages.
The first difference is that Atomic Data is not a single piece of software but a _specification_.
However, we can compare Neo4j as a _product_ with the open source [Atomic-Server](https://crates.io/crates/atomic-server).
Atomic-Server is fully open source and free (MIT licensed), whereas Neo4j is partially open source and GPL licensed.

### Labeled Property Graph

The data model of Neo4j features a _labeled property graph_, which means that edges (relationships between nodes) can have their own properties.
This can be useful when adding data to relationship between nodes.
For example: in the `john - (knows) -> mary` relationship, you might want to specify _for how long_ they have known each other.
In Neo4j, we can add this data to the labeled property graph.

In Atomic Data, we'd have to make a new resource to describe the relation between the two, if we wanted to add information about the relationship itself.
This is called _reification_.
This process can be time consuming, especially in Atomic Data, as this means that you'll have to specify the Class of this relationship and its properties.
However, one benefit of this approach, is that the relationship itself becomes clearly defined and re-usable.
Another benefit is that the simpler model of Atomic Data maps perfectly to datamodels like JSON, which makes things very convenient and familiar for developers.

### Query language vs REST

Neo4j supports multiple query languages, but its mainly known for _Cypher_.
It is used for doing practically everything: reading, writing, modelling, and more.

Atomic Data on the other hand does not have a query language.
It uses a RESTful HTTP + JSON-AD approach for everything.
Atomic Data uses [Endpoints](../endpoints.md) for specific goals that you'd do in a query language:

 - [Collections](../schema/collections.md) (which can filter by Property or Value, and sort by any Property) to generate lists of resources
 - [Paths](../core/paths.md) for traversing graphs by property

And finally, data is written using [Commits](../commits/intro.md).
Commits are very strict, as each one describes modifications to individual resources, and every Commits has to be signed.
This means that with Atomic Data, we get _versioning + audit trails_ for all data, but at the cost of more storage requirements and a bit more expensive write process.

### Schema language and type safety

In Neo4j, constraints can be added to the database by
Atomic Data uses [Atomic Schema](../schema/intro.md) for validating datatypes and required properties in [Classes](../schema/classes.md).

### Other differences

- Atomic Data has an [Authentication model](../agents.md) and [Hierarchy model](../hierarchy.md) for authorization. Neo4j uses [roles](https://neo4j.com/docs/operations-manual/current/authentication-authorization/built-in-roles/#auth-built-in-roles).
- Neo4j is actually used in production by many big organizations
