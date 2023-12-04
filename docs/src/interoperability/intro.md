{{#title Atomic Data Interoperability - Relationship and comparison to other technology}}
# Interoperability: Relation to other technology

Atomic data is designed to be easy to use in existing projects, and be interoperable with existing formats.
This section will discuss how Atomic Data differs from or is similar to various data formats and paradigms, and how it can interoperate.

## Upgrade guide

* [Upgrade](upgrade.md): How to make your existing (server-side) application serve Atomic Data. From easy, to hard.

## Data formats

* [JSON](json.md): Atomic Data is designed to be easily serializable to clean, idiomatic JSON. However, if you want to turn JSON into Atomic Data, you'll have to make sure that all keys in the JSON object are URLs that link to Atomic Properties, and the data itself also has to be available at its Subject URL.
* [RDF](rdf.md): Atomic Data is a strict subset of RDF, and can therefore be trivially serialized to all RDF formats (Turtle, N-triples, RDF/XML, JSON-LD, and others). The other way around is more difficult. Turning RDF into Atomic Data requires that all predicates are Atomic Properties, the values must match its properties datatype, the atoms must be available at the subject URL, and the subject-predicate combinations must be unique.

## Protocols

* [Solid](solid.md): A set of specifications that has many similarities with Atomic Data
* [IPFS](ipfs.md): Content-based addressing to prevent 404s and centralization

## Database paradigms

* [SQL](sql.md): How Atomic Data differs from and could interact with SQL databases
* [Graph](graph-database.md): How it differs from some labeled property graphs, such as Neo4j
