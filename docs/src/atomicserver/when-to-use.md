# Should you use AtomicServer?

## When should you use AtomicServer

- You want a **lightweight, fast, realtime** and easy to use **headless CMS** with live updates, editors, modelling capabilities and an intuitive API
- You want **realtime** updates and collaboration functionality
- You want **high performance**: AtomicServer is incredibly fast and can handle thousands of requests per second.
- You want **standalone app**: no need for any external applications or dependencies (like a database / nginx).
- You want **versioning** or **full-text search**.
- You want to build a webapplication, and like working with using [React](https://github.com/atomicdata-dev/atomic-data-browser) or [Svelte](https://github.com/atomicdata-dev/atomic-svelte).
- You want to make (high-value) **datasets as easily accessible as possible**
- You want to specify and share a **common vocabulary** / ontology / schema for some specific domain or dataset. Example classes [here](https://atomicdata.dev/classes).
- You want to use and **share linked data**, but don't want to deal with most of [the complexities of RDF](https://docs.atomicdata.dev/interoperability/rdf.html), SPARQL, Triple Stores, Named Graphs and Blank Nodes.
- You are interested in **re-decentralizing the web** or want want to work with tech that improves data ownership and interoperability.

## When _not_ to use AtomicServer

- High-throughput **numerical data / numerical analysis**. AtomicServer does not have aggregate queries.
- If you need **high stability**, look further (for now). This is beta sofware and can change.
- You're dealing with **very sensitive / private data**. The built-in authorization mechanisms are relatively new and not rigorously tested. The database itself is not encrypted.
- **Complex query requirements**. We have queries with filters and features for path traversal, but it may fall short. Check out NEO4j, Apache Jena or maybe TerminusDB.

## Up next

Next, we'll get to run AtomicServer!
