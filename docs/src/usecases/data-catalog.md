{{#title Atomic Server as a Data Catalog}}
# Using Atomic-Server as a Data Catalog

A data catalog is a system that collects metadata - data about data.
They are inventories of datasets.

They are often used to:

- **Increase data-reuse of (open) datasets**. By making descriptions of datasets, you increase their discoverability.
- **Manage data quality**. The more datasets you have, the more you'll want to make sure they are usable. This could mean settings serialization requirements or schema compliance.
- **Manage compliance with privacy laws**. If you have datasets that contain GDPR-relevant data (personal data), you're legally required to maintain a list of where that data is stored, what you need it for and what you're doing with it.

## Why Atomic Server could be great for Data Catalogs

[Atomic-Server](https://docs.atomicdata.dev/atomic-server.html) is a powerful Database that can be used as a modern, powerful data catalog. It has a few advantages over others:

- Free & **open source**. MIT licensed!
- Many built-in features, like **full-text search**, **history**, **live synchronization** and **rights management**.
- Great **performance**. Requests take nanoseconds to milliseconds.
- Very **easy to setup**. One single binary, no weird runtime dependencies.
- Everything is linked data. Not just datasets (which you might), but also everything around them (users, comments, implementations).
- Powerful **CMS capabilities**. With built in support for Tables and Documents, you can easily create webpages with articles or other types of resources using Atomic Server.
- [Atomic Schema](../schema/intro.md) can be used to describe the **shape of your datasets**: the properties you use, which fields are required - things like that. Because Atomic Schema uses URLs, we can easily re-use properties and class definitions. This helps to make your datasets highly interoperable.

## When Atomic-Server is used for hosting the data, too

Most datacatalogs only have metadata. However, if you convert your existing CSV / JSON / XML / ... datasets to _Atomic Data_, you can host them on Atomic-Server as well. This has a few advantages:

- **Data previews** in the browser, users can navigate through the data without leaving the catalog.
- Data itself becomes **browseable**, too, which means you can traverse a graph by clicking on link values.
- **Standardized Querying** means you can easily, from the data catalog, can filter and sort the data.
- **Cross-dataset search**. Search queries can be performed over multiple Atomic Data servers at once, enabling searching over multiple datasets. This is also called _federated search_.

## Atomic Server compared to CKAN

- Atomic-Server is MIT licensed - which is more permissive than CKAN's AGPL license.
- Whereas CKAN needs an external database, a python runtime, solrd and a HTTPS server, Atomic-Server has all of these built-in!
- CKAN uses plain RDF, which has some [very important drawbacks](../interoperability/rdf.md).
- But... Atomic-Server still misses a few essentials right now:

## What we should add to Atomic-Server before it's a decent Data Catalog

- Add a model for datasets. This is absolutely essential. It could be based on (and link to) DCAT, but needs to be described using Atomic Schema. This step means we can generate forms for Datasets and we can validate their fields.
- Add views for datasets. Atomic-Server already renders decent views for unknown resources, but a specific view should be created for Datasets. [Add a PR](https://github.com/atomicdata-dev/atomic-data-browser) if you have a React view!
