{{#title How does Atomic Data relate to SQL?}}
# Atomic Data and SQL

Atomic Data has some characteristics that make it similar and different from SQL.

- Atomic Data has a _dynamic_ schema. Any Resource could have different properties, so you can **add new properties** to your data without performing any migrations. However, the properties themselves are still validated (contrary to most NoSQL solutions)
- Atomic Data uses **HTTP URLs** in its data, which means it's easy to **share and reuse**.
- Atomic Data separates _reading_ and _writing_, whereas SQL has one language for both.
- Atomic Data has a standardized way of **storing changes** ([Commits](../commits/intro.md))

## Tables and Rows vs. Classes and Properties

At its core, SQL is a query language based around _tables_ and _rows_.
The _tables_ in SQL are similar to `Classes` in Atomic Data: they both define a set of `properties` which an item could have.
Every single item in a table is called a _row_ in SQL, and a `Resource` in Atomic Data.
One difference is that in Atomic Data, you can add new properties to resources, without making changes to any tables (migrations).

## Dynamic vs static schema

In SQL, the schema of the database defines which shape the data can have, which properties are required, what datatypes they have.
In Atomic Data, the schema exists as a Resource on the web, which means that they can be retrieved using HTTP.
An Atomic Database (such as [Atomic-Server](https://crates.io/crates/atomic-server)) uses a _dynamic schema_,
which means that any Resource can have different properties, and the properties themselves can be validated, even when the server is not aware of these properties beforehand.
In SQL, you'd have to manually adjust the schema of your database to add a new property.
Atomic Data is a decentralized, open system, which can read new schema data from other sources.
SQL is a centralized, closed system, which relies on the DB manager to define the schema.

## Identifiers: numbers vs. URLs

In SQL, rows have numbers as identifiers, whereas in Atomic Data, every resource has a resolvable HTTP URL as an identifier.
URLs are great identifiers, because you can open them and get more information about something.
This means that with Atomic Data, other systems can re-use your data by referencing to it, and you can re-use data from other systems, too.
With Atomic Data, you're making your data part of a bigger _web of data_, which opens up a lot of possibilities.

## Atomic Server combines server and database

If you're building an App with SQL, you will always need some server that connects to your database.
If you're building an App with Atomic Server, the database can function as your server, too. It deals with authentication, authorization, and more.

## Querying

The SQL query language is for both _reading_ and _writing_ data.
In Atomic Data a distinction is made between Query and Command - getting and setting (Command Query Responsibility Segregation, [CQRS](https://martinfowler.com/bliki/CQRS.html)).
The [Query side](../core/querying.md) is handled using Subject Fetching (sending a GET request to a URL, to get a single resource) and [Collections](../schema/collections.md) (filtering and sorting data).
The Command side is typically done using [Atomic Commits](../commits/intro.md), although you're free not to use it.

SQL is way more powerful, as a query language.
In SQL, the one creating the query basically defines the shape of a table that is requested, and the database returns that shape.
Atomic Data does not offer such functionality.
So if you need to create custom tables at runtime, you might be better off using SQL, or move your Atomic Data to a query system.

## Convert an SQL database to Atomic Data

If you want to make your existing SQL project serve Atomic Data, you can keep your existing SQL database, see [the upgrade guide](upgrade.md).
It basically boils down to mapping the rows (properties) in your SQL tables to Atomic Data [Properties](https://atomicdata.dev/classes/Property).

When you want to _import arbitrary Atomic Data_, though, it might be easier to use `atomic-server`.
If you want to store arbitrary Atomic Data in a SQL database, you might be best off by creating a `Resources` table with a `subject` and a `propertyValues` column, or create both a `properties` table and a `resources` one.

## Limitations of Atomic Data

- SQL is far more common, many people will know how to use it.
- SQL databases are battle-tested and has been powering countless of products for tens of years, whereas Atomic Server is at this moment in beta.
- SQL databases have a more powerful and expressive query language, where you can define tables in your query and combine resources.
- Atomic Data doesn't have a [mutli-node / distributed option](https://github.com/atomicdata-dev/atomic-server/issues/213)

## FAQ

### Is Atomic Data NOSQL or SQL?

Generally, Atomic Data apps do not use SQL - so they are NOSQL.
Atomic-server, for example, internally uses a key-value store (sled) for persistence.

Like most NOSQL systems, Atomic Data does not limit data entries to a specific table shape, so you can add any property that you like to a resource.
However, unlike most NOSQL systems, Atomic Data _does_ perform validations on each value.
So in a way, Atomic Data tries to combine best of both worlds: the extendibility and flexibility of NOSQL, with the type safety of SQL.

### Is Atomic Data transactional / ACID?

Yes, if you use Atomic-Server, then you can only write to the server by using Atomic Commits, which are in fact transactions.
This means that if part of the transaction fails, it is reverted - transactions are only applied when they are 100% OK.
This prevents inconsistent DB states.

### How does Atomic Server build indexes for its resources if the schema is not known in advance

It creates indexed collections when users perform queries.
This means that the first time your perform some type of query (that sorts and filters by some properties), it will be slow, but the next time you perform a similar query, it will be fast.
