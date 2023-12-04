{{#title Upgrade your existing application to serve Atomic Data}}
# Upgrade your existing application to serve Atomic Data

You don't have to use [Atomic-Server](https://crates.io/crates/atomic-server) and ditch your existing projects or apps, if you want to adhere to Atomic Data specs.

As the Atomic Data spec is modular, you can start out simply and conform to more specs as needed:

1. Map your JSON keys to new or existing Atomic Data properties
2. Add `@id` fields to your resources, make sure these URLs resolve using HTTP
3. Implement parts of the [Extended spec](../extended.md)

There's a couple of levels you can go to, when adhering to the Atomic Data spec.

## Easy: map your JSON keys to Atomic Data Properties

If you want to make your existing project compatible with Atomic Data, you probably don't have to get rid of your existing storage / DB implementation.
The only thing that matters, is how you make the data accessible to others: the _serialization_.
You can keep your existing software and logic, but simply change the last little part of your API.

In short, this is what you'll have to do:

Map all properties of resources to Atomic Properties.
Either use [existing ones](https://atomicdata.dev/properties), or [create new ones](https://atomicdata.dev/app/new?classSubject=https%3A%2F%2Fatomicdata.dev%2Fclasses%2FProperty&parent=https%3A%2F%2Fatomicdata.dev%2Fagents%2F8S2U%2FviqkaAQVzUisaolrpX6hx%2FG%2FL3e2MTjWA83Rxk%3D&newSubject=https%3A%2F%2Fatomicdata.dev%2Fproperty%2Fsu98ox6tvkh).
This means: take your JSON objects, and change things like `name` to `https://atomicdata.dev/properties/name`.

That's it, you've done the most important step!

Now your data is already more interoperable:

- Every field has a clear **semantic meaning** and **datatype**
- Your data can now be **easily imported** by Atomic Data systems

## Medium: add `@id` URLs that properly resolve

Make sure that when the user requests some URL, that you return that resource as a [JSON-AD](../core/json-ad.md) object (at the very least if the user requests it using an HTTP `Accept: application/ad+json` header).

- Your data can now be **linked to** by external data sources, it can become part of a **web of data**!

## Hard: implement Atomic Data Extended protocols

You can go all out, and implement Commits, Hierarchies, Authentication, Collections and [more](https://docs.atomicdata.dev/extended.html).
I'd suggest starting with [Commits](../commits/intro.md), as these allow users to modify data whilst maintaining versioning and auditability.
Check out the [Atomic-Server source code](https://github.com/atomicdata-dev/atomic-server/tree/master/server) to get inspired on how to do this.

## Reach out for help

If you need any help, join our [Discord](https://discord.gg/a72Rv2P).

Also, share your thoughts on creating Atomic Data in [this issue on github](https://github.com/ontola/atomic-data-docs/issues/95).
