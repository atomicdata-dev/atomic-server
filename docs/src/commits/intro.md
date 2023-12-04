{{#title Atomic Commits - Event standard for Atomic Data}}
# Atomic Commits

_Disclaimer: Work in progress, prone to change._

Atomic Commits is a specification for communicating _state changes_ (events / transactions / patches / deltas / mutations) of [Atomic Data](../core/concepts.md).
It is the part of Atomic Data that is concerned with writing, editing, removing and updating information.

## Design goals

- **Event sourced**: Store and standardize _changes_, as well as the _current_ state. This enables versioning, history playback, undo, audit logs, and more.
- **Traceable origin**: Every change should be traceable to an actor and a point in time.
- **Verifiable**: Have cryptographic proof for every change. Know _when_, and _what_ was changed by _whom_.
- **Identifiable**: A single commit has an identifier - it is a resource.
- **Decentralized**: Commits can be shared in P2P networks from device to device, whilst maintaining verifiability.
- **Extensible**: The methods inside a commit are not fixed. Use-case specific methods can be added by anyone.
- **Streamable**: The commits could be used in streaming context.
- **Familiar**: Introduces as little new stuff as possible (no new formats or language to learn)
- **Pub/Sub**: Subscribe to changes and get notified on changes.
- **ACID-compliant**: An Atomic commit will only occur if it results in a valid state.
- **Atomic**: All the Atomic Data design goals also apply here.

## Motivation

Although it's a good idea to keep data at the source as much as possible, we'll often need to synchronize two systems.
For example when data has to be queried or indexed differently than its source can support.
Doing this synchronization can be very difficult, since most of our software is designed to only maintain and share the _current state_ of a system.

I noticed this mainly when working on OpenBesluitvorming.nl - an open data project where we aimed to fetch and standardize meeting data (votes, meeting minutes, documents) from 150+ local governments in the Netherlands.
We wrote software that fetched data from various systems (who all had different models, serialization formats and APIs), transformed this data to a single standard and share it through an API and a fulltext search endpoint.
One of the hard parts was keeping our data in sync with the sources.
How could we now if something was changed upstream?
We queried all these systems every night for _all meetings from the next and previous month_, and made deep comparisons to our own data.

This approach has a couple of issues:

- It costs a lot of resources, both for us and for the data suppliers.
- It's not real-time - we can only run this once every 24 ours (because of how costly it is).
- It's very prone to errors. We've had issues during all phases of Extraction, Transformation and Loading (ETL) processing.
- It causes privacy issues. When some data at the source is removed (because it contained faulty or privacy sensitive data), how do we learn about that?

Persisting and sharing state changes could solve these issues.
In order for this to work, we need to standardize this for all data suppliers.
We need a specification that is easy to understand for most developers.

Keeping track of where data comes from is essential to knowing whether you can trust it - whether you consider it to be true.
When you want to persist data, that quickly becomes bothersome.
Atomic Data and Atomic Commits aim to make this easier by using cryptography for ensuring data comes from some particular source, and is therefore trustworthy.

If you want to know how Atomic Commits differ from other specs, see the [compare section](compare.md)
