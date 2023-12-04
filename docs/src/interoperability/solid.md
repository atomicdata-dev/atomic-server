{{#title How does Atomic Data relate to Solid?}}
# Atomic Data and Solid

The [Solid project](https://solidproject.org/) is an initiative by the inventor of linked data and the world wide web: sir Tim Berners-Lee.
In many ways, it has **similar goals** to Atomic Data:

- Decentralize the web
- Make things more interoperable
- Give people more control over their data

Technically, both are also similar:

- Usage of **personal servers**, or PODs (Personal Online Datastores). Both Atomic Data and Solid aim to provide users with a highly personal server where all sorts of data can be stored.
- Usage of **linked data**. All Atomic Data is valid RDF, which means that **all Atomic Data is compatible with Solid**. However, the other way around is more difficult. In other words, if you choose to use Atomic Data, you can always put it in your Solid Pod.

But there are some important **differences**, too, which will be explained in more detail below.

- Atomic Data uses a strict built-in schema to ensure type safety
- Atomic Data standardizes state changes (which also provides version control / history, audit trails)
- Atomic Data is more easily serializable to other formats (like JSON)
- Atomic Data has different models for authentication, authorization and hierarchies
- Atomic Data does not depend on existing semantic web specifications
- Atomic Data is a smaller and younger project, and as of now a one-man show

_Disclaimer: I've been quite involved in the development of Solid, and have a lot of respect for all the people who are working on it.
Solid and RDF have been important inspirations for the design of Atomic Data.
The following is not meant as a critique on Solid, let alone the individuals working on it._

## Atomic Data is type-safe, because of its built-in schema

Atomic Data is more strict than Solid - which means that it only accepts data that conforms to a specific shape.
In a Solid Pod, you're free to add any shape of data that you like - it is not _validated_ by some schema.
Yes, there are some efforts of using SHACL or SHEX to _constrain_ data before putting it in, but as of now it is not part of the spec or any implementation that I know of.
A lack of schema strictness can be helpful during prototyping and rapid development, especially if you write data by hand, but it also limits how easy it is to build reliable apps with that data.
Atomic Data aims to be very friendly for developers that re-use data, and that's why we take a different approach: all data _must be_ validated by Atomic Schema before it's stored on a server.
This means that all Atomic Properties will have to exist on a publicly accessible URL, before the property can be used somewhere.

You can think of Atomic Data more like a (dynamic) SQL database that offers guarantees about its content type, and a Solid Pod more like a document store that takes in all kinds of content.
Most of the differences have to do with how Atomic Schema aims to make linked data easier to work with, but that is covered in the previous [RDF chapter](./rdf.md).

## Atomic Data standardizes state changes (event sourcing)

With Solid, you change a Resource by sending a POST request to the URL that you want to change.
With Atomic, you change a Resource by sending a signed Commit that contains the requested changes to a Server.

Event sourcing means that all changes are stored (persisted) and used to calculate the current state of things.
In practice, this means that users get a couple of nice features for free:

- **Versioning for all items by default**. Storing events means that these events can be _replayed_, which means you get to traverse time / undo / redo.
- **Edit / audit log for everything**. Events contain information about who made which change at which point in time. Can be useful for finding out why things are the way they are.
- **Easier to add query options / indexes**. Any system can play-back the events, which means that the events can be used as an API to add new query options / fill new indexes. This is especially useful if you want to add things like full-text search, or some geolocation index.

It also means that, compared to Solid, there is a relatively simple and strict API for changing data.
Atomic Data has a **uniform write API**.
All changes to data are done by posting Commits to the `/commits` endpoint of a Server.
This removes the need to think about differences between all sorts of HTTP methods like POST / PUT / PATCH, and how servers should reply to that.

_EDIT: as of december 2021, Solid has introduced `.n3 patch` for standardizing state changes. Although this adds a uniform way of describing changes, it still lacks the power of Atomic Commits. It does not specify signatures, mention versioning, or deals with persisting changesets. On top of that, it is quite difficult to read or parse, being `.n3`._

## Atomic Data is more easily serializable to other formats (like JSON)

Atomic Data is designed with the modern (web)developer in mind.
One of the things that developers expect, is to be able to traverse (JSON) objects easily.
Doing this with RDF is not easily possible, because doing this requires _subject-predicate uniqueness_.
Atomic Data does not have this problem (properties _must_ be unique), which means that traversing objects becomes easy.

Another problem that Atomic Data solves, is dealing with long URLs as property keys.
Atomic Data uses `shortnames` to map properties to short, human-readable strings.

For more information about these differences, see the previous [RDF chapter](./rdf.md).


## Authentication

Both Solid an Atomic Data use URLs to refer to individuals / users / Agents.

Solid's identity system is called WebID.
There are multiple supported authentication protocols, the most common being [WebID-OIDC](https://github.com/solid/webid-oidc-spec).

Atomic Data's [authentication model](../authentication.md) is more similar to how SSH works.
Atomic Data identities (Agents) are a combination of HTTP based, and cryptography (public / private key) based.
In Atomic, all actions (from GET requests to Commits) are signed using the private key of the Agent.
This makes Atomic Data a bit more unconventional, but also makes its auth mechanism very decentralized and lightweight.

## Hierarchy and authorization

Atomic Data uses `parent-child` [hierarchies](../hierarchy.md) to model data structures and perform authorization checks.
This closely resembles how filesystems work (including things like Google Drive).
Per resource, `write` and `read` rights can be defined, which both contain lists of Agents.

Solid is working on the [Shape Trees](https://shapetrees.org/TR/specification/) spec, which also describes hierarchies.
It uses SHEX to perform shape validation, similar to how Atomic Schema does.


## No dependency on existing semantic web specifications

The Solid specification (although still in draft) builds on a 20+ year legacy of committee meetings on semantic web standards such as RDF, SPARQL, OWL and XML.
I think the process of designing specifications in [various (fragmented) committees](https://en.wikipedia.org/wiki/Design_by_committee) has led to a set of specifications that lack simplicity and consistency.
Many of these specifications have been written long before there were actual implementations.
Much of the effort was spent on creating highly formal and abstract descriptions of common concepts, but too little was spent on making specs that are easy to use and solve actual problems for developers.

Aaron Scharz (co-founder or reddit, inventor of RSS and Markdown) wrote this in his [unfinished book 'A Programmable Web'](https://ieeexplore.ieee.org/document/6814657):

> Instead of the “let’s just build something that works” attitude that made the Web (and the Internet) such a roaring success, they brought the formalizing mindset of mathematicians and the institutional structures of academics and defense
contractors.
> They formed committees to form working groups to write drafts of ontologies that carefully listed (in 100-page Word documents) all possible things in the universe and the various properties they could have, and they spent hours in Talmudic debates over whether a washing machine was a kitchen appliance or a household cleaning device.

(The book is a great read on this topic, by the way!)

So, in a nutshell, I think this legacy makes Solid unnecessarily hard to use for developers, for the following reasons:

- **RDF Quirks**: Solid has to deal with all the [complexities of the RDF data model](./rdf.md), such as blank nodes, named graphs, subject-predicate duplication.
- **Multiple (uncommon) serialization formats** need to be understood, such as `n3`, `shex` and potentially all the various RDF serialization formats. These will feel foreign to most (even very experienced) developers and can have a high degree of complexity.
- **A heritage of broken URLs**. Although a lot if RDF data exists, only a small part of it is actually resolvable as machine-readable RDF. The large majority won't give you the data when sending a HTTP GET request with the correct `Accept` headers to the subject's URL. Much of it is stored in documents on a different URL (`named graphs`), or behind some SPARQL endpoint that you will first need to find. Solid builds on a lot of standards that have these problems.
- **Confusing specifications**. Reading up on RDF, Solid, and the Semantic Web can be a daunting (yet adventurous) task. I've seen many people traverse a similar path as I did: read the RDF specs, dive into OWL, install protege, create ontologies, try doing things that OWL doesn't do (validate data), read more complicated specs that don't help to clear things, become frustrated... It's a bit of a rabbit hole, and I'd like to prevent people from falling into it. There's a lot of interesting ideas there, but it is not a pragmatic framework to develop interoperable apps with.

## Atomic Data and Solid server implementations

Both Atomic Data and Solid are specifications that have different implementations.
Some open source Solid implementations are the [Node Solid Server](https://github.com/solid/node-solid-server), the [Community Solid Server](https://github.com/solid/community-server) (also nodejs based) and the [DexPod](https://gitlab.com/ontola/dexpod) (Ruby on Rails based).

[Atomic-Server](https://github.com/atomicdata-dev/atomic-server/) is a database + server written in the Rust programming language, that can be considered an alternative to Solid Pod implementations.
It was definitely built to be one, at least.
It implements every part of the Atomic Data specification.
I believe that as of today (february 2022), Atomic-Server has quite a few advantages over existing Solid implementations:

<!-- List copied from https://github.com/atomicdata-dev/atomic-server/blob/master/README.md -->
- **Dynamic schema validation** / type checking using [Atomic Schema](https://docs.atomicdata.dev/schema/intro.html), combining the best of RDF, JSON and type safety.
- **Fast** (1ms responses on my laptop)
- **Lightweight** (8MB download, no runtime dependencies)
- **HTTPS + HTTP2 support** with Built-in LetsEncrypt handshake.
- **Browser GUI included** powered by [atomic-data-browser](https://github.com/atomicdata-dev/atomic-data-browser). Features dynamic forms, tables, authentication, theming and more. Easy to use!
- **Event-sourced versioning** / history powered by [Atomic Commits](https://docs.atomicdata.dev/commits/intro.html)
- **Many serialization options**: to JSON, [JSON-AD](https://docs.atomicdata.dev/core/serialization.html#json-ad), and various Linked Data / RDF formats (RDF/XML, N-Triples / Turtle / JSON-LD).
- **Full-text search** with fuzzy search and various operators, often <3ms responses.
- **Pagination, sorting and filtering** using [Atomic Collections](https://docs.atomicdata.dev/schema/collections.html)
- **Invite and sharing system** with [Atomic Invites](https://docs.atomicdata.dev/invitations.html)
- **Desktop app** Easy desktop installation, with status bar icon, powered by [tauri](https://github.com/tauri-apps/tauri/).
- **MIT licensed** So fully open-source and free forever!

## Things that Atomic Data misses, but Solid has

Atomic Data is not even two years old, and although progress has been fast, it does lack some specifications.
Here's a list of things missing in Atomic Data, with links to their open issues and links to their existing Solid counterpart.

- No inbox or [notifications](https://www.w3.org/TR/ldn/) yet ([issue](https://github.com/ontola/atomic-data/issues/28))
- No OIDC support yet. ([issue](https://github.com/atomicdata-dev/atomic-server/issues/277))
- No support from a big community, a well-funded business or the inventor of the world wide web.
