{{#title Motivation for creating Atomic Data}}
# Motivation: Why Atomic Data?

<!--

## Ending the mapping problem

Every time a developer builds an app, they have to define their data model.
Almost every new app has a `User` with a `name` and an `e-mail` field, and so on.

## Waste less time

-

-->

## Give people more control over their data

The world wide web was designed by Tim Berners-Lee to be a decentralized network of servers that help people share information.
As I'm writing this, it is exactly 30 years ago that the first website has launched.
Unfortunately, the web today is not the decentralized network it was supposed to be.
A handful of large tech companies are in control of how the internet is evolving, and where and how our data is being stored.
The various services that companies like Google and Microsoft offer (often for free) integrate really well with their other services, but are mostly designed to _lock you in_.
Vendor lock-in means that it is often difficult to take your information from one app to another.
This limits innovation, and limits users to decide how they want to interact with their data.
Companies often have incentives that are not fully aligned with what users want.
For example, Facebook sorts your newsfeed not to make you satisfied, but to make you spend as much time looking at ads.
They don't want you to be able to control your own newsfeed.
Even companies like Apple, that don't have an ad-revenue model, still have a reason to (and very much do) lock you in.
To make things even worse, even open-source projects made by volunteers often don't work well together.
That's not because of bad intentions, that's because it is _hard_ to make things interoperable.

If we want to change this, we need open tech that works really well together.
And if we want that, we need to _standardize_.
The existing standards are well-suited for documents and webpages, but not for structured personal data.
If we want to have that, we need to standardize the _read-write web_, which includes standardizing how items are changed, how their types are checked, how we query lists, and more.
I want all people to have a (virtual) private server that contains their own data, that they control.
This [Personal Data Store](usecases/personal-data-store.md) could very well be an old smartphone with a broken screen that is always on, running next to your router.

Atomic Data is designed to be a standard that achieves this.
But we need more than a standard to get adoption - we need implementations.
That's why I've been working on a server, various libraries, a GUI and [more](tooling.md) - all MIT licensed.
If Atomic Data will be successful, there will likely be other, better implementations.

## Linked data is awesome, but it is too difficult for developers in its current form

[Linked data](https://ontola.io/blog/what-is-linked-data/) (RDF / the semantic web) enables us to use the web as a large, decentralized graph database.
Using links everywhere in data has amazing merits: links remove ambiguity, they enable exploration, they enable connected datasets.
But the existing specs are too difficult to use, and that is harming adoption.

At my company [Ontola](https://ontola.io/), we've been working with linked data quite intensely for the last couple of years.
We went all-in on RDF, and challenged ourselves to create software that communicates exclusively using it.
That has been an inspiring, but at times also a frustrating journey.
While building our e-democracy platform [Argu.co](https://argu.co/), we had to [solve many RDF related problems](https://ontola.io/blog/full-stack-linked-data/).
How to properly model data in RDF? How to deal with [sequences](https://ontola.io/blog/ordered-data-in-rdf/)? How to communicate state changes? Which [serialization format](https://ontola.io/blog/rdf-serialization-formats/) to use? How to convert [RDF to HTML, and build a front-end](https://ontola.io/blog/rdf-solid-react-tutorial-link/)?
We tackled some of these problems by having a tight grip on the data that we create (e.g. we know the type of data, because we control the resources), and another part is creating new protocols, formats, tools, and libraries.
But it took a long time, and it was hard.
It's been almost 15 years since the [introduction of linked data](https://www.w3.org/DesignIssues/LinkedData.html), and its adoption has been slow.
We know that some of its merits are undeniable, and we truly want the semantic web to succeed.
I believe the lack of growth partially has to do with a lack of tooling, but also with some problems that lie in the RDF data model.

Atomic Data aims to take the best parts from RDF, and learn from the past to make a more developer-friendly, performant and reliable data model to achieve a truly linked web.
Read more about [how Atomic Data relates to RDF, and why these changes have been made](interoperability/rdf.md).

## Make standardization easier and cheaper

Standards for data sharing are great, but creating one can be very costly endeavor.
Committees with stakeholders write endless documents describing the intricacies of domain models, which fields are allowed and which are required, and how data is serialized.
In virtually all cases, these documents are only written for humans - and not for computers.
Machine readable ways to describe data models like UML diagrams and OpenAPI specifications (also known as Swagger) help to have machine-readable descriptions, but these are still not _really_ used by machines - they are mostly only used to generate _visualizations for humans_.
This ultimately means that implementations of a standard have to be _manually checked_ for compliance, which often results in small (yet important) differences that severely limit interoperability.
These implementations will also often want to _extend_ the original definitions, but they are almost always unable to describe _what_ they have extended.

Standardizing with Atomic Data solves these issues.
Atomic Data takes the semantic value of ontologies, and merges it with a machine-readable [schemas](schema/intro.md).
This makes standards created using Atomic Data easy to read for humans, and easy to validate for computers (which guarantees interoperability).
Atomic Data has a highly standardized protocol for fetching data, which means that Atomic Schemas can link to each other, and _re-use existing Properties_.
For developers (the people who need to actually implement and use the data that has been standardized), this means their job becomes easier.
Because Properties have URLs, it becomes trivial to _add new Properties_ that were initially not in the main specification, without sacrificing type safety and validation abilities.

## Make it easier for developers to build feature-rich, interoperable apps

Every time a developer builds an application, they have to figure a lot of things out.
How to design the API, how to implement forms, how to deal with authentication, authorization, versioning, search...
A lot of time is essentially wasted on solving these issues time and time again.

By having a more complete, strict standard, Atomic Data aims to decrease this burden.
[Atomic Schema](schema/intro.md) enables developers to easily share their datamodels, and re-use those from others.
[Atomic Commits](commits/intro.md) helps developers to deal with versioning, history, undo and audit logs.
[Atomic Hierarchies](hierarchy.md) provides an intuitive model for authorization and access control.
And finally, the [existing open source Atomic Data software](tooling.md) (such as a server + database, a browser GUI, various libraries and React templates) help developers to have these features without having to do the heavy lifting themselves.
