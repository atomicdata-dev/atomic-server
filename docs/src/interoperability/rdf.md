{{#title How does Atomic Data relate to RDF?}}
# How does Atomic Data relate to RDF?

RDF (the [Resource Description Framework](https://www.w3.org/TR/rdf-primer/)) is a W3C specification from 1999 that describes the original data model for linked data.
It is the forerunner of Atomic Data, and is therefore highly similar in its model.
Both heavily rely on using URLs, and both have a fundamentally simple and uniform model for data statements.
Both view the web as a single, connected graph database.
Because of that, Atomic Data is also highly compatible with RDF - **all Atomic Data is also valid RDF**.
Atomic Data can be thought of as a **more constrained, type safe version of RDF**.
However, it does differ in some fundamental ways.

- Atomic calls the three parts of a Triple `subject`, `property` and `value`, instead of `subject`, `predicate`, `object`.
- Atomic does not support having multiple statements with the same `<subject> <predicate>`, every combination must be unique.
- Atomic does not have `literals`, `named nodes` and `blank nodes` - these are all `values`, but with different datatypes.
- Atomic uses `nested Resources` and `paths` instead of `blank nodes`
- Atomic requires URL (not URI) values in its `subjects` and `properties` (predicates), which means that they should be resolvable. Properties must resolve to an `Atomic Property`, which describes its datatype.
- Atomic only allows those who control a resource's `subject` URL endpoint to edit the data. This means that you can't add triples about something that you don't control.
- Atomic has no separate `datatype` field, but it requires that `Properties` (the resources that are shown when you follow a `predicate` value) specify a datatype. However, it is allowed to serialize the datatype explicitly, of course.
- Atomic has no separate `language` field.
- Atomic has a native Event (state changes) model ([Atomic Commits](../commits/intro.md)), which enables communication of state changes
- Atomic has a native Schema model ([Atomic Schema](../schema/intro.md)), which helps developers to know what data types they can expect (string, integer, link, array)
- Atomic does not support Named Graphs. These should not be needed, because all statements should be retrievable by fetching the Subject of a resource. However, it _is_ allowed to include other resources in a response.

## Why these changes?

I have been working with RDF for quite some time now, and absolutely believe in some of the core premises of RDF.
I started a company that specializes in Linked Data ([Ontola](https://ontola.io)), and we use it extensively in our products and services.
Using URIs (and more-so URLs, which are URIs that can be fetched) for everything is a great idea, since it helps with interoperability and enables truly decentralized knowledge graphs.
However, some of the characteristics of RDF make it hard to use, and have probably contributed to its relative lack of adoption.

### It's too hard to select a specific value (object) in RDF

For example, let's say I want to render someone's birthday:

```ttl
<example:joep> <schema:birthDate> "1991-01-20"^^xsd:date
```

Rendering this item might be as simple as fetching the subject URL, filtering by predicate URL, and parsing the `object` as a date.

However, this is also valid RDF:

```ttl
<example:joep> <schema:birthDate> "1991-01-20"^^xsd:date <example:someNamedGraph>
<example:joep> <schema:birthDate> <example:birthDateObject> <example:someOtherNamedGraph>
<example:joep> <schema:birthDate> "20th of januari 1991"@en <example:someNamedGraph>
<example:joep> <schema:birthDate> "20 januari 1991"@nl <example:someNamedGraph>
<example:joep> <schema:birthDate> "2000-02-30"^^xsd:date <example:someNamedGraph>
```

Now things get more complicated if you just want to select the original birthdate value:

1. **Select the named graph**. The triple containing that birthday may exist in some named graph different from the `subject` URL, which means that I first need to identify and fetch that graph.
1. **Select the subject**.
1. **Select the predicate**.
1. **Select the datatype**. You probably need a specific datatype (in this case, a Date), so you need to filter the triples to match that specific datatype.
1. **Select the language**. Same could be true for language, too, but that is not necessary in this birthdate example.
1. **Select the specific triple**. Even after all our previous selectors, we _still_ might have multiple values. How do I know which is the triple I'm supposed to use?

To be fair, with a lot of RDF data, only steps 2 and 3 are needed, since there are often no `subject-predicate` collisions.
And if you _control_ the data of the source, you can set any constraints that you like, inlcluding `subject-predicate` uniqueness.
But if you're building a system that uses arbitrary RDF, that system also needs to deal with steps 1,4,5 and 6.
That often means writing a lot of conditionals and other client-side logic to get the value that you need.
It also means that serializing to a format like JSON becomes complicated - you can't just map predicates to keys - you might get collisions.
And you can't use key-value stores for storing RDF, at least not in a trivial way.
Every single _selected value_ should be treated as an array of unknown datatypes, and that makes it really difficult to build software.
All this complexity is the direct result of the lack of `subject-predicate` uniqueness.

As a developer who uses RDF data, I want to be able to do something like this:

```js
// Fetches the resource
const joep = get("https://example.com/person/joep")
// Returns the value of the birthDate atom
console.log(joep.birthDate()) // => Date(1991-01-20)
// Fetches the employer relation at possibly some other domain, checks that resource for a property with the 'name' shortkey
console.log(joep.employer().name()) // => "Ontola.io"
```

Basically, I'd like to use all knowledge of the world as if it were a big JSON object.
Being able to do that, requires using some things that are present in JSON, and using some things that are present in RDF.

- Traverse data on various domains (which is already possible with RDF)
- Have [unique `subject-predicate` combinations](#subject-predicate-uniqueness) (which is default in JSON)
- Map properties URLs to keys (which often requires local mapping with RDF, e.g. in JSON-LD)
- Link properties to datatypes (which is possible with ontologies like SHACL / SHEX)

### Less focus on semantics, more on usability

One of the core ideas of the semantic web, is that anyone should be able to say anything about anything, using semantic triples.
This is one of the reasons why it can be so hard to select a specific value in RDF.
When you want to make all graphs mergeable (which is a great idea), but also want to allow anyone to create any triples about any subject, you get `subject-predicate` non-uniqueness.
For the Semantic Web, having _semantic_ triples is great.
For linked data, and connecting datasets, having atomic triples (with unique `subject-predicate` combinations) seems preferable.
Atomic Data chooses a more constrained approach, which makes it easier to use the data, but at the cost of some expressiveness.

### Changing the names

RDF's `subject`, `predicate` and `object` terminology can be confusing to newcomers, so Atomic Data uses `subject`, `property`, `value`.
This more closely resembles common CS terminology. ([discussion](https://github.com/ontola/atomic-data/issues/3))

### Subject + Predicate uniqueness

As discussed above, in RDF, it's very much possible for a graph to contain multiple statements that share both a `subject` and a `predicate`.
This is probably because of two reasons:

1. RDF graphs must always be **mergeable** (just like Atomic Data).
1. Anyone can make **any statement** about **any subject** (_unlike_ Atomic Data, see next section).

However, this introduces a lot extra complexity for data users (see above), which makes it not very attractive to use RDF in any client.
Whereas most languages and datatypes have `key-value` uniqueness that allow for unambiguous value selection, RDF clients have to deal with the possibility that multiple triples with the same `subject-predicate` combination might exist.
It also introduces a different problem: How should you interpret a set of `subject-predicate` combinations?
Does this represent a non-ordered collection, or did something go wrong while setting values?\
In the RDF world, I've seen many occurences of both.

Atomic Data requires `subject-property` uniqueness, which means that these issues are no more.
However, in order to guarantee this, and still retain _graph merge-ability_, we also need to limit who creates statements about a subject:

### Limiting subject usage

RDF allows that `anne.com` creates and hosts statements about the subject `john.com`.
In other words, domain A creates statements about domain B.
It allows anyone to say anything about any subject, thus allowing for extending data that is not under your control.

For example, developers at both Ontola and Inrupt (two companies that work a lot with RDF) use this feature to extend the Schema.org ontology with translations.
This means they can still use standards from Schema.org, and have their own translations of these concepts.

However, I think this is a flawed approach.
In the example above, two companies are adding statements about a subject.
In this case, both are adding translations.
They're doing the same work twice.
And as more and more people will use that same resource, they will be forced to add the same translations, again and again.

I think one of the core perks of linked data, is being able to make your information highly re-usable.
When you've created statements about an external thing, these statements are hard to re-use.

This means that someone using RDF data about domain B cannot know that domain B is actually the source of the data.
Knowing _where data comes from_ is one of the great things about URIs, but RDF does not require that you can think of subjects as the source of data.
Many subjects in RDF don't actually resolve to all the known triples of the statement.
It would make the conceptual model way simpler if statements about a subject could only be made from the source of the domain owner of the subject.
When triples are created about a resource, in a place other than where the subject is hosted, these triples are hard to share.

The way RDF projects deal with this, is by using _named graphs_.
As a consequence, all systems that use these triples should keep track of another field for every atom.
To make things worse, it makes `subject-predicate` uniqueness _impossible_ to guarantee.
That's a high price to pay.

I've asked two RDF developers (who did not know each other) working on RDF about limiting subject usage, and both were critical.
Interestingly, they provided the same usecase for using named graphs that would conflict with the limiting subject usage constraint.
They both wanted to extend the schema.org ontology by adding properties to these items in a local graph.
I don't think even this usecase is appropriate for named graphs. They were actually using an external resource that did not provide them with the things they needed. The things that they would add (the translations) are not re-usable, so in the end they will just keep spreading a URL that doesn't provide people with the things that they will come to expect. The schema.org URL still won't provide the translations that they wrote!
I believe a better solution is to copy the resource (in this case a part of the schema.org ontology), and extend it, and host it somewhere else, and use that URL.
Or even better: have a system for [sharing your change suggestions](https://github.com/ontola/atomic-data/issues/21) with the source of the data, and allow for easy collaboration on ontologies.

### No more literals / named nodes

In RDF, an `object` can either be a `named node`, `blank node` or `literal`. A `literal` has a `value`, a `datatype` and an optional `language` (if the `literal` is a string).
Although RDF statements are often called `triples`, a single statement can consist of five fields: `subject`, `predicate`, `object`, `language`, `datatype`.
Having five fields is way more than most information systems. Usually we have just `key` and `value`.
This difference leads to compatibility issues when using RDF in applications.
In practice, clients have to run a lot of checks before they can use the data - which makes RDF in most contexts harder to use than something like JSON.

Atomic Data drops the `named node` / `literal` distinction.
We just have `values`, and they are interpreted by looking at the `datatype`, which is defined in the `property`.
When a value is a URL, we don't call it a named node, but we simply use a URL datatype.

### Requiring URLs

A URL (Uniform Resource _Locator_) is a specific and cooler version of a URI (Uniform Resource _Identifier_), because a URL tells you where you can find more information about this thing (hence _Locator_).

RDF allows any type of URIs for `subject` and `predicate` value, which means they can be URLs, but don't have to be.
This means they don't always resolve, or even function as locators.
The links don't work, and that restricts how useful the links are.
Atomic Data takes a different approach: these links MUST Resolve. Requiring [Properties](https://atomicdata.dev/classes/Property) to resolve is part of what enables the type system of Atomic Schema - they provide the `shortname` and `datatype`.

Requiring URLs makes things easier for data users, but makes things a bit more difficult for the data producer.
With Atomic Data, the data producer MUST offer the data at the URL of the subject.
This is a challenge that requires tooling, which is why I've built [Atomic-Server](https://crates.io/crates/atomic-server): an easy to use, performant, open source data management sytem.

Making sure that links _actually work_ offer tremendous benefits for data consumers, and that advantage is often worth the extra trouble.

### Replace blank nodes with paths

Blank (or anonymous) nodes are RDF resources with identifiers that exist only locally.
In other words, their identifiers are not URLs.
They are sometimes also called `anonymous nodes`.
They make life easier for data producers, who can easily create (nested) resources without having to mint all the URLs.
In most non-RDF data models, blank nodes are the default.
For example, we nest JSON object without thinking twice.

Unfortunately, blank nodes tend to make things harder for clients.
These clients will now need to keep track of where these blank nodes came from, and they need to create internal identifiers that will not collide.
Cache invalidation with blank nodes also becomes a challenge.
To make this a bit easier, Atomic Data introduces a new way of dealing with names of things that you have not given a URL yet: [Atomic Paths](../core/paths.md).

Since Atomic Data has `subject-predicate` uniqueness (like JSON does, too), we can use the _path_ of triples as a unique identifier:

```
https://example.com/john https://schema.org/employer
```

This prevents collisions and still makes it easy to point to a specific value.

Serialization formats are free to use nesting to denote paths - which means that it is not necessary to include these path strings explicitly in most serialization formats, such as in JSON-AD.

### Combining datatype and predicate

Having both a `datatype` and a `predicate` value can lead to confusing situations.
For example, the [`schema:dateCreated`](https://schema.org/dateCreated) Property requires an ISO DateTime string (according to the schema.org definition), but using a value `true` with an `xsd:boolean` datatype results in perfectly valid RDF.
This means that client software using triples with a `schema:dateCreated` predicate cannot safely assume that its value will be a DateTime.
So if the client wants to use `schema:dateCreated` values, the client must also specify which type of data it expects, check the datatype field of every Atom and provide logic for when these don't match.
Also important combining `datatype` and `predicate` fits the model of most programmers and languages better - just look at how every single struct / model / class / shape is defined in programming languages: `key: datatype`.
This is why Atomic Data requires that a `predicate` links to a Property which must have a `Datatype`.

### Adding shortnames (slugs / keys) in Properties

Using full URI strings as keys (in RDF `predicates`) results in a relatively clunky Developer Experience.
Consider the short strings that developers are used to in pretty much all languages and data formats (`object.attribute`).
Adding a _required_ / tightly integrated key mapping (from long URLs to short, simple strings) in Atomic Properties solves this issue, and provides developers a way to write code like this: `someAtomicPerson.bestFriend.name => "Britta"`.
Although the RDF ecosystem does have some solutions for this (@context objects in JSON-LD, @prefix mappings, the @ontologies library), these prefixes are not defined in Properties themselves and therefore are often defined locally or separate from the ontology, which means that developers have to manually map them most of the time.
This is why Atomic Data introduces a `shortname` field in Properties, which forces modelers to choose a 'key' that can be used in ORM contexts.

### Adding native arrays

RDF lacks a clear solution for dealing with [ordered data](https://ontola.io/blog/ordered-data-in-rdf/), resulting in confusion when developers have to create lists of content.
Adding an Array data type as a base data type helps solve this. ([discussion](https://github.com/ontola/atomic-data/issues/4))

### Adding a native state changes standard

There is no integrated standard for communicating state changes.
Although [linked-delta](https://github.com/ontola/linked-delta) and [rdf-delta](https://afs.github.io/rdf-delta/) do exist, they aren't referred to by the RDF spec.
I think developers need guidance when learning a new system such as RDF, and that's why [Atomic Commits](../commits/intro.md) is included in this book.

### Adding a schema language and type safety

A schema language is necessary to constrain and validate instances of data.
This is very useful when creating domain-specific standards, which can in turn be used to generate forms or language-specific types / interfaces.
Shape validations are already possible in RDF using both [SHACL](https://www.w3.org/TR/shacl/) and [SHEX](https://shex.io/), and these are both very powerful and well designed.

However, with Atomic Data, I'm going for simplicity.
This also means providing an all-inclusive documentation.
I want people who read this book to have a decent grasp of creating, modeling, sharing, versioning and querying data.
It should provide all information that most developers (new to linked data) will need to get started quickly.
Simply linking to SHACL / SHEX documentation could be intimidating for new developers, who simply want to define a simple shape with a few keys and datatypes.

Also, SHACL requires named graphs (which are not specified in Atomic Data) and SHEX requires a new serialization format, which might limit adoption.
Atomic Data has some unique constrains (such as subject-predicate uniqueness) which also might make things more complicated when using SHEX / SHACL.

_However_, it is not the intention of Atomic Data to create a modeling abstraction that is just as powerful as the ones mentioned above, so perhaps it is better to include a SHACL / SHEX tutorial and come up with a nice integration of both worlds.

### A new name, with new docs

Besides the technical reasons described above, I think that there are social reasons to start with a new concept and give it a new name:

- The RDF vocabulary is intimidating. When trying to understand RDF, you're likely to traverse many pages with new concepts: `literal`, `named node`, `graph`, `predicate`, `named graph`, `blank node`... The core specification provides a formal description of these concepts, but fails to do this in a way that results in quick understanding and workable intuitions. Even experienced RDF developers tend to be confused about the nuances of the core model.
- There is a lack of learning resources that provide a clear, complete answer to the lifecycle of RDF data: modeling data, making data, hosting it, fetching it, updating it. Atomic Data aims to provide an opinionated answer to all of these steps. It feels more like a one-stop-shop for questions that developers are likely to encounter, whilst keeping the extendability.
- All Core / Schema URLs should resolve to simple, clear explanations with both examples and machine readable definitions. Especially the Property and Class concepts.
- The Semantic Web community has had a lot of academic attention from formal logic departments, resulting in a highly developed standard for knowledge modeling: the Web Ontology Language (OWL). While this is mostly great, its open-world philosophy and focus on reasoning abilities can confuse developers who are simply looking for a simple way to share models in RDF.

## Convert RDF to Atomic Data

- **All the `subject` URLs MUST actually resolve, and return all triples about that subject**. All `blank nodes` should be converted into URLs. Atomic Data tools might help to achieve this, for example by hosting the data.
- **All `predicates` SHOULD resolve to Atomic Properties, and these SHOULD have a `datatype`**. You will probably need to change predicate URLs to Atomic Property URLs, or update the things that the predicate points to to include the required Atomic Property items (e.g. having a Datatype and a Shortname). This also means that the `datatype` in the original RDF statement can be dropped.
- Literals with a `language` tag are converted to TranslationBox resources, which also means their identifiers must be created. Keep in mind that Atomic Data does not allow for blank nodes, so the TranslationBox identifiers must be URLs.

Step by step, it entails:

1. Set up some server to make sure the URLs will resolve.
1. Create (or find and refer to) Atomic Properties for all the `predicates`. Make sure they have a DataType and a Shortname.
1. If you have triples about a subject that you don't control, change the URL to some that you _can_ control, and refer to that external resource.

Atomic Data will need [tooling](../tooling.md) to facilitate in this process.
This tooling should help to create URLs, Properties, and host everything on an easy to use server.

## Convert Atomic data to RDF

Since all Atomic Data is also valid RDF, it's trivial to convert / serialize Atoms to RDF.
This is why [atomic](https://github.com/atomicdata-dev/atomic-data-browser) can serialize Atomic Data to RDF. (For example, try `atomic-cli get https://atomicdata.dev/properties/description --as n3`)

However, contrary to Atomic Data, RDF has optional Language and Datatype elements in every statement.
It is good practice to use these RDF concepts when serializing Atomic Data into Turtle / RDF/XML, or other [RDF serialization formats](https://ontola.io/blog/rdf-serialization-formats/).

- Convert Atoms with linked `TranslationBox` Resources to Literals with an `xsd:string` datatype and the corresponding language in the tag.
- Convert Atoms with ResourceArrays to [Collections](https://ontola.io/blog/ordered-data-in-rdf/) that are native to that serialization format.
- Dereference the Property and Datatype from Atomic Properties, and add the URLs in `datatypes` in RDF statements.
