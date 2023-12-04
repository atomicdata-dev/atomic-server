{{#title How does Atomic Data relate to JSON?}}
# How does Atomic Data relate to JSON?

Because JSON is so popular, Atomic Data is designed with JSON in mind.

Atomic Data is often (by default) serialized to [JSON-AD](../core/json-ad.md), which itself uses JSON.
JSON-AD uses URLs as keys, which is what gives Atomic Data many of its perks, but using these long strings as keys is not very easy to use in many contexts.
That's why you can serialize Atomic Data to simple, clean JSON.

## From Atomic Data to plain JSON

The JSON keys are then derived from the `shortnames` of properties.
For example, we could convert this JSON-AD:

```json
{
  "@id": "https://atomicdata.dev/properties/description",
  "https://atomicdata.dev/properties/datatype": "https://atomicdata.dev/datatypes/markdown",
  "https://atomicdata.dev/properties/description": "A textual description of something. When making a description, make sure that the first few words tell the most important part. Give examples. Since the text supports markdown, you're free to use links and more.",
  "https://atomicdata.dev/properties/isA": [
    "https://atomicdata.dev/classes/Property"
  ],
  "https://atomicdata.dev/properties/shortname": "description"
}
```

... into this plain JSON:

```json
{
  "@id": "https://atomicdata.dev/properties/description",
  "datatype": "https://atomicdata.dev/datatypes/markdown",
  "description": "A textual description of something. When making a description, make sure that the first few words tell the most important part. Give examples. Since the text supports markdown, you're free to use links and more.",
  "is-a": [
    "https://atomicdata.dev/classes/Property"
  ],
  "shortname": "description"
}
```

Note that when you serialize Atomic Data to plain JSON, some information is lost: the URLs are no longer there.
This means that it is no longer possible to find out what the datatype of a single value is - we now only know if it's a `string`, but not if it actually represents a markdown string or something else.
Most Atomic Data systems will therefore _not_ use this plain JSON serialization, but for some clients (e.g. a front-end app), it might be easier to use the plain JSON, as the keys are easier to write than the long URLs that JSON-AD uses.

## From JSON to JSON-AD

Atomic Data requires a bit more information about pieces of data than JSON tends to contain. Let's take a look at a regular JSON example:

```json
{
  "name": "John",
  "birthDate": "1991-01-20"
}
```

We need more information to convert this JSON into Atomic Data.
The following things are missing:

* What is the **Subject** URL of the resource being described?
* What is the **Property** URL of the keys being used? (`name` and `birthDate`), and consequentially, how should the values be parsed? What are their DataTypes?

In order to make this conversion work, we need to link to three URLs that _resolve to atomic data resources_.
The `@id` subject should resolve to the Resource itself, returning the JSON-AD from below.
The Property keys (e.g. "https://example.com/properties/name") need to resolve to Atomic Properties.

```json
{
  "@id": "https://example.com/people/john",
  "https://example.com/properties/name": "John",
  "https://example.com/properties/birthDate": "1991-01-20"
}
```

In practice, the easiest approach to make this conversion, is to create the data and host it using software like [Atomic Server](https://github.com/atomicdata-dev/atomic-server/blob/master/server/README.md).

## From Atomic Data to JSON-LD

Atomic Data is a strict subset of RDF, and the most popular serialization of RDF for JSON data is [JSON-LD](https://json-ld.org/).

Since Atomic Schema requires the presence of a `key` slug in Properties, converting Atomic Data to JSON results in dev-friendly objects with nice shorthands.

```json
{
  "@id": "https://example.com/people/John",
  "https://example.com/properties/lastname": "John",
  "https://example.com/properties/bestFriend": "https://example.com/sarah",
}
```

Can be automatically converted to:

```json
{
  "@context": {
    "@id": "https://example.com/people/John",
    "name": "https://example.com/properties/lastname",
    "bestFriend": "https://example.com/properties/bestFriend",
  },
  "name": "John",
  "bestFriend": {
    "@id": "https://example.com/sarah"
  },
}
```

The `@context` object provides a _mapping_ to the original URLs.

JSON-AD and JSON-LD are very similar by design, but there are some important differences:

- JSON-AD is designed just for atomic data, and is therefore easier and more performant to parse / serialize.
- JSON-LD uses `@context` to map keys to URLs. Any type of mapping is valid. JSON-AD, on the other hand, doesn't map anything - all keys are URLs.
- JSON-LD uses nested objects for links and sequences, such as `@list`. JSON-AD does not.
- Arrays in JSON-LD do not indicate ordered data - they indicate that for some subject-predicate combination, multiple values exist. This is a result of how RDF works.

## JSON-LD Requirements for valid Atomic Data

- Make sure the URLs used in the `@context` resolve to Atomic Properties.
<!-- Not sure about this.. maybe use RDF collections or some other model? -->
- Convert JSON-LD arrays into ResourceArrays
- Creating nested JSON objects is possible (by resolving the identifiers from `@id` relations), but it is up to the serializer to decide how deep this object nesting should happen.

Note that as of now, there are no JSON-LD parsers for Atomic Data.
