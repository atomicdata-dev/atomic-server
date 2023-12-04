{{#title JSON-AD: The Atomic Data serialization format}}
# JSON-AD: The Atomic Data serialization format

Although you can use various serialization formats for Atomic Data, `JSON-AD` is the _default_ and _only required_ serialization format.
It is what the current [Rust](https://github.com/atomicdata-dev/atomic-data-browser) and [Typescript / React](https://github.com/atomicdata-dev/atomic-data-browser) implementations use to communicate.
It is designed to feel familiar to developers and to be easy and performant to parse and serialize.
It is inspired by [JSON-LD](https://json-ld.org/).

It uses [JSON](https://www.ecma-international.org/publications-and-standards/standards/ecma-404/), but has some additional constraints:

- Every single Object is a `Resource`.
- Every Key is a [`Property`](https://atomicdata.dev/classes/Property) URL. Other keys are invalid. Each Property URL must resolve to an online Atomic Data Property.
- The `@id` field is special: it defines the `Subject` of the `Resource`. If you send an HTTP GET request there with an `content-type: application/ad+json` header, you should get the full JSON-AD resource.
- JSON arrays are mapped to [Resource Arrays](https://atomicdata.dev/datatypes/resourceArray)
- Numbers can be [Integers](https://atomicdata.dev/datatypes/integer), [Timestamps](https://atomicdata.dev/datatypes/timestamp) or [Floats](https://atomicdata.dev/datatypes/float).
- JSON booleans map to [Booleans](https://atomicdata.dev/datatypes/boolean).
- JSON strings can be many datatypes, including [String](https://atomicdata.dev/datatypes/string), [Markdown](https://atomicdata.dev/datatypes/markdown), [Date](https://atomicdata.dev/datatypes/date) or other.
- Nested JSON Objects are Nested Resources. A Nested Resource can either be _Anonymous_ (without an `@id` subject) or a Named Nested Resource (with an `@id` subject). Everywhere a Subject URL can be used as a value (i.e. all properties with the datatype [atomicURL](https://atomicdata.dev/datatypes/atomicURL)), a Nested Resource can be used instead. This also means that an item in an `ResourceArray` can be a Nested Resource.
- The root data structure must either be a Named Resource (with an `@id`), or an Array containing Named Resources. When you want to describe multiple Resources in one JSON-AD document, use an array as the root item.

Let's look at an example JSON-AD Resource:

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

The mime type (for HTTP content negotiation) is `application/ad+json` ([registration ongoing](https://github.com/ontola/atomic-data-docs/issues/60)).

## Nested, Anonymous and Named resources

In JSON-AD, a Resource can be respresented in multiple ways:

- **Subject**: A URL string, such as `https://atomicdata.dev/classes/Class`.
- **Named Resource**: A JSON Object with an `@id` field containing the Subject.
- **Anonymous Nested Resource** A JSON Object without an `@id` field. This is only possible if it is a Nested Resource, which means that it has a parent Resource.

Note that this is also valid for `ResourceArrays`, which usually only contain Subjects, but are allowed to contain Nested Resources.

In the following JSON-AD example, the `address` is a nested resource:

```json
{
  "@id": "https://example.com/arnold",
  "https://example.com/properties/address": {
    "https://example.com/properties/firstLine": "Longstreet 22",
    "https://example.com/properties/city": "Watertown",
    "https://example.com/properties/country": "the Netherlands",
  }
}
```

Nested Resources can be _named_ or _anonymous_. An _Anonymous Nested Resource_ does not have it's own `@id` field.
It _does_ have its own unique [path](./paths.md), which can be used as its identifier.
The `path` of the anonymous resource in the example above is `https://example.com/arnold https://example.com/properties/address`.

## JSON-AD Parsers, serializers and other libraries

- **Typescript / Javacript**: [@tomic/lib](https://www.npmjs.com/package/@tomic/lib) JSON-AD parser + in-memory store. Works with [@tomic/react](https://www.npmjs.com/package/@tomic/lib) for rendering Atomic Data in React.
- **Rust**: [atomic_lib](https://crates.io/crates/atomic_lib) has a JSON-AD parser / serializer (and does a lot more).

## Canonicalized JSON-AD

When you need deterministic serialization of Atomic Data (e.g. when calculating a cryptographic hash or signature, used in Atomic Commits), you can use the following procedure:

1. Serialize your Resource to JSON-AD
1. Do not include empty objects, empty arrays or null values.
1. All keys are sorted alphabetically (lexicographically) - both in the root object, as in any nested objects.
1. The JSON-AD is minified: no newlines, no spaces.

The last two steps of this process is more formally defined by the JSON Canonicalization Scheme (JCS, [rfc8785](https://tools.ietf.org/html/rfc8785)).

## Interoperability with JSON and JSON-LD

[Read more about this subject](../interoperability/json.md).
