{{#title JSON-AD: The Atomic Data serialization format}}

# JSON-AD: The Atomic Data serialization format

Although you can use various serialization formats for Atomic Data, `JSON-AD` is the _default_ and _only required_ serialization format.
It is what the current [Rust](https://github.com/ontola/atomic-server/tree/develop/browser) and [Typescript / React](https://github.com/ontola/atomic-server/tree/develop/browser) implementations use to communicate.
It is designed to feel familiar to developers and to be easy and performant to parse and serialize.
It is inspired by [JSON-LD](https://json-ld.org/).

It is [JSON](https://www.ecma-international.org/publications-and-standards/standards/ecma-404/) with the additional constraint that the root data structure must either be a Named Resource (with an `@id`), or an Array containing Named Resources.

The mime type (for HTTP content negotiation) is `application/ad+json` ([registration ongoing](https://github.com/ontola/atomic-data-docs/issues/60)).

## Named Resources

A named resource is a JSON Object that represents an Atomic Data resource.
Each key represents a property, therefore each key must be a valid [Property](https://atomicdata.dev/classes/Property) URL with the exception of the mandatory `@id` field.
The `@id` field is special: it defines the `Subject` of the `Resource`. If you send an HTTP GET request there with an `content-type: application/ad+json` header, you should get the full JSON-AD resource.

The types of values allowed are determined by the [datatype](../schema/datatypes.md) of the property.

- **string**, **slug**, **markdown**, **uri** and **date** datatype fields must be a `string`.
- **integer**, **float** and **timestamp** datatype fields must be a `number`.
- **boolean** datatype fields must be a `boolean`.
- **atomic-url** datatype fields must be either a `string` (url) or an `object` (nested resource).
- **resource-array** datatype fields must be an `array` of strings (must be a url) or objects (must be an nested resource).
- **json** datatype fields can be any valid JSON value.
- **lorodoc** datatype fields must be a base64-encoded [Loro CRDT](https://loro.dev) binary string.

Named Resources are only allowed in the following places:

- The root of the JSON-AD document.
- As an item in an array that is directly under the root of the JSON-AD document.

Example of a named resource in JSON-AD format:

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

## Nested Resources

Nested resources are resources that do not have an `@id` field.
It _does_ have its own unique [path](./paths.md), which can be used as its identifier.

Nested resources are only allowed in the following places:

- The value of a property with an **atomic-url** datatype.
- As an item in a **resource-array** property's array value.

In the example below is a named resource with the subject: `https://example.com/arnold`.
The `address` property has an nested resource as its value, therefore the path of the nested resource is: `https://example.com/arnold https://example.com/properties/address`.

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

## Regular JSON

Properties with a **json** datatype can contain any valid JSON value.
If any JSON-AD data is present in these values it will not be treated as JSON-AD, but as regular JSON.

Because these JSON values do not benefit from any of Atomic Data's features you should avoid using them unless your value is truly JSON data, for example when you need to store a config of some application.

## JSON-AD Parsers, serializers and other libraries

- **Typescript / Javacript**: [@tomic/lib](https://www.npmjs.com/package/@tomic/lib) JSON-AD parser + in-memory store.
- **Rust**: [atomic_lib](https://crates.io/crates/atomic_lib) has a JSON-AD parser / serializer (and does a lot more).

## Canonicalized JSON-AD

When you need deterministic serialization of Atomic Data (e.g. when calculating a cryptographic hash or signature, used in Atomic Commits), you can use the following procedure:

1. Serialize your Resource to JSON-AD
1. Do not include empty objects, empty arrays or null values.
1. All keys are sorted alphabetically (lexicographically) - both in the root object, as in any nested objects.
1. The JSON-AD is minified: no newlines, no spaces.

The last two steps of this process are more formally defined by the JSON Canonicalization Scheme (JCS, [rfc8785](https://tools.ietf.org/html/rfc8785)).

## Interoperability with JSON and JSON-LD

[Read more about this subject](../interoperability/json.md).
