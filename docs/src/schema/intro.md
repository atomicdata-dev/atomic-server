{{#title Atomic Data Schema - modelling Atomic Data}}
# Atomic Schema

Atomic Schema is the proposed standard for specifying classes, properties and datatypes in Atomic Data.
You can compare it to UML diagrams, or what XSD is for XML.
Atomic Schema deals with validating and constraining the shape of data.
It is designed for checking if all the required properties are present, and whether the values conform to the datatype requirements (e.g. `datetime`, or `URL`).

This section will define various Classes, Properties and Datatypes (discussed in [Atomic Core: Concepts](../core/concepts.md)).

## Design Goals

- **Decentralized**: Classes and Properties can be defined in external systems, and are resolved using web protocols such as HTTP.
- **Typed**: Every Atom of data has a clear datatype. Validated data should be highly predictable.
- **IDE-friendly**: Although Atomic Schema uses many URLs, users / developers should not have to type full URLs. The schema uses shortnames as aliases.
- **Self-documenting**: When seeing a piece of data, simply following links will explain you how the data model is to be understood. This removes the need for (most of) existing API documentation.
- **Extensible**: Anybody can create their own Datatypes, Properties and Classes.
- **Accessible**: Support for languages, easily translatable. Useful for humans and machines.
- **Atomic**: All the design goals of Atomic Data itself also apply here. Atomic Schema is defined using Atomic Data.

## In short

In short, Atomic Schema works like this:

The Property _field_ in an Atom, or the _key_ in a JSON-AD object, links to a **Property _Resource_**.
It is important that the URL to the Property Resource resolves, as others can re-use it and check its datatype.
This Property does three things:

1. it links to a **Datatype** which indicates which Value is acceptable.
1. it has a **description** which tells you what the property means, what the relationship between the Subject and the Value means.
1. it provides a **Shortname**, which is sometimes used as an alternative to the full URL of the Property.

**DataTypes** define the shape of the Value, e.g. a Number (`124`) or Boolean (`true`).

**Classes** are a special kind of Resource that describe an abstract class of things (such as "Person" or "Blog").
Classes can _recommend_ or _require_ a set of Properties.
They behave as Models, similar to `struts` in C or `interfaces` in Typescript.
A Resource _could_ have one or more classes, which _could_ provide information about which Properties are expected or required.

**example:**

```json
{
  "@id": "https://atomicdata.dev/classes/Agent",
  "https://atomicdata.dev/properties/description": "An Agent is a user that can create or modify data. It has two keys: a private and a public one. The private key should be kept secret. The public key is used to verify signatures (on [Commits](https://atomicdata.dev/classes/Commit)) set by the of the Agent.",
  "https://atomicdata.dev/properties/isA": [
    "https://atomicdata.dev/classes/Class"
  ],
  "https://atomicdata.dev/properties/recommends": [
    "https://atomicdata.dev/properties/name",
    "https://atomicdata.dev/properties/description"
  ],
  "https://atomicdata.dev/properties/requires": [
    "https://atomicdata.dev/properties/publicKey"
  ],
  "https://atomicdata.dev/properties/shortname": "agent"
}
```
