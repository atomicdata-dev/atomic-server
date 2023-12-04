{{#title Serialization of Atomic Data}}
# Serialization of Atomic Data

Atomic Data is not necessarily bound to a single serialization format.
It's fundamentally a data model, and that's an important distinction to make.
It can be serialized in different ways, but there is only one required: `JSON-AD`.

## JSON-AD

[`JSON-AD`](json-ad.md) (more about that on the next page) is specifically designed to be a simple, complete and performant format for Atomic Data.

```json
{
  "@id": "https://atomicdata.dev/properties/description",
  "https://atomicdata.dev/properties/datatype": "https://atomicdata.dev/datatypes/markdown",
  "https://atomicdata.dev/properties/description": "A textual description of something. When making a description, make sure that the first few words tell the most important part. Give examples. Since the text supports markdown, you're free to use links and more.",
  "https://atomicdata.dev/properties/isA": [
    "https://atomicdata.dev/classes/Property"
  ],
  "https://atomicdata.dev/properties/parent": "https://atomicdata.dev/properties",
  "https://atomicdata.dev/properties/shortname": "description"
}
```

[Read more about JSON-AD](json-ad.md)

## JSON (simple)

Atomic Data is designed to be serializable to clean, simple [JSON](../interoperability/json.md), for usage in (client) apps that don't need to know the full URLs of properties.

````json
{
  "@id": "https://atomicdata.dev/properties/description",
  "datatype": "https://atomicdata.dev/datatypes/markdown",
  "description": "A textual description of something. When making a description, make sure that the first few words tell the most important part. Give examples. Since the text supports markdown, you're free to use links and more.",
  "is-a": [
    "https://atomicdata.dev/classes/Property"
  ],
  "parent": "https://atomicdata.dev/properties",
  "shortname": "description"
}
````

[Read more about JSON and Atomic Data](json-ad.md)


## RDF serialization formats

Since Atomic Data is a strict subset of RDF, RDF serialization formats can be used to communicate and store Atomic Data, such as N-Triples, Turtle, HexTuples, JSON-LD and [other RDF serialization formats](https://ontola.io/blog/rdf-serialization-formats/).
However, not all valid RDF is valid Atomic Data.
Atomic Data is more strict.
Read more about serializing Atomic Data to RDF in the [RDF interoperability section](../interoperability/rdf.md).

JSON-LD:

```json
{
  "@context": {
    "datatype": {
      "@id": "https://atomicdata.dev/properties/datatype",
      "@type": "@id"
    },
    "description": "https://atomicdata.dev/properties/description",
    "is-a": {
      "@container": "@list",
      "@id": "https://atomicdata.dev/properties/isA"
    },
    "parent": {
      "@id": "https://atomicdata.dev/properties/parent",
      "@type": "@id"
    },
    "shortname": "https://atomicdata.dev/properties/shortname"
  },
  "@id": "https://atomicdata.dev/properties/description",
  "datatype": "https://atomicdata.dev/datatypes/markdown",
  "description": "A textual description of something. When making a description, make sure that the first few words tell the most important part. Give examples. Since the text supports markdown, you're free to use links and more.",
  "is-a": [
    "https://atomicdata.dev/classes/Property"
  ],
  "parent": "https://atomicdata.dev/properties",
  "shortname": "description"
}
```

Turtle / N-Triples:

```turtle
<https://atomicdata.dev/properties/description> <https://atomicdata.dev/properties/datatype> <https://atomicdata.dev/datatypes/markdown> .
<https://atomicdata.dev/properties/description> <https://atomicdata.dev/properties/parent> <https://atomicdata.dev/properties> .
<https://atomicdata.dev/properties/description> <https://atomicdata.dev/properties/shortname> "description"^^<https://atomicdata.dev/datatypes/slug> .
<https://atomicdata.dev/properties/description> <https://atomicdata.dev/properties/isA> "https://atomicdata.dev/classes/Property"^^<https://atomicdata.dev/datatypes/resourceArray> .
<https://atomicdata.dev/properties/description> <https://atomicdata.dev/properties/description> "A textual description of something. When making a description, make sure that the first few words tell the most important part. Give examples. Since the text supports markdown, you're free to use links and more."^^<https://atomicdata.dev/datatypes/markdown> .
```
