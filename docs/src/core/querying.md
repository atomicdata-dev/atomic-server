{{#title Querying Atomic Data}}
# Querying Atomic Data

There are multiple ways of getting Atomic Data into some system:

- [**Subject Fetching**](#subject-fetching-http) requests a single subject right from its source
- [**Atomic Collections**](../schema/collections.md) can filter, sort and paginate resources
- [**Atomic Paths**](paths.md) is a simple way to traverse Atomic Graphs and target specific values
- [**Triple Pattern Fragments**](#triple-pattern-fragments) allows querying for specific (combinations of) Subject, Property and Value.
- [**SPARQL**](#SPARQL) is a powerful Query language for traversing linked data graphs

## Subject fetching (HTTP)

The simplest way of getting Atomic Data when the Subject is an HTTP URL, is by sending a GET request to the subject URL.
Set the `Content-Type` header to an Atomic Data compatible mime type, such as `application/ad+json`.

```HTTP
GET https://atomicdata.dev/test HTTP/1.1
Content-Type: application/ad+json
```

The server SHOULD respond with all the Atoms of which the requested URL is the subject:

```HTTP
HTTP/1.1 200 OK
Content-Type: application/ad+json
Connection: Closed

{
  "@id": "https://atomicdata.dev/test",
  "https://atomicdata.dev/properties/shortname": "1611489928"
}
```

The server MAY also include other resources, if they are deemed relevant.

## Atomic Collections

Collections are Resources that provide simple query options, such as filtering by Property or Value, and sorting.
They also paginate resources.
Under the hood, Collections are powered by Triple Pattern Fragments.
Use query parameters to traverse pages, filter, or sort.

[Read more about Collections](../schema/collections.md)

## Atomic Paths

An Atomic Path is a string that consist of one or more URLs, which when traversed point to an item.

[Read more about Atomic Paths](paths.md)

## SPARQL

[SPARQL](https://www.w3.org/TR/rdf-sparql-query/) is a powerful RDF query language.
Since all Atomic Data is also valid RDF, it should be possible to query Atomic Data using SPARQL.
None of the exsisting implementations support a SPARQL endpoint, though.

- Convert / serialize Atomic Data to RDF (for example by using an `accept` header: `curl -i -H "Accept: text/turtle" "https://atomicdata.dev"`)
- Load it into a SPARQL engine of your choice
