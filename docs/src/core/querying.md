{{#title Querying Atomic Data}}
# Querying Atomic Data

There are multiple ways of getting Atomic Data into some system:

- [**Subject Fetching**](#subject-fetching-http) requests a single subject right from its source
- [**Atomic Collections**](../schema/collections.md) can filter, sort and paginate resources
- [**Atomic Paths**](paths.md) is a simple way to traverse Atomic Graphs and target specific values
- **Query endpoint** (`/query`) works virtually identical to `Collections`, but it does not require a Collection Resource be defined.

## Subject fetching (HTTP)

The simplest way of getting Atomic Data when the Subject is an HTTP URL, is by sending a GET request to the subject URL.
Set the `accept` header to an Atomic Data compatible mime type, such as `application/ad+json`.

```HTTP
GET https://atomicdata.dev/test HTTP/1.1
accept: application/ad+json
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
For example, a search result might include nested children to speed up rendering.

Also note that AtomicServer supports other `Content-Type`s, such as `application/json`, `application/ld+json`, `text/turtle`.

## Atomic Collections

Collections are Resources that provide simple query options, such as filtering by Property or Value, and sorting.
They also paginate resources.
Under the hood, Collections are powered by Triple Pattern Fragments.
Use query parameters to traverse pages, filter, or sort.

[Read more about Collections](../schema/collections.md)

## Atomic Paths

An Atomic Path is a string that consist of one or more URLs, which when traversed point to an item.

[Read more about Atomic Paths](paths.md)

## Full text search

AtomicServer supports a full text `/search` endpoint.
Because this is an [Endpoint](../endpoints.md), you can simply [open it to see the available query parameters](https://atomicdata.dev/search).
