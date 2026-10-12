# API

The API of AtomicServer uses _Atomic Data_.

All Atomic Data resources have a unique URL, which can be fetched using HTTP.
Every single Class, Property or Endpoint also is a resource, which means you can visit these in the browser!
This effectively makes most of the API **browsable** and **self-documenting**.

Every individual resource URL can be fetched using a GET request using your favorite HTML tool or library.
You can also simply open every resource in your browser!
If you want some specific representation (e.g. `JSON`), you will need to add an `Accept` header to your request.

```sh
# Fetch as JSON-AD (de facto standard for Atomic Data)
curl -i -H "Accept: application/ad+json" https://atomicdata.dev/properties/shortname
# Fetch as JSON-LD
curl -i -H "Accept: application/ld+json" https://atomicdata.dev/properties/shortname
# Fetch as JSON
curl -i -H "Accept: application/json" https://atomicdata.dev/properties/shortname
# Fetch as Turtle / N3
curl -i -H "Accept: text/turtle" https://atomicdata.dev/properties/shortname
```

## Endpoints

The various [Endpoints](../endpoints.md) in AtomicServer can be seen at `/endpoints` of your local instance.
These include functionality to post signed changes to `/commit`, query data using `/query`, get `/versions`, or do full-text search queries using `/search`.
Typically, you pass query parameters to these endpoints to specify what you want to do.

<!-- We have a subset of the [API documented using Swagger / OpenAPI](https://editor.swagger.io/?url=https://raw.githubusercontent.com/atomicdata-dev/atomic-server/master/server/openapi.yml). -->

## Fetching `atomic:` resources over HTTP

Most resources created since the move to [local-first](../local-first.md) are named by a [`atomic:` identifier](../urls.md) rather than by an HTTP URL.
An AtomicServer that holds such a resource serves it at a `/did` endpoint, and also accepts the identifier as a path:

```sh
curl -H "Accept: application/ad+json" "https://atomicdata.dev/did?subject=did%3Aad%3A{genesis}"
curl -H "Accept: application/ad+json" "https://atomicdata.dev/atomic:{genesis}"
```

The response's `@id` is the DID, and a `Link: <atomic:…>; rel="canonical"` header names it too, so a client that arrived through this server's address can remember the location-independent identity.
Writes never go through a resource URL: they are signed commits, sent over the [sync](../sync.md) connection or to `/commit`.

## Libraries or API?

You can use the REST API if you want, but it's recommended to use one of our [libraries](../tooling.md).
