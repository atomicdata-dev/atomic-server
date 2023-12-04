# API

The API of AtomicServer uses _Atomic Data_.

All Atomic Data resources have a unique URL, which van be fetched using HTTP.
Every single Class, Property or Endpoint also is a resource, which means you can visit these in the browser!
This effectively makes most of the API **browsable** and **self-documenting**.

## Fetching resources

You can fetch individual items by sending a GET request to their URL.

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

We have a subset of the [API documented using Swagger / OpenAPI](https://editor.swagger.io/?url=https://raw.githubusercontent.com/atomicdata-dev/atomic-server/master/server/openapi.yml).

## Example requests

```HTTP
### Get a thing as JSON
GET https://atomicdata.dev/properties/isA HTTP/1.1
Accept: application/json

### Get a thing as JSON-AD
GET https://atomicdata.dev/properties/isA HTTP/1.1
Accept: application/ad+json

### Get a thing as JSON-LD
GET https://atomicdata.dev/properties/isA HTTP/1.1
Accept: application/ld+json

### Get a thing as turtle
GET https://atomicdata.dev/properties/isA HTTP/1.1
Accept: text/turtle

### Full text search
GET http://localhost:9883/search?q=Foo HTTP/1.1
Accept: application/ld+json

### Full text search, return full resource bodies. A bit slower, but could actually result in a faster UX.
GET http://localhost:9883/search?q=Foo&include=true HTTP/1.1
Accept: application/ld+json

### Send a Commit
### The hard part here is setting the correct signature.
### Use a library (@tomic/lib for JS, and atomic_lib for Rust).
POST http://localhost:9883/commit HTTP/1.1
Accept: application/json
Content-Type: application/json

{
  "subject": "http://localhost:9883/test",
  "created_at": 1601239744,
  "signer": "http://localhost:9883/agents/root",
  "set": {
    "https://atomicdata.dev/properties/requires": "[\"http/properties/requires\"]"
  },
  "remove": ["https://atomicdata.dev/properties/shortname"],
  "destroy": false,
  "signature": "correct_signature"
}
```
