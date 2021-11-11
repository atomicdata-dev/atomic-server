# Use Atomic-Server as a Search endpoint for RDF / Solid

Atomic-Server provides a full-text search endpoint (+ GUI) that allows searching in RDF documents.
You can use it like this:

- Run `atomic-server` wit the `--rdf-search` flag, or set the `ATOMIC_RDF_SEARCH=true` environment variable if you're running from docker. See the [readme](./README.md) for other instructions.
- **Add an RDF resource to the index** by sendig an HTTP POST request to `/search` with a Turtle / N-Triples serialized RDF document. If you get a `405` response, make sure the `--rdf-search` flag is set.
- **Perform a query** by sendig an HTTP GET request to `/search?q=query` with an `Accept` header set to `application/ld+json`.

```HTTP
### Full text search, return only subjects
GET http://localhost/search?q=somestring HTTP/1.1
Accept: application/ld+json

### Index at (RDF) document for search
POST http://localhost/search HTTP/1.1
Content-Type: text/turtle

@prefix schema: <http://schema.org/> .
    <http://example.com/foo> a schema:Person ;
        schema:name  "Foo" .
    <http://example.com/bar> a schema:Person ;
        schema:name  "asdfsajhdfgbasdf" .
```

## Query parameters

- the `q` parameter contains the actual query, see below for instructions
- `limit` is for setting a maximum response count (default is 30)

## Query string options

- Uses fuzzy matching by default
- Use `AND` or `OR` keywords

## Limitations

- Blank Nodes are not indexed (ignored)
- No support for Quads (will error)
- Only returns subjects of triples that matched the query; does not return full resources.

## Acknowledgements

- Thanks to the NLNet Search & Discovery grant for making a financial contribution to this project!
- Thanks to Ruben Verborgh, Jos van den Oever and Thom van Kalkeren for helping out with the architectural design.
- Powered by amazing Rust libraries, most notably Tantivy, Actix and Rio_turtle.
- Written by Joep Meindertsma @joepio for Ontola.io.
