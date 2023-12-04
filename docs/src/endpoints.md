{{#title Atomic Data Endpoints - describe how RESTful HTTP APIs behave}}
# Atomic Endpoints

_URL: https://atomicdata.dev/classes/Endpoint_

An Endpoint is a resource that accepts parameters in order to generate a response.
You can think of it like a function in a programming language, or a API endpoint in an OpenAPI spec.
It can be used to perform calculations on the server side, such as filtering data, sorting data, selecting a page in a collection, or performing some calculation.
Because Endpoints are resources, they can be defined and read programmatically.
This means that it's possible to render Endpoints as forms.

The most important property in an Endpoint is [`parameters`](https://atomicdata.dev/properties/endpoint/parameters), which is the list of Properties that can be filled in.

You can find a list of Endpoints supported by Atomic-Server on [atomicdata.dev/endpoints](https://atomicdata.dev/endpoints).

Endpoint Resources are _dynamic_, because their properties could be calculated server-side.
When a Property tends to be calculated server-side, they will have a [`isDynamic` property](https://atomicdata.dev/properties/isDynamic) set to `true`, which tells the client that it's probably useless to try to overwrite it.

## Incomplete resources

A Server can also send one or more partial Resources for an Endpoint to the client, which means that some properties may be missing.
When this is the case, the Resource will have an [`incomplete`](https://atomicdata.dev/properties/incomplete) property set to `true`.
This tells the client that it has to individually fetch the resource from the server to get the full body.

One scenario where this happens, is when fetching Collections that have other Collections as members.
If we would not have incomplete resources, the server would have to perform expensive computations even if the data is not needed by the client.

## Design Goals

- **Familiar API**: should look like something that most developers already know
- **Auto-generate forms**: a front-end app should present Endpoints as forms that non-developers can interact with

([Discussion](https://github.com/atomicdata-dev/atomic-data-docs/issues/15))
