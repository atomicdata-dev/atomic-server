{{#title Atomic Data Websockets - live synchronization}}
# WebSockets in Atomic Data

WebSockets are a very fast and efficient way to have a client and server communicate in an asynchronous fashion.
They are used in Atomic Data to allow real-time updates, which makes it possible to create things like collaborative applications and multiplayer games.
These have been implemented in `atomic-server` and `atomic-data-browser` (powered by `@tomic/lib`).

## Initializing a WebSocket connection

Send an HTTP `GET` request to the `/ws` endpoint of an `atomic-server`. The Server should update that request to a secure WebSocket (`wss`) connection.
Use `x-atomic` [authentication headers (read more here)](./authentication.md) and use `ws` as a subject when signing.
The `WebSocket-Protocol` is `AtomicData`.

## Client to server messages

- `SUBSCRIBE ${subject}` tells the Server that you'd like to receive Commits about this Subject.
- `UNSUBSCRIBE ${subject}` tells the Server that you'd like to stop receiving Commits about this Subject.
- `GET ${subject}` fetch an individual resource.
- `AUTHENTICATE ${authenticationResource}` to set a user session for this websocket and allow authorized messages. The `authenticationResource` is a JSON-AD resource containing the signature and more, see [Authentication](../src/authentication.md).

## Server to client messages

- `COMMIT ${CommitBody}` an entire [Commit](../src/commits/concepts.md) for a resource that you're subscribed to.
- `RESOURCE ${Resource}` a JSON-AD Resource as a response to a `GET` message. If there is something wrong with this request (e.g. 404), return a `Error` Resource with the requested subject, similar to how the HTTP protocol server does this.`
- `ERROR ${ErrorBody}` an Error resource is sent whenever something goes wrong. The `ErrorBody` is a plaintext, typically English description of what went wrong.

## Considerations

- For many messages, there is no response to give if things are processed correctly. If a message is unknown or there is a different problem, return an `ERROR`.

## Example implementations

- [Example client implementation in Typescript (@tomic/lib).](https://github.com/atomicdata-dev/atomic-data-browser/blob/main/lib/src/websockets.ts)
- [Example server implementation in Rust using Actix-Web](https://github.com/atomicdata-dev/atomic-server/blob/master/server/src/handlers/web_sockets.rs)
