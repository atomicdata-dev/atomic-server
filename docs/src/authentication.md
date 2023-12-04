# Authentication in Atomic Data

Authentication means knowing _who_ is doing something, either getting access or creating some new data.
When an Agent wants to _edit_ a resource, they have to send a signed [Commit](commits/intro.md), and the signatures are checked in order to authorize a Commit.

But how do we deal with _reading_ data, how do we know who is trying to get access?
There are two ways users can authenticate themselves:

- Signing an `Authentication Resource` and using that as a cookie
- Opening a WebSocket, and passing an `Authentication Resource`.
- Signing every single HTTP request (more secure, less flexible)

## Design goals

- **Secure**: Because, what's the point of authentication if it's not?
- **Easy to use**: Setting up an identity should not require _any_ effort, and proving identity should be minimal effort.
- **Anonimity allowed**: Users should be able to have multiple identities, some of which are fully anonymous.
- **Self-sovereign**: No dependency on servers that user's don't control. Or at least, minimise this.
- **Dummy-proof**: We need a mechanism for dealing with forgetting passwords / client devices losing data.
- **Compatible with Commits**: Atomic Commits require clients to sign things. Ideally, this functionality / strategy would also fit with the new model.
- **Fast**: Of course, authentication will always slow things down. But let's keep that to a minimum.

## Authentication Resources

An _Authentication Resource_ is a JSON-AD object containing all the information a Server needs to make sure a valid Agent requests a session at some point in time.
These are used both in Cookie-based auth, as well as in [WebSockets](websockets.md)

We use the following fields (be sure to use the full URLs in the resource, see the example below):

- `requestedSubject`: The URL of the requested resource.
  - If we're authenticating a *WebSocket*, we use the `wss` address as the `requestedSubject`. (e.g. `wss://example.com/ws`)
  - If we're authenticating a *Cookie* of *Bearer token*, we use the origin of the server (e.g. `https://example.com`)
  - If we're authentication a *single HTTP request*, use the same URL as the `GET` address (e.g. `https://example.com/myResource`)
- `agent`: The URL of the Agent requesting the subject and signing this Authentication Resource.
- `publicKey`: base64 serialized ED25519 public key of the agent.
- `signature`: base64 serialized ED25519 signature of the following string: `{requestedSubject} {timestamp}` (without the brackets), signed by the private key of the Agent.
- `timestamp`: Unix timestamp of when the Authentication was signed
- `validUntil` (optional): Unix timestamp of when the Authentication should be no longer valid. If not provided, the server will default to 30 seconds from the `timestamp`.

Here's what a JSON-AD Authentication Resource looks like for a WebSocket:

```json
{
  "https://atomicdata.dev/properties/auth/agent": "http://example.com/agents/N32zQnZHoj1LbTaWI5CkA4eT2AaJNBPhWcNriBgy6CE=",
  "https://atomicdata.dev/properties/auth/requestedSubject": "wss://example.com/ws",
  "https://atomicdata.dev/properties/auth/publicKey": "N32zQnZHoj1LbTaWI5CkA4eT2AaJNBPhWcNriBgy6CE=",
  "https://atomicdata.dev/properties/auth/timestamp": 1661757470002,
  "https://atomicdata.dev/properties/auth/signature": "19Ce38zFu0E37kXWn8xGEAaeRyeP6EK0S2bt03s36gRrWxLiBbuyxX3LU9qg68pvZTzY3/P3Pgxr6VrOEvYAAQ=="
}
```

## Atomic Cookies Authentication

In this approach, the client creates and signs a Resource that proves that an Agent wants to access a certain server for some amount of time.
This Authentication Resource is stored as a cookie, and passed along in every HTTP request to the server.

### Setting the cookie

1. Create a signed Authentication object, as described above.
2. Serialize it as JSON-AD, then as a base64 string.
3. Store it in a Cookie:
   1. Name the cookie `atomic_session`
   2. The expiration date of the cookie should be set, and should match the expiration date of the Authentication Resource.
   3. Set the `Secure` attribute to prevent Man-in-the-middle attacks over HTTP

## Bearer Token Authentication

Similar to creating the Cookie, except that we pass the base64 serialized Authentication Resource as a Bearer token in the `Authorization` header.

```http
GET /myResource HTTP/1.1
Authorization: Bearer {base64 serialized Authentication Resource}
```

In Data Browser, you can find the `token` tab in `/app/token` to create a token.

## Authenticating Websockets

After [opening a WebSocket connection](websockets.md), create an Authentication Resource.
Send a message like so: `AUTHENTICATE {authenticationResource}`.
The server will only respond if there is something wrong.

## Per-Request Signing

Atomic Data allows **signing every HTTP request**.
This method is most secure, since a MITM attack would only give access to the specific resource requested, and only for a short amount of time.
Note that signing every single request takes a bit of time.
We picked a fast algorithm (Ed25519) to minimize this cost.

### HTTP Headers

All of the following headers are required, if you need authentication.

- `x-atomic-public-key`: The base64 public key (Ed25519) of the Agent sending the request
- `x-atomic-signature`: A base64 signature of the following string: `{subject} {timestamp}`
- `x-atomic-timestamp`: The current time (when sending the request) as milliseconds since unix epoch
- `x-atomic-agent`: The subject URL of the Agent sending the request.

### Sending a request

Here's an example (js) client side implementation with comments:

```ts
// The Private Key of the agent is used for signing
// https://atomicdata.dev/properties/privateKey
const privateKey = "someBase64Key";
const timestamp = Math.round(new Date().getTime());;
// This is what you will need to sign.
// The timestmap is to limit the harm of a man-in-the-middle attack.
// The `subject` is the full HTTP url that is to be fetched.
const message = `${subject} ${timestamp}`;
// Sign using Ed25519, see example implementation here: https://github.com/atomicdata-dev/atomic-data-browser/blob/30b2f8af59d25084de966301cb6bd1ed90c0eb78/lib/src/commit.ts#L176
const signed = await signToBase64(message, privateKey);
// Set all of these headers
const headers = new Headers;
headers.set('x-atomic-public-key', await agent.getPublicKey());
headers.set('x-atomic-signature', signed);
headers.set('x-atomic-timestamp', timestamp.toString());
headers.set('x-atomic-agent', agent?.subject);
const response = await fetch(subject, {headers});
```

## Verifying an Authentication

- If none of the `x-atomic` HTTP headers are present, the server assigns the [PublicAgent](https://atomicdata.dev/agents/publicAgent) to the request. This Agent represents any guest who is not signed in.
- If some (but not all) of the `x-atomic` headers are present, the server will return with a `500`.
- The server must check if the `validUntil` has not yet passed.
- The server must check whether the public key matches the one from the Agent.
- The server must check if the signature is valid.
- The server should check if the request resource can be accessed by the Agent using [hierarchy](hierarchy.md) (e.g. check `read` right in the resource or its parents).

## Hierarchies for authorization

Atomic Data uses [Hierarchies](hierarchy.md) to describe who gets to access some resource, and who can edit it.

## Limitations / considerations

- Since we need the Private Key to sign Commits and requests, the client should have this available. This means the client software as well as the user should deal with key management, and that can be a security risk in some contexts (such as a web browser). [See issue #49](https://github.com/ontola/atomic-data-docs/issues/49).
- When using the Agent's subject to authenticate somewehere, the authorizer must be able to check what the public key of the agent is. This means the agent must be publicly resolvable. This is one of the reasons we should work towards a server-independent identifier, probably as base64 string that contains the public key (and, optionally, also the https identifier). See [issue #59 on DIDs](https://github.com/ontola/atomic-data-docs/issues/59).
- We'll probably also introduce some form of token-based-authentication created server side in the future. [See #87](https://github.com/ontola/atomic-data-docs/issues/87)
