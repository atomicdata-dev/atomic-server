{{#title Atomic Data Invitations - Sharing using Tokens }}
# Invitations & Tokens

([Discussion](https://github.com/ontola/atomic-data/issues/23))

At some point on working on something in a web application, you're pretty likely to share that, often not with the entire world.
In order to make this process of inviting others as simple as possible, we've come up with an Invitation standard.

## Design goals

- **Edit without registration**. Be able to edit or view things without being required to complete a registration process.
- **Share with a single URL**. A single URL should contain all the information needed.
- **Stateless**. Invitations are self-contained signed tokens. The server does not need to store invite state.

## Flow

1. The Owner of a resource creates an invite token. This token is signed with the owner's private key and contains the `target` resource, optional `write` rights, an expiration timestamp and, optionally, a usage limit (`https://atomicdata.dev/properties/invite/usagesLeft`: the number of different agents that may accept it).
1. The token is encoded into a URL: `/invites?token={token}&public-key={publicKey}`.
1. The Guest opens the invite URL. If the guest provides a `public-key` query parameter, the server derives a DID-based Agent (`atomic:{publicKey}`) from that key.
1. The server verifies the token signature, grants the requested rights to the guest's Agent, and responds with a Redirect to the `target` resource.
1. The Guest will now be able to access the Resource.

## Limitations and gotcha's

- Invite tokens are signed by the issuer. If the issuer loses write access to the target resource, previously issued tokens will fail when redeemed.
- Tokens have an expiration timestamp. Expired tokens are rejected.
- A usage limit is part of the signed token, so it cannot be raised afterwards. The server records which agents accepted a token and rejects further agents with "This invite has no usages left" once the limit is reached. An agent that already accepted can open the link again without using a place. The count lives on the server that accepts the invite, so a drive that is available on several servers counts per server. Invites for drives that sync directly between browsers never reach a server and cannot be limited.
