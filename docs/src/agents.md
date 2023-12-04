{{#title Atomic Data Agents - Users and identities }}
# Atomic Agents

Atomic Agents are used for [authentication](./authentication.md): to set an identity and prove who an actor actually is.
Agents can represent both actual individuals, or machines that interact with data.
Agents are the entities that can get write / read rights.
Agents are used to sign Requests and [Commits](commits/intro.md) and to accept [Invites](invitations.md).

## Design goals

- **Decentralized**: Atomic Agents can be created by anyone, at any domain
- **Easy**: It should be easy to work with, code with, and use
- **Privacy-friendly**: Agents should allow for privacy friendly workflows
- **Verifiable**: Others should be able to verify who did what
- **Secure**: Resistant to attacks by malicious others

## The Agent model

_url: https://atomicdata.dev/classes/Agent_

An Agent is a Resource with its own URL.
When it is created, the one creating the Agent will generate a cryptographic (Ed25519) keypair.
It is _required_ to include the [`publicKey`](https://atomicdata.dev/properties/publicKey) in the Agent resource.
The [`privateKey`](https://atomicdata.dev/properties/privateKey) should be kept secret, and should be safely stored by the creator.
For convenience, a `secret` can be generated, which is a single long string of characters that encodes both the `privateKey` and the `subject` of the Agent.
This `secret` can be used to instantly, easily log in using a single string.

The `publicKey` is used to verify commit signatures by that Agent, to check if that Agent actually did create and sign that Commit.

## Creating an Agent

Since an Agent is used for verification of commits, the Agent's `subject` should resolve and be publicly available.
This means that the one creating the Agent has to deal with this.
One way of doing this, is by hosting an [Atomic Server](https://crates.io/crates/atomic-server).
An easier way of doing this, is by accepting an [Invite](invitations.md) that exists on someone else's server.
