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

An Agent is identified by an `atomic:agent:{publicKey}` identifier derived from its public key. The legacy `did:ad:agent:{publicKey}` spelling is accepted forever and names the same agent.
When a client generates a keypair, the public key immediately determines the Agent's subject, without needing to register it on a server first.
See the [DID specification](did.md) for details on how agent DIDs work and are resolved.

One way to start using your Agent is by accepting an [Invite](invitations.md) with your public key.
The server will derive the `atomic:agent:` identifier and grant the requested rights.
Alternatively, you can host an [Atomic Server](https://crates.io/crates/atomic-server) and use the `/setup` invite to configure the root Agent.
