{{#title Atomic Data Invitations - Sharing using Tokens }}
# Invitations & Tokens

([Discussion](https://github.com/ontola/atomic-data/issues/23))

At some point on working on something in a web application, you're pretty likely to share that, often not with the entire world.
In order to make this process of inviting others as simple as possible, we've come up with an Invitation standard.

## Design goals

- **Edit without registration**. Be able to edit or view things without being required to complete a registration process.
- **Share with a single URL**. A single URL should contain all the information needed.
- **(Un)limited URL usage**. A URL might be re-usable, or maybe not.

## Flow

1. The Owner or a resource creates an [Invite](https://atomicdata.dev/classes/Invite). This Invite points to a `target` Resource, provides `read` rights by default but can additionally add `write` rights, contains a bunch of `usagesLeft`.
1. The Guest opens the Invite URL. This returns the Invite resource, which provides the client with the information needed to do the next request which adds the actual rights.
1. The browser client app might generate a set of keys, or use an existing one. It sends the Agent URL to the Invite in a query param.
1. The server will respond with a Redirect resource, which links to the newly granted `target` resource.
1. The Guest will now be able to access the Resource.

Try it on [https://atomicdata.dev/invites/1](https://atomicdata.dev/invites/1)

## Limitations and gotcha's

- The one creating the Invite has to take security in consideration. Some URLs can be easily guessed! When implementing Invitations, make sure to use a good amount of randomness when creating the Subject.
- Make sure that the invite is not publicly discoverable (e.g. through a Collection), this can happen if you set the `parent` of the invite to a public resource.
