{{#title Atomic Data and Verifiable Credentials / SSI}}
# Atomic Data and Verifiable Credentials / SSI

## What are Verifiable Credentials / Self-Sovereign Identity

Verifiable Credentials are pieces of information that have cryptographic proof by some reliable third party.
For example, you could have a credential that proves your degree, signed by your education.
These credentials an enable privacy-friendly transactions where a credential owner can prove being part of some group, without needing to actually identify themselves.
For example, you could prove that you're over 18 by showing a credential issued by your government, without actually having to show your ID card with your birthdate.
Verifiable Credentials are still not that widely used, but various projects exists that have had moderate success in implementing it.

## What makes Atomic Data suitable for this

Firstly, [Atomic Commit](../commits/intro.md) are already verifiable using signatures that contain all the needed information.
Secondly, [Atomic Schema](../schema/intro.md) can be used for standardizing Credential Schemas.

## Every Atomic Commit is a Verifiable Credential

Every time an Agent updates a Resource, an [Atomic Commit](../commits/intro.md) is made.
This Commit is cryptographically signed by an Agent, just like how Verfifiable Credentials are signed.
In essence, this means that _all atomic data created through commits is fully verifiable_.

How could this verification work?

- **Find the Commit** that has created / edited the value that you want to verify. This can be made easier with a specialized Endpoint that takes a `resource`, `property` and `signer` and returns the associated Commit(s).
- **Check the signer of the Commit**. Is that an Agent that you trust?
- **Verify the signature** of the Commit using the public key of the Agent.

Sometimes, credentials need to be revoked.
How could revocation work?

- **Find the Commit** (see above)
- **Get the signer** (see above)
- **Find the `/isRevoked` Endpoint of that signer**, send a Request there to make sure the linked Commit is still valid and not revoked.

([Discussion](https://github.com/ontola/atomic-data-docs/issues/22))

## Use Atomic Schema for standardizing Credentials

If you are a Verifier who wants to check someone's _birthdate_, you'll probably expect a certain datatype in return, such as a [date](https://atomicdata.dev/datatypes/date) that is formatted in some specific way.
[Atomic Schema](../schema/intro.md) makes it possible to express which _properties_ are [required](https://atomicdata.dev/properties/requires) in a certain [Class](https://atomicdata.dev/classes/Class), and it also makes it possible to describe which [datatype](https://atomicdata.dev/classes/Datatype) is linked to a specific [Property](https://atomicdata.dev/classes/Property).
Combined, they allow for fine-grained descriptions of models / classes / schemas.
