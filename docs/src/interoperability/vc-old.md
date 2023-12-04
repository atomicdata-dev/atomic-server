# Atomic Data and Verifiable Credentials

Verifiable Credentials are pieces of information that have cryptographic proof by some reliable third party.
For example, you could have a credential that proves your degree, signed by your education.
These credentials an enable privacy-friendly transactions where a credential owner can prove being part of some group, without needing to actually identify themselves.
For example, you could prove that you're over 18 by showing a credential issued by your government, without actually having to show your ID card with your birthdate.
Verifiable Credentials are still not that widely used, but various projects exists that have had moderate success in implementing it.

In Atomic Data, _all information created with Atomic Commits is verifiable_.
Atomic Commits are signed by specific individuals, and these signatures can be verified with the Public Key from the Agent who signed the Commit.

## W3C Verifiable Credentials spec

The W3C Verifiable Credentials (W3CVC) specification has helped to create a spec to describe credentials.
However, the approach is fundamentally different from how Atomic Data works.
In the W3CVC spec, every credential is a resource.
In Atomic Data, having a new type of `Credential` class that maps to W3CVC Credentials is definitely possible, but it is also highly redundant, as Commits already provide the same information.
That's why we've opted for only signing Commits.

In Atomic Commits, the _change in information_ is signed, instead of the _state_ of the data.
This is by design, as storing signed state changes allows for fully verifiable and reversible history / version control with audit logs.

## Verifying data with Atomic Commits

If you want to know whether a specific value that you see is signed by a specific Agent, you need to find the Commit that created the value.

This can be achieved by using a Collection.
The easiest way to do this, is by using the [`/all-versions` Endpoint](https://atomicdata.dev/all-versions) and finding the Signer of the version that is relevant to your question.

In the near future, we will introduce a `/verify` Endpoint that will allow you to verify a specific value.

Visit the [issue on github](https://github.com/ontola/atomic-data-docs/issues/22) to join the discussion about this subject.
