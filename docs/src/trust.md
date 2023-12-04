# Atomic Trust

_status: just an idea_

Not all information on the web can be trusted.
Instead of relying on some centralized authority to say which content is to be trusted, we can leverage our existing trust networks to determine what we can trust or not.

Atomic Trust is a specification to share which actors, domains and resources we trust on the web.
It's a decentralized model defined with Atomic Schema to create explicit trust networks.
It can be used to calculate a score about a resource (such as a webpage).

## How it works

When you view some resource (e.g. a news article on some website), your client (e.g. a browser plugin) checks your _trusted peers_ to find whether they (or their peers) have a _rating_ about that _resource_.

## Concepts

### ResourceRating

A ResourceRating describes how an Actor (e.g. a person) rates some Resource (e.g. a specific article).

Properties:

- about: The resource that is being rated
- ratedBy: The actor (Person or Organization) rating the resource
- score: Number between -1 and 1. 1 is "Very trustworthy", 0 is "neutral" and -1 is "very untrustworthy".
- comment: A string that describes the _why_.

### DomainRating

A DomainRating describes how an Actor (e.g. a person) rates some Resource (e.g. a specific article).

Same props as ResourceRating.

### Actor

The individual that creates the rating.

Properties

- ratingList: A Collection of ratings
