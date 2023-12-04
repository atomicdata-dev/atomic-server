# Atomic Suggestions

Atomic Suggestions is a proposed standard that enables decentralized collaboration on resources.
It's basically Git for linked data.
Practically, it should enable right-clicking on any piece of Atomic Data on the web, and suggesting an edit to the owner.

## Design goals

- **Asynchronous collaboration**: Various users can work on the same thing at the same time.
- **Branching & merging**: Issues that result from async changes (merge conflicts) can be resolved.

## Concepts

### Fork

Forking is the first step to making a suggestion.
Forking refers to:

1. copying some resource
1. changing the subject URL to some URL that you control
1. adding a reference to the original URL using the `atomic:originalSubject` Property.

The newly created copy with the different URL is a _Fork_.
Since the Fork is a resource that you own (see [Ownership](ownership.md)), you can make changes to is.

Whenever you make changes, the app making the changes _should_ keep track of them as Atomic Commits.
These Commits make it easier to apply (small) changes to (large) resources, even when multiple people are working on the same thing at the same time.

### Suggestion

When you've forked some resource and made some changes, you can Suggest these changes to the original owner.
This is done by sending an HTTP POST request containing the Commits to the Owner URL.

A Suggestion is a (set of?) Commit(s?) that is proposed to be appended to some Ledger.
The important difference between a Suggestion and a Commit, is that a Commit has been verified, signed and approved by the Controller.

### Controller

The actor (person / organization) that is in control of a specific Resource and its Commits.

### Inbox

An Inbox represents a resource that contains incoming Suggestions.
It's similar to an e-mail inbox.
