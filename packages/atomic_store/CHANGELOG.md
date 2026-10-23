## Unreleased

* `Resource.moveTo`; `set` stores a `String` as a link for `Props.parent` and
  `Props.isA` (`Props.linkProperties`).
* `JsonValue.strings` / `.encode` / `.data`, `Resource.setStrings`,
  `getStrings`, `setJson`, `getJson`.
* `search(isA:)` and `watchChildren(isA:)`. `StoreBackend.search` takes `isA`.
* `InMemoryBackend.search` scopes by ancestry and fills `className`, `drive`
  and `title` like the real index.

## 0.1.0

* `Store` and `Resource` over an injectable `StoreBackend`: `getResource`,
  `search`, `createDrive`, `newResource`, `watch`/`subscribe`; `Resource.get`,
  `set`, `remove`, `save`, `isA`, `children`.
* Typed `Value`s and `StoreException` kinds; `InMemoryBackend` for tests.
