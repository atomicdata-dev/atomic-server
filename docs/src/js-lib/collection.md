# Collection & CollectionBuilder

The `Collection` class is a wrapper around a [collection](../schema/collections.md), these are Atomics way of querying large amounts of data.

Collections consist of two main components, a 'property' and a 'value'.
They collect all resources that have the specified property with the specified value.
Currently, it is only possible to query one property value pair at a time.

## Creating Collections

The `CollectionBuilder` class is used to create new Collections.

```typescript
import { CollectionBuilder, core } from '@tomic/lib';

const collection = new CollectionBuilder(store)
  .setProperty(core.properties.isA)
  .setValue(core.classes.agent)
  .build();
```

Additionally, some parameters can be set on the CollectionBuilder to further refine the query

```typescript
const collection = new CollectionBuilder(store)
  .setProperty(core.properties.isA)
  .setValue(core.classes.agent)
  .sortBy(core.properties.name) // Sort the results on the value of a specific property.
  .setSortDesc(true) // Sort the results in descending order.
  .setPageSize(100) // Set the amount of results per page.
  .build();
```

When a collection is created this way it might not have all data right away.

For example, reading the `.totalMembers` property is only available after the first page is fetched.
To make sure the first page is fetched you should await `collection.waitForReady()`.
Alternatively, you could use `await collectionBuilder.buildAndFetch()` instead of `.build()`.

## Reading data

There are many ways to get data from a collection.

If you just want an array of all members in the collection use `.getAllMembers()`.

```typescript
const members = await collection.getAllMembers();
```

Get a member at a specific index using `.getMemberWithIndex()`.

```typescript
const member = await collection.getMemberWithIndex(8);
```

Get all members on a specific page using `.getMembersOnPage()`.
This is very useful for building paginated layouts.

```typescript
function renderPage(page: number) {
  const members = await collection.getMembersOnPage(page);
  // Render the members
}
```

Collection can also act as an async iterable, which means you can use it in a for-await loop.

```typescript
const resources: Resource = [];

for await (const member of collection) {
  resources.push(await store.getResource(member));
}
```

## Caveats

Some things to keep in mind when using collections:

- Unlike normal resources, you can't subscribe to a collection. You can refresh the collection using `.refresh()`.
- There is currently no support for multiple property-value pairs on a single collection. You might be able to manage by filtering the results further on the client.
