# Step 2: a Store and a Drive, with no server

A `Store` is the in-memory graph your app reads and writes.
It used to need a `serverUrl`; now that is optional.
Give it the Agent from step 1 and it can create, sign and edit data on its own.

```ts
import { Store, core } from '@tomic/lib';

const store = new Store({ agent });
```

## Create a Drive

A [Drive](../hierarchy.md) is the top-level container: the unit that gets shared, synced and backed up.
Every Agent has a *personal* Drive whose identifier is derived from the Agent's key, so the same identity gets the same Drive on every device without anything to look up.

```ts
const drive = await store.createDrive('Reading list', { localOnly: true });
store.setDrive(drive.subject);

console.log(drive.subject); // atomic:…
```

`localOnly: true` tells the sync engine to leave this Drive alone even if a server is connected later.
You will lift that in step 4.
Without it, the Store would try to offer the Drive to whatever server it connects to, which is the right default for an app that always has one.

## Create and edit Resources

A Book is a Resource with a name and a description.
This guide reuses two Properties from the core vocabulary so it needs no schema of its own; a real app defines its own Classes and Properties in the [ontology editor](../atomicserver/gui.md) and generates types with [`@tomic/cli`](../js-cli.md).

```ts
async function addBook(title: string, note: string) {
  const book = await store.newResource({
    parent: drive.subject,
    propVals: {
      [core.properties.name]: title,
      [core.properties.description]: note,
    },
  });

  await book.save();

  return book;
}

const book = await addBook('The Dispossessed', 'Recommended by Anna');
console.log(book.subject); // atomic:… (a fresh identifier, minted here)
```

`newResource` mints a `atomic:` identifier from a genesis certificate signed by your Agent.
`save()` writes to the Resource's Loro document, marks it dirty in the outbox, and applies it locally at once.
There is no server to wait for, so the Promise resolves as soon as the local write is done.

Editing is the same call:

```ts
book.set(core.properties.description, 'Recommended by Anna. Finished it in a weekend.');
await book.save();
```

## Read and subscribe

```ts
const same = await store.getResource(book.subject);
console.log(same.get(core.properties.name)); // The Dispossessed

const unsubscribe = store.subscribe(book.subject, updated => {
  render(updated.get(core.properties.description));
});
```

`subscribe` fires for local edits now, and for edits arriving from other devices once you sync.
The callback does not care which.

## What you have

An identity, a Drive and a Book, all signed, all created without a network request.
Reload the page, though, and the Store starts empty again: this step keeps everything in memory.
Fixing that is the next step.

Next: [persisting across reloads](4-persist.md).
