{{#title @tomic/lib: The Atomic Data library for typescript/javascript}}

# @tomic/lib: The Atomic Data library for typescript/javascript

Core typescript library for creating and editing data locally, signing Commits, [syncing](sync.md) with servers and peers, handling JSON-AD parsing, full-text search and more.

Runs in most common JS contexts like the browser, node, deno, bun etc.
A server is optional: a `Store` with only an Agent can mint identifiers, create Drives and save signed edits on its own, and connect to a server later.
The [local-first guide](local-first-guide/1-index.md) walks through that path end to end; the snippets below show the shortest route when you already have a server.

## Installation

Install using your preferred package manager:

```sh
npm install @tomic/lib
pnpm add @tomic/lib
deno add npm:@tomic/lib
```

### Create a Store

```ts
import { Store, Agent, core } from '@tomic/lib';

const store = new Store({
  // You can create a secret from the `User settings` page using the AtomicServer UI
  agent: Agent.fromSecret('my-secret-key'),
  // Optional. Leave it out to work locally and call store.setServerUrl() later.
  serverUrl: 'https://my-atomic-server.dev',
});
```

### Fetching a resource and reading its data

```ts
// When the class is known.
const resource = await store.getResource<Person>('https://my-atomic-server.dev/some-resource');
const job = resource.props.job;

// When the class is unknown
const resource = await store.getResource('https://my-atomic-server.dev/some-resource');
const job = resource.get(myOntology.properties.job);
```

### Editing a resource

```ts
resource.set(core.properties.description, 'Hello World');

// Sign the change and apply it locally. If a server is connected it is sent
// right away; otherwise it waits in the outbox until one is.
await resource.save();
```

### Creating a new resource

```ts
const newResource = await store.newResource({
  isA: myOntology.classes.person,
  propVals: {
    [core.properties.name]: 'Jeff',
  },
});

// Sign the genesis and save. The subject is a atomic: identifier minted here.
await newResource.save();
```

### Subscribing to changes

```ts
// --------- Subscribe to changes ---------
const unsub = store.subscribe('https://my-atomic-server.dev/some-resource', resource => {
  // Called for every change: your own local edits, and edits arriving from
  // other devices over the sync connection.
  // Do something with the changed resource...
});
```

## What's next?

Next check out [Store](./js-lib/store.md) to learn how to set up a store and fetch data.

If you rather want to see a step-by-step guide on how to use the library in a project check out the [Astro + AtomicServer Guide](astro-guide/1-index.md)
