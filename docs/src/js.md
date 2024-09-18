{{#title @tomic/lib: The Atomic Data library for typescript/javascript}}

# @tomic/lib: The Atomic Data library for typescript/javascript

Core typescript library for fetching data, handling JSON-AD parsing, storing data, signing Commits, setting up WebSockets and full-text search and more.

Runs in most common JS contexts like the browser, node, bun etc.

## Installation

```sh
npm install @tomic/lib
```

## TL;DR

### Create a Store

```ts
import { Store, Agent, core } from '@tomic/lib';

const store = new Store({
  // You can create a secret from the `User settings` page using the AtomicServer UI
  agent: Agent.fromSecret('my-secret-key'),
  // Set a default server URL
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

// Commit the changes to the server.
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

// Commit the new resource to the server.
await newResource.save();
```

### Subscribing to changes

```ts
// --------- Subscribe to changes (using websockets) ---------
const unsub = store.subscribe('https://my-atomic-server.dev/some-resource', resource => {
  // This callback is called each time a change is made to the resource on the server.
  // Do something with the changed resource...
});
```

## What's next?

Next check out [Store](./js-lib/store.md) to learn how to set up a store and fetch data.
Or read the [Generated Typedocs](https://atomic-lib.netlify.app/modules/_tomic_lib)

If you rather want to see a step-by-step guide on how to use the library in a project check out the [Astro + AtomicServer Guide](<javascript:alert('TODO: Add link');>)
