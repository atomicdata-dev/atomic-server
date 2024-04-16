{{#title @tomic/lib: The Atomic Data library for typescript/javascript}}

# @tomic/lib: The Atomic Data library for typescript/javascript

Core typescript library for fetching data, handling JSON-AD parsing, storing data, signing Commits, setting up WebSockets and full-text search and more.

## Installation

```sh
npm install @tomic/lib
```

## TL;DR

```ts
import { Store, Agent, core } from '@tomic/lib';

// --------- Create a Store ---------.
const store = new Store({
  // You can create a secret from the `User settings` page using the AtomicServer UI
  agent: Agent.fromSecret('my-secret-key'),
  // Set a default server URL
  serverUrl: 'https://my-atomic-server.dev',
});

// --------- Get a resource ---------
const gotResource = await store.getResource(subject);

const atomString = gotResource.get(core.properties.description);

// --------- Create & save a new resource ---------
const newResource = await store.newResource({
  subject: 'https://my-atomic-server.dev/test',
  propVals: {
    [core.properties.description]: 'Hi World :)',
  },
});

await newResource.save();

// --------- Write data to a resource ---------
newResource.set(core.properties.description, 'Hello World');
await newResource.save();

// --------- Subscribe to changes (using websockets) ---------
const unsub = store.subscribe('https://my-atomic-server.dev/test', resource => {
  // This callback is called each time a change is made to the resource client or serverside.
  // Do something with the changed resource...
});
```

## What's next?

Next check out [Store](./js-lib/store.md) to learn how to set up a store and fetch data.
Or read the [Generated Typedocs](https://atomic-lib.netlify.app/modules/_tomic_lib)

If you rather want to see a step-by-step guide on how to use the library in a project check out the [Astro + AtomicServer Guide](<javascript:alert('TODO: Add link');>)
