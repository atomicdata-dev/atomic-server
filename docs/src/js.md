{{#title @tomic/lib: The Atomic Data library for typescript/javascript}}
# @tomic/lib: The Atomic Data library for typescript/javascript

[**docs**](https://atomic-lib.netlify.app/modules/_tomic_lib)

Core typescript library for fetching data, handling JSON-AD parsing, storing data, signing Commits, setting up WebSockets and more.

## Basic usage

```sh
# Add it to your JS / TS project
npm install @tomic/lib
```

```ts
import { Store, Agent, core } from "@tomic/lib";

// --------- Create a Store ---------.
const store = new Store({
  // You can create a secret from the `User settings` page using the AtomicServer UI
  agent: Agent.fromSecret("my-secret-key"),
  // Set a default server URL
  serverUrl: "https://my-atomic-server.dev",
});

// --------- Get a resource ---------
const gotResource = await store.getResourceAsync(subject);

const atomString = gotResource.get(core.properties.description)

// --------- Create & save a new resource ---------
const newResource = await store.newResource({
  subject: 'https://my-atomic-server.dev/test',
  propVals: {
    [core.properties.description]: 'Hi World :)'
  }
});

await newResource.save(store);

// --------- Subscribe to changes (using websockets) ---------
const unsub = store.subscribe('https://my-atomic-server.dev/test', (resource) => {
  // This callback is called each time a change is made to the resource client or serverside.

  // Do something with the changed resource...
})
```

## Advanced usage

See the [Atomic Data Browser codebase](https://github.com/atomicdata-dev/atomic-server/tree/develop/browser) for examples or read the [**docs**](https://atomic-lib.netlify.app/modules/_tomic_lib)!
