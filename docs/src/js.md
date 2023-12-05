{{#@tomic/lib: The Atomic Data library for typescript/javascript}}
# @tomic/lib: The Atomic Data library for typescript/javascript

[**docs**](https://atomic-lib.netlify.app/modules/_tomic_lib)

Core typescript library for fetching data, handling JSON-AD parsing, storing data, signing Commits, setting up WebSockets and more.

## Basic usage

```sh
# Add it to your JS / TS project
npm install @tomic/lib
```

```ts
// Import the Store
import { Store, Agent, urls } from "@tomic/lib";

const opts = {
  // You can create a secret from the `User settings` page using the AtomicServer UI
  agent: Agent.fromSecret("my-secret-key"),
  // Set a default server URL
  serverUrl: "https://atomicdata.dev",
}
const store = new Store(opts);

// Get a resource
const gotResource = store.getResourceLoading(subject);
const atomString = gotResource!
  .get(urls.properties.description)!
  .toString();

// Create & save a new resource
const subject = 'https://atomicdata.dev/test';
const newResource = new Resource(subject);
await newResource.set(urls.properties.description, 'Hi world');
newResource.save(store);
```

## Advanced usage

See the [Atomic Data Browser codebase](https://github.com/atomicdata-dev/atomic-server/tree/develop/browser) for examples or read the [**docs**](https://atomic-lib.netlify.app/modules/_tomic_lib)!
