# Store

The `Store` class is a central component in the @tomic/lib library that provides a convenient interface for managing and interacting with atomic data resources. It allows you to fetch resources, subscribe to changes, create new resources, perform full-text searches, and more.

## Setting up a store

Creating a store is done with the Store constructor.

```typescript
const store = new Store();
```

It takes an object with the following options

| Name      | Type                | Description                                                                                                                              |
|-----------|---------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| serverUrl | string              | **(optional)** URL of the always-on device to sync with. Without it the store works locally; set one later with `setServerUrl()` |
| agent     | [Agent](./agent.md) | **(optional)** The agent the store should use to fetch resources and to sign commits when editing resources, defaults to a public agent |
| connect   | boolean             | **(optional)** Open a WebSocket to `serverUrl` right away. Defaults to `true` |

```typescript
const store = new Store({
  serverUrl: 'https://my-atomic-server.com',
  agent: Agent.fromSecret('my-agent-secret'),
});
```

> [!NOTE]
> You can always change or set both the serverUrl and agent at a later time using `store.setServerUrl()` and `store.setAgent()` respectively.

### A store without a server

A store with an Agent and no `serverUrl` is a complete [local-first](../local-first.md) client: it mints `atomic:` identifiers, creates Drives, signs edits and keeps them in an outbox.

```typescript
const store = new Store({ agent });

const drive = await store.createDrive('Notes', { localOnly: true });
store.setDrive(drive.subject);
```

`localOnly` keeps the sync engine from offering the Drive to a server you connect later; lift it with `store.promoteLocalDrive(drive.subject)` once you want it replicated.
To keep data across reloads attach the WASM client database with `store.setClientDb()`; the [local-first guide](../local-first-guide/4-persist.md) shows the setup.
Sync status (connected, pending edits, last drive sync) is on `store.getSyncStatus()` and the `StoreEvents.SyncStatusChanged` event.

### One vs Many Stores

Generally in a client application with one authenticated user, you'll want to have a single instance of a `Store` that is shared throughout the app.
This way you'll never fetch resources more than once while still receiving updates via websocket messages.
If `store` is used on the server however, you might want to consider creating a new store for each request as a store can only have a single agent associated with it and changing the agent will reauthenticate all websocket connections.

## Fetching resources

> [!NOTE]
> If you're using atomic in a frontend library like React or Svelte there might be other ways to fetch resources that are better suited to those libraries. Check [@tomic/react](../usecases/react.md) or [@tomic/svelte](../svelte.md)

Fetching resources is generally done using the `store.getResource()` method.

```typescript
const resource = await store.getResource('https://my-resource-subject');
```

`getResource` takes the [subject](../core/concepts.md#subject-field) of the resource as a parameter and returns a promise that resolves to the requested resource.
The subject can be an `https://` URL or a `atomic:` identifier; see [URLs and identifiers](../urls.md).
The store answers from memory, then from the local database if one is attached, and only then fetches from the server. It subscribes to changes, so subsequent requests return the cached version and updates arrive through the sync connection.

## Subscribe to changes

Atomic makes it easy to build real-time applications.
When you subscribe to a subject you get notified every time the resource changes: by your own code, or by another device whose edit arrived through sync.

```typescript
store.subscribe('https://my-resource-subject', myResource => {
  // do something with the changed resource.
  console.log(`${myResource.title} changed!`);
});
```

### Unsubscribing

You should not forget to unsubscribe your listeners as this can lead to a growing memory footprint (just like DOM event listeners).
To unsubscribe you can either use the returned unsubscribe function or call `store.unsubscribe(subject, callback)`.

```typescript
const unsubscribe = store.subscribe(
  'https://my-resource-subject',
  myResource => {
    // ...
  },
);

unsubscribe();
```

```typescript
const callback = myResource => {
  // ...
};

store.subscribe('https://my-resource-subject', callback);

store.unsubscribe('https://my-resource-subject', callback);
```

## Creating new resources

Creating resources is done using the `store.newResource` method.
It takes an options object with the following properties:

| Name     | Type                      | Description                                                                                                                       |
|----------|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| subject  | string                    | **(optional)** The subject the new resource should have. By default a `atomic:` identifier is minted from a genesis certificate signed by the store's Agent |
| parent   | string                    | **(optional)** The parent of the new resource, defaults to the store's `serverUrl`. Pass the Drive or folder it belongs in       |
| isA      | string \| string[]        | **(optional)** The 'type' of the resource. determines what class it is. Supports multiple classes.                                |
| propVals | Record<string, JSONValue> | **(optional)** Any additional properties you want to set on the resource. Should be an object with subjects of properties as keys |

```typescript
// Basic:
const resource = await store.newResource();

await resource.save();
```

```typescript
// With options:
import { core } from '@tomic/lib';

const resource = await store.newResource({
  parent: 'https://myatomicserver.com/some-folder',
  isA: 'https://myatomicserver.com/article',
  propVals: {
    [core.properties.name]: 'How to create new resources',
    [core.properties.description]: 'lorem ipsum dolor sit amet',
    'https://myatomicserver.com/written-by':
      'https://myatomicserver.com/agents/superman',
  },
});

await resource.save();
```

## Choosing a subject

`store.newResource()` gives a resource its final subject when it is created, before it is saved.
For a DID agent that is a `atomic:` derived from a signed genesis certificate; otherwise it is a random subject under the parent.
There is no separate step to reserve a subject first: create the resource and read `resource.subject`.
`store.createSubject()`, which returned a temporary subject that was renamed on first save, is deprecated.

```typescript
const resource = await store.newResource({ parent: parent.subject, isA: core.classes.folder });
resource.subject; // final, also after resource.save()
```

> [!WARNING]
> Keep in mind that subjects never change once they are set, even if the parent changes.
> This means you can't reliably infer the parent from the subject.

## Full-Text Search

AtomicServer comes included with a full-text search API.
Using this API is very easy in @tomic/lib.

```typescript
const results = await store.search('lorem ipsum');
```

To further refine your query you can pass an options object with the following properties:

| Name    | Type                   | Description                                                                                                                                       |
|---------|------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| include | boolean                | **(optional)** If true sends full resources in the response instead of just the subjects                                                          |
| limit   | number                 | **(optional)** The max number of results to return, defaults to 30.                                                                               |
| parents | string[]               | **(optional)** Only include resources that have these given parents somewhere as an ancestor                                                      |
| filters | Record<string, string> | **(optional)** Only include resources that have matching values for the given properties. Should be an object with subjects of properties as keys |

Example: search AtomicServer for all files with 'holiday-1995' in their name:

```typescript
import { core, server } from '@tomic/lib';

const results = store.search('holiday-1995', {
  filters: {
    [core.properties.isA]: server.classes.file,
  },
});
```

## Preloading resources

Sometimes you might want to prefetch a resource and all the resources it depends on ahead of time.
For example when using @tomic/react or @tomic/svelte on the server.
This can be done using the `store.preloadResourceTree()` method.
The method takes a subject and an object representing a tree of referenced resources that need to be preloaded.

```js

// Preload a blog post, its header image, the author and the author's profile image
await store.preloadResourceTree('https://myapp.com/my-blog-post', {
  [myOntology.properties.headerImage]: true,
  [myOntology.properties.author]: {
    [myOntology.properties.profileImage]: true,
  },
});
```

The tree does not have to be complete and can contain any property, this way you can preload any resource even if you're not sure of what type it might be.

## Events

Store emits a few types of events that your app can listen to.

To listen to these events use the `store.on` method.

```typescript
import { StoreEvents } from '@tomic/lib';

store.on(StoreEvents.Error, error => {
  notifyErrorReportingServer(error);
});
```

The following events are available

| Event ID                      | Handler type                 | Description                                |
|-------------------------------|------------------------------|--------------------------------------------|
| `StoreEvents.ResourceSaved`   | (resource: Resource) => void | Fired when any resource was saved          |
| `StoreEvents.ResourceRemoved` | (resource: Resource) => void | Fired when any resource was deleted        |
| `StoreEvents.AgentChanged`    | (agent: Agent) => void       | Fired when a new agent is set on the store |
| `StoreEvents.Error`           | (error: Error) => void       | Fired when store encounters an error       |

## (Advanced) Fetching resources in render code

> [!WARNING]
> The following is mostly intended for library authors.

When building frontends it is often critical to render as soon as possible, waiting for requests to finish leads to a sluggish UI.
Store provides the `store.getResourceLoading` method that immediately returns an empty resource with `resource.loading` set to `true`.
You can then subscribe to the subject and rerender when the resource changes.

```jsx
// some component in a hypothetical framework
function renderSomeComponent(subject: string) {
  const resource = store.getResourceLoading(subject);

  store.subscribe(subject, () => {
    rerender();
  });

  return (
    <div>
      <h1>{resource.loading ? 'loading...' : resource.title}</h1>
      <p> other UI that does not rely on the resource being ready</p>
    </div>
  );
}
```

For a real-world example check out how we use it inside [@tomic/react useResource hook](https://github.com/ontola/atomic-server/blob/ff8abb8503c72ef040cbb3f88fdd6c0318c16051/browser/react/src/hooks.ts#L36)
