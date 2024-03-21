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
| serverUrl | string              | URL of your atomic server                                                                                                                |
| agent     | [Agent](./agent.md) | **(optional)** The agent the store should use to fetch resources and to sign commits when editting resources, defaults to a public agent |

```typescript
const store = new Store({
  serverUrl: 'https://my-atomic-server.com',
  agent: Agent.fromSecret('my-agent-secret'),
});
```

> **NOTE** </br>
> You can always change or set both the serverUrl and agent at a later time using `store.setServerUrl()` and `store.setAgent()` respectively.

### One vs Many Stores

Generally in a client application with one authenticated user, you'll want to have a single instance of a `Store` that is shared throughout the app.
This way you'll never fetch resources more than once while still receiving updates via websocket messages.
If `store` is used on the server however, you might want to consider creating a new store for each request as a store can only have a single agent associated with it and changing the agent will reauthenticate all websocket connections.

## Fetching resources

> **NOTE:** </br>
> If you're using atomic in a frontend library like React or Svelte there might be other ways to fetch resources that are better suited to those libraries. Check [@tomic/react](../usecases/react.md) or [@tomic/svelte](../svelte.md)

Fetching resources is generally done using the `store.getResource()` method.

```typescript
const resource = await store.getResource('https://my-resource-subject');
```

`getResource` takes the [subject](../core/concepts.md#subject-field) of the resource as a parameter and returns a promise that resolves to the requested resource.
The store will cache the resource in memory and subscribe to the server for changes to the resource, subsequent requests for the resource will not fetch over the network but return the cached version.

## Subscribe to changes

Atomic makes it easy to build real-time applications.
When you subscribe to a subject you get notified every time the resource changes on the server.

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
| subject  | string                    | **(optional)** The subject the new resource should have, by default a random subject is generated                                 |
| parent   | string                    | **(optional)** The parent of the new resource, defaults to the store's `serverUrl`                                                |
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

## (Advanced) Fetching resources in render code

> **NOTE:** </br>
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

For a real-world example check out how we use it inside [@tomic/react useResource hook](https://github.com/atomicdata-dev/atomic-server/blob/ff8abb8503c72ef040cbb3f88fdd6c0318c16051/browser/react/src/hooks.ts#L36)

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
