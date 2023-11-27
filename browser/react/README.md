# @tomic/react: The Atomic Data library for React

A library for viewing and creating Atomic Data.
Re-exports `@tomic/lib`.

[**demo + template on codesandbox**!](https://codesandbox.io/s/atomic-data-react-template-4y9qu?file=/src/MyResource.tsx:0-1223)

[**docs**](https://atomic-lib.netlify.app/modules/_tomic_react)

## Setup

When initializing your App, initialize the store, which will contain all data.
Wrap your App in a `StoreContext.Provider`, and pass the newly initialized store to it.

```ts
// App.tsx
import { StoreContext, Store } from "@tomic/react";
import { MyResource } from "./MyResource";

// The store contains all the data for
const store = new Store();

export default function App() {
  return (
    <StoreContext.Provider value={store}>
      <MyResource subject={subject} />
    </StoreContext.Provider>
  );
}
```

Now, your Store can be accessed in React's context, which you can use the `atomic-react` hooks!

## Hooks

### useResource, useString, useTitle

```ts
// Get the Resouce, and all its properties
const resource = useResource('https://atomicdata.dev/classes/Agent');
// The title takes either the Title, the Shortname or the URL of the resource
const title = useTitle(resource);
// All useValue / useString / useArray / useBoolean hooks have a getter and a setter.
// Use the setter in forms.
const [description, setDescription] = useString(resource, 'https://atomicdata.dev/properties/description');
// The current Agent is the signed in user, inluding their private key. This enables you to create Commits and update data on a server.
const [agent, setAgent] = useCurrentAgent();

return (
  <>
    <h1>{title}</h2>
    <textarea value={description} onChange={e => setDescription(e.target.value)} />
    <button type={button} onClick={resource.save}>Save & commit</button>
  </>
)

```
